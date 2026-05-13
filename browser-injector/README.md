# 🛠️ BrowserInjector: Advanced Chromium ABE Bypass & Data Extractor

**BrowserInjector** is a powerful tool for security researchers and Red Team specialists, designed to bypass the **App-Bound Encryption (ABE)** mechanism in Chromium-based browsers (Chrome, Edge, Brave, etc.) and extract sensitive data.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized penetration testing** only. Using this software to attack targets without prior mutual consent is illegal. The developer is not responsible for any damage caused by the misuse of this tool.

---

## 📖 What is App-Bound Encryption?

In recent Chromium versions (starting from 127+), the **App-Bound Encryption** mechanism was introduced. It protects encryption keys (Master Key) using a COM service that verifies the identity of the calling process. This means that traditional "stealers" operating as third-party processes can no longer simply read the `Local State` and decrypt cookies or passwords via DPAPI.

**BrowserInjector** bypasses this protection by injecting a payload directly into the browser's context and using the browser's legitimate COM interfaces for decryption.

---

## ✨ Key Features

- **🚀 ABE (App-Bound Encryption) Bypass**: Leveraging `IElevator` and `IElevator2` COM interfaces to retrieve the master key.
- **🌐 Support for 20+ Browsers**: Including Chrome (Stable, Beta, Dev, Canary), Microsoft Edge, Brave, Opera (Stable, GX), Vivaldi, Yandex, Avast Browser, and many others.
- **🛡️ EDR/AV Evasion**:
  - Use of **Direct Syscalls** to bypass user-mode hooks.
  - Dynamic SSN (System Service Number) resolution.
  - Payload (DLL) encryption using the **ChaCha20** algorithm.
  - **Suspended Process Injection** technique.
- **📊 Extensive Extraction**: Extraction of Cookies, Passwords, Bank Cards, and Autofill data.
- **🔍 Fingerprinting**: Detailed system and browser information gathering.
- **💻 Cross-Architecture**: Support for **x64** and **ARM64** systems.

---

## 🏗️ Project Architecture

The project is divided into several key components:

1.  **Injector (`browser_injector.exe`)**:
    *   Discovers installed browsers.
    *   Terminates running processes (optional).
    *   Creates a new browser process in a suspended state.
    *   Injects the encrypted Payload DLL.
    *   Manages communication via Named Pipes.
2.  **Payload (`chrome_decrypt.dll`)**:
    *   Executes within the browser's context.
    *   Interacts with the browser's COM service for key decryption.
    *   Reads SQLite profile databases.
    *   Sends results back to the injector.
3.  **Encryptor (`tools/encryptor.cpp`)**:
    *   A utility for encrypting the Payload DLL before building the main injector.

---

## 🛠️ Building

### Prerequisites
*   **Windows 10/11**
*   **Visual Studio 2022** (with C++ components and assemblers: `ml64.exe` for x64 or `armasm64.exe` for ARM64).
*   **Windows SDK**.

### Build Process
Use `make.bat` for automatic building:

```cmd
:: Full build of all components
make.bat build_target_only

:: Clean build artifacts
make.bat clean
```

The build result will be `browser_injector.exe` in the root directory.

---

## 🚀 Usage

Run the compiled executable from the command line:

```bash
browser_injector.exe [options] <browser_name | all>
```

### Examples:
- Extract data from all discovered browsers:
  ```bash
  browser_injector.exe all
  ```
- Extract data from Chrome with verbose output:
  ```bash
  browser_injector.exe chrome -v
  ```
- Gather fingerprint and force-kill the browser before extraction:
  ```bash
  browser_injector.exe edge -f -k
  ```

### Available Options:
| Option | Description |
| :--- | :--- |
| `-v`, `--verbose` | Show detailed execution logs. |
| `-f`, `--fingerprint` | Gather system information. |
| `-k`, `--kill` | Terminate browser processes before starting. |
| `-o`, `--output-path` | Specify the path to save results. |

---

## 🌍 Supported Browsers

| Category | Supported Versions / Brands |
| :--- | :--- |
| **Google Chrome** | Stable, Beta, Dev, Canary, Chromium |
| **Microsoft Edge** | Stable, Beta, Dev, Canary |
| **Opera** | Opera Stable, Opera GX |
| **Specialized** | Brave, Vivaldi, Avast Browser, Yandex Browser |
| **Asian Market** | Coc Coc, 360 Safe Browser, 360 Chrome, QQ Browser, Sogou, UC Browser, Baidu |

---

## 🛡️ Technical Details (EDR Evasion)

The tool employs advanced techniques to hide its activity:
- **Syscall Trampolines**: Instead of direct API calls, the project uses custom assembly stubs to execute syscalls, making them impossible to intercept via standard user-mode hooks.
- **Embedded Encrypted Payload**: The core decryption logic is stored in an encrypted state within the injector and is decrypted only in the target process's memory.
- **No CRT dependency in critical parts**: Minimizing the use of standard libraries to reduce the signature profile.

---

## 📜 License

This project is distributed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---
*(c) 2024 Alexander 'xaitax' Hagenah. Enhanced and documented for educational purposes.*
