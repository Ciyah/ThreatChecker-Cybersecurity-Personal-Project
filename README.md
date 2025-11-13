# ThreatChecker
> 🐍 A cross-platform Python CLI tool to automate domain reputation checks using the VirusTotal API.

---

## 💡 About This Project
ThreatChecker is a simple, cross-platform Python tool that automates domain reputation checks by querying the **VirusTotal API**. Built with `requests` and `argparse`, it provides a fast and easy way to get threat intelligence directly from your terminal.

## ✨ Features
* **Automated Lookups:** Instantly check domain reputation.
* **Cross-Platform:** Runs natively on Windows, macOS, and Linux.
* **Simple CLI:** Uses `argparse` for easy-to-use command-line flags.
* **Standalone:** Can be bundled into a single executable for any OS.

## 🛠️ Tech Stack
* **`Python`:** The core language for the script.
* **`requests`:** Used to make HTTP requests to the VirusTotal API.
* **`argparse`:** Used to create the professional command-line interface (handling the `-d` flag).
* **`PyInstaller`:** Used to package the script into a standalone, cross-platform executable.

### Topics
`python` `cybersecurity` `cli` `virustotal` `api` `threat-intelligence` `automation` `security-tool` `cross-platform`

---

## 📖 User Manual

### Setup Instructions
1.  **Install Dependencies:** This script requires the `requests` library.
    ```bash
    python -m pip install requests
    ```
2.  **Set API Key:** You MUST get a free API key from [VirusTotal.com](https://www.virustotal.com/). Paste your new, private key into the `API_KEY` variable in `Script.py`.

### Command Guide
Run this script from your terminal. You must provide a domain using the `-d` or `--domain` flag.

* **Basic Syntax**
    ```bash
    python Script.py -d <domain_to_check>
    ```

* **Examples**
    
    * **Check a safe domain**
    ```bash
    python Script.py -d google.com
    ```

    * **Check a malicious test domain**
    ```bash
    python Script.py -d wicar.org
    ```

---

## 📦 How to Create a Standalone Executable
You can bundle this script into a **single executable** for your operating system so you can run it without needing to install Python.

1.  **Install PyInstaller:**
    ```bash
    python -m pip install pyinstaller
    ```
2.  **Run the build command:**
    PyInstaller will create an executable for the OS you are currently on.

    * **On Windows (.exe):**
        ```bash
        pyinstaller --onefile -n ThreatChecker.exe Script.py
        ```
    * **On macOS or Linux:**
        ```bash
        pyinstaller --onefile -n ThreatChecker Script.py
        ```
3.  **Find  and run your executable:** Your new executable (`ThreatChecker.exe` or `ThreatChecker`) will be inside the new `dist` folder.
    
     * **On Windows**
    ```bash
    .\dist\ThreatChecker.exe -d wicar.org
    ```

    * **On macOS/Linux**
    ```bash
    ./dist/ThreatChecker -d wicar.org
    ```
