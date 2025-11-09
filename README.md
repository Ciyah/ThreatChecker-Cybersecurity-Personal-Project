# ThreatChecker
> 🐍 A simple Python CLI tool to check domain reputation using the VirusTotal API.

---

## 💡 About This Project
ThreatChecker is a Python command-line tool to automate domain threat intelligence gathering. It queries the **VirusTotal API** using the `requests` library to fetch and parse malicious/suspicious domain reports. The tool features a user-friendly CLI built with `argparse`, robust error handling for API-related issues, and can be packaged into a standalone Windows executable (`.exe`) using **PyInstaller**.

### Topics
`python` `cybersecurity` `cli` `virustotal` `api` `threat-intelligence` `automation` `security-tool`

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

* **Full Path Command (Windows Example)**
    ```bash
    & C:/Users/user/AppData/Local/Programs/Python/Python314/python.exe c:/Users/user/OneDrive/Desktop/Script.py -d <domain_to_check>
    ```

* **Examples**
    ```bash
    # Check a safe domain
    python Script.py -d google.com

    # Check a malicious test domain
    python Script.py -d wicar.org
    ```

---

## 📦 How to Create a .EXE (Executable)
This turns your script into a standalone `.exe` file that can be run on any Windows computer, even without Python installed.

1.  **Install PyInstaller:**
    ```bash
    python -m pip install pyinstaller
    ```
2.  **Navigate to your script's folder:**
    ```bash
    cd C:\Users\user\OneDrive\Desktop
    ```
3.  **Run the PyInstaller command:**
    ```bash
    pyinstaller --onefile -n ThreatChecker.exe Script.py
    ```
4.  **Find your file:** Your new `ThreatChecker.exe` will be inside a new `dist` folder.

5.  **Run your new .exe:**
    ```bash
    .\ThreatChecker.exe -d wicar.org
    ```
