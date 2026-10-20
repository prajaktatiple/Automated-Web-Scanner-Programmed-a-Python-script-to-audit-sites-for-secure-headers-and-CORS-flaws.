# Automated Web Vulnerability Scanner

A beginner-friendly Python project that performs a **basic, non-invasive** check of HTTP security headers and a small number of CORS response-header signals.

> **Permission and safety:** Only scan websites you own or have explicit permission to assess. This project sends a single ordinary HTTP GET request. It does not exploit vulnerabilities and is not a full penetration-testing tool.

## Features

- Checks six common HTTP security headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy
- Reports whether the final page uses HTTPS.
- Displays basic CORS response-header signals.
- Labels findings with simple severity levels.
- Saves a JSON report.

## Requirements

- Python 3.10 or later
- Internet connection for scanning a permitted website
- `requests` Python package

## Run in VS Code

1. Extract the project ZIP into a folder.
2. Open that folder in VS Code.
3. Open **Terminal → New Terminal**.
4. (Recommended) Create a virtual environment:

   **Windows PowerShell**
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt or run the commands below with `py -m pip` without activating the environment.

5. Install the dependency:
   ```powershell
   py -m pip install -r requirements.txt
   ```

6. Run against a site you own or have permission to test:
   ```powershell
   py scanner.py https://your-authorized-domain.example
   ```

7. The findings appear in the terminal and are saved to `scan_report.json`.

Optional arguments:
```powershell
py scanner.py https://your-authorized-domain.example --timeout 15 --output my_report.json
```

## Project files

- `scanner.py` — main Python source code.
- `requirements.txt` — Python dependency list.
- `README.md` — setup and usage guide.
- `PROJECT_REPORT.md` — project report for submission.
- `scan_report.json` — generated when you run a scan.

## Limitations

- Missing headers are observations, not automatic proof of a vulnerability.
- CORS checks are only a basic review of response headers; browser behavior and application context matter.
- This tool does not crawl pages, test authentication, exploit issues, or replace a professional security assessment.
