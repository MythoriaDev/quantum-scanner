# Quantum-Readiness Scanner

Checks whether a website is protected against "harvest now, decrypt later" quantum attacks, then
produces a branded client report you can send to prospects.

## Put it online for free (about 15 minutes, no coding)

1. **Create a GitHub account** at https://github.com/signup (free).
2. **Create a repository:** click **+** (top right) → **New repository** → name it quantum-scanner
   → choose **Public** → **Create repository**.
3. **Upload the files:** on the new repository page, click **uploading an existing file**, then drag in
   all four files: app.py, scanner.py, report.py, requirements.txt (and this README).
   Click **Commit changes**.
4. **Deploy:** go to https://share.streamlit.io → **Continue with GitHub** → **Create app**
   → **Deploy a public app from GitHub**.
   - Repository: your-username/quantum-scanner
   - Branch: main
   - Main file path: app.py
   - Click **Deploy**. After about 2 minutes you get a public link like https://quantum-scanner.streamlit.app.

## Or run it on your own computer

1. Install Python 3.10+ from https://www.python.org/downloads/ (on Windows, tick **Add Python to PATH**).
2. Open a terminal in this folder and run:


       pip install -r requirements.txt
       streamlit run app.py

3. Your browser opens the app at http://localhost:8501.

## How to use it

- **Report branding (left sidebar):** enter your business name and contact details. They appear on every report.
- **Scan a website:** enter a domain → **Scan** → **Download client report**. Open the report and use
  Print → Save as PDF to send it as a PDF.
- **Bulk scan:** paste up to 25 domains → **Scan all** → download a CSV of results plus a ZIP of all the reports.
  Websites without post-quantum protection are your best prospects.

## What it checks

| Check | Points |
|---|---|
| Post-quantum hybrid key exchange (X25519MLKEM768) | 50 |
| TLS 1.3 support | 20 |
| Cipher strength | 10 |
| Certificate trusted, valid, and with a strong key | 20 |

Grades: A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, F < 40. An untrusted or expired certificate caps the score at 50.

The scanner makes only a normal HTTPS connection to the site, the same as a web browser would.
It only checks the public website, not internal systems. Those are covered by your paid audit.
