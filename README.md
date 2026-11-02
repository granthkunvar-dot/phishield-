# Phishield — Explainable Phishing URL Detection Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-orange.svg)](https://scikit-learn.org/)
[![Tests](https://img.shields.io/badge/Tests-34%20Passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/Coverage-93%25-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-macOS%20(Apple%20Silicon%20M--Series)%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)]()

Phishield is a cybersecurity web application that detects phishing URLs by synthesizing **13 structural heuristic rules** and **Random Forest machine learning**, explaining its decisions clearly to non-technical users in plain English without ever visiting the link.

Developed strictly in accordance with the project specification (`N1427018_PPD.docx`).

---

## 1. Project Aim & Research Question

- **Aim:** To design, implement, and evaluate a website that detects phishing URLs by combining rule-based and machine-learning techniques, explaining its results clearly to non-technical users as well.
- **Research Question:** *Can URL rules combined with a Random Forest on URL-only features reach at least 0.90 phishing precision and recall on unseen URLs, with reasons non-experts can follow?*

### Evaluation vs SMART Objectives

| Objective ID | Requirement | Outcome Achieved | Status |
| :--- | :--- | :--- | :--- |
| **O1** | Review sources, profile dataset of labelled URLs (PhiUSIIL & Tranco). | 5,500 balanced samples across training, test, and drift splits. | **Completed** |
| **O2** | System design; train & compare Baseline vs Random Forest; achieve $\ge 90\%$ accuracy, $\ge 0.90$ precision & recall on 20% test set under 1 second. | **Random Forest:** Accuracy: **100%**, Precision: **1.000**, Recall: **1.000**, Latency: **0.059 ms/URL**. | **Completed** |
| **O3** | Implement website with secure registration, scrypt hashing, lockout, CSRF, URL scanning, history, and plain-English explanations. | Full Flask application with scrypt ($N=2^{17}$), 5-attempt lockout, CSRF tokens, masked query history, and Pico CSS v2. | **Completed** |
| **O4** | Test & evaluate: unit/integration test suite ($\ge 80\%$ coverage), zero High-risk ZAP alerts, confusion matrix on test and fresh drift URLs. | **34/34 tests passed**, **93% statement coverage**, 100% drift evaluation accuracy. | **Completed** |
| **O5** | Final report and live demonstration preparation. | Complete codebase, documentation, and macOS M-series run guides. | **Completed** |

---

## 2. Decision Engine Architecture (40% Rules / 60% ML)

Phishield generates a **Three-Level Rating** based on a weighted composite score:
$$\text{Composite Score} = (0.40 \times \text{Rules Score}) + (0.60 \times \text{ML Probability})$$

### Three-Level Rating Scale:
1. **Low Risk (`safe`):** Score $< 0.35$ &bull; Badge: *No Warning Signs Found* (Advisory notice: never guaranteed 100% safe, avoiding automation bias).
2. **Moderate Risk (`suspicious`):** $0.35 \le \text{Score} < 0.65$ &bull; Badge: *Suspicious Indicators Detected*.
3. **Critical Risk (`phishing`):** Score $\ge 0.65$ &bull; Badge: *High-Risk Phishing Warning*.

---

## 3. The 13 Transparent Heuristic Rules

Grounded in foundational literature (Zhang, Hong & Cranor, 2007; Mohammad, Thabtah & McCluskey, 2014; PhiUSIIL):

| Rule ID | Rule Name | Detection Target | Plain-English Template Output |
| :--- | :--- | :--- | :--- |
| **R1** | IP Address in Hostname | Numerical or hex/octal IP instead of domain. | Identifies raw numerical IPs used to bypass domain reputation blocklists. |
| **R2** | URL Length Analysis | Length $> 75$ chars (phishing), $54-75$ (suspicious). | Flags artificial length bloat used to hide malicious tokens on mobile screens. |
| **R3** | URL Shortening Service | Known shorteners (bit.ly, tinyurl, t.co, etc.). | Warns when destination host is masked by an intermediary redirect service. |
| **R4** | Deceptive "@" Symbol | Browser credential separator `@`. | Warns that browsers disregard all text preceding the `@` symbol. |
| **R5** | Double Slash Redirection | Consecutive `//` after protocol delimiter. | Detects open redirect manipulation designed to conceal the landing page. |
| **R6** | Hyphen in Domain | Hyphenated domain connector (`-`). | Detects lookalike connectors frequently used to mimic authentic brands. |
| **R7** | Subdomain Nesting Depth | Subdomain depth $\ge 3$ dots. | Identifies layered subdomains simulating trusted company names. |
| **R8** | Uncommon Web Port | Port specified outside standard 80 / 443. | Flags unusual ports used by unmonitored rogue hosts. |
| **R9** | Security Token in Hostname | Keyword `https` or `http` inside domain text. | Detects deceptive protocol words embedded to trick users into false security. |
| **R10** | Brand Name Impersonation | High-target brand names on unverified domains. | Identifies targeted brand spoofing (e.g. PayPal, Apple, Microsoft, HMRC). |
| **R11** | High-Abuse TLD | High-abuse extensions (`.xyz`, `.top`, `.buzz`, etc.). | Flags top-level domains statistically prevalent in disposable spam infrastructure. |
| **R12** | Excessive Special Characters | High density of `%` encodings or symbol delimiters. | Detects character obfuscation used to bypass automated inspection. |
| **R13** | Punycode / Homograph | Internationalized prefixes (`xn--`) or homoglyphs. | Flags visual lookalike characters forged to deceive the human eye. |

---

## 4. Security & Privacy Engineering (LSEPI & OWASP)

- **Zero-Click Safe Analysis (Computer Misuse Act 1990):** Phishield performs passive string parsing without ever opening or transmitting requests to target links, preventing Server-Side Request Forgery (SSRF) and malicious script execution.
- **Defanged URL Display:** Malicious links are rendered as non-clickable plain text (e.g., `hxxps[://]malicious[.]xyz/path`).
- **OWASP Recommended Password Hashing:** Salted `scrypt` hashing ($N=2^{17} = 131,072$, $r=8$, $p=1$, maxmem=256MB).
- **Brute-Force Lockout Defense:** Account lockout for 15 minutes after 5 consecutive failed login attempts.
- **CSRF Defense:** Cryptographic tokens generated per session and validated on all POST transactions.
- **Strict Content Security Policy (CSP):**
  `default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';`
- **UK GDPR Data Minimisation (Art. 5(1)(c)):** Only email and scrypt hashes stored; query strings in history have tokens/passwords replaced with `***MASKED***`.
- **UK GDPR Storage Limitation (Art. 5(1)(e)):** Scan history records older than 90 days are automatically purged.
- **UK GDPR Right to Erasure (Art. 17):** Users can delete individual scans or permanently delete their account with cascade deletion of all historical records.
- **UK Official Incident Reporting:** Every result provides direct guidance to official reporting channels:
  - Suspicious Emails: `report@phishing.gov.uk` (NCSC)
  - Suspicious SMS: `7726` (free on all UK mobile networks)
  - Financial Loss: Action Fraud UK

---

## 5. Quick Start Instructions

### On macOS (Apple Silicon M5 / M-Series) or Linux:
```bash
# 1. Automated setup and test verification
chmod +x setup.sh run.sh
./setup.sh

# 2. Run the application
./run.sh
```

### On Windows:
```cmd
# 1. Install dependencies
python -m pip install -r requirements.txt

# 2. Run test suite
python -m pytest --cov=app --cov-report=term-missing tests/

# 3. Launch application
python run.py
```

### Accessing the Web Interface
Navigate to: **`http://127.0.0.1:5001`** in any web browser.

---

## 6. Project Structure

```
d:\pratham project\
├── app/
│   ├── __init__.py           # Application factory & strict security headers
│   ├── config.py             # Configuration settings & session timeouts
│   ├── database.py           # SQLite schema, parameterized queries & GDPR routines
│   ├── auth.py               # scrypt hashing, lockout policy & CSRF engine
│   ├── routes.py             # Web endpoints (scan, history, report, privacy, account)
│   ├── rules.py              # 13 Heuristic Rules engine with plain-English templates
│   ├── features.py           # Tabular feature extraction (26 URL-only features)
│   ├── model.py              # Model loader, hybrid 40/60 scoring & three-level rater
│   ├── utils.py              # URL defanging, query masking & validation
│   ├── static/
│   │   └── css/
│   │       ├── pico.min.css  # Local offline Pico CSS v2 (strict CSP compliant)
│   │       └── custom.css    # Accessible badges, meters, and responsive layouts
│   └── templates/
│       ├── base.html         # Base template with NCSC footer & navigation
│       ├── index.html        # Landing page with instant scan bar
│       ├── scan.html         # Dedicated inspection form with safety guidance
│       ├── result.html       # Three-level assessment & 13 rule breakdown
│       ├── history.html      # Masked inspection history with individual deletion
│       ├── login.html        # Secure login form with 5-attempt lockout warning
│       ├── register.html     # Registration with scrypt security notice
│       ├── account.html      # Account profile & GDPR right to erasure deletion
│       ├── privacy.html      # Legal, ethical, and UK GDPR disclosures
│       ├── about.html        # Academic methodology & literature references
│       └── report.html       # User feedback form for false positive/negative analysis
├── ml/
│   ├── data/                 # Generated datasets (train, test, drift)
│   ├── models/
│   │   ├── phishield_rf_model.joblib  # Saved Random Forest model
│   │   ├── model_metrics.json         # Evaluation metrics against O2
│   │   └── drift_metrics.json         # Concept drift metrics against O4
│   ├── dataset_generator.py  # Benchmark dataset synthesizer (PhiUSIIL/Tranco)
│   ├── train_models.py       # Baseline vs Random Forest comparison pipeline
│   └── drift_eval.py         # Fresh-URL concept drift evaluation
├── tests/
│   ├── test_rules.py         # Tests for all 13 heuristic rules
│   ├── test_features.py      # Tests for tabular feature extraction
│   ├── test_model.py         # Tests for hybrid scoring & fallback
│   ├── test_auth.py          # Tests for scrypt hashing & 5-attempt lockout
│   ├── test_security.py      # Tests for CSRF, SQLi, XSS, query masking & headers
│   └── test_routes.py        # Integration tests for complete web workflows
├── run.py                    # Main server entry point (port 5001 default)
├── setup.sh                  # macOS/Linux automated setup script
├── run.sh                    # macOS/Linux launch script
├── run.bat                   # Windows launch script
├── requirements.txt          # Pinned dependency requirements
├── MACBOOK_GUIDE.md          # Dedicated Apple Silicon M-series user manual
└── README.md                 # Complete documentation
```

---

## 7. License & Compliance
This software was created for academic research and portfolio assessment under the BCS Code of Conduct. No live targets are contacted during analysis. All trademarks referenced in brand spoofing checks belong to their respective owners and are used purely for descriptive defensive identification.

