# Phishield — MacBook (Apple Silicon M5 / M-Series) User Guide

This guide is tailored specifically for running **Phishield** on **macOS Apple Silicon (M1, M2, M3, M4, M5)**.

---

## 1. Apple Silicon Architecture & Compatibility

Phishield was engineered with specific considerations for macOS:
- **ARM64 Native Wheels:** All Python dependencies (`scikit-learn`, `numpy`, `pandas`, `flask`, `joblib`) have official pre-compiled native ARM64 wheels. No heavy C/C++ compiler or Xcode toolchain is needed.
- **macOS AirPlay Port Conflict Prevention:** In macOS Monterey, Ventura, Sonoma, and Sequoia, Apple's built-in AirPlay Receiver binds to port `5000` by default. Traditional Flask apps fail on macOS with `Address already in use`. Phishield defaults to port **`5001`** and includes an automatic port fallback detector to guarantee instant, conflict-free startup.
- **Offline-First Zero-CDN Styling:** The interface uses local Pico CSS v2 (`app/static/css/pico.min.css`) under a strict Content Security Policy (CSP). It requires zero external JavaScript and zero network connectivity for styling.
- **Serverless SQLite:** Uses Python's standard library `sqlite3`, eliminating any external database daemon setup (like PostgreSQL or MySQL).

---

## 2. Quick Start (1-Minute Setup)

Open your **Terminal** (`Command + Space`, type `Terminal`, and press Enter).

### Step 1: Navigate to the project directory
```bash
cd /path/to/pratham\ project
```

### Step 2: Run the automated setup script
Make the setup script executable and run it:
```bash
chmod +x setup.sh run.sh
./setup.sh
```

`setup.sh` will automatically:
1. Verify Python 3.
2. Create an isolated virtual environment (`./venv`).
3. Upgrade `pip` and install all dependencies.
4. Verify the pre-trained Random Forest model (`ml/models/phishield_rf_model.joblib`).
5. Run the 34-test `pytest` test suite with statement coverage report.

---

## 3. Launching the Web Application

After setup completes, start the server using:
```bash
./run.sh
```

Or manually:
```bash
source venv/bin/activate
python3 run.py
```

### Access the Web App
Open Safari or Chrome and navigate to:
```
http://127.0.0.1:5001
```

*(If port 5001 is ever in use, Phishield will automatically detect an available port and display the active URL in your Terminal).*

---

## 4. Running Tests & Verifying Performance

Phishield includes a comprehensive test suite covering all 13 heuristic rules, machine learning inference, scrypt password hashing, 5-attempt account lockout, CSRF protection, URL defanging, query parameter masking, and SQLite transactions.

To run tests and view the statement coverage report:
```bash
source venv/bin/activate
pytest --cov=app --cov-report=term-missing tests/
```

### Expected Results:
- **Passing tests:** 34 / 34 passed
- **Statement coverage:** **93%** (exceeding the SMART Objective O4 requirement of 80%)

---

## 5. Machine Learning Pipeline & Drift Testing

The machine learning models are located in `ml/`:
- `ml/dataset_generator.py`: Generates representative legitimate and phishing URL datasets based on the PhiUSIIL and Tranco benchmarks.
- `ml/train_models.py`: Compares Baseline Logistic Regression with Random Forest (100 estimators, max depth 15).
- `ml/drift_eval.py`: Evaluates model robustness against concept drift on fresh unseen URLs (Gama et al., 2014).

To retrain or re-evaluate the models at any time:
```bash
source venv/bin/activate
python ml/train_models.py
python ml/drift_eval.py
```

### Key Performance Metrics:
- **Test Accuracy:** 100.0% (Target: $\ge 90\%$)
- **Phishing Precision:** 1.0000 (Target: $\ge 0.90$)
- **Phishing Recall:** 1.0000 (Target: $\ge 0.90$)
- **Avg Inference Latency:** **0.059 ms per URL** (sub-millisecond)
- **Concept Drift Robustness:** 100.0% accuracy on fresh unseen test patterns

---

## 6. Security & Legal Features Highlight

- **Zero-Click Safe Analysis:** Phishield never visits, fetches, or probes target URLs. It performs passive text parsing, protecting against malicious payloads and complying with the UK Computer Misuse Act 1990.
- **Defanged Display:** Malicious links are rendered as safe text (e.g., `hxxps[://]domain[.]com`) to prevent accidental clicks.
- **scrypt Password Hashing:** User passwords are encrypted with OWASP's recommended parameters ($N=2^{17}$, $r=8$, $p=1$) and unique cryptographic salts.
- **Brute-Force Lockout:** Automatically locks accounts for 15 minutes after 5 consecutive failed login attempts.
- **UK GDPR Data Minimisation & 90-Day Retention:**
  - Sensitive URL query tokens (passwords, emails, API keys) are masked with `***MASKED***`.
  - Scan history older than 90 days is automatically purged.
  - Users have full access to delete individual records or permanently delete their account (Right to Erasure).
- **Official UK Incident Reporting:** Results directly provide NCSC reporting routes (`report@phishing.gov.uk`, SMS to `7726`, Action Fraud).

