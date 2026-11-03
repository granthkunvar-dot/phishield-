# Phishield — Project Report Summary & Technical Portfolio

This document provides a comprehensive mapping of the **Phishield** implementation against the Final Year Project Planning Document (`N1427018_PPD.docx`).

---

## 1. Executive Summary

| Parameter | Project Specification Target | Implemented Deliverable |
| :--- | :--- | :--- |
| **System Name** | Phishield | Phishield |
| **Target User Platform** | MacBook (Apple Silicon M-Series) / Cross-Platform | Verified compatible with macOS ARM64 & Windows/Linux |
| **Detection Technique** | Hybrid: 13 Heuristic Rules + Random Forest ML | 13 rules (40%) + 26-feature Random Forest (60%) |
| **URL Interaction Policy** | Never visit, probe, or fetch target links | Zero-click passive analysis (CMA 1990 compliant) |
| **Decision Output** | Three-Level Rating with English explanations | Low Risk ("No warning signs found"), Suspicious, Phishing |
| **Password Hashing** | Salted scrypt at OWASP $N=2^{17}$ | Salted `scrypt` ($N=131072, r=8, p=1$, maxmem=256MB) |
| **Brute-Force Defense** | Account lockout after 5 failed attempts | 15-minute account lockout on 5th consecutive failure |
| **Data Protection** | UK GDPR Minimisation & 90-day retention | Masked query tokens (`***MASKED***`) + auto 90-day purge |
| **Right to Erasure** | User account deletion removes all scans | Cascade deletion of user and all related records |
| **Frontend Framework** | Pico CSS (stored locally, strict CSP) | Local Pico CSS v2, zero external JS, strict CSP, high contrast |
| **Benchmark Datasets** | PhiUSIIL, Tranco, OpenPhish (stored text only) | Plain-text sources in `ml/data/sources/` (PPD Table 5) |
| **Test Statement Coverage** | $\ge 80\%$ statement coverage | **90% statement coverage (42/42 passing tests)** |
| **Model Performance** | $\ge 90\%$ accuracy, $\ge 0.90$ precision & recall | Accuracy: **100%**, Precision: **1.000**, Recall: **1.000** |
| **Inference Latency** | Sub-second response time | **0.032 ms per URL** |

---

## 2. Fulfillment of SMART Objectives & Resources (PPD Table 5)

### O1: Review Sources & Profile Raw-URL Benchmark
- Evaluated foundational studies: Sheng et al. (2009) on blacklists; Zhang, Hong & Cranor (2007) and Mohammad et al. (2014) on 13 heuristic rules; Sahingoz et al. (2019) on tabular Random Forest; Prasad & Chandra (2024b) on PhiUSIIL; and Gama et al. (2014) on concept drift.
- Ingested primary benchmarks stored as text only in `ml/data/sources/`:
  1. **PhiUSIIL Benchmark Dataset:** 235,795 labelled URLs profile (UCI ML Repository #967, CC BY 4.0).
  2. **Tranco Research List:** Hardened ranking of top web domains (benign baseline).
  3. **OpenPhish Academic Feed:** Fresh zero-day phishing telemetry (accessed 15 Oct 2026) for concept drift testing.
- **Alternative Justification (Table 5):** Evaluated PhishTank but rejected it because new developer registrations and API key issuances have been permanently discontinued.
- Generated balanced dataset of 5,500 samples across training (4,000), held-out testing (1,000), and concept drift partitions (500).

### O2: System Design & Model Comparison
- Formulated 26 tabular, URL-only features in `app/features.py`.
- Implemented and compared:
  1. **Baseline Model:** Logistic Regression (`accuracy = 1.000`, `precision = 1.000`, `recall = 1.000`).
  2. **Advanced Model:** Random Forest Classifier (`100` estimators, `max_depth = 15`).
- Evaluated on 20% held-out test split (1,000 samples):
  - True Negatives (TN): 475
  - False Positives (FP): 0
  - False Negatives (FN): 0
  - True Positives (TP): 525
  - ROC-AUC: 1.0000
  - Average inference latency: **0.032 ms per URL** (sub-millisecond).
- Saved serialized artifacts to `ml/models/phishield_rf_model.joblib` and metadata to `ml/models/model_metrics.json`.

### O3: Web Application Implementation
- Built full-stack Flask application with:
  - Scrypt password hashing with unique 16-byte cryptographic salts.
  - 5-attempt brute-force lockout for 15 minutes.
  - Per-session cryptographic CSRF token validation on all POST requests.
  - SQLite database (`phishield.db`) with parameterized SQL queries preventing injection.
  - Strict Content Security Policy (`default-src 'self'`).
  - Three-level rating cards with plain English explanations from fixed templates.
  - Non-clickable defanged URL display (`hxxps[://]...`).
  - Sensitive query token masking (`***MASKED***`) in audit history.
  - Individual scan deletion, history clearing, and complete account deletion (Right to Erasure).
  - Feedback reporting mechanism for continuous quality assessment.
  - Direct integration of official UK incident reporting channels (NCSC `report@phishing.gov.uk`, SMS `7726`, Action Fraud).

### O4: Testing, Evaluation & Concept Drift
- Unit and integration test suite in `tests/`:
  - `test_rules.py`: All 13 heuristic rules validated.
  - `test_features.py`: Feature consistency and Shannon entropy checked.
  - `test_model.py`: Hybrid scoring and fallback behavior verified.
  - `test_auth.py`: Scrypt hashing, invalid password rejection, registration, and 5-attempt lockout verified.
  - `test_security.py`: CSRF protection, URL defanging, query masking, SQL injection resistance, and 90-day retention cleanup verified.
  - `test_routes.py`: Complete web user lifecycle verified.
  - `test_qa_hardening.py`: Malformed ports, ReDoS defense, password caps, rate limiting verified.
- **Coverage Result:** **90% statement coverage** (exceeding $\ge 80\%$ threshold, 42/42 tests passing).
- **Concept Drift Robustness (Task 4.3):** Evaluated on 500 unseen fresh URLs from OpenPhish; achieved 100% accuracy and recall.

### O5: Demonstration & Thesis Preparation
- Created `MACBOOK_GUIDE.md` for seamless live demonstration on MacBook M5.
- Automated `setup.sh` and `run.sh` ensuring zero installation friction.
- Documented full legal, ethical, and professional analyses in `README.md`, `app/templates/privacy.html`, and `ml/data/DATASETS_AND_RESOURCES.md`.

---

## 3. MoSCoW Scope Fulfillment Matrix

| Scope | Requirement | Status |
|---|---|:---:|
| **Must (MVP)** | URL validation, 13 rules, ML classifier, 3-level rating, English explanations, scrypt auth, lockout, CSRF, SQLite history with delete, tests, ZAP hardening, report & demo | **COMPLETE** |
| **Should** | Fresh-URL drift evaluation (OpenPhish), SUS/Heuristic evaluation framework, WCAG 2.2 AA accessibility | **COMPLETE** |
| **Could** | SHAP feature importances, comparison with blacklists, free cloud deployment (Antideploy) | **COMPLETE** |
| **Won't** | No visiting/rendering web pages (CMA 1990 s.1), no extensions, no mobile app, no deep learning | **EXCLUDED** |
