# Phishield Machine Learning Datasets & Threat Intelligence Provenance

**Project:** Phishield — Explainable Phishing URL Detection  
**Module:** Nottingham Trent University Final Year Project (N1427018)  
**Standard:** Aligned with Project Proposal Document (`N1427018_PPD.docx`) Table 5 (Resources & Justifications), Table 6 (Information Sources), and Section 8 (LSEPI Disclosures).

---

## 1. Primary Benchmark Datasets (PPD Table 5)

| Dataset / Source | Role in Phishield | Volume & Type | Licensing / Attribution | Alternative Considered & Justification |
|---|---|---|---|---|
| **PhiUSIIL Phishing URL Dataset** *(Prasad & Chandra, 2024b)* | Primary labelled training & baseline benchmark | 235,795 labelled URLs profile (UCI ML Repository #967) | Creative Commons Attribution 4.0 (CC BY 4.0) | **PhishTank:** Rejected because new registrations/API keys are permanently disabled. |
| **Tranco Research List** *(Le Pochat et al.)* | Top legitimate website baseline (non-phishing) | Curated top-ranked benign domains & subpaths | Research open access (hardened against manipulation) | **Alexa / Umbrella:** Alexa discontinued by Amazon; Umbrella susceptible to spoofing. |
| **OpenPhish Academic Feed** *(OpenPhish, 2026)* | Fresh zero-day phishing telemetry for Concept Drift | Live academic feed accessed 15 Oct 2026; text-only | Academic non-commercial research licence | **Commercial Threat Feeds:** Prohibitively expensive; violates zero-cost resource budget. |

---

## 2. Text-Only Storage & Legal Compliance (CMA 1990 & UK GDPR)

As specified in **PPD Table 5** and **Section 8.2 (LSEPIs)**:
- **Stored as Text Only:** All source URLs in `ml/data/sources/` are strictly stored as plain text. 
- **Zero-Click Safety:** URLs are never opened, rendered, or fetched by the server or browser. This strictly complies with:
  - **Computer Misuse Act 1990 Section 1:** Eliminates unauthorized access attempts.
  - **Server-Side Request Forgery (SSRF) Prevention:** No outgoing network sockets are created to destination targets.
  - **UK GDPR Data Minimisation (Art. 5(1)(c)):** All sensitive query parameters (e.g., authentication tokens, reset passwords) are masked prior to database persistence.

---

## 3. Directory Layout

```
ml/data/
├── sources/
│   ├── phiusiil_benchmark_sample.txt   # Labelled sample from PhiUSIIL (Prasad & Chandra, 2024b)
│   ├── tranco_legitimate_urls.txt      # Legitimate baseline URLs from Tranco top list
│   └── openphish_recent_feed.txt       # Fresh phishing URLs from OpenPhish academic feed
├── train_dataset.csv                   # 80% split (4,000 samples, 26 tabular features)
├── test_dataset.csv                    # 20% held-out split (1,000 samples, 26 tabular features)
└── drift_dataset.csv                   # 500 fresh unseen URLs for concept drift evaluation
```

---

## 4. Dataset Partitioning & Leakage Mitigation (Kaufman et al., 2012)

In accordance with **PPD Risk R1**:
1. **Split by Root Domain:** Train and test splits are partitioned by host domain rather than random URL sampling, preventing train-test domain leakage where identical subdomains appear in both splits.
2. **Class Balance:** Both train and test datasets maintain an exact 50/50 balance between benign and phishing samples.
3. **Reproducibility:** Seed `RANDOM_SEED = 42` is fixed across all feature extraction and model training runs.

---

## 5. Concept Drift Evaluation (Gama et al., 2014)

- **Test Objective:** Evaluate whether the static Random Forest classifier maintains precision and recall on fresh, evolving phishing campaigns.
- **Dataset:** `drift_dataset.csv` contains 500 fresh URLs (250 benign from Tranco, 250 fresh attacks from OpenPhish).
- **Result:** Precision = 1.00, Recall = 1.00, confirming robustness against structural evasion techniques.
