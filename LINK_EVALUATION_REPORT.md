# Phishield — Real-World Phishing Link Evaluation Report
**Dataset Evaluated:** `link.txt` (300 Real-World Threat URLs)  
**Evaluation Engine:** Phishield Hybrid Decision Engine (13 Heuristic Rules @ 40% + Random Forest ML @ 60%)  
**Module:** Nottingham Trent University Final Year Project (N1427018)  
**Execution Timestamp:** 2026-11-03 12:52 UTC  
**Average Latency:** **19.19 ms per URL** (Total run time: 5.76s for 300 URLs)

---

## 1. Executive Evaluation Summary

All 300 links from `link.txt` were ingested and evaluated through Phishield's passive, zero-click hybrid detection pipeline. Each link underwent 13 deterministic heuristic rule checks and 26-dimensional tabular feature extraction for Random Forest inference.

### Overall Rating Breakdown
| Rating Category | Count | Percentage | Primary Indicators / Threat Characteristics |
|---|:---:|:---:|---|
| 🟡 **Suspicious** | **191** | **63.7%** | Cloudflare Pages (`.pages.dev`), Elementor Cloud, Vercel app abuse, deep subdomain nesting (R7), synthetic hyphenation (R6), excessive length (R2), disposable TLDs (R11). |
| 🟢 **No Warning Signs (Safe)** | **109** | **36.3%** | Unlisted regional ccTLD lookalikes (`.com.et`, `.com.gr`), typosquatting domains (`robiox`, `steomcomnmunity`), and unlisted custom redirect shorteners (`s4w.in`). |
| **Total Evaluated** | **300** | **100.0%** | **Zero server crashes, zero network requests executed (100% offline).** |

---

## 2. Quantitative Metric Distribution

```
Composite Score Range: 0.0000 to 0.6343 (Mean: 0.3473)
┌───────────────────────────┬──────────┬────────────┐
│ Score Bracket             │ Count    │ Percentage │
├───────────────────────────┼──────────┼────────────┤
│ 0.5000 – 0.6343 (High)    │  42      │  14.0%     │
│ 0.3500 – 0.4999 (Moderate)│ 149      │  49.7%     │
│ 0.2500 – 0.3499 (Marginal)│  29      │   9.7%     │
│ 0.0000 – 0.2499 (Low)     │  80      │  26.7%     │
└───────────────────────────┴──────────┴────────────┘
```

---

## 3. Heuristic Rules Trigger Frequency (The 13 Rules)

Across the 300 threat samples, the heuristic engine flagged the following syntactic patterns:

| Rule ID | Rule Name | Times Triggered | % of Corpus | Primary Driver in Real-World Phishing |
|---|---|:---:|:---:|---|
| **R7** | **Subdomain Nesting Depth** | **246** | **82.0%** | Heavy reliance on multi-tiered subdomains on free cloud platforms (e.g. `*.pages.dev`, `*.elementor.cloud`, `*.cprapid.com`). |
| **R6** | **Hyphen in Domain Name** | **201** | **67.0%** | Synthetic hyphenated domain tokens used to simulate authentic multi-word portals (`outlook-mailer`, `tokinim-cdn79-hk54`). |
| **R2** | **URL Length Analysis** | **104** | **34.7%** | Base64 tracking payloads, long query tokens, and path overflow techniques designed to push deceptive domains off mobile viewports. |
| **R11** | **High-Abuse TLD** | **8** | **2.7%** | Disposable TLDs such as `.click`, `.lol`, `.pics`, `.icu`. |
| **R10** | **Brand Impersonation** | **4** | **1.3%** | Unauthorized inclusion of tracked brand names (`paypal`, `microsoft`, `apple`) in subdomains. |
| **R3** | **URL Shortening Service** | **1** | **0.3%** | Known shortener domains (`is.gd/steamcommunity...`). |
| **R4** | **Deceptive `@` Symbol** | **1** | **0.3%** | Userinfo delimiter obfuscation (`bible-readings...#lorixpro@...`). |
| **R12** | **Excessive Special Chars** | **1** | **0.3%** | Abnormal delimiter density. |
| **R1, R5, R8, R9, R13** | **IP, Redirect, Port, Token, IDN** | **0** | **0.0%** | Not represented in this specific sample corpus. |

---

## 4. Notable Threat Cases & Detection Insights

### Case 1: Complex Cloud-Hosted Credential Harvester (Flagged: Suspicious - Score: 0.6339)
- **URL:** `http://wquie-eiiow201113.pages.dev/help/contact/292730103411180appeals/submit-appeal-form/return`
- **Defanged:** `hxxp[://]wquie-eiiow201113[.]pages[.]dev/help/contact/292730103411180appeals/submit-appeal-form/return`
- **Engine Breakdown:**
  - Rules Score: `0.3104` (Triggered **R2 Length**, **R6 Hyphen**, **R7 Subdomains**)
  - ML Score: `0.8496` (Random Forest identified abnormal path length and character entropy)
  - Composite Score: `0.6339` $\rightarrow$ **Moderate Suspicion / High Alert**

### Case 2: Inverted Userinfo `@` Credential Smuggling (Flagged: Suspicious - Score: 0.6343)
- **URL:** `http://www.coastalrealtyconnections.com/wp-content/uploads/2026/10/bible-readings-1.html#lorixpro@532a50b8bfb6dfe5bd534e5def05c5e17816.com`
- **Defanged:** `hxxp[://]www[.]coastalrealtyconnections[.]com/wp-content/...#lorixpro[@]532a50b8...`
- **Engine Breakdown:**
  - Rules Score: `0.3527` (Triggered **R2 Length**, **R4 Deceptive `@` Delimiter**)
  - ML Score: `0.8221` (High token variance detected)
  - Composite Score: `0.6343` $\rightarrow$ **Moderate Suspicion / High Alert**

### Case 3: Disposable TLD Campaign (Flagged: Suspicious - Score: 0.5881)
- **URL:** `http://tokemim-cdn2-hk2.click/`
- **Defanged:** `hxxp[://]tokemim-cdn2-hk2[.]click/`
- **Engine Breakdown:**
  - Rules Score: `0.2187` (Triggered **R6 Hyphen**, **R11 High-Abuse TLD `.click`**)
  - ML Score: `0.8343`
  - Composite Score: `0.5881` $\rightarrow$ **Moderate Suspicion**

---

## 5. Critical Academic Analysis: Typosquatting & Automation Bias

### The Typosquatting Evasion Phenomenon
A notable cluster in `link.txt` represents gaming / social engineering lookalikes:
- `roblox.com.et` (ccTLD `.et` for Ethiopia)
- `robiox.com.gr` (Visual homoglyph: Latin `i` substituted for `l` on `.gr` ccTLD)
- `robloxr.com.es` (Appended suffix on `.es` ccTLD)
- `steomcomnmunity.ru` (`steomcomnmunity` misspelling of Steam Community)

**Why did these score in the Low Risk (<0.35) band?**
1. **Lexical Normalcy:** Unlike brute-force phishing kits that generate long, query-heavy URLs, these attack links are structurally clean (short paths, HTTPS enabled, standard delimiter counts).
2. **Target Scope:** The static heuristic rule R10 matches high-finance and enterprise brands (PayPal, Microsoft, Apple, Google, HMRC, UK Gov). Gaming platforms such as Roblox and Steam are not in the standard corporate dictionary.
3. **ccTLD Diversity:** The ccTLDs `.et`, `.gr`, `.es` are legitimate national country-code registries, not statistically classified as disposable infrastructure like `.xyz` or `.top`.

### Alignment with PPD Dissertation Literature
This finding directly validates the core thesis and ethical framework of the Final Year Project:
- **Parasuraman & Riley (1997) & PPD Section 8.1:** Demonstrates why safe classifications **MUST NEVER be labeled as a guarantee of safety** and why Phishield words them as *"No warning signs found"*.
- **Miller (2019) & Explainability:** Because Phishield exposes the 13 individual rules, a user can immediately observe that R10 was clear and make an informed contextual decision rather than suffering from automation bias.
- **Continuous Improvement via User Feedback:** The *"Report a wrong result"* button on Phishield empowers users to submit unflagged typosquats to calibrate future model training iterations.

---

## 6. Output Files Generated

1. **`link_eval_results.csv`** (Project Root): Full tabular report with all 300 rows, including original URL, defanged URL, rating, composite score, rules score, ML score, and triggered rule lists.
2. **`link_eval_summary.json`** (Project Root): Structured JSON metadata and statistical summary for automated reporting.
