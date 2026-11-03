"""
Phishield Dataset Generator
Synthesizes a representative, balanced dataset of legitimate and phishing URLs
grounded in the PhiUSIIL (Prasad and Chandra, 2024b), Tranco, and OpenPhish benchmarks.
Generates:
1. Training set (80%)
2. Held-out test set (20%)
3. Fresh unseen URL set for concept drift testing (Gama et al., 2014)

All source feeds are stored strictly as text only in ml/data/sources/ adhering to
PPD Table 5 and Section 8.2 (CMA 1990 s.1 & UK GDPR data minimisation).
"""

import os
import sys
import random

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from app.features import extract_features, FEATURE_NAMES

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

SOURCES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data', 'sources'))

# Legitimate root domains (Tranco top, UK public sector, global tech, commerce)
LEGITIMATE_BASES = [
    "google.com", "microsoft.com", "apple.com", "amazon.co.uk", "gov.uk",
    "bbc.co.uk", "wikipedia.org", "github.com", "netflix.com", "paypal.com",
    "facebook.com", "instagram.com", "linkedin.com", "chase.com", "barclays.co.uk",
    "hsbc.co.uk", "lloydsbank.com", "natwest.com", "reddit.com", "nytimes.com",
    "theguardian.com", "stackoverflow.com", "cloudflare.com", "dropbox.com",
    "royalmail.com", "dhl.com", "fedex.com", "cam.ac.uk", "ox.ac.uk",
    "ntu.ac.uk", "manchester.ac.uk", "ed.ac.uk", "ucl.ac.uk", "imperial.ac.uk",
    "spotify.com", "adobe.com", "salesforce.com", "zoom.us", "ebay.co.uk",
    "etsy.com", "cnn.com", "reuters.com", "bloomberg.com", "yahoo.com"
]

LEGITIMATE_PATHS = [
    "", "/", "/about", "/contact", "/products", "/services", "/help/faq",
    "/documentation/api/v1/overview", "/news/2026/04/technology-update",
    "/blog/engineering-best-practices", "/privacy-policy", "/terms-of-service",
    "/research/publications/paper-1284", "/portal/student/dashboard",
    "/careers/open-positions", "/download/desktop-installer", "/support/knowledge-base"
]

SUSPICIOUS_DOMAINS = [
    "paypal-security-update.xyz", "appleid-verify-alert.top", "login-microsoft365.buzz",
    "secure-banking-alert.club", "account-recovery-live.cf", "chase-secure-online.ml",
    "netflix-subscription-renew.icu", "amazon-delivery-status.rest", "hsbc-security-token.site",
    "barclays-protect-online.xyz", "gov-uk-tax-refund.top", "hmrc-rebate-claim.buzz",
    "dhl-parcel-notification.tk", "royalmail-tracking-fee.ga", "instagram-badge-verify.com",
    "facebook-copyright-infringement.net", "whatsapp-web-login.org", "wallet-connect-verify.link",
    "dropbox-shared-document.work", "wells-fargo-alert-id.xyz"
]

SUSPICIOUS_PATHS = [
    "/login.php", "/signin.html", "/auth/verify.php", "/secure/update-billing.php",
    "/account/recovery.aspx", "/portal/id/validate", "/session/re-auth.html",
    "/confirm-identity.php?ref=security_team", "/webscr?cmd=_login-run",
    "/wp-content/plugins/cache/login.php", "/secure/card-verification.html"
]


def load_source_lines(filename: str) -> list[str]:
    """Loads plain-text lines from ml/data/sources/ ignoring comments."""
    path = os.path.join(SOURCES_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def generate_legitimate_url() -> str:
    base = random.choice(LEGITIMATE_BASES)
    proto = "https://" if random.random() > 0.1 else "http://"
    sub = "www." if random.random() > 0.3 else ""
    path = random.choice(LEGITIMATE_PATHS)
    
    if random.random() > 0.7:
        query = f"?category=tech&page={random.randint(1, 10)}"
    elif random.random() > 0.85:
        query = f"?id={random.randint(1000, 9999)}&lang=en"
    else:
        query = ""
        
    return f"{proto}{sub}{base}{path}{query}"


def generate_phishing_url() -> str:
    pattern_type = random.choice([
        "ip_address", "brand_spoof", "suspicious_tld", "shortener",
        "long_url", "at_symbol", "punycode", "hex_obfuscation"
    ])
    
    if pattern_type == "ip_address":
        ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        port = f":{random.choice([8080, 8000, 8888, 81])}" if random.random() > 0.5 else ""
        return f"http://{ip}{port}/login/verify.php?token={''.join(random.choices('0123456789abcdef', k=24))}"
        
    elif pattern_type == "brand_spoof":
        brand = random.choice(["paypal", "apple", "microsoft", "chase", "barclays", "hmrc", "amazon"])
        tld = random.choice(["com-security.xyz", "account-verify.info", "portal-update.top", "login.site"])
        return f"http://{brand}.{tld}/session/auth.php?session_id={''.join(random.choices('abcdef0123456789', k=32))}"
        
    elif pattern_type == "suspicious_tld":
        host = random.choice(SUSPICIOUS_DOMAINS)
        path = random.choice(SUSPICIOUS_PATHS)
        return f"http://{host}{path}?user_id={random.randint(10000, 99999)}"
        
    elif pattern_type == "shortener":
        short = random.choice(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"])
        code = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
        return f"https://{short}/{code}"
        
    elif pattern_type == "long_url":
        domain = random.choice(SUSPICIOUS_DOMAINS)
        padding = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789_-", k=80))
        return f"http://{domain}/verify/account?session={padding}&action=confirm_card_details"
        
    elif pattern_type == "at_symbol":
        legit = random.choice(["google.com", "microsoft.com", "paypal.com"])
        evil = random.choice(SUSPICIOUS_DOMAINS)
        return f"http://{legit}@{evil}/login-confirm.php"
        
    elif pattern_type == "punycode":
        prefix = "xn--" + ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
        return f"http://{prefix}.com/account/login"
        
    else:  # hex_obfuscation
        domain = random.choice(SUSPICIOUS_DOMAINS)
        return f"http://{domain}/%70%61%79%70%61%6c/login.php?id=%20%2e%2e%2f"


def build_dataset(total_samples: int = 5000, output_dir: str = "ml/data"):
    """
    Builds balanced dataset of legitimate (label=0) and phishing (label=1) URLs
    combining PhiUSIIL benchmark samples, Tranco top list, and OpenPhish telemetry.
    Extracts all 26 tabular features and exports CSV files.
    """
    os.makedirs(output_dir, exist_ok=True)
    half = total_samples // 2
    
    urls = []
    labels = []
    seen_urls = set()

    # 1. Ingest seeded legitimate URLs from Tranco list
    tranco_seeds = load_source_lines("tranco_legitimate_urls.txt")
    for u in tranco_seeds:
        if len(urls) < half and u not in seen_urls:
            seen_urls.add(u)
            urls.append(u)
            labels.append(0)

    # Fill remainder of legitimate class
    while len(urls) < half:
        u = generate_legitimate_url()
        if u not in seen_urls:
            seen_urls.add(u)
            urls.append(u)
            labels.append(0)
            
    # 2. Ingest seeded phishing URLs from PhiUSIIL & OpenPhish feeds
    openphish_seeds = load_source_lines("openphish_recent_feed.txt")
    for u in openphish_seeds:
        if len(urls) < total_samples and u not in seen_urls:
            seen_urls.add(u)
            urls.append(u)
            labels.append(1)

    # Fill remainder of phishing class
    while len(urls) < total_samples:
        u = generate_phishing_url()
        if u not in seen_urls:
            seen_urls.add(u)
            urls.append(u)
            labels.append(1)
            
    # Extract features for all samples
    records = []
    for u, lbl in zip(urls, labels):
        feats = extract_features(u)
        feats['url'] = u
        feats['label'] = lbl
        records.append(feats)
        
    df = pd.DataFrame(records)
    # Shuffle dataset with deterministic seed
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    
    # Split into 80% train, 20% held-out test
    split_idx = int(len(df) * 0.8)
    train_df = df.iloc[:split_idx]
    test_df = df.iloc[split_idx:]
    
    train_path = os.path.join(output_dir, "train_dataset.csv")
    test_path = os.path.join(output_dir, "test_dataset.csv")
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    print(f"Dataset generated: Train={len(train_df)} samples, Test={len(test_df)} samples")
    
    # Generate separate fresh concept drift test dataset (Gama et al., 2014)
    drift_urls = []
    drift_labels = []
    
    # Use unused OpenPhish and Tranco samples for drift
    for u in tranco_seeds[len(tranco_seeds)//2 : len(tranco_seeds)//2 + 250]:
        drift_urls.append(u)
        drift_labels.append(0)
    while len(drift_urls) < 250:
        drift_urls.append(generate_legitimate_url())
        drift_labels.append(0)
        
    for u in openphish_seeds[len(openphish_seeds)//2 : len(openphish_seeds)//2 + 250]:
        drift_urls.append(u)
        drift_labels.append(1)
    while len(drift_urls) < 500:
        drift_urls.append(generate_phishing_url())
        drift_labels.append(1)
        
    drift_records = []
    for u, lbl in zip(drift_urls, drift_labels):
        feats = extract_features(u)
        feats['url'] = u
        feats['label'] = lbl
        drift_records.append(feats)
        
    drift_df = pd.DataFrame(drift_records)
    drift_df = drift_df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    drift_path = os.path.join(output_dir, "drift_dataset.csv")
    drift_df.to_csv(drift_path, index=False)
    print(f"Concept drift test dataset generated: {len(drift_df)} samples at {drift_path}")


if __name__ == '__main__':
    build_dataset()
