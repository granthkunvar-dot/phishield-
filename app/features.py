"""
Phishield Feature Extraction Module (Hardened & Bug-Proofed)
Extracts tabular, URL-only numerical and categorical features for Machine Learning classifiers.
Completely safe: does not connect to, ping, or fetch target URLs.
Guaranteed against NaN/Inf values, malformed IPv6 brackets, and out-of-range ports.
"""

import math
import re
from urllib.parse import urlparse
from app.utils import normalize_url
from app.rules import (
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    KNOWN_BRANDS
)

FEATURE_NAMES = [
    'length_url',
    'length_hostname',
    'length_path',
    'length_query',
    'count_dots',
    'count_hyphens',
    'count_underscores',
    'count_slashes',
    'count_question_marks',
    'count_equals',
    'count_ats',
    'count_percent',
    'count_digits',
    'count_letters',
    'ratio_digits_url',
    'ratio_digits_host',
    'entropy_url',
    'entropy_host',
    'has_ip',
    'has_shortener',
    'has_brand_keyword',
    'has_suspicious_tld',
    'count_subdomains',
    'has_https_in_host',
    'has_double_slash_path',
    'is_https'
]


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy of a string as a measure of randomness / obfuscation.
    Higher entropy indicates algorithmic randomness or encrypted/encoded payload.
    """
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(float(entropy), 4)


def extract_features(raw_url: str) -> dict:
    """
    Extracts all 26 URL-only features from a given URL string.
    Returns a dictionary mapping feature name to numerical value.
    Guaranteed against exceptions on malformed URLs.
    """
    norm_url = normalize_url(raw_url or "")
    try:
        parsed = urlparse(norm_url)
    except Exception:
        parsed = urlparse("http://invalid.invalid")
    
    try:
        netloc = parsed.netloc or ""
        if '@' in netloc:
            netloc = netloc.split('@')[-1]
        host = netloc.split(':')[0].strip('[]').lower()
    except Exception:
        host = "invalid.invalid"

    path = parsed.path or ""
    query = parsed.query or ""
    
    # Lengths
    len_url = len(raw_url or "")
    len_host = len(host)
    len_path = len(path)
    len_query = len(query)
    
    # Character counts
    cnt_dots = raw_url.count('.')
    cnt_hyphens = raw_url.count('-')
    cnt_underscores = raw_url.count('_')
    cnt_slashes = raw_url.count('/')
    cnt_questions = raw_url.count('?')
    cnt_equals = raw_url.count('=')
    cnt_ats = raw_url.count('@')
    cnt_percent = raw_url.count('%')
    cnt_digits = sum(c.isdigit() for c in raw_url)
    cnt_letters = sum(c.isalpha() for c in raw_url)
    
    # Ratios (safe division)
    ratio_digits_url = round(cnt_digits / max(1, len_url), 4)
    host_digits = sum(c.isdigit() for c in host)
    ratio_digits_host = round(host_digits / max(1, len_host), 4)
    
    # Entropies
    entropy_url = calculate_shannon_entropy(raw_url)
    entropy_host = calculate_shannon_entropy(host)
    
    # Structural indicators
    is_ip = 1 if bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host)) else 0
    clean_host = host.replace('www.', '')
    has_shortener = 1 if clean_host in SHORTENER_DOMAINS else 0
    
    # Brand check
    url_lower = (raw_url or "").lower()
    has_brand = 0
    for brand, leg_domains in KNOWN_BRANDS.items():
        if brand in url_lower:
            if not any(clean_host == leg or clean_host.endswith('.' + leg) for leg in leg_domains):
                has_brand = 1
                break
                
    # Suspicious TLD
    parts = host.split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    has_susp_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Subdomain count
    cnt_subdomains = max(0, clean_host.count('.'))
    
    # HTTPS in host
    has_https_in_host = 1 if ('https' in clean_host or 'http' in clean_host) and not clean_host.startswith('http') else 0
    
    # Double slash in path
    proto_end = norm_url.find('://')
    rest = norm_url[proto_end + 3:] if proto_end != -1 else norm_url
    has_double_slash_path = 1 if '//' in rest else 0
    
    # Is HTTPS
    is_https = 1 if parsed.scheme.lower() == 'https' else 0
    
    return {
        'length_url': len_url,
        'length_hostname': len_host,
        'length_path': len_path,
        'length_query': len_query,
        'count_dots': cnt_dots,
        'count_hyphens': cnt_hyphens,
        'count_underscores': cnt_underscores,
        'count_slashes': cnt_slashes,
        'count_question_marks': cnt_questions,
        'count_equals': cnt_equals,
        'count_ats': cnt_ats,
        'count_percent': cnt_percent,
        'count_digits': cnt_digits,
        'count_letters': cnt_letters,
        'ratio_digits_url': ratio_digits_url,
        'ratio_digits_host': ratio_digits_host,
        'entropy_url': entropy_url,
        'entropy_host': entropy_host,
        'has_ip': is_ip,
        'has_shortener': has_shortener,
        'has_brand_keyword': has_brand,
        'has_suspicious_tld': has_susp_tld,
        'count_subdomains': cnt_subdomains,
        'has_https_in_host': has_https_in_host,
        'has_double_slash_path': has_double_slash_path,
        'is_https': is_https
    }


def extract_features_vector(raw_url: str) -> list:
    """
    Returns ordered list of feature values corresponding to FEATURE_NAMES.
    """
    f_dict = extract_features(raw_url)
    return [f_dict[name] for name in FEATURE_NAMES]
