"""
Unit Tests for Phishield 13 Heuristic Rules Engine
Validates all 13 rules against ground truth literature and test URLs.
"""

import pytest
from app.rules import PhishieldRuleEngine


def test_rule_1_ip_address():
    # IP host
    engine_ip = PhishieldRuleEngine("http://192.168.1.1/login")
    r1 = engine_ip.rule_1_ip_address()
    assert r1['triggered'] is True
    assert r1['score'] == 1.0
    assert "raw numerical IP address" in r1['explanation']

    # Normal domain
    engine_dom = PhishieldRuleEngine("https://example.com/login")
    r1_dom = engine_dom.rule_1_ip_address()
    assert r1_dom['triggered'] is False
    assert r1_dom['score'] == 0.0


def test_rule_2_url_length():
    # Short URL (<54)
    short_url = "https://example.com/short"
    r2_short = PhishieldRuleEngine(short_url).rule_2_url_length()
    assert r2_short['triggered'] is False
    assert r2_short['score'] == 0.0

    # Moderate URL (54-75)
    med_url = "https://example.com/very/interesting/path/for/investigation/test"
    r2_med = PhishieldRuleEngine(med_url).rule_2_url_length()
    assert r2_med['triggered'] is True
    assert r2_med['score'] == 0.5

    # Long URL (>75)
    long_url = "https://example.com/" + "a" * 80
    r2_long = PhishieldRuleEngine(long_url).rule_2_url_length()
    assert r2_long['triggered'] is True
    assert r2_long['score'] == 1.0


def test_rule_3_shortening_service():
    # Known shortener
    engine_short = PhishieldRuleEngine("https://bit.ly/3xY9kL")
    r3 = engine_short.rule_3_url_shortener()
    assert r3['triggered'] is True
    assert r3['score'] == 1.0

    # Standard domain
    engine_norm = PhishieldRuleEngine("https://ntu.ac.uk/study")
    r3_norm = engine_norm.rule_3_url_shortener()
    assert r3_norm['triggered'] is False


def test_rule_4_at_symbol():
    # URL with @
    engine_at = PhishieldRuleEngine("http://google.com@phishing-target.com/login")
    r4 = engine_at.rule_4_at_symbol()
    assert r4['triggered'] is True
    assert r4['score'] == 1.0

    # Clean URL
    engine_clean = PhishieldRuleEngine("https://google.com/search?q=test")
    r4_clean = engine_clean.rule_4_at_symbol()
    assert r4_clean['triggered'] is False


def test_rule_5_double_slash_redirect():
    # URL with // in path
    engine_ds = PhishieldRuleEngine("https://example.com/path//evil-redirect.com")
    r5 = engine_ds.rule_5_double_slash_redirect()
    assert r5['triggered'] is True
    assert r5['score'] == 1.0

    # Standard path
    engine_norm = PhishieldRuleEngine("https://example.com/path/normal/page.html")
    r5_norm = engine_norm.rule_5_double_slash_redirect()
    assert r5_norm['triggered'] is False


def test_rule_6_prefix_suffix_hyphen():
    # Hyphenated lookalike domain
    engine_hyphen = PhishieldRuleEngine("https://paypal-security-update.com/signin")
    r6 = engine_hyphen.rule_6_prefix_suffix_hyphen()
    assert r6['triggered'] is True

    # Authentic domain
    engine_auth = PhishieldRuleEngine("https://paypal.com/signin")
    r6_auth = engine_auth.rule_6_prefix_suffix_hyphen()
    assert r6_auth['triggered'] is False


def test_rule_7_multiple_subdomains():
    # Deeply nested subdomains (>=3 dots in host)
    engine_sub = PhishieldRuleEngine("https://login.account.security.update.evil.com/auth")
    r7 = engine_sub.rule_7_multiple_subdomains()
    assert r7['triggered'] is True
    assert r7['score'] == 1.0

    # Normal 1 dot domain
    engine_norm = PhishieldRuleEngine("https://example.com/auth")
    r7_norm = engine_norm.rule_7_multiple_subdomains()
    assert r7_norm['triggered'] is False


def test_rule_8_non_standard_port():
    # Non standard port
    engine_port = PhishieldRuleEngine("http://phishing.site:8080/portal")
    r8 = engine_port.rule_8_non_standard_port()
    assert r8['triggered'] is True

    # Standard port 443
    engine_std = PhishieldRuleEngine("https://example.com:443/portal")
    r8_std = engine_std.rule_8_non_standard_port()
    assert r8_std['triggered'] is False


def test_rule_9_https_token_in_domain():
    # Deceptive https in hostname
    engine_https = PhishieldRuleEngine("http://https-secure-login.com")
    r9 = engine_https.rule_9_https_token_in_domain()
    assert r9['triggered'] is True

    # Standard domain
    engine_clean = PhishieldRuleEngine("https://secure.bank.com")
    r9_clean = engine_clean.rule_9_https_token_in_domain()
    assert r9_clean['triggered'] is False


def test_rule_10_brand_impersonation():
    # Brand spoofing (paypal keyword on unauthentic domain)
    engine_spoof = PhishieldRuleEngine("http://paypal-verification-desk.net/login")
    r10 = engine_spoof.rule_10_brand_impersonation()
    assert r10['triggered'] is True
    assert "paypal" in r10['explanation'].lower()

    # Authentic brand
    engine_legit = PhishieldRuleEngine("https://www.paypal.com/signin")
    r10_legit = engine_legit.rule_10_brand_impersonation()
    assert r10_legit['triggered'] is False


def test_rule_11_suspicious_tld():
    # Suspicious high abuse TLD (.xyz)
    engine_tld = PhishieldRuleEngine("https://secure-login.xyz")
    r11 = engine_tld.rule_11_suspicious_tld()
    assert r11['triggered'] is True

    # Established TLD (.org)
    engine_norm = PhishieldRuleEngine("https://wikipedia.org")
    r11_norm = engine_norm.rule_11_suspicious_tld()
    assert r11_norm['triggered'] is False


def test_rule_12_excessive_special_chars():
    # Many percent encodings and symbols
    engine_chars = PhishieldRuleEngine("https://example.com/path?a=%20&b=%21&c=%23&d=%24&e=%25&f=%26")
    r12 = engine_chars.rule_12_excessive_special_chars()
    assert r12['triggered'] is True

    # Standard parameters
    engine_clean = PhishieldRuleEngine("https://example.com/search?q=cybersecurity")
    r12_clean = engine_clean.rule_12_excessive_special_chars()
    assert r12_clean['triggered'] is False


def test_rule_13_punycode_homograph():
    # Punycode prefix
    engine_puny = PhishieldRuleEngine("http://xn--pple-43d.com/login")
    r13 = engine_puny.rule_13_punycode_homograph()
    assert r13['triggered'] is True

    # Normal ascii
    engine_norm = PhishieldRuleEngine("https://apple.com/uk")
    r13_norm = engine_norm.rule_13_punycode_homograph()
    assert r13_norm['triggered'] is False


def test_evaluate_all_summary():
    engine = PhishieldRuleEngine("http://192.168.1.1:8080/paypal-update?token=secret12345678901234567890")
    res = engine.evaluate_all()
    assert res['total_rules'] == 13
    assert res['triggered_count'] > 0
    assert 0.0 <= res['rules_score'] <= 1.0

