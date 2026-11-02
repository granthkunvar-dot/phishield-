"""
Unit Tests for Phishield Feature Extractor
"""

from app.features import (
    extract_features,
    extract_features_vector,
    calculate_shannon_entropy,
    FEATURE_NAMES
)


def test_shannon_entropy():
    # Constant string has 0 entropy
    assert calculate_shannon_entropy("aaaaa") == 0.0
    # Diverse string has higher entropy
    h_rand = calculate_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
    assert h_rand > 4.0
    # Empty string
    assert calculate_shannon_entropy("") == 0.0


def test_feature_names_consistency():
    url = "https://www.example.com/login?user=test"
    feats = extract_features(url)
    assert len(feats) == len(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert name in feats
        assert isinstance(feats[name], (int, float))


def test_feature_vector_order():
    url = "http://192.168.0.1:8080/secure/auth"
    vec = extract_features_vector(url)
    assert len(vec) == len(FEATURE_NAMES)
    feats = extract_features(url)
    for i, name in enumerate(FEATURE_NAMES):
        assert vec[i] == feats[name]


def test_structural_feature_flags():
    # IP URL
    ip_url = "http://10.0.0.1/test"
    f_ip = extract_features(ip_url)
    assert f_ip['has_ip'] == 1
    assert f_ip['is_https'] == 0

    # HTTPS URL with shortener
    short_url = "https://bit.ly/xyz123"
    f_short = extract_features(short_url)
    assert f_short['has_shortener'] == 1
    assert f_short['is_https'] == 1

