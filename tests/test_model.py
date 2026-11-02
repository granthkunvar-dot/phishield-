"""
Unit Tests for Phishield Model & Hybrid Decision Engine
"""

import os
from app.model import PhishieldDetector


def test_detector_with_valid_model():
    detector = PhishieldDetector()
    assert detector.model is not None

    # Test Legitimate URL
    legit_res = detector.predict("https://www.google.com/search?q=cybersecurity")
    assert legit_res['rating'] == 'safe'
    assert legit_res['rating_label'] == 'No Warning Signs Found'
    assert legit_res['composite_score'] < 0.35
    assert 'hxxps[://]' in legit_res['url_defanged']

    # Test Phishing URL
    phish_res = detector.predict("http://192.168.1.1:8080/paypal-account-verify.xyz/login.php?token=secret123456789")
    assert phish_res['rating'] == 'phishing'
    assert phish_res['rating_label'] == 'High-Risk Phishing Warning'
    assert phish_res['composite_score'] >= 0.65
    assert len(phish_res['rules_breakdown']) == 13


def test_detector_fallback_mode():
    # Pass non-existent path to trigger heuristic fallback
    detector = PhishieldDetector(model_path="non_existent_model.joblib")
    assert detector.model is None

    res = detector.predict("https://www.wikipedia.org/wiki/Phishing")
    assert res['model_available'] is False
    assert 0.0 <= res['composite_score'] <= 1.0
    assert len(res['rules_breakdown']) == 13


def test_rating_boundaries():
    detector = PhishieldDetector()
    res = detector.predict("https://example.com")
    assert res['rating'] in ['safe', 'suspicious', 'phishing']
    assert 0.0 <= res['composite_score'] <= 1.0
    assert 0.0 <= res['rules_score'] <= 1.0
    assert 0.0 <= res['ml_score'] <= 1.0

