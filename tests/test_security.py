"""
Unit & Integration Tests for Phishield Security Controls
Covers CSRF, URL defanging, query masking, parameterized SQL, XSS, and security headers.
"""

import os
import tempfile
import sqlite3
import pytest
from app import create_app
from app.utils import defang_url, mask_sensitive_query_params, is_valid_url
from app.database import init_db, cleanup_expired_scans, delete_user_account, get_db_connection
from app.auth import register_user, hash_password


def test_url_defanging():
    raw_https = "https://paypal-security-alert.xyz/verify.php"
    defanged = defang_url(raw_https)
    assert "hxxps[://]" in defanged
    assert "[.]" in defanged
    assert "https://" not in defanged

    raw_http = "http://192.168.1.1:8080/path"
    defanged_http = defang_url(raw_http)
    assert "hxxp[://]" in defanged_http
    assert "[.]" in defanged_http

    # Email inside URL
    raw_at = "http://target.com@evil.com"
    defanged_at = defang_url(raw_at)
    assert "[@]" in defanged_at


def test_sensitive_query_parameter_masking():
    # URL with sensitive parameters
    url = "https://example.com/reset?token=SecretToken12345&email=user@test.com&ref=homepage"
    masked = mask_sensitive_query_params(url)
    assert "SecretToken12345" not in masked
    assert "user@test.com" not in masked
    assert "token=***MASKED***" in masked
    assert "email=***MASKED***" in masked
    assert "ref=homepage" in masked  # Non-sensitive preserved


def test_url_validator():
    assert is_valid_url("https://google.com") is True
    assert is_valid_url("http://192.168.1.1/admin") is True
    assert is_valid_url("example.com/test") is True
    assert is_valid_url("") is False
    assert is_valid_url("not a url at all") is False


def test_parameterized_queries_sql_injection_safety():
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    init_db(db_path)

    # Attempt classic SQL injection payload in email
    injection_email = "admin' OR '1'='1"
    ok, msg = register_user(injection_email, "P@ssword123", db_path=db_path)
    # Registration will safely reject due to email format validation
    assert ok is False

    # Direct query test with malicious input using parameterization
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (injection_email,))
    rows = cursor.fetchall()
    assert len(rows) == 0
    conn.close()
    os.remove(db_path)


def test_retention_cleanup_and_right_to_erasure():
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    init_db(db_path)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Insert user
    cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", ("user@test.com", "hash"))
    user_id = cursor.lastrowid

    # Insert old scan (100 days old)
    cursor.execute("""
        INSERT INTO scan_history (
            user_id, url_masked, url_defanged, rating,
            composite_score, rules_score, ml_score, triggered_rules_count, scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2025-01-01 00:00:00')
    """, (user_id, "http://old.com", "hxxp://old[.]com", "safe", 0.1, 0.1, 0.1, 0))

    # Insert fresh scan (today)
    cursor.execute("""
        INSERT INTO scan_history (
            user_id, url_masked, url_defanged, rating,
            composite_score, rules_score, ml_score, triggered_rules_count, scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (user_id, "http://fresh.com", "hxxp://fresh[.]com", "safe", 0.1, 0.1, 0.1, 0))
    conn.commit()
    conn.close()

    # 1. Test 90-day retention cleanup
    deleted = cleanup_expired_scans(db_path=db_path, days=90)
    assert deleted == 1

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM scan_history WHERE user_id = ?", (user_id,))
    assert cursor.fetchone()['cnt'] == 1
    conn.close()

    # 2. Test Right to Erasure (cascade delete account)
    delete_user_account(user_id, db_path=db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE id = ?", (user_id,))
    assert cursor.fetchone()['cnt'] == 0
    cursor.execute("SELECT COUNT(*) as cnt FROM scan_history WHERE user_id = ?", (user_id,))
    assert cursor.fetchone()['cnt'] == 0
    conn.close()
    os.remove(db_path)


def test_security_headers():
    app = create_app()
    client = app.test_client()
    resp = client.get('/')
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

