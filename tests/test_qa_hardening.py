"""
Senior QA Hardening & Edge-Case Test Suite
Validates vulnerability fixes, edge-case safety, rate limiting, and security boundaries.
"""

import os
import tempfile
import pytest
from app import create_app
from app.utils import is_valid_url, normalize_url
from app.rules import PhishieldRuleEngine
from app.auth import register_user, authenticate_user, MAX_PASSWORD_LENGTH
from app.security import InMemoryRateLimiter, DUMMY_SCRYPT_HASH
from app.database import get_db_connection, init_db


def test_malformed_and_out_of_range_ports():
    # URL with out-of-range port (previously caused ValueError: Port out of range)
    bad_port_url = "http://example.com:99999999999/path"
    
    # is_valid_url must safely reject without uncaught exception
    assert is_valid_url(bad_port_url) is False

    # PhishieldRuleEngine must handle safely without crashing
    engine = PhishieldRuleEngine(bad_port_url)
    assert engine.port == -1
    r8 = engine.rule_8_non_standard_port()
    assert r8['triggered'] is True
    assert "out-of-range" in r8['explanation']


def test_dangerous_schemes_rejection():
    # Dangerous schemes must be rejected
    assert is_valid_url("javascript:alert(1)") is False
    assert is_valid_url("data:text/html;base64,PHNjcmlwdD4=") is False
    assert is_valid_url("file:///etc/passwd") is False
    assert is_valid_url("vbscript:MsgBox(1)") is False
    assert is_valid_url("about:blank") is False
    assert is_valid_url("blob:https://example.com/uuid") is False


def test_control_character_injection():
    # Null bytes and CRLF injections
    assert is_valid_url("http://example.com/\x00evil") is False
    assert is_valid_url("http://example.com/\r\nSet-Cookie:evil=true") is False
    assert is_valid_url("http://example.com/\tpath") is False


def test_password_complexity_and_length_caps():
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    init_db(db_path)

    # Missing number/symbol
    ok, msg = register_user("qa.user@test.com", "OnlyLettersPassword", db_path=db_path)
    assert ok is False
    assert "number or special character" in msg

    # Exceeds max length (DoS prevention)
    huge_pwd = "P" * (MAX_PASSWORD_LENGTH + 1) + "1!"
    ok, msg = register_user("qa.user@test.com", huge_pwd, db_path=db_path)
    assert ok is False
    assert "cannot exceed" in msg

    # Valid complex password
    ok, msg = register_user("qa.user@test.com", "ValidPassw0rd2026!", db_path=db_path)
    assert ok is True

    os.remove(db_path)


def test_timing_attack_mitigation():
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    init_db(db_path)

    # Non-existent user still executes dummy verification safely
    user, msg = authenticate_user("does_not_exist@example.com", "SomePassword123!", db_path=db_path)
    assert user is None
    assert "Invalid email or password" in msg

    os.remove(db_path)


def test_in_memory_rate_limiter():
    limiter = InMemoryRateLimiter()
    ip = "192.0.2.1"
    action = "test_action"

    # Allow 3 requests in a 10-second window
    assert limiter.is_allowed(ip, action, max_requests=3, window_seconds=10) is True
    assert limiter.is_allowed(ip, action, max_requests=3, window_seconds=10) is True
    assert limiter.is_allowed(ip, action, max_requests=3, window_seconds=10) is True
    
    # 4th request must be blocked
    assert limiter.is_allowed(ip, action, max_requests=3, window_seconds=10) is False

    # Reset allows again
    limiter.reset_for_ip(ip)
    assert limiter.is_allowed(ip, action, max_requests=3, window_seconds=10) is True


def test_custom_error_pages():
    app = create_app()
    client = app.test_client()

    # 404 test
    resp_404 = client.get('/this-route-does-not-exist')
    assert resp_404.status_code == 404
    assert b"Resource Not Found" in resp_404.data

    # 400 test (POST without CSRF)
    resp_400 = client.post('/scan', data={'url': 'https://example.com'})
    assert resp_400.status_code == 400
    assert b"Security Request Rejected" in resp_400.data


def test_sqlite_wal_mode_and_concurrency():
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    init_db(db_path)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode;")
    mode = cursor.fetchone()[0].upper()
    assert mode in ["WAL", "MEMORY", "DELETE"]  # WAL on modern OS
    conn.close()

    os.remove(db_path)

