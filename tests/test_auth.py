"""
Unit Tests for Phishield Authentication & Lockout Engine
"""

import os
import tempfile
import pytest
from app.auth import (
    hash_password,
    verify_password,
    register_user,
    authenticate_user,
    MAX_FAILED_ATTEMPTS
)
from app.database import init_db


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_scrypt_hashing_and_verification():
    password = "CorrectHorseBatteryStaple123!"
    h = hash_password(password)
    assert h.startswith("scrypt:131072:8:1$")
    assert verify_password(password, h) is True
    assert verify_password("WrongPassword!", h) is False
    assert verify_password("", h) is False
    assert verify_password(password, "invalid_hash_string") is False


def test_user_registration(temp_db):
    # Success
    ok, msg = register_user("student@ntu.ac.uk", "StrongP@ssw0rd2026", db_path=temp_db)
    assert ok is True
    assert "successful" in msg.lower()

    # Duplicate email
    ok_dup, msg_dup = register_user("student@ntu.ac.uk", "AnotherPassword123", db_path=temp_db)
    assert ok_dup is False
    assert "already exists" in msg_dup.lower()

    # Invalid email format
    ok_inv, msg_inv = register_user("not-an-email", "StrongP@ssw0rd2026", db_path=temp_db)
    assert ok_inv is False
    assert "valid email" in msg_inv.lower()

    # Short password (<8 chars)
    ok_short, msg_short = register_user("user2@test.com", "short", db_path=temp_db)
    assert ok_short is False
    assert "at least 8" in msg_short.lower()


def test_authentication_and_lockout(temp_db):
    email = "security.user@example.com"
    pwd = "MyValidPassword2026!"
    register_user(email, pwd, db_path=temp_db)

    # 1. Successful login
    user, msg = authenticate_user(email, pwd, db_path=temp_db)
    assert user is not None
    assert user['email'] == email
    assert "successful" in msg.lower()

    # 2. Failed logins up to limit - 1 (4 attempts)
    for i in range(1, MAX_FAILED_ATTEMPTS):
        user, msg = authenticate_user(email, "WrongPassword", db_path=temp_db)
        assert user is None
        assert f"{MAX_FAILED_ATTEMPTS - i} attempt(s) remaining" in msg

    # 3. 5th failed login triggers lockout
    user, msg = authenticate_user(email, "WrongPassword", db_path=temp_db)
    assert user is None
    assert "locked for 15 minutes" in msg.lower()

    # 4. Immediate attempt even with CORRECT password is denied due to active lockout
    user_locked, msg_locked = authenticate_user(email, pwd, db_path=temp_db)
    assert user_locked is None
    assert "locked due to multiple failed login attempts" in msg_locked.lower()

