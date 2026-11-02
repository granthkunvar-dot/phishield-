"""
Phishield Authentication & Security Module (Hardened & Bug-Proofed)
Implements:
- OWASP Recommended scrypt password hashing (N=2^17 = 131072, r=8, p=1, salt=16 bytes, maxmem=256MB)
- Account lockout policy: Lockout for 15 minutes after 5 consecutive failed login attempts
- Anti-enumeration timing defense (dummy scrypt verification on non-existent accounts)
- Password length caps (8-128 chars) preventing CPU/memory exhaustion attacks
- Cryptographic CSRF token generation and constant-time verification
- Parameterized SQL for complete injection prevention
"""

import os
import re
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort
from app.database import get_db_connection
from app.security import DUMMY_SCRYPT_HASH

# OWASP Recommended scrypt parameters
SCRYPT_N = 131072  # 2^17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 268435456  # 256 MB allowance for N=2^17
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using scrypt with N=2^17 and 16-byte cryptographically secure salt.
    Format: scrypt:131072:8:1$<salt_hex>$<hash_hex>
    """
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM
    )
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against a stored scrypt hash using constant-time comparison.
    """
    if not stored_hash or not stored_hash.startswith("scrypt:"):
        return False
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        header, salt_hex, hash_hex = stored_hash.split('$')
        _, n_str, r_str, p_str = header.split(':')
        n = int(n_str)
        r = int(r_str)
        p = int(p_str)
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        
        derived = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=SCRYPT_MAXMEM
        )
        return hmac.compare_digest(derived, expected_hash)
    except Exception:
        return False


def generate_csrf_token() -> str:
    """Generates and stores a unique CSRF token in session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token(token_to_verify: str) -> bool:
    """Validates the submitted CSRF token using constant-time comparison."""
    session_token = session.get('csrf_token')
    if not session_token or not token_to_verify:
        return False
    return hmac.compare_digest(session_token, token_to_verify)


def login_required(f):
    """Decorator to enforce authenticated session for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('auth.login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def register_user(email: str, password: str, db_path: str = None) -> tuple[bool, str]:
    """
    Registers a new user with email and scrypt-hashed password.
    Enforces email format and password complexity (8-128 chars, requires digit or symbol).
    """
    cleaned_email = (email or '').strip().lower()
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', cleaned_email):
        return False, "Please provide a valid email address."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password cannot exceed {MAX_PASSWORD_LENGTH} characters."
    if not any(c.isdigit() or not c.isalnum() for c in password):
        return False, "Password must contain at least one number or special character."
        
    pwd_hash = hash_password(password)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (cleaned_email, pwd_hash)
        )
        conn.commit()
        return True, "Registration successful. You can now log in."
    except Exception as e:
        if "UNIQUE" in str(e).upper():
            return False, "An account with this email already exists."
        return False, "An error occurred during registration. Please try again."
    finally:
        conn.close()


def authenticate_user(email: str, password: str, db_path: str = None) -> tuple[dict | None, str]:
    """
    Authenticates a user, checking for account lockout and updating failed attempt counters.
    Applies timing attack mitigation (computes dummy scrypt on missing user).
    Returns (user_dict or None, status_message).
    """
    cleaned_email = (email or '').strip().lower()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (cleaned_email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        # Timing attack mitigation: compute dummy verification so response duration matches
        verify_password(password or "dummy", DUMMY_SCRYPT_HASH)
        return None, "Invalid email or password."
        
    user_id = user['id']
    failed_attempts = user['failed_attempts']
    locked_until = user['locked_until']
    now = datetime.now(timezone.utc)
    
    # 1. Check if account is currently locked out
    if locked_until:
        try:
            lock_time = datetime.fromisoformat(locked_until)
        except ValueError:
            lock_time = datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S')
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
            
        if now < lock_time:
            remaining = int((lock_time - now).total_seconds() / 60) + 1
            conn.close()
            return None, f"Account is locked due to multiple failed login attempts. Try again in {remaining} minute(s)."
        else:
            # Lockout period expired; reset failed attempts
            cursor.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
            conn.commit()
            failed_attempts = 0

    # 2. Verify password with scrypt
    if verify_password(password, user['password_hash']):
        # Reset failed attempts on success
        cursor.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        conn.commit()
        user_data = dict(user)
        conn.close()
        return user_data, "Login successful."
    else:
        # Increment failed attempts
        new_attempts = failed_attempts + 1
        if new_attempts >= MAX_FAILED_ATTEMPTS:
            new_locked_until = (now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_attempts, new_locked_until, user_id)
            )
            conn.commit()
            conn.close()
            return None, f"Too many failed login attempts. Your account is locked for {LOCKOUT_DURATION_MINUTES} minutes."
        else:
            remaining_tries = MAX_FAILED_ATTEMPTS - new_attempts
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_attempts, user_id)
            )
            conn.commit()
            conn.close()
            return None, f"Invalid email or password. {remaining_tries} attempt(s) remaining before account lockout."
