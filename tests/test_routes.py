"""
Integration Tests for Phishield Routes & Web Workflows
"""

import os
import tempfile
import pytest
from app import create_app
from app.database import init_db


@pytest.fixture
def app_and_client():
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    class TestConfig:
        TESTING = True
        SECRET_KEY = 'test-secret-key'
        DATABASE_PATH = db_path
        WTF_CSRF_ENABLED = False

    app = create_app(TestConfig)
    client = app.test_client()
    yield app, client, db_path
    
    if os.path.exists(db_path):
        os.remove(db_path)


def test_public_pages(app_and_client):
    _, client, _ = app_and_client
    
    # Home
    r = client.get('/')
    assert r.status_code == 200
    assert b"Explainable Phishing URL Detection" in r.data

    # Scan form
    r = client.get('/scan')
    assert r.status_code == 200
    assert b"Inspect a Suspicious Web Link" in r.data

    # Scan form with prefill
    r_pre = client.get('/scan?url=https://example.com')
    assert r_pre.status_code == 200
    assert b"https://example.com" in r_pre.data

    # About
    r = client.get('/about')
    assert r.status_code == 200
    assert b"13 Transparent URL Heuristic Rules" in r.data

    # Privacy
    r = client.get('/privacy')
    assert r.status_code == 200
    assert b"UK GDPR" in r.data

    # Report GET
    r_rep_get = client.get('/report?url=https://example.com&rating=safe')
    assert r_rep_get.status_code == 200
    assert b"Report a Wrong Result" in r_rep_get.data


def test_csrf_protection_on_post(app_and_client):
    _, client, _ = app_and_client
    # POST without CSRF token must fail with 400
    r = client.post('/scan', data={'url': 'https://example.com'})
    assert r.status_code == 400


def test_scan_flow_with_csrf(app_and_client):
    _, client, _ = app_and_client
    
    # 1. Fetch scan page to obtain CSRF token from session
    r = client.get('/scan')
    assert r.status_code == 200
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')

    # 2. Submit scan with valid token
    r = client.post('/scan', data={'url': 'https://www.wikipedia.org', 'csrf_token': token})
    assert r.status_code == 200
    assert b"Inspection Assessment" in r.data
    assert b"hxxps[://]www[.]wikipedia[.]org" in r.data

    # 3. Submit empty scan
    r_empty = client.post('/scan', data={'url': '', 'csrf_token': token}, follow_redirects=True)
    assert r_empty.status_code == 200
    assert b"Please enter a web address" in r_empty.data

    # 4. Submit invalid url
    r_inv = client.post('/scan', data={'url': 'invalid url with space', 'csrf_token': token})
    assert r_inv.status_code == 200
    assert b"Invalid web address format" in r_inv.data


def test_auth_and_history_lifecycle(app_and_client):
    _, client, _ = app_and_client
    
    # Get CSRF
    client.get('/auth/register')
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')

    # Register with mismatched passwords
    r_mis = client.post('/auth/register', data={
        'email': 'student@university.ac.uk',
        'password': 'SecurePassword2026!',
        'confirm_password': 'MismatchPassword!',
        'csrf_token': token
    })
    assert b"Passwords do not match" in r_mis.data

    # Register successfully
    r = client.post('/auth/register', data={
        'email': 'student@university.ac.uk',
        'password': 'SecurePassword2026!',
        'confirm_password': 'SecurePassword2026!',
        'csrf_token': token
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Registration successful" in r.data

    # Invalid login attempt
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r_fail = client.post('/auth/login', data={
        'email': 'student@university.ac.uk',
        'password': 'WrongPassword123!',
        'csrf_token': token
    })
    assert b"Invalid email or password" in r_fail.data

    # Successful Login with relative next redirect
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r = client.post('/auth/login?next=/history', data={
        'email': 'student@university.ac.uk',
        'password': 'SecurePassword2026!',
        'csrf_token': token
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Welcome back" in r.data

    # Scan as authenticated user
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r = client.post('/scan', data={
        'url': 'http://phishing-portal.xyz/login.php?token=secret123',
        'csrf_token': token
    })
    assert r.status_code == 200

    # View history
    r = client.get('/history')
    assert r.status_code == 200
    assert b"token=***MASKED***" in r.data
    assert b"phishing-portal.xyz" in r.data

    # Delete single scan
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r_del = client.post('/history/delete/1', data={'csrf_token': token}, follow_redirects=True)
    assert r_del.status_code == 200
    assert b"successfully removed" in r_del.data

    # Clear history
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r = client.post('/history/clear', data={'csrf_token': token}, follow_redirects=True)
    assert r.status_code == 200
    assert b"purged" in r.data

    # View Account page
    r_acc = client.get('/auth/account')
    assert r_acc.status_code == 200
    assert b"student@university.ac.uk" in r_acc.data

    # Fail to delete account without typing 'DELETE'
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r_acc_fail = client.post('/auth/account', data={
        'confirm_delete': 'NOPE',
        'csrf_token': token
    }, follow_redirects=True)
    assert b"DELETE" in r_acc_fail.data and b"uppercase" in r_acc_fail.data

    # Submit feedback report
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r_rep = client.post('/report', data={
        'url': 'https://example.com',
        'reported_rating': 'safe',
        'expected_rating': 'phishing',
        'comments': 'Testing report mechanism',
        'csrf_token': token
    }, follow_redirects=True)
    assert r_rep.status_code == 200
    assert b"Thank you for submitting feedback" in r_rep.data

    # Delete Account (GDPR Article 17)
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
    r_acc_del = client.post('/auth/account', data={
        'confirm_delete': 'DELETE',
        'csrf_token': token
    }, follow_redirects=True)
    assert r_acc_del.status_code == 200
    assert b"permanently erased" in r_acc_del.data

    # Logout
    r_logout = client.get('/auth/logout', follow_redirects=True)
    assert r_logout.status_code == 200
    assert b"securely logged out" in r_logout.data
