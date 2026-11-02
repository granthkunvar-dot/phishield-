"""
Phishield Configuration Settings
"""

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishield-secret-key-production-grade-2026')
    DATABASE_PATH = os.environ.get('PHISHIELD_DB_PATH', os.path.join(os.path.dirname(__file__), '..', 'phishield.db'))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes session timeout
    MAX_CONTENT_LENGTH = 16 * 1024  # 16 KB request limit to avoid denial of service
    SEND_FILE_MAX_AGE_DEFAULT = 0  # Revalidate static files immediately on new deploy

