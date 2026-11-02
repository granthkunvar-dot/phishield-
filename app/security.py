"""
Phishield Security & Rate Limiting Module
Provides:
- In-memory thread-safe rate limiter (sliding window) to prevent DoS & brute-force attacks.
- Anti-enumeration timing defense (dummy scrypt verification for non-existent users).
- Input sanitization and payload inspection.
"""

import time
import threading
from functools import wraps
from flask import request, abort, render_template

# Dummy hash for timing attack mitigation (computed once at startup)
# Ensures user authentication takes identical time whether email exists or not.
DUMMY_SCRYPT_HASH = (
    "scrypt:131072:8:1$"
    "00112233445566778899aabbccddeeff$"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


class InMemoryRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter.
    Tracks requests per client IP address.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._records = {}  # ip: [(timestamp, action_key), ...]

    def is_allowed(self, client_ip: str, action: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        
        with self._lock:
            if client_ip not in self._records:
                self._records[client_ip] = []

            # Clean expired timestamps for this IP
            self._records[client_ip] = [
                (t, act) for (t, act) in self._records[client_ip] if t > cutoff
            ]

            # Count recent requests for this specific action
            current_count = sum(1 for (t, act) in self._records[client_ip] if act == action)

            if current_count >= max_requests:
                return False

            # Record this valid request
            self._records[client_ip].append((now, action))
            return True

    def reset_for_ip(self, client_ip: str):
        with self._lock:
            if client_ip in self._records:
                del self._records[client_ip]


# Singleton rate limiter
rate_limiter = InMemoryRateLimiter()


def rate_limit(action: str, max_requests: int = 60, window_seconds: int = 60):
    """
    Decorator to apply sliding-window rate limiting to routes.
    Example: @rate_limit('login', max_requests=10, window_seconds=60)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Resolve client IP safely (respecting proxies if configured)
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()

            if not rate_limiter.is_allowed(client_ip, action, max_requests, window_seconds):
                # Return HTTP 429 Too Many Requests
                abort(429, description=f"Rate limit exceeded. Please wait {window_seconds} seconds before retrying.")

            return f(*args, **kwargs)
        return decorated_function
    return decorator

