"""
Phishield URL Utilities (Hardened & Bug-Proofed)
Provides URL normalization, validation, defanging, and sensitive query parameter masking.
Enforces UK GDPR data minimisation and prevents accidental clicks or malicious scheme execution.
"""

import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# Schemes that are strictly disallowed to prevent XSS / local file disclosure / SSRF
DISALLOWED_SCHEMES = {
    'javascript', 'data', 'file', 'vbscript', 'about', 'blob', 'filesystem',
    'chrome', 'res', 'jar', 'view-source', 'gopher'
}

# Only web protocols allowed for inspection
ALLOWED_SCHEMES = {'http', 'https', 'ftp'}

# Sensitive parameter names to mask in query strings (UK GDPR Minimisation)
SENSITIVE_PARAM_KEYS = {
    'token', 'access_token', 'id_token', 'refresh_token', 'auth', 'authentication',
    'key', 'apikey', 'api_key', 'secret', 'password', 'pass', 'pwd',
    'email', 'user', 'username', 'session', 'session_id', 'code', 'reset',
    'verification_code', 'signature', 'sig'
}


def normalize_url(raw_url: str) -> str:
    """
    Trims and normalizes a URL.
    Safely strips control characters and whitespace.
    If no scheme is present, defaults to 'http://' for structural evaluation.
    """
    if not raw_url:
        return ""
    # Strip null bytes and control characters
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', raw_url.strip())
    
    # Check if raw string starts with a scheme like "scheme://" or "scheme:"
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', cleaned):
        cleaned = 'http://' + cleaned
    return cleaned


def is_valid_url(url: str) -> bool:
    """
    Validates whether the string represents a plausible, safe HTTP/HTTPS URL format.
    Does NOT connect to or ping the host.
    Rejects dangerous schemes (javascript:, file:), control characters, and malformed hosts.
    """
    if not url or len(url) > 4096:
        return False

    # Control chars or whitespace within URL are invalid
    if any(c in url for c in [' ', '\r', '\n', '\t', '\x00']):
        return False

    # Check for dangerous non-HTTP schemes
    url_lower = url.strip().lower()
    for bad_scheme in DISALLOWED_SCHEMES:
        if url_lower.startswith(f"{bad_scheme}:"):
            return False

    try:
        norm = normalize_url(url)
        parsed = urlparse(norm)
        
        # Must be an allowed web scheme
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return False

        if not parsed.netloc:
            return False

        # Safely extract host without port, handling malformed ports
        try:
            # Check port range safely
            _ = parsed.port
        except ValueError:
            # Port is out of range 0-65535, invalid URL
            return False

        host = parsed.netloc.split(':')[0].strip('[]').lower()
        if not host or len(host) < 2:
            return False

        # Host must contain valid characters (letters, numbers, hyphens, dots, underscores)
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', host):
            return False

        # Must contain at least one dot (domain.tld or IP) or be localhost
        if '.' not in host and host != 'localhost':
            return False

        return True
    except Exception:
        return False


def defang_url(url: str) -> str:
    """
    Converts a live URL into a non-clickable, defanged representation
    to prevent accidental opening or browser pre-fetching of malicious sites.
    Example: https://malicious.example.com/login -> hxxps[://]malicious[.]example[.]com/login
    """
    if not url:
        return ""

    match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*)://(.*)$', url.strip())
    if match:
        scheme, rest = match.groups()
        scheme_lower = scheme.lower()
        if scheme_lower == 'https':
            scheme_part = 'hxxps[://]'
        elif scheme_lower == 'http':
            scheme_part = 'hxxp[://]'
        elif scheme_lower == 'ftp':
            scheme_part = 'fxp[://]'
        else:
            scheme_part = f"{scheme}[://]"
    else:
        scheme_part = ''
        rest = url.strip()

    # Split host from path
    if '/' in rest:
        host, path = rest.split('/', 1)
        path = '/' + path
    else:
        host = rest
        path = ''

    # Defang dots in the host and defang @ symbol
    host_defanged = host.replace('.', '[.]').replace('@', '[@]')
    
    return f"{scheme_part}{host_defanged}{path}"


def mask_sensitive_query_params(url: str) -> str:
    """
    Masks values of sensitive query parameters (e.g., token, email, secret) with '***MASKED***'
    in accordance with UK GDPR Principle of Data Minimisation.
    """
    if not url:
        return ""
    try:
        norm = normalize_url(url)
        parsed = urlparse(norm)
        if not parsed.query:
            return url
        
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        masked_items = []
        for key, vals in query_dict.items():
            key_lower = key.lower()
            if key_lower in SENSITIVE_PARAM_KEYS or any(s in key_lower for s in ['token', 'secret', 'pass']):
                masked_items.append((key, '***MASKED***'))
            else:
                for v in vals:
                    masked_items.append((key, v))
        
        # Use safe='*' so asterisks are kept intact
        new_query = urlencode(masked_items, safe='*')
        reconstructed = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        return reconstructed
    except Exception:
        return url
