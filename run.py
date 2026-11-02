"""
Phishield Application Server Entry Point
Designed for full cross-platform compatibility (macOS Apple Silicon M-series, Linux, Windows).
Avoids common macOS AirPlay port 5000 conflicts by defaulting to port 5001 with automatic port fallback.
"""

import os
import sys
import socket
from app import create_app

def find_available_port(default_port=5001, fallback_ports=(5000, 5002, 8000, 8080)):
    """Finds an open port, gracefully avoiding macOS AirPlay Receiver port 5000 clashes."""
    for p in [default_port] + list(fallback_ports):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', p))
                return p
            except OSError:
                continue
    return default_port

if __name__ == '__main__':
    app = create_app()
    
    # Allow port to be specified via environment variable, CLI, or auto-selected
    env_port = os.environ.get('PORT')
    host = os.environ.get('HOST', '0.0.0.0' if env_port else '127.0.0.1')
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            port = find_available_port(5001)
    else:
        port = find_available_port(5001)

    print("=" * 65)
    print("  PHISHIELD: Explainable Phishing Detection Framework")
    print("  - 13 Transparent Structural Rules (40% Weight)")
    print("  - Random Forest Machine Learning (60% Weight)")
    print("  - UK GDPR Data Minimisation & Retention Enabled")
    print("  - Zero-Click Safe Analysis (Never visits target links)")
    print("=" * 65)
    print(f"  * Running on: http://{host}:{port}")
    print(f"  * Optimized for macOS Apple Silicon (M1/M2/M3/M4/M5) & Cross-Platform")
    print("  * Press Ctrl+C to stop the server")
    print("=" * 65)
    
    app.run(host=host, port=port, debug=False)

