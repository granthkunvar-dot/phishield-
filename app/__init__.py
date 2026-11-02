"""
Phishield Application Factory
Initializes Flask app, security headers, CSP, database, and blueprints.
"""

from flask import Flask
from app.config import Config
from app.database import init_db


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database
    init_db(app.config.get('DATABASE_PATH'))

    # Register blueprints
    from app.routes import main_bp, auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Security Headers Middleware (Strict CSP, Clickjacking, MIME-sniffing protection)
    @app.after_request
    def set_security_headers(response):
        # Allow self assets and inline styling/scripting required for responsive UI and chart widgets
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "script-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    return app


# Expose default WSGI application for production servers (e.g. Gunicorn `app:app`)
app = create_app()

