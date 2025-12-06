from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv('RATELIMIT_STORAGE_URL', 'memory://')
)

# Content Security Policy configuration
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-ancestors': ["'none'"],
}

def create_app(config_name='default'):
    """
    Application factory pattern for creating Flask app instances.

    Security benefits:
    - Allows for different configurations (dev, test, prod)
    - Prevents circular imports
    - Enables testing with different security settings
    """
    app = Flask(__name__)

    # Security Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(32))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///secure_banking.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = False  # Disable in production to prevent SQL injection info leakage

    # Session Security Configuration
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout

    # Security headers and HTTPS enforcement
    app.config['FORCE_HTTPS'] = os.getenv('FORCE_HTTPS', 'True') == 'True'

    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', os.urandom(32))
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1800  # 30 minutes

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # HTTPS enforcement and security headers
    if app.config['FORCE_HTTPS']:
        Talisman(
            app,
            force_https=True,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,  # 1 year
            content_security_policy=csp,
            content_security_policy_nonce_in=['script-src'],
            referrer_policy='strict-origin-when-cross-origin',
            feature_policy={
                'geolocation': "'none'",
                'microphone': "'none'",
                'camera': "'none'",
            }
        )

    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.session_protection = 'strong'  # Protect against session hijacking

    # Register blueprints
    from app.controllers import auth, main, account, admin

    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(account.bp)
    app.register_blueprint(admin.bp)

    # Error handlers with security considerations
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors without revealing system information"""
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors, rollback DB and don't reveal stack traces"""
        db.session.rollback()
        from flask import render_template
        return render_template('errors/500.html'), 500

    @app.errorhandler(429)
    def ratelimit_handler(error):
        """Handle rate limit exceeded"""
        from flask import render_template
        return render_template('errors/429.html'), 429

    # Create database tables
    with app.app_context():
        db.create_all()

    return app
