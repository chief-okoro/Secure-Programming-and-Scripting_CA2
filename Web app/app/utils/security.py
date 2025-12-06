import bleach
import re
from markupsafe import escape
from flask import request, abort
from functools import wraps
from app.models.user import AuditLog
from app import db


# Allowed HTML tags for rich text (very restrictive)
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u']
ALLOWED_ATTRIBUTES = {}


def sanitize_input(text, allow_html=False):
    """

    Security: Removes dangerous HTML/JavaScript while preserving safe content.

  
    """
    if not text:
        return ""

    if allow_html:
        # Use bleach to remove dangerous HTML while keeping safe tags
        return bleach.clean(
            text,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True
        )
    else:
        # For plain text, escape all HTML
        return escape(str(text))


def validate_email(email):
    """
    Validate email format.

    Security: Prevents injection through malformed email addresses.
    """
    if not email:
        return False

    # RFC 5322 compliant email regex (simplified)
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password_strength(password):
    """

    Requirements:
    - At least 8 characters
    - Contains uppercase letter
    - Contains lowercase letter
    - Contains number
    - Contains special character

    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, ""


def validate_username(username):
    """
    Validate username format.

    Security: Only allows alphanumeric and underscore to prevent injection.
    """
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"

    if len(username) > 20:
        return False, "Username must be less than 20 characters"

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"

    return True, ""


def log_security_event(user_id, action, success=True, details=None):
    """
    Log security event to audit trail.

    Security: Creates forensic trail for security analysis.
    """
    try:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent', '')[:255] if request else None,
            success=success,
            details=details
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        # Don't fail the request if logging fails
        print(f"Failed to log security event: {e}")


def admin_required(f):
    """
    Security: Enforces authorization checks.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user

        if not current_user.is_authenticated:
            abort(401)  # Unauthorized

        if not current_user.is_admin:
            log_security_event(
                current_user.id,
                f"Unauthorized admin access attempt to {request.endpoint}",
                success=False
            )
            abort(403)  # Forbidden

        return f(*args, **kwargs)

    return decorated_function


def validate_account_ownership(f):
    """
    Security: Prevents horizontal privilege escalation.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        from app.models.user import BankAccount

        account_id = kwargs.get('account_id')
        if not account_id:
            abort(400)

        account = BankAccount.query.get_or_404(account_id)

        if account.user_id != current_user.id and not current_user.is_admin:
            log_security_event(
                current_user.id,
                f"Unauthorized account access attempt: account_id={account_id}",
                success=False
            )
            abort(403)

        return f(*args, **kwargs)

    return decorated_function


class VulnerableQueries:
    @staticmethod
    def vulnerable_login(username, password):
        """
        VULNERABLE: SQL Injection via string concatenation

        Attack example:
        username: admin' OR '1'='1
        password: anything

        Result: Bypasses authentication
        """
     
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        # This query is vulnerable to SQL injection
        return query

    @staticmethod
    def vulnerable_search(search_term):
        """
        VULNERABLE: SQL Injection in search

        Attack example:
        search_term: '; DROP TABLE users; --

        Result: Deletes users table
        """
        # WARNING: NEVER DO THIS!
        query = f"SELECT * FROM transactions WHERE description LIKE '%{search_term}%'"
        return query


class SecureQueries:
    """
    SECURE: Proper SQL query patterns using SQLAlchemy ORM

    """

    @staticmethod
    def secure_login(username):
        """
        SECURE: Uses SQLAlchemy ORM with parameterized queries

        """
        from app.models.user import User
        # Parameterized query - SQLAlchemy handles escaping
        return User.query.filter_by(username=username).first()

    @staticmethod
    def secure_search(search_term):
        """
        SECURE: Uses SQLAlchemy with proper parameter binding

        """
        from app.models.user import Transaction
        # Safe: SQLAlchemy parameterizes the LIKE query
        return Transaction.query.filter(
            Transaction.description.like(f'%{search_term}%')
        ).all()


def demonstrate_xss_prevention():
    """
    Demonstrates XSS attack and prevention.

    """
    malicious_input = "<script>alert('XSS Attack!')</script>"

    return {
        'input': malicious_input,
        'vulnerable': malicious_input,  # Rendered as-is, executes script
        'secure': sanitize_input(malicious_input),  # Escaped, renders as text
        'explanation': 'The secure version escapes HTML, preventing script execution'
    }


def check_suspicious_activity(user):
    """
    Check for suspicious user activity patterns.

   """
    from datetime import datetime, timedelta

    suspicious = False
    reasons = []

    # Check for multiple failed logins
    if user.failed_login_attempts >= 3:
        suspicious = True
        reasons.append(f"Multiple failed login attempts ({user.failed_login_attempts})")

    # Check for recent rapid transactions
    recent_transactions = user.transactions.filter(
        Transaction.timestamp >= datetime.utcnow() - timedelta(minutes=10)
    ).count()

    if recent_transactions > 10:
        suspicious = True
        reasons.append(f"High transaction frequency ({recent_transactions} in 10 minutes)")

    return suspicious, reasons
