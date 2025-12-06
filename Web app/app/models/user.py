from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import os
import secrets
import pyotp
import bcrypt

# Initialize encryption for sensitive data
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)


class User(UserMixin, db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)

    # Password stored as hash using bcrypt
    password_hash = db.Column(db.String(255), nullable=False)

    # Personal information (encrypted)
    _encrypted_ssn = db.Column('ssn', db.LargeBinary, nullable=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)

    # Account security
    account_locked = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

    # MFA settings
    mfa_enabled = db.Column(db.Boolean, default=False)
    _encrypted_mfa_secret = db.Column('mfa_secret', db.LargeBinary, nullable=True)

    # Session management
    session_token = db.Column(db.String(255), nullable=True)
    session_expiry = db.Column(db.DateTime, nullable=True)

    # Account metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    # Relationships
    accounts = db.relationship('BankAccount', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    transactions = db.relationship('Transaction', backref='user', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def set_password(self, password):
        """
        Hash password using bcrypt with salt.

        Security: bcrypt is designed to be slow, making brute force attacks impractical.
        Each password gets a unique salt, preventing rainbow table attacks.
        """
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds provides good security/performance balance
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        """
        Verify password against stored hash.

        Security: Uses constant-time comparison to prevent timing attacks.
        """
        if self.account_locked:
            return False

        try:
            is_valid = bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

            if is_valid:
                # Reset failed attempts on successful login
                self.failed_login_attempts = 0
                self.last_login = datetime.utcnow()
                self.generate_session_token()
            else:
                # Increment failed attempts
                self.failed_login_attempts += 1
                self.last_failed_login = datetime.utcnow()

                # Lock account after 5 failed attempts
                if self.failed_login_attempts >= 5:
                    self.account_locked = True

            db.session.commit()
            return is_valid
        except Exception as e:
            return False

    def generate_session_token(self):
        """
        Generate secure session token.

        Security: Uses secrets module for cryptographically strong random tokens.
        Token expires after configured session timeout.
        """
        self.session_token = secrets.token_urlsafe(32)
        self.session_expiry = datetime.utcnow() + timedelta(minutes=30)
        return self.session_token

    def validate_session(self):
        """Check if current session is valid and not expired."""
        if not self.session_token or not self.session_expiry:
            return False
        return datetime.utcnow() < self.session_expiry

    def invalidate_session(self):
        """Invalidate current session (logout)."""
        self.session_token = None
        self.session_expiry = None
        db.session.commit()

    # Encrypted SSN property
    @property
    def ssn(self):
        """Decrypt and return SSN."""
        if self._encrypted_ssn:
            return cipher_suite.decrypt(self._encrypted_ssn).decode('utf-8')
        return None

    @ssn.setter
    def ssn(self, value):
        """Encrypt and store SSN."""
        if value:
            self._encrypted_ssn = cipher_suite.encrypt(value.encode('utf-8'))

    # MFA methods
    def enable_mfa(self):
        """
        Enable MFA and generate TOTP secret.

        Security: Uses TOTP (Time-based One-Time Password) standard.
        Secret is encrypted at rest.
        """
        secret = pyotp.random_base32()
        self._encrypted_mfa_secret = cipher_suite.encrypt(secret.encode('utf-8'))
        self.mfa_enabled = True
        db.session.commit()
        return secret

    def disable_mfa(self):
        """Disable MFA."""
        self.mfa_enabled = False
        self._encrypted_mfa_secret = None
        db.session.commit()

    def get_mfa_secret(self):
        """Get decrypted MFA secret."""
        if self._encrypted_mfa_secret:
            return cipher_suite.decrypt(self._encrypted_mfa_secret).decode('utf-8')
        return None

    def verify_mfa_token(self, token):
        """
        Verify MFA token.

        Security: Validates TOTP token with 30-second time window.
        """
        if not self.mfa_enabled:
            return True

        secret = self.get_mfa_secret()
        if not secret:
            return False

        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 1 window before/after for clock skew

    def get_mfa_qr_uri(self):
        """Get URI for QR code generation."""
        secret = self.get_mfa_secret()
        if secret:
            totp = pyotp.TOTP(secret)
            return totp.provisioning_uri(
                name=self.email,
                issuer_name='SecureBank'
            )
        return None

    def unlock_account(self):
        """Unlock account (admin function)."""
        self.account_locked = False
        self.failed_login_attempts = 0
        db.session.commit()

    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login user loader callback.

    Security: Loads user from database for each request.
    Validates session is still active.
    """
    user = User.query.get(int(user_id))
    if user and user.validate_session():
        return user
    return None


class BankAccount(db.Model):
    """
    Bank account model with encrypted account numbers.

    Security: Account numbers encrypted at rest.
    """
    __tablename__ = 'bank_accounts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Encrypted account number
    _encrypted_account_number = db.Column('account_number', db.LargeBinary, nullable=False)
    account_type = db.Column(db.String(20), nullable=False)  # checking, savings
    balance = db.Column(db.Float, default=0.0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    @property
    def account_number(self):
        """Decrypt and return account number."""
        return cipher_suite.decrypt(self._encrypted_account_number).decode('utf-8')

    @account_number.setter
    def account_number(self, value):
        """Encrypt and store account number."""
        self._encrypted_account_number = cipher_suite.encrypt(value.encode('utf-8'))

    def __repr__(self):
        return f'<BankAccount {self.account_type}>'


class Transaction(db.Model):
    """Transaction model with audit trail."""
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), nullable=False)

    transaction_type = db.Column(db.String(20), nullable=False)  # deposit, withdrawal, transfer
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))

    # For transfers
    to_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='completed')  # completed, pending, failed

    account = db.relationship('BankAccount', foreign_keys=[account_id], backref='transactions_from')
    to_account = db.relationship('BankAccount', foreign_keys=[to_account_id], backref='transactions_to')

    def __repr__(self):
        return f'<Transaction {self.transaction_type} ${self.amount}>'


class AuditLog(db.Model):
    """
    Audit log for security events.

    Security: Tracks all security-relevant actions for forensics.
    """
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'
