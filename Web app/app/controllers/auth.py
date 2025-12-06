from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.user import User
from app.utils.security import (
    sanitize_input,
    validate_email,
    validate_password_strength,
    validate_username,
    log_security_event
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import qrcode
import io
import base64

bp = Blueprint('auth', __name__, url_prefix='/auth')


class RegistrationForm(FlaskForm):
    """
    Registration form with validation.

    Security: Uses CSRF tokens automatically via Flask-WTF
    """
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=3, max=20, message='Username must be 3-20 characters')
        ]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(message='Invalid email address')]
    )
    first_name = StringField(
        'First Name',
        validators=[DataRequired(), Length(max=100)]
    )
    last_name = StringField(
        'Last Name',
        validators=[DataRequired(), Length(max=100)]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8, message='Password must be at least 8 characters')
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match')
        ]
    )
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Validate username doesn't exist and meets requirements."""
        # Sanitize input to prevent XSS
        clean_username = sanitize_input(username.data)

        # Check format
        is_valid, error = validate_username(clean_username)
        if not is_valid:
            raise ValidationError(error)

        # Check uniqueness
        user = User.query.filter_by(username=clean_username).first()
        if user:
            raise ValidationError('Username already taken')

    def validate_email(self, email):
        """Validate email doesn't exist."""
        clean_email = sanitize_input(email.data.lower())

        if not validate_email(clean_email):
            raise ValidationError('Invalid email format')

        user = User.query.filter_by(email=clean_email).first()
        if user:
            raise ValidationError('Email already registered')

    def validate_password(self, password):
        """Validate password strength."""
        is_valid, error = validate_password_strength(password.data)
        if not is_valid:
            raise ValidationError(error)


class LoginForm(FlaskForm):
    """Login form with CSRF protection."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    mfa_token = StringField('MFA Code (if enabled)', validators=[])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class MFASetupForm(FlaskForm):
    """MFA setup form."""
    token = StringField(
        'Verification Code',
        validators=[DataRequired(), Length(min=6, max=6)]
    )
    submit = SubmitField('Verify and Enable')


@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Prevent registration spam
def register():
    """
    User registration endpoint.

    Security:
    - Rate limited to prevent spam
    - Validates all inputs
    - Sanitizes user input
    - Logs registration attempts
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            # Sanitize all inputs
            username = sanitize_input(form.username.data)
            email = sanitize_input(form.email.data.lower())
            first_name = sanitize_input(form.first_name.data)
            last_name = sanitize_input(form.last_name.data)

            # Create new user
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name
            )
            user.set_password(form.password.data)

            db.session.add(user)
            db.session.commit()

            # Log successful registration
            log_security_event(
                user.id,
                "User registered",
                success=True,
                details=f"Username: {username}, Email: {email}"
            )

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            log_security_event(
                None,
                "Registration failed",
                success=False,
                details=str(e)
            )
            flash('Registration failed. Please try again.', 'danger')

    return render_template('auth/register.html', form=form)


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Prevent brute force attacks
def login():
    """
    User login endpoint.

    Security:
    - Rate limited to prevent brute force
    - Account lockout after failed attempts
    - MFA validation if enabled
    - Session token generation
    - Audit logging
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        # Sanitize username input
        username = sanitize_input(form.username.data)

        # Find user
        user = User.query.filter_by(username=username).first()

        if user is None:
            # Don't reveal whether user exists
            log_security_event(
                None,
                "Failed login attempt",
                success=False,
                details=f"Unknown username: {username}"
            )
            flash('Invalid username or password', 'danger')
            return render_template('auth/login.html', form=form)

        # Check if account is locked
        if user.account_locked:
            log_security_event(
                user.id,
                "Login attempt on locked account",
                success=False
            )
            flash('Account is locked due to multiple failed login attempts. Contact support.', 'danger')
            return render_template('auth/login.html', form=form)

        # Verify password
        if not user.check_password(form.password.data):
            log_security_event(
                user.id,
                "Failed login attempt - invalid password",
                success=False
            )
            flash(f'Invalid username or password. Attempts remaining: {5 - user.failed_login_attempts}', 'danger')
            return render_template('auth/login.html', form=form)

        # If MFA is enabled, verify token
        if user.mfa_enabled:
            mfa_token = form.mfa_token.data

            if not mfa_token:
                flash('MFA code required', 'warning')
                return render_template('auth/login.html', form=form, mfa_required=True)

            if not user.verify_mfa_token(mfa_token):
                log_security_event(
                    user.id,
                    "Failed login attempt - invalid MFA token",
                    success=False
                )
                flash('Invalid MFA code', 'danger')
                return render_template('auth/login.html', form=form, mfa_required=True)

        # Successful login
        login_user(user, remember=form.remember.data)

        log_security_event(
            user.id,
            "Successful login",
            success=True
        )

        flash(f'Welcome back, {user.first_name}!', 'success')

        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):  # Prevent open redirect
            return redirect(next_page)
        return redirect(url_for('main.dashboard'))

    return render_template('auth/login.html', form=form)


@bp.route('/logout')
@login_required
def logout():
    """
    User logout endpoint.

    Security: Invalidates session token
    """
    log_security_event(
        current_user.id,
        "User logout",
        success=True
    )

    current_user.invalidate_session()
    logout_user()

    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


@bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """
    MFA setup endpoint.

    Security: Generates TOTP secret and QR code
    """
    if current_user.mfa_enabled:
        flash('MFA is already enabled', 'info')
        return redirect(url_for('account.settings'))

    form = MFASetupForm()

    # Generate secret and QR code
    if request.method == 'GET':
        secret = current_user.enable_mfa()
        qr_uri = current_user.get_mfa_qr_uri()

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64 for display
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qr_code = base64.b64encode(buf.getvalue()).decode()

        # Store secret in session temporarily for verification
        session['mfa_setup_secret'] = secret

        return render_template('auth/mfa_setup.html', form=form, qr_code=qr_code, secret=secret)

    # Verify token
    if form.validate_on_submit():
        if current_user.verify_mfa_token(form.token.data):
            log_security_event(
                current_user.id,
                "MFA enabled",
                success=True
            )
            flash('MFA has been enabled successfully!', 'success')
            return redirect(url_for('account.settings'))
        else:
            # Disable MFA if verification fails
            current_user.disable_mfa()
            flash('Invalid verification code. MFA setup cancelled.', 'danger')
            return redirect(url_for('auth.mfa_setup'))

    return render_template('auth/mfa_setup.html', form=form)


@bp.route('/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    """Disable MFA."""
    if not current_user.mfa_enabled:
        flash('MFA is not enabled', 'info')
        return redirect(url_for('account.settings'))

    current_user.disable_mfa()
    log_security_event(
        current_user.id,
        "MFA disabled",
        success=True
    )

    flash('MFA has been disabled', 'info')
    return redirect(url_for('account.settings'))
