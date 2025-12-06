"""Admin controllers."""
from flask import Blueprint, render_template
from flask_login import login_required
from app.utils.security import admin_required, log_security_event
from app.models.user import User, AuditLog

bp = Blueprint('admin', __name__, url_prefix='/admin')


@bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard with security logs."""
    users = User.query.all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('admin/dashboard.html', users=users, logs=recent_logs)
