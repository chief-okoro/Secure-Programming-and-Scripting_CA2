"""Account management controllers."""
from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from app.utils.security import log_security_event

bp = Blueprint('account', __name__, url_prefix='/account')


@bp.route('/settings')
@login_required
def settings():
    """User account settings page."""
    return render_template('account/settings.html')


@bp.route('/transactions')
@login_required
def transactions():
    """View transaction history."""
    log_security_event(current_user.id, "Viewed transaction history")
    transactions = current_user.transactions.order_by('timestamp desc').all()
    return render_template('account/transactions.html', transactions=transactions)
