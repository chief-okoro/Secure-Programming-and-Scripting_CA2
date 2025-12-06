from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.user import Transaction
from app.utils.security import log_security_event

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Public home page."""
    return render_template('main/index.html')


@bp.route('/dashboard')
@login_required
def dashboard():
    """
    User dashboard.

    Security: Requires authentication, shows only user's data.
    """
    log_security_event(current_user.id, "Accessed dashboard")

    # Get user's recent transactions
    recent_transactions = current_user.transactions.order_by(
        Transaction.timestamp.desc()
    ).limit(10).all()

    # Get user's accounts
    accounts = current_user.accounts.filter_by(is_active=True).all()

    # Calculate total balance
    total_balance = sum(account.balance for account in accounts)

    return render_template(
        'main/dashboard.html',
        accounts=accounts,
        transactions=recent_transactions,
        total_balance=total_balance
    )


@bp.route('/security-demo')
def security_demo():
    """
    Security demonstration page showing vulnerable vs secure code.
    """
    from app.utils.security import demonstrate_xss_prevention, VulnerableQueries, SecureQueries

    xss_demo = demonstrate_xss_prevention()

    sql_examples = {
        'vulnerable': {
            'login': VulnerableQueries.vulnerable_login("admin' OR '1'='1", "any"),
            'search': VulnerableQueries.vulnerable_search("'; DROP TABLE users; --")
        },
        'secure': {
            'explanation': 'Uses SQLAlchemy ORM with parameterized queries'
        }
    }

    return render_template(
        'main/security_demo.html',
        xss_demo=xss_demo,
        sql_examples=sql_examples
    )
