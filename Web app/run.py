from app import create_app, db
from app.models.user import User, BankAccount
import os

app = create_app()


@app.shell_context_processor
def make_shell_context():
    """Make database and models available in Flask shell."""
    return {
        'db': db,
        'User': User,
        'BankAccount': BankAccount
    }


@app.cli.command()
def init_db():
    """Initialize the database with sample data."""
    db.create_all()

    # Create admin user
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@securebank.com',
            first_name='Admin',
            last_name='User',
            is_admin=True
        )
        admin.set_password('Admin@123')
        db.session.add(admin)

    # Create test user
    test_user = User.query.filter_by(username='testuser').first()
    if not test_user:
        test_user = User(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        test_user.set_password('Test@123')
        test_user.ssn = '123-45-6789'

        db.session.add(test_user)
        db.session.commit()

        # Create sample account
        account = BankAccount(user_id=test_user.id, account_type='checking')
        account.account_number = '1234567890'
        account.balance = 5000.00
        db.session.add(account)

    db.session.commit()
    print("Database initialized successfully!")


if __name__ == '__main__':

    # For local development, run without SSL
    app.run(debug=True, host='127.0.0.1', port=5000)



