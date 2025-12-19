import pytest

from pathlib import Path

from app import create_app
from models import db, User, RoleEnum, Loan, LoanStatusEnum


@pytest.fixture
def app():
    # Create app in testing mode
    app = create_app('default', testing=True)
    # Use a fresh DB file in the project directory for tests
    with app.app_context():
        db.create_all()
    yield app
    # Teardown
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_register_login_apply_and_review_flow(client, app):
    username = "alice"
    password = "s3cureP@ssword123"
    email = "alice@example.com"

    # Register
    r = client.post('/auth/register', json={
        'username': username,
        'email': email,
        'password': password,
    })
    assert r.status_code == 201

    # Login
    r = client.post('/auth/login', json={'username': username, 'password': password})
    assert r.status_code == 200

    # Apply for loan
    loan_payload = {'amount': 5000, 'purpose': 'home improvement', 'term_months': 24}
    r = client.post('/loans/apply', json=loan_payload)
    assert r.status_code == 201
    loan_id = r.get_json().get('loan_id')
    assert loan_id is not None

    # Ensure loan appears in my-applications
    r = client.get('/loans/my-applications')
    assert r.status_code == 200
    loans = r.get_json().get('loans', [])
    assert any(l['id'] == loan_id for l in loans)

    # Customer should not be able to review loan
    r = client.patch(f'/loans/review/{loan_id}', json={'decision': 'approve'})
    assert r.status_code in (401, 403)

    # Promote user to officer directly in DB
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        assert user is not None
        user.role = RoleEnum.OFFICER
        db.session.add(user)
        db.session.commit()

    # Attempt review again as the same logged-in session (Flask-Login should reload)
    r = client.patch(f'/loans/review/{loan_id}', json={'decision': 'approve', 'comment': 'Looks good'})
    assert r.status_code == 200
    assert r.get_json().get('status') == LoanStatusEnum.APPROVED.value
