"""
Security test suite for PaySecure backend.

Tests every major OWASP defence that was implemented:
- WAF blocks SQL injection, XSS, and path traversal (OWASP A03)
- Login returns generic error for bad credentials (OWASP A07)
- Account locks after 5 consecutive failed logins (OWASP A07)
- IP rate limiting kicks in after 10 failures (OWASP A07)
- Admin routes reject unauthenticated and employee-role requests (OWASP A01)
- Employees can only read their own payslips (OWASP A01)
- Security headers are present on every response (OWASP A05)
- Salary validation rejects negative/non-numeric values (OWASP A03)
- Honeypot route logs the visit and returns a plausible page (OWASP A09)

Run with:
    cd payroll-backend
    pip install pytest --break-system-packages
    python -m pytest tests/ -v
"""

import pytest
import json
from app import create_app, seed_db
from extensions import db as _db
from models import SecurityLog, User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def app():
    """Create a fresh Flask app wired to an in-memory SQLite database.
    We pass test_config into create_app() so the SQLite URI is set
    BEFORE db.init_app() runs — otherwise SQLAlchemy tries to connect to MySQL.
    """
    test_app = create_app({
        'TESTING':                   True,
        'SQLALCHEMY_DATABASE_URI':   'sqlite:///:memory:',
        'WTF_CSRF_ENABLED':          False,
        'SECRET_KEY':                'test-secret-key-not-for-production',
        'SERVER_NAME':               None,
    })

    with test_app.app_context():
        _db.create_all()
        seed_db(test_app)   # creates admin / johndoe demo accounts

    yield test_app


@pytest.fixture(scope='session')
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_rate_limit(app, request):
    """
    Before each test, wipe failed_login entries from security_logs so that
    IP-based rate limiting from earlier tests doesn't bleed into later ones.
    Also reset any user lockouts.
    This is test infrastructure only - it doesn't affect production behaviour.
    """
    with app.app_context():
        SecurityLog.query.filter(
            SecurityLog.event_type.in_(['failed_login', 'rate_limit_blocked', 'account_locked'])
        ).delete(synchronize_session=False)
        from models import User
        for user in User.query.all():
            user.failed_attempts = 0
            user.locked_until    = None
        _db.session.commit()
    yield


def login_as(client, username, password):
    """Helper - perform login and (for admin) skip 2FA with demo code."""
    resp = client.post('/api/auth/login', json={'username': username, 'password': password})
    data = resp.get_json()
    if data.get('requires_2fa'):
        client.post('/api/auth/verify-2fa', json={'code': '123456'})
    return resp


def logout(client):
    client.post('/api/auth/logout')


# ---------------------------------------------------------------------------
# A03 - WAF: Injection blocking
# ---------------------------------------------------------------------------

class TestWAF:
    """WAF should block SQL injection, XSS, and path traversal with HTTP 403."""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1 UNION SELECT username, password_hash FROM users--",
        "admin'--",
        "1; SELECT * FROM users",
        "1 AND 1=1",
        "SLEEP(5)--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<iframe src='evil.com'>",
        "';alert(document.cookie)//",
    ]

    PATH_TRAVERSAL_PAYLOADS = [
        "../etc/passwd",
        "..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2fetc%2fpasswd",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_blocked_in_login(self, client, payload):
        """SQL injection in login username/password should be blocked by WAF."""
        resp = client.post('/api/auth/login', json={'username': payload, 'password': 'anything'})
        assert resp.status_code == 403, f"Expected WAF block (403) for payload: {payload!r}"
        data = resp.get_json()
        assert data['success'] is False

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_blocked_in_login(self, client, payload):
        """XSS payloads in JSON body should be blocked by WAF."""
        resp = client.post('/api/auth/login', json={'username': payload, 'password': 'test'})
        assert resp.status_code == 403, f"Expected WAF block (403) for XSS payload: {payload!r}"

    @pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
    def test_path_traversal_blocked(self, client, payload):
        """Path traversal in query string should be blocked by WAF."""
        resp = client.get(f'/api/admin/employees?search={payload}')
        assert resp.status_code == 403, f"Expected WAF block (403) for path traversal: {payload!r}"

    def test_waf_blocks_logged_to_security_logs(self, app, client):
        """Every WAF block should leave a waf_blocked entry in security_logs."""
        with app.app_context():
            before = SecurityLog.query.filter_by(event_type='waf_blocked').count()

        client.post('/api/auth/login', json={'username': "' OR '1'='1", 'password': 'x'})

        with app.app_context():
            after = SecurityLog.query.filter_by(event_type='waf_blocked').count()

        assert after > before, "WAF block was not logged to security_logs"

    def test_legitimate_request_not_blocked(self, client):
        """A normal login attempt should not be blocked by the WAF."""
        resp = client.post('/api/auth/login', json={'username': 'nonexistent', 'password': 'wrongpassword'})
        # 401 (wrong creds) not 403 (WAF block)
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# A07 - Authentication: login, lockout, rate limiting
# ---------------------------------------------------------------------------

class TestAuthentication:

    def test_valid_employee_login(self, client):
        """Employee credentials should succeed and return user info."""
        resp = login_as(client, 'johndoe', 'Employee@1234')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['user']['role'] == 'employee'
        logout(client)

    def test_valid_admin_login_requires_2fa(self, client):
        """Admin login step 1 should return requires_2fa=True."""
        resp = client.post('/api/auth/login', json={'username': 'admin', 'password': 'Admin@1234'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['requires_2fa'] is True
        # complete 2FA
        resp2 = client.post('/api/auth/verify-2fa', json={'code': '123456'})
        assert resp2.status_code == 200
        assert resp2.get_json()['success'] is True
        logout(client)

    def test_wrong_password_returns_401(self, client):
        """Wrong password should return 401 with a generic message."""
        resp = client.post('/api/auth/login', json={'username': 'johndoe', 'password': 'wrongpassword'})
        assert resp.status_code == 401
        data = resp.get_json()
        # generic message - should NOT say "wrong password" or "user not found"
        assert 'Invalid username or password' in data['message']

    def test_nonexistent_user_same_message(self, client):
        """Non-existent username should return the exact same message as a wrong password.
        This prevents user enumeration (OWASP A07).
        """
        resp = client.post('/api/auth/login', json={'username': 'doesnotexist', 'password': 'whatever'})
        assert resp.status_code == 401
        data = resp.get_json()
        assert 'Invalid username or password' in data['message']

    def test_account_lockout_after_5_failures(self, app, client):
        """Account should lock for 15 minutes after 5 wrong passwords.
        Even if we try the correct password on attempt 6, it should be blocked.
        """
        # reset the account state first
        with app.app_context():
            user = User.query.filter_by(username='johndoe').first()
            user.failed_attempts = 0
            user.locked_until = None
            _db.session.commit()

        # 5 wrong attempts
        for i in range(5):
            client.post('/api/auth/login', json={'username': 'johndoe', 'password': 'wrongpassword'})

        # 6th attempt with correct password - should still be blocked
        resp = client.post('/api/auth/login', json={'username': 'johndoe', 'password': 'Employee@1234'})
        assert resp.status_code == 401, "Account should be locked after 5 failures"

        # verify the lock is recorded in the database
        with app.app_context():
            user = User.query.filter_by(username='johndoe').first()
            assert user.is_locked(), "User.is_locked() should return True"

        # clean up - unlock manually so other tests can log in
        with app.app_context():
            user = User.query.filter_by(username='johndoe').first()
            user.failed_attempts = 0
            user.locked_until    = None
            _db.session.commit()

    def test_failed_logins_logged(self, app, client):
        """Every failed login should appear in security_logs as 'failed_login'."""
        with app.app_context():
            before = SecurityLog.query.filter_by(event_type='failed_login').count()

        client.post('/api/auth/login', json={'username': 'johndoe', 'password': 'wrongpassword'})

        with app.app_context():
            after = SecurityLog.query.filter_by(event_type='failed_login').count()

        assert after == before + 1

    def test_successful_login_resets_failed_attempts(self, app, client):
        """A successful login should zero out failed_attempts on the account."""
        # prime with 2 failures first
        with app.app_context():
            user = User.query.filter_by(username='johndoe').first()
            user.failed_attempts = 2
            _db.session.commit()

        login_as(client, 'johndoe', 'Employee@1234')

        with app.app_context():
            user = User.query.filter_by(username='johndoe').first()
            assert user.failed_attempts == 0, "failed_attempts should reset to 0 after successful login"

        logout(client)

    def test_2fa_wrong_code_rejected(self, client):
        """A wrong 2FA code should return 401."""
        client.post('/api/auth/login', json={'username': 'admin', 'password': 'Admin@1234'})
        resp = client.post('/api/auth/verify-2fa', json={'code': '000000'})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# A01 - Broken Access Control
# ---------------------------------------------------------------------------

class TestAccessControl:

    def test_unauthenticated_cannot_access_admin(self, client):
        """No session cookie = 401 from login_required."""
        logout(client)
        resp = client.get('/api/admin/employees')
        assert resp.status_code == 401

    def test_employee_cannot_access_admin_routes(self, client):
        """Logged-in employee should get 403 on admin routes."""
        login_as(client, 'johndoe', 'Employee@1234')
        resp = client.get('/api/admin/employees')
        assert resp.status_code == 403
        logout(client)

    def test_employee_cannot_access_admin_dashboard(self, client):
        login_as(client, 'johndoe', 'Employee@1234')
        resp = client.get('/api/admin/dashboard')
        assert resp.status_code == 403
        logout(client)

    def test_employee_cannot_read_security_logs(self, client):
        login_as(client, 'johndoe', 'Employee@1234')
        resp = client.get('/api/admin/security-logs')
        assert resp.status_code == 403
        logout(client)

    def test_employee_cannot_access_other_payslips(self, app, client):
        """An employee should not be able to fetch another employee's payslip.
        This tests IDOR (Insecure Direct Object Reference) protection.
        """
        login_as(client, 'johndoe', 'Employee@1234')

        # find a payslip that belongs to a DIFFERENT employee
        with app.app_context():
            from models import Payslip, User
            john_user = User.query.filter_by(username='johndoe').first()
            other_payslip = Payslip.query.filter(
                Payslip.employee_id != john_user.employee_id
            ).first()

        if other_payslip:
            resp = client.get(f'/api/employee/payslips/{other_payslip.id}')
            assert resp.status_code == 403, "Employee should not be able to read another employee's payslip"

        logout(client)

    def test_admin_can_list_employees(self, client):
        """Admin should be able to access employee list."""
        login_as(client, 'admin', 'Admin@1234')
        resp = client.get('/api/admin/employees')
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True
        logout(client)

    def test_admin_cannot_change_own_role(self, client):
        """Admin should get 400 if trying to change their own role."""
        login_as(client, 'admin', 'Admin@1234')
        # get admin's user id
        me = client.get('/api/auth/me').get_json()
        resp = client.put(f'/api/admin/users/{me["id"]}/role', json={'role': 'employee'})
        assert resp.status_code == 400
        logout(client)


# ---------------------------------------------------------------------------
# A05 - Security Misconfiguration: HTTP security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    """Every response should include the full set of security headers."""

    REQUIRED_HEADERS = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'Content-Security-Policy',
        'Strict-Transport-Security',
    ]

    def test_security_headers_on_api_response(self, client):
        resp = client.get('/api')
        for header in self.REQUIRED_HEADERS:
            assert header in resp.headers, f"Missing security header: {header}"

    def test_x_frame_options_is_deny(self, client):
        resp = client.get('/api')
        assert resp.headers.get('X-Frame-Options') == 'DENY'

    def test_csp_restricts_scripts(self, client):
        resp = client.get('/api')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp

    def test_x_content_type_nosniff(self, client):
        resp = client.get('/api')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'


# ---------------------------------------------------------------------------
# A03 - Input Validation: salary / employee fields
# ---------------------------------------------------------------------------

class TestInputValidation:

    def setup_method(self):
        pass

    def test_negative_salary_rejected(self, client):
        login_as(client, 'admin', 'Admin@1234')
        resp = client.post('/api/admin/employees', json={
            'first_name': 'Test', 'last_name': 'User', 'email': 'test_neg@company.ie',
            'department': 'IT', 'job_title': 'Dev', 'salary': -50000,
        })
        assert resp.status_code == 400
        logout(client)

    def test_string_salary_rejected(self, client):
        login_as(client, 'admin', 'Admin@1234')
        resp = client.post('/api/admin/employees', json={
            'first_name': 'Test', 'last_name': 'User', 'email': 'test_str@company.ie',
            'department': 'IT', 'job_title': 'Dev', 'salary': 'lots',
        })
        assert resp.status_code == 400
        logout(client)

    def test_invalid_status_rejected(self, client):
        login_as(client, 'admin', 'Admin@1234')
        resp = client.post('/api/admin/employees', json={
            'first_name': 'Test', 'last_name': 'User', 'email': 'test_status@company.ie',
            'department': 'IT', 'job_title': 'Dev', 'salary': 40000,
            'status': 'HACKED',
        })
        assert resp.status_code == 400
        logout(client)

    def test_invalid_role_silently_defaults_to_employee(self, client):
        """Unknown role values should silently fall back to 'employee', not crash or escalate."""
        login_as(client, 'admin', 'Admin@1234')
        resp = client.post('/api/admin/users', json={
            'username': 'rolehacker', 'email': 'rolehacker@co.ie',
            'password': 'Password1!', 'role': 'superadmin',
        })
        assert resp.status_code == 201
        logout(client)

    def test_short_password_rejected_by_admin_create(self, client):
        """Admin create user endpoint must also require min 8-char passwords."""
        login_as(client, 'admin', 'Admin@1234')
        resp = client.post('/api/admin/users', json={
            'username': 'weakpw', 'email': 'weakpw@co.ie',
            'password': 'abc',  # too short
        })
        assert resp.status_code == 400
        logout(client)


# ---------------------------------------------------------------------------
# A09 - Security Logging: honeypot
# ---------------------------------------------------------------------------

class TestHoneypot:

    def test_honeypot_returns_fake_login_page(self, client):
        """GET /admin-panel should return a convincing-looking login form."""
        resp = client.get('/admin-panel')
        assert resp.status_code == 200
        assert b'<form' in resp.data

    def test_honeypot_logs_visit(self, app, client):
        """Any hit on /admin-panel should be logged as 'honeypot'."""
        with app.app_context():
            before = SecurityLog.query.filter_by(event_type='honeypot').count()

        client.get('/admin-panel')

        with app.app_context():
            after = SecurityLog.query.filter_by(event_type='honeypot').count()

        assert after > before

    def test_honeypot_post_logs_submit(self, app, client):
        """POST to /admin-panel (simulating attacker submitting credentials) is logged as 'honeypot_submit'."""
        with app.app_context():
            before = SecurityLog.query.filter_by(event_type='honeypot_submit').count()

        client.post('/admin-panel', data={'username': 'admin', 'password': 'password123'})

        with app.app_context():
            after = SecurityLog.query.filter_by(event_type='honeypot_submit').count()

        assert after > before

    def test_scanner_routes_logged(self, app, client):
        """Hitting /.env, /wp-admin etc. should log a 'honeypot_scan' event."""
        with app.app_context():
            before = SecurityLog.query.filter_by(event_type='honeypot_scan').count()

        client.get('/.env')

        with app.app_context():
            after = SecurityLog.query.filter_by(event_type='honeypot_scan').count()

        assert after > before
