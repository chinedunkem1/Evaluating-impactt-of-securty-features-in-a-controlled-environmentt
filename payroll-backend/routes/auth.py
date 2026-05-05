"""
Authentication routes - login, 2FA, logout, register

Security measures implemented:
- Account lockout after 5 failed attempts (OWASP A07)
- IP-based rate limiting - block after 10 failures in 15 minutes (OWASP A07)
- Generic error messages - don't reveal whether username exists (OWASP A07)
- All failures logged to security_logs (OWASP A09)

References:
- OWASP A07:2021 Identification and Authentication Failures
  https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- OWASP Authentication Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Logging Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
"""

from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from models import User, SecurityLog
from extensions import db
from datetime import datetime, timedelta
import pyotp

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# lockout settings
# Reference: OWASP Authentication Cheat Sheet
# https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
MAX_FAILED_ATTEMPTS  = 5    # lock account after this many failures
LOCKOUT_MINUTES      = 15   # how long to lock for
IP_RATE_LIMIT        = 10   # max failed attempts from one IP in the window
IP_RATE_WINDOW_MINS  = 15   # time window for IP rate limiting


def log_event(event_type, payload=None, username=None):
    """Write a security event to the security_logs table."""
    entry = SecurityLog(
        event_type=event_type,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:300],
        endpoint=request.path,
        payload=str(payload) if payload else None,
        username=username,
    )
    db.session.add(entry)
    db.session.commit()


def is_ip_rate_limited(ip):
    """
    Check if an IP has exceeded the failed login threshold in the rate window.
    Reference: OWASP Authentication Cheat Sheet - Brute Force Protection
    https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
    """
    window_start = datetime.utcnow() - timedelta(minutes=IP_RATE_WINDOW_MINS)
    recent_failures = SecurityLog.query.filter(
        SecurityLog.event_type == 'failed_login',
        SecurityLog.ip_address == ip,
        SecurityLog.timestamp >= window_start
    ).count()
    return recent_failures >= IP_RATE_LIMIT


@auth_bp.route('/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    # IP-based rate limiting check - blocks brute force from same IP
    # Reference: OWASP A07:2021 - Authentication Failures
    if is_ip_rate_limited(request.remote_addr):
        log_event('rate_limit_blocked', username=username)
        return jsonify({
            'success': False,
            'message': 'Too many failed attempts. Please try again later.'
        }), 429

    user = User.query.filter_by(username=username).first()

    # check if account is locked out
    # Reference: OWASP Authentication Cheat Sheet - Account Lockout
    if user and user.is_locked():
        log_event('login_attempt_locked_account', username=username)
        # generic message - don't confirm the account exists
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        }), 401

    if not user or not user.check_password(password):
        log_event('failed_login', username=username)

        # increment failed attempts counter on the account
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                log_event('account_locked', username=username)
            db.session.commit()

        # always return the same generic error message
        # never reveal whether the username exists or not
        # Reference: OWASP Authentication Cheat Sheet
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

    # successful credential check - reset the failed attempts counter
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()

    # admin requires 2FA before being fully logged in
    if user.is_admin():
        session['pending_admin_id'] = user.id
        return jsonify({'success': True, 'requires_2fa': True}), 200

    login_user(user, remember=False)
    return jsonify({
        'success': True,
        'requires_2fa': False,
        'user': {
            'id':          user.id,
            'username':    user.username,
            'role':        user.role,
            'employee_id': user.employee_id,
        }
    }), 200


@auth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    """
    Verify TOTP 2FA code for admin login.
    Reference: OWASP Multi-factor Authentication Cheat Sheet
    https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
    """
    data = request.get_json()
    code = data.get('code', '').strip()

    pending_id = session.get('pending_admin_id')
    if not pending_id:
        return jsonify({'success': False, 'message': 'No pending login'}), 400

    user = User.query.get(pending_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    totp = pyotp.TOTP(user.totp_secret) if hasattr(user, 'totp_secret') and user.totp_secret else None

    # demo mode: accept 123456 if no TOTP secret is configured yet
    demo_mode = not totp
    valid = (demo_mode and code == '123456') or (totp and totp.verify(code))

    if not valid:
        log_event('2fa_fail', username=user.username)
        return jsonify({'success': False, 'message': 'Invalid 2FA code'}), 401

    session.pop('pending_admin_id', None)
    login_user(user, remember=False)

    return jsonify({
        'success': True,
        'user': {
            'id':       user.id,
            'username': user.username,
            'role':     user.role,
        }
    }), 200


@auth_bp.route('/register', methods=['POST'])
def register():
    data     = request.get_json()
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'employee')

    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    # enforce minimum password length
    # Reference: OWASP Authentication Cheat Sheet - Password Strength
    # https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already taken'}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'}), 409

    # only existing admins can create admin accounts
    # Reference: OWASP A01:2021 - Broken Access Control
    if role == 'admin' and (not current_user.is_authenticated or not current_user.is_admin()):
        role = 'employee'

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Account created', 'user_id': user.id}), 201


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'}), 200


@auth_bp.route('/me', methods=['GET'])
@login_required
def me():
    return jsonify({
        'id':          current_user.id,
        'username':    current_user.username,
        'email':       current_user.email,
        'role':        current_user.role,
        'employee_id': current_user.employee_id,
    }), 200
