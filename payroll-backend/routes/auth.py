from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from models import User, SecurityLog
from extensions import db
import pyotp

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


def log_event(event_type, payload=None, username=None):
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


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        log_event('failed_login', username=username)
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

    # admin needs to do 2FA before we fully log them in
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
    data = request.get_json()
    code = data.get('code', '').strip()

    pending_id = session.get('pending_admin_id')
    if not pending_id:
        return jsonify({'success': False, 'message': 'No pending login'}), 400

    user = User.query.get(pending_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    totp = pyotp.TOTP(user.totp_secret) if hasattr(user, 'totp_secret') and user.totp_secret else None

    # demo mode: if no TOTP secret is set, accept 123456 for testing
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
    data = request.get_json()
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'employee')

    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already taken'}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'}), 409

    # don't let someone register as admin unless they're already an admin
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
