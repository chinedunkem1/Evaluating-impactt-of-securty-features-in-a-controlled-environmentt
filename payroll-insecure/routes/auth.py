from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
import hashlib

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # VULNERABLE: raw SQL query with no parameterisation
    # attacker can type:  admin' OR '1'='1  as the username and bypass the password check entirely
    password_md5 = hashlib.md5(password.encode()).hexdigest()

    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_md5}'"

    result = db.session.execute(db.text(sql)).fetchone()

    if not result:
        # no rate limiting, no logging - attacker can try unlimited times
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

    from models import User
    user = User.query.get(result[0])

    # no 2FA at all - just log straight in
    login_user(user, remember=False)

    return jsonify({
        'success': True,
        'user': {
            'id':          user.id,
            'username':    user.username,
            'role':        user.role,
            'employee_id': user.employee_id,
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    return jsonify({'success': True}), 200


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
