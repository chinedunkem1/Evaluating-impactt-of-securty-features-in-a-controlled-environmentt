"""
Admin routes - employee management, payslip generation, user management, security logs.

Security measures:
- admin_required decorator enforces authentication + admin role on every route (OWASP A01)
- Input validation and type-checking on all write endpoints (OWASP A03)
- Salary clamped to a sensible range - rejects negatives and obviously invalid values
- Sensitive actions (create user, delete employee, role change) written to security_logs (OWASP A09)
- Role values restricted to a fixed allow-list to prevent privilege escalation (OWASP A01)

References:
- OWASP A01:2021 Broken Access Control
  https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP A09:2021 Security Logging and Monitoring Failures
  https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
- OWASP Input Validation Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from functools import wraps
from models import Employee, Payslip, User, SecurityLog
from extensions import db
from datetime import date

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

ALLOWED_ROLES    = {'admin', 'employee'}
ALLOWED_STATUSES = {'Active', 'On Leave', 'Inactive'}
SALARY_MIN       = 1_000      # sanity floor  - nothing below €1k/year
SALARY_MAX       = 1_000_000  # sanity ceiling - nothing above €1M/year


def log_admin_event(event_type, payload=None):
    """Write a security/audit event triggered by an admin action."""
    entry = SecurityLog(
        event_type=event_type,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:300],
        endpoint=request.path,
        payload=str(payload)[:500] if payload else None,
        username=current_user.username,
    )
    db.session.add(entry)
    # caller is responsible for commit (so we don't issue an extra round-trip)


# decorator to block non-admins
# Reference: OWASP A01:2021 Broken Access Control
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return jsonify({'success': False, 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return login_required(decorated)


@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    total_employees  = Employee.query.filter_by(status='Active').count()
    all_payslips     = Payslip.query.filter_by(status='Processed').all()
    pending_payslips = Payslip.query.filter_by(status='Pending').all()

    total_payroll_cost = sum(p.gross_pay for p in all_payslips)
    pending_payroll    = sum(p.gross_pay for p in pending_payslips)
    recent_deductions  = sum(p.deductions for p in all_payslips[-45:])

    return jsonify({
        'success':            True,
        'total_employees':    total_employees,
        'total_payroll_cost': total_payroll_cost,
        'pending_payroll':    pending_payroll,
        'recent_deductions':  recent_deductions,
    }), 200


@admin_bp.route('/employees', methods=['GET'])
@admin_required
def list_employees():
    employees = Employee.query.order_by(Employee.last_name).all()
    return jsonify({'success': True, 'employees': [e.to_dict() for e in employees]}), 200


@admin_bp.route('/employees', methods=['POST'])
@admin_required
def add_employee():
    data = request.get_json()

    required = ['first_name', 'last_name', 'email', 'department', 'job_title', 'salary']
    for field in required:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'Missing field: {field}'}), 400

    # validate salary is a number in a sensible range
    # Reference: OWASP Input Validation Cheat Sheet
    try:
        salary = float(data['salary'])
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Salary must be a number'}), 400
    if not (SALARY_MIN <= salary <= SALARY_MAX):
        return jsonify({'success': False, 'message': f'Salary must be between {SALARY_MIN} and {SALARY_MAX}'}), 400

    # reject unknown status values
    status = data.get('status', 'Active')
    if status not in ALLOWED_STATUSES:
        return jsonify({'success': False, 'message': 'Invalid status value'}), 400

    if Employee.query.filter_by(email=data['email']).first():
        return jsonify({'success': False, 'message': 'Email already in use'}), 409

    try:
        start = date.fromisoformat(data['start_date']) if data.get('start_date') else date.today()
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid start_date format (use YYYY-MM-DD)'}), 400

    emp = Employee(
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        department=data['department'],
        job_title=data['job_title'],
        salary=salary,
        status=status,
        start_date=start,
        iban=data.get('iban'),
        pps_number=data.get('pps_number'),
    )
    db.session.add(emp)
    # log the action for audit trail
    log_admin_event('admin_add_employee', {'email': emp.email, 'department': emp.department})
    db.session.commit()

    return jsonify({'success': True, 'message': 'Employee added', 'employee': emp.to_dict()}), 201


@admin_bp.route('/employees/<int:emp_id>', methods=['PUT'])
@admin_required
def update_employee(emp_id):
    emp  = Employee.query.get_or_404(emp_id)
    data = request.get_json()

    # validate salary if provided
    if 'salary' in data:
        try:
            salary = float(data['salary'])
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Salary must be a number'}), 400
        if not (SALARY_MIN <= salary <= SALARY_MAX):
            return jsonify({'success': False, 'message': f'Salary must be between {SALARY_MIN} and {SALARY_MAX}'}), 400
        emp.salary = salary

    # reject unknown status values
    if 'status' in data and data['status'] not in ALLOWED_STATUSES:
        return jsonify({'success': False, 'message': 'Invalid status value'}), 400

    emp.first_name = data.get('first_name', emp.first_name)
    emp.last_name  = data.get('last_name',  emp.last_name)
    emp.email      = data.get('email',      emp.email)
    emp.department = data.get('department', emp.department)
    emp.job_title  = data.get('job_title',  emp.job_title)
    emp.status     = data.get('status',     emp.status)

    db.session.commit()
    return jsonify({'success': True, 'message': 'Employee updated', 'employee': emp.to_dict()}), 200


@admin_bp.route('/employees/<int:emp_id>', methods=['DELETE'])
@admin_required
def delete_employee(emp_id):
    emp = Employee.query.get_or_404(emp_id)
    # log before delete so we still have the name
    log_admin_event('admin_delete_employee', {'employee_id': emp_id, 'name': emp.full_name})
    db.session.delete(emp)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Employee deleted'}), 200


@admin_bp.route('/payslips', methods=['GET'])
@admin_required
def list_payslips():
    emp_id = request.args.get('employee_id', type=int)
    query  = Payslip.query
    if emp_id:
        query = query.filter_by(employee_id=emp_id)
    payslips = query.order_by(Payslip.pay_date.desc()).all()
    return jsonify({'success': True, 'payslips': [p.to_dict() for p in payslips]}), 200


@admin_bp.route('/payslips/generate', methods=['POST'])
@admin_required
def generate_payslips():
    data     = request.get_json()
    period   = data.get('period')
    pay_date = data.get('pay_date')

    if not period or not pay_date:
        return jsonify({'success': False, 'message': 'period and pay_date are required'}), 400

    employees = Employee.query.filter_by(status='Active').all()
    created   = 0

    for emp in employees:
        existing = Payslip.query.filter_by(employee_id=emp.id, period=period).first()
        if existing:
            continue

        gross      = emp.monthly_gross
        deductions = round(gross * 0.145, 2)
        net        = round(gross - deductions, 2)

        p = Payslip(
            employee_id=emp.id,
            period=period,
            pay_date=date.fromisoformat(pay_date),
            gross_pay=gross,
            deductions=deductions,
            net_pay=net,
            status='Processed',
        )
        db.session.add(p)
        created += 1

    db.session.commit()
    return jsonify({'success': True, 'message': f'{created} payslips generated'}), 201


@admin_bp.route('/security-logs', methods=['GET'])
@admin_required
def security_logs():
    event_type = request.args.get('type')
    query = SecurityLog.query
    if event_type:
        query = query.filter_by(event_type=event_type)
    logs = query.order_by(SecurityLog.timestamp.desc()).limit(200).all()
    return jsonify({'success': True, 'logs': [l.to_dict() for l in logs]}), 200


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({'success': True, 'users': [{
        'id':          u.id,
        'username':    u.username,
        'email':       u.email,
        'role':        u.role,
        'employee_id': u.employee_id,
        'created_at':  u.created_at.strftime('%Y-%m-%d %H:%M'),
    } for u in users]}), 200


@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def update_user_role(user_id):
    # don't let admin demote themselves
    if user_id == current_user.id:
        return jsonify({'success': False, 'message': "You can't change your own role"}), 400

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    new_role = data.get('role')

    if new_role not in ALLOWED_ROLES:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    old_role  = user.role
    user.role = new_role
    log_admin_event('admin_role_change', {'user_id': user_id, 'username': user.username, 'old_role': old_role, 'new_role': new_role})
    db.session.commit()
    return jsonify({'success': True, 'message': f'Role updated to {new_role}'}), 200


@admin_bp.route('/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json()
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'employee')

    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    # minimum 8 chars - matches the rule in auth.py /register
    # Reference: OWASP Authentication Cheat Sheet - Password Strength
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already taken'}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already in use'}), 409

    if role not in ALLOWED_ROLES:
        role = 'employee'

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    log_admin_event('admin_create_user', {'username': username, 'role': role})
    db.session.commit()

    return jsonify({'success': True, 'message': 'User created', 'user_id': user.id}), 201
