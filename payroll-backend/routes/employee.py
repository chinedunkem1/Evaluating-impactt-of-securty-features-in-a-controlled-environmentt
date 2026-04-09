from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models import Employee, Payslip
from extensions import db

employee_bp = Blueprint('employee', __name__, url_prefix='/api/employee')


@employee_bp.route('/me', methods=['GET'])
@login_required
def get_my_profile():
    if not current_user.employee:
        return jsonify({'success': False, 'message': 'No employee record linked to this account'}), 404

    emp = current_user.employee
    return jsonify({'success': True, 'employee': emp.to_dict()}), 200


@employee_bp.route('/payslips', methods=['GET'])
@login_required
def get_my_payslips():
    if not current_user.employee_id:
        return jsonify({'success': False, 'message': 'No employee record found'}), 404

    payslips = (
        Payslip.query
        .filter_by(employee_id=current_user.employee_id)
        .order_by(Payslip.pay_date.desc())
        .all()
    )
    return jsonify({'success': True, 'payslips': [p.to_dict() for p in payslips]}), 200


@employee_bp.route('/payslips/<int:payslip_id>', methods=['GET'])
@login_required
def get_payslip(payslip_id):
    payslip = Payslip.query.get_or_404(payslip_id)

    # make sure this payslip belongs to the logged in user
    if payslip.employee_id != current_user.employee_id:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    return jsonify({'success': True, 'payslip': payslip.to_dict()}), 200


@employee_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if not current_user.employee_id:
        return jsonify({'success': False, 'message': 'No employee record'}), 404

    payslips = (
        Payslip.query
        .filter_by(employee_id=current_user.employee_id, status='Processed')
        .order_by(Payslip.pay_date.desc())
        .all()
    )

    total_earnings = sum(p.net_pay for p in payslips)
    latest = payslips[0].to_dict() if payslips else None
    recent = [p.to_dict() for p in payslips[:3]]

    return jsonify({
        'success':         True,
        'total_earnings':  total_earnings,
        'latest_payslip':  latest,
        'recent_payslips': recent,
        'employee':        current_user.employee.to_dict(),
    }), 200
