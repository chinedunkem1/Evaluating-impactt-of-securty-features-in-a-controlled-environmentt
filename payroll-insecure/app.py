from flask import Flask, jsonify, request, send_from_directory
from flask_login import current_user
from config import Config
from extensions import db, login_manager
from models import User
import os


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({'success': False, 'message': 'Login required'}), 401

    from routes.auth import auth_bp
    from routes.employee import employee_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp)
    app.register_blueprint(admin_bp)

    # no honeypot, no scanner traps, nothing - wide open

    @app.route('/')
    @app.route('/<path:path>')
    def serve_frontend(path=''):
        frontend = os.path.join(os.path.dirname(__file__), '..', 'payroll-insecure.html')
        if os.path.exists(frontend):
            return send_from_directory(os.path.dirname(frontend), 'payroll-insecure.html')
        return jsonify({'message': 'Insecure Payroll API'}), 200

    @app.after_request
    def add_cors(response):
        origin = request.headers.get('Origin', '')
        if origin in ('http://localhost:5001', 'http://127.0.0.1:5001'):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return response

    @app.route('/api/auth/login', methods=['OPTIONS'])
    @app.route('/api/auth/logout', methods=['OPTIONS'])
    @app.route('/api/auth/me', methods=['OPTIONS'])
    def handle_options():
        return '', 204

    return app


def seed_db(app):
    with app.app_context():
        db.create_all()

        if User.query.first():
            print("Already seeded.")
            return

        from models import Employee, Payslip
        from datetime import date

        print("Seeding insecure database...")

        employees = [
            Employee(first_name='Alice',   last_name='Smith',   email='alice@company.ie',   department='Sales',       job_title='Sales Executive',    salary=50400, start_date=date(2022, 1, 15)),
            Employee(first_name='Michael', last_name='Johnson', email='michael@company.ie', department='IT',          job_title='Sysadmin',           salary=49200, start_date=date(2021, 6, 1)),
            Employee(first_name='Sara',    last_name='Lee',     email='sara@company.ie',    department='HR',          job_title='HR Manager',         salary=48000, start_date=date(2020, 3, 10)),
            Employee(first_name='David',   last_name='Walsh',   email='david@company.ie',   department='Finance',     job_title='Accountant',         salary=54000, start_date=date(2023, 9, 1), status='On Leave'),
            Employee(first_name='Emma',    last_name='Murphy',  email='emma@company.ie',    department='Engineering', job_title='Senior Developer',   salary=57600, start_date=date(2019, 11, 20)),
            Employee(first_name='John',    last_name='Doe',     email='john@company.ie',    department='Engineering', job_title='Software Developer', salary=48000, start_date=date(2022, 1, 15)),
        ]
        for e in employees:
            db.session.add(e)
        db.session.flush()

        periods = [
            ('March 2024',    date(2024, 4, 1)),
            ('February 2024', date(2024, 3, 1)),
            ('January 2024',  date(2024, 2, 1)),
        ]
        for emp in employees:
            for period, pay_date in periods:
                gross = emp.monthly_gross
                deductions = round(gross * 0.145, 2)
                net = round(gross - deductions, 2)
                db.session.add(Payslip(
                    employee_id=emp.id, period=period, pay_date=pay_date,
                    gross_pay=gross, deductions=deductions, net_pay=net, status='Processed'
                ))

        admin_user = User(username='admin', email='admin@company.ie', role='admin')
        admin_user.set_password('admin123')  # weak password, stored as MD5

        john_user = User(username='johndoe', email='john@company.ie', role='employee', employee_id=employees[5].id)
        john_user.set_password('password1')  # weak password

        db.session.add_all([admin_user, john_user])
        db.session.commit()

        print("Done. Insecure demo accounts:")
        print("  Admin:    username=admin    password=admin123")
        print("  Employee: username=johndoe  password=password1")


if __name__ == '__main__':
    app = create_app()
    seed_db(app)
    app.run(debug=True, host='0.0.0.0', port=5001)  # different port to the secure version
