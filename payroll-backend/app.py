"""
PaySecure - Secure Payroll Application
Main Flask application factory

Security features implemented here:
- WAF middleware (A03 Injection)
- Security response headers (A05 Security Misconfiguration)
- Honeypot routes (A09 Logging & Monitoring)
- CORS restricted to same origin (A05)

References:
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- OWASP A05:2021 Security Misconfiguration
  https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_login import current_user
from config import Config
from extensions import db, login_manager
from models import User, SecurityLog
from waf import register_waf
import os


def create_app(test_config=None):
    app = Flask(__name__, static_folder='../static', template_folder='../templates')
    app.config.from_object(Config)

    # allow test suite to override config (e.g. swap MySQL for in-memory SQLite)
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({'success': False, 'message': 'Login required'}), 401

    # register WAF - must be before blueprints so it runs first
    # Reference: OWASP A03:2021 Injection
    # https://owasp.org/Top10/A03_2021-Injection/
    register_waf(app)

    # register blueprints
    from routes.auth import auth_bp
    from routes.employee import employee_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp)
    app.register_blueprint(admin_bp)

    # honeypot route
    # looks like a real admin panel to attract bots/attackers scanning the site
    # Reference: OWASP A09:2021 Security Logging and Monitoring Failures
    # https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
    @app.route('/admin-panel', methods=['GET', 'POST'])
    def honeypot():
        entry = SecurityLog(
            event_type='honeypot',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:300],
            endpoint=request.path,
            payload=str(request.form.to_dict()) if request.form else str(request.get_data(as_text=True))[:500],
        )
        db.session.add(entry)
        db.session.commit()

        if request.method == 'POST':
            entry2 = SecurityLog(
                event_type='honeypot_submit',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:300],
                endpoint=request.path,
                payload=str(request.get_json(silent=True) or request.form.to_dict())[:500],
            )
            db.session.add(entry2)
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 403

        return '''
        <!DOCTYPE html><html><head><title>Admin Panel</title></head>
        <body style="font-family:sans-serif;display:flex;justify-content:center;padding:80px;">
          <div style="width:320px;">
            <h2>System Administration</h2>
            <form method="POST">
              <div><label>Username</label><br>
              <input name="username" type="text" style="width:100%;padding:8px;margin:6px 0 12px;"></div>
              <div><label>Password</label><br>
              <input name="password" type="password" style="width:100%;padding:8px;margin:6px 0 12px;"></div>
              <button type="submit" style="width:100%;padding:10px;background:#333;color:#fff;border:none;cursor:pointer;">Login</button>
            </form>
          </div>
        </body></html>
        ''', 200

    # catch common paths that automated scanners probe for
    @app.route('/wp-admin')
    @app.route('/wp-login.php')
    @app.route('/.env')
    @app.route('/phpmyadmin')
    def honeypot_scanner():
        entry = SecurityLog(
            event_type='honeypot_scan',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:300],
            endpoint=request.path,
        )
        db.session.add(entry)
        db.session.commit()
        return jsonify({'error': 'Not found'}), 404

    # serve the frontend
    @app.route('/')
    @app.route('/<path:path>')
    def serve_frontend(path=''):
        frontend = os.path.join(os.path.dirname(__file__), '..', 'payroll-app.html')
        if os.path.exists(frontend):
            return send_from_directory(os.path.dirname(frontend), 'payroll-app.html')
        return jsonify({'message': 'PaySecure API is running'}), 200

    @app.after_request
    def add_security_headers(response):
        """
        Add HTTP security headers to every response.
        Reference: OWASP Secure Headers Project
        https://owasp.org/www-project-secure-headers/
        Reference: OWASP A05:2021 Security Misconfiguration
        https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
        """

        # prevent the browser from rendering this page inside a frame/iframe
        # protects against clickjacking attacks
        # Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
        response.headers['X-Frame-Options'] = 'DENY'

        # prevent browsers from MIME-sniffing a response away from the declared content-type
        # Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # enable browser's built-in XSS filter (older browsers)
        # Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # control how much referrer info is sent with requests
        # Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # restrict access to browser features
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        # Content Security Policy - restricts where scripts/styles/etc can be loaded from
        # 'unsafe-inline' needed because our frontend uses inline JS - in production
        # you would move to external JS files and remove this
        # Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )

        # HSTS - tell browsers to only connect over HTTPS
        # (only takes effect when served over HTTPS, but good practice)
        # Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # handle CORS for local development
        origin = request.headers.get('Origin', '')
        if origin in ('http://localhost:5000', 'http://127.0.0.1:5000', 'http://localhost:5500'):
            response.headers['Access-Control-Allow-Origin']      = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Headers']     = 'Content-Type'
            response.headers['Access-Control-Allow-Methods']     = 'GET, POST, PUT, DELETE, OPTIONS'

        return response

    @app.route('/api/auth/login', methods=['OPTIONS'])
    @app.route('/api/auth/verify-2fa', methods=['OPTIONS'])
    @app.route('/api/auth/logout', methods=['OPTIONS'])
    @app.route('/api/auth/me', methods=['OPTIONS'])
    def handle_options():
        return '', 204

    @app.route('/api', methods=['GET'])
    def api_root():
        return jsonify({'message': 'PaySecure API v1.0', 'status': 'running'}), 200

    return app


def upgrade_db(app):
    """
    Add new columns to existing tables without dropping the database.
    Safe to run multiple times - ignores errors if columns already exist.
    """
    with app.app_context():
        for sql in [
            "ALTER TABLE users ADD COLUMN failed_attempts INT DEFAULT 0",
            "ALTER TABLE users ADD COLUMN locked_until DATETIME NULL",
        ]:
            try:
                db.session.execute(db.text(sql))
                db.session.commit()
            except Exception:
                db.session.rollback()


def seed_db(app):
    """Create tables and seed demo data on first run."""
    with app.app_context():
        db.create_all()

        if User.query.first():
            print("Database already seeded.")
            return

        from models import Employee, Payslip
        from datetime import date

        print("Seeding database...")

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
        admin_user.set_password('Admin@1234')

        john_user = User(username='johndoe', email='john@company.ie', role='employee', employee_id=employees[5].id)
        john_user.set_password('Employee@1234')

        db.session.add_all([admin_user, john_user])
        db.session.commit()

        print("Done. Demo accounts created:")
        print("  Admin:    username=admin       password=Admin@1234")
        print("  Employee: username=johndoe     password=Employee@1234")


if __name__ == '__main__':
    app = create_app()
    upgrade_db(app)   # add new columns to existing DB safely
    seed_db(app)
    app.run(debug=True, host='0.0.0.0', port=5000)
