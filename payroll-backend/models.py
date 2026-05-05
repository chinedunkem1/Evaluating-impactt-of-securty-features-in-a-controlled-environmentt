from datetime import datetime
from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default='employee')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # account lockout fields
    # Reference: OWASP Authentication Cheat Sheet - Account Lockout
    # https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)

    # linked employee record (admin accounts won't have one)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=True)
    employee    = db.relationship('Employee', backref='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def __repr__(self):
        return f'<User {self.username} [{self.role}]>'


class Employee(db.Model):
    __tablename__ = 'employees'

    id         = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80),  nullable=False)
    last_name  = db.Column(db.String(80),  nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(80),  nullable=False)
    job_title  = db.Column(db.String(100), nullable=False)
    salary     = db.Column(db.Float,       nullable=False)
    status     = db.Column(db.String(30),  default='Active')  # Active, On Leave, Inactive
    start_date = db.Column(db.Date,        nullable=False, default=datetime.utcnow)
    iban       = db.Column(db.String(40),  nullable=True)
    pps_number = db.Column(db.String(20),  nullable=True)
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    payslips = db.relationship('Payslip', backref='employee', lazy=True, cascade='all, delete-orphan')

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    @property
    def monthly_gross(self):
        return round(self.salary / 12, 2)

    def to_dict(self):
        return {
            'id':         self.id,
            'full_name':  self.full_name,
            'first_name': self.first_name,
            'last_name':  self.last_name,
            'email':      self.email,
            'department': self.department,
            'job_title':  self.job_title,
            'salary':     self.salary,
            'status':     self.status,
            'start_date': self.start_date.isoformat() if self.start_date else None,
        }

    def __repr__(self):
        return f'<Employee {self.full_name}>'


class Payslip(db.Model):
    __tablename__ = 'payslips'

    id          = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    period      = db.Column(db.String(20), nullable=False)   # e.g. "March 2024"
    pay_date    = db.Column(db.Date,       nullable=False)
    gross_pay   = db.Column(db.Float,      nullable=False)
    deductions  = db.Column(db.Float,      nullable=False, default=0.0)
    net_pay     = db.Column(db.Float,      nullable=False)
    status      = db.Column(db.String(20), default='Pending')  # Pending, Processed
    created_at  = db.Column(db.DateTime,   default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':          self.id,
            'employee_id': self.employee_id,
            'period':      self.period,
            'pay_date':    self.pay_date.isoformat() if self.pay_date else None,
            'gross_pay':   self.gross_pay,
            'deductions':  self.deductions,
            'net_pay':     self.net_pay,
            'status':      self.status,
        }

    def __repr__(self):
        return f'<Payslip {self.employee_id} - {self.period}>'


# logs honeypot hits, failed logins, 2fa failures etc.
class SecurityLog(db.Model):
    __tablename__ = 'security_logs'

    id         = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50),  nullable=False)
    ip_address = db.Column(db.String(50),  nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    endpoint   = db.Column(db.String(200), nullable=True)
    payload    = db.Column(db.Text,        nullable=True)
    username   = db.Column(db.String(80),  nullable=True)
    timestamp  = db.Column(db.DateTime,    default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':         self.id,
            'event_type': self.event_type,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'endpoint':   self.endpoint,
            'payload':    self.payload,
            'username':   self.username,
            'timestamp':  self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        }
