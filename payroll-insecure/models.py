from datetime import datetime
from extensions import db
from flask_login import UserMixin
import hashlib

# INSECURE VERSION - passwords stored as plain MD5, no salting


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password      = db.Column(db.String(256), nullable=False)  # plain MD5 - no bcrypt
    role          = db.Column(db.String(20),  nullable=False, default='employee')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=True)
    employee    = db.relationship('Employee', backref='user', uselist=False)

    def set_password(self, password):
        # MD5 with no salt - extremely weak, easily cracked
        self.password = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password == hashlib.md5(password.encode()).hexdigest()

    def is_admin(self):
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username}>'


class Employee(db.Model):
    __tablename__ = 'employees'

    id         = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80),  nullable=False)
    last_name  = db.Column(db.String(80),  nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(80),  nullable=False)
    job_title  = db.Column(db.String(100), nullable=False)
    salary     = db.Column(db.Float,       nullable=False)
    status     = db.Column(db.String(30),  default='Active')
    start_date = db.Column(db.Date,        nullable=False, default=datetime.utcnow)
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


class Payslip(db.Model):
    __tablename__ = 'payslips'

    id          = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    period      = db.Column(db.String(20), nullable=False)
    pay_date    = db.Column(db.Date,       nullable=False)
    gross_pay   = db.Column(db.Float,      nullable=False)
    deductions  = db.Column(db.Float,      nullable=False, default=0.0)
    net_pay     = db.Column(db.Float,      nullable=False)
    status      = db.Column(db.String(20), default='Pending')
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
