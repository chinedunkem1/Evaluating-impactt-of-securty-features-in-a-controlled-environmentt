# PaySecure – Payroll Security Testing Project

**BSc Cybersecurity | Final Year Project**

---

## What This Is

PaySecure is a payroll web application built from scratch to demonstrate how common security vulnerabilities work in practice, and how they can be fixed. The project was developed as part of a BSc Cybersecurity dissertation, with the goal of showing the real-world impact of the [OWASP Top 10:2021](https://owasp.org/Top10/2021/) — the industry-standard list of the most critical web application security risks.

The app simulates a company payroll system where employees can log in, view their salary, and where admins can manage users and payslips. It was deliberately built in a way that makes security flaws easy to demonstrate, test, and then compare against a hardened version.

---

## What Was Built

The backend is a Flask (Python) web application backed by a MySQL database. Three versions of the app exist across the codebase, representing different security postures:

- **Vulnerable version** — intentionally insecure, used as the attack target
- **Naïve version** — partial fixes, still exploitable in subtle ways
- **Secure version** — full mitigations applied, all OWASP tests pass

The frontend is a single-page HTML/CSS interface. The backend handles authentication, session management, payroll data retrieval, and all security controls.

---

## Security Tests Performed

Ten penetration tests were carried out based on the OWASP Web Security Testing Guide (WSTG). Each test was run against the vulnerable version and then re-run against the secure version to compare results.

| Test | OWASP Category | What Was Tested |
|------|---------------|-----------------|
| T01 | A01 – Broken Access Control | Role-based access: non-admin users attempting to reach admin-only endpoints |
| T02 | A01 – Broken Access Control | Client-side role escalation via fetch + server-side enforcement |
| T03 | A03 – Injection | SQL injection on login and search inputs |
| T04 | A03 – Injection | Cross-site scripting (XSS) via stored input fields |
| T05 | A01 – Broken Access Control | Insecure Direct Object Reference (IDOR) on payslip IDs |
| T06 | A02 – Cryptographic Failures | Sensitive data exposed over unencrypted connections |
| T07 | A05 – Security Misconfiguration | Verbose error messages leaking stack traces |
| T08 | A05 – Security Misconfiguration | Server header disclosing framework and version info |
| T09 | A05 – Security Misconfiguration | Missing security response headers (CSP, HSTS, X-Frame-Options) |
| T10 | A07 – Authentication Failures | Brute force attack — no account lockout mechanism |

---

## Key Security Controls Implemented

- **`@admin_required` decorator** — server-side access control that rejects any request to admin endpoints from non-admin sessions, regardless of what the client sends
- **Content Security Policy (CSP)** — `connect-src 'self'` header blocks cross-origin fetch requests made by injected scripts
- **Server header suppression** — a custom `WSGIRequestHandler` subclass (`HideServerHeader`) strips the `Server` header from every response
- **Account lockout** — after 5 consecutive failed login attempts, the account is locked for 15 minutes; tracked via `failed_attempts` and `locked_until` columns in the database
- **Parameterised queries** — Flask-SQLAlchemy ORM prevents SQL injection by never concatenating user input into raw SQL
- **WAF middleware** — `waf.py` applies regex-based pattern matching to block known injection signatures before they reach the app logic

---

## Setup Instructions

### Prerequisites
- Python 3.8+
- MySQL (e.g. MySQL Workbench)
- pip

### Step 1 — Clone the repo

```bash
git clone https://github.com/chinedunkem1/Payroll-Project
cd Payroll-Project
```

### Step 2 — Set up the database

1. Open MySQL Workbench and connect to your local server
2. Open a new query tab, load `setup.sql`, and run it
3. This creates the `payroll_db` database with all required tables and seed data

### Step 3 — Configure your database password

Open `payroll-backend/config.py` and set your MySQL password as an environment variable, or edit the default directly:

```python
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'your_password_here')
```

> **Note:** If your password contains special characters like `@` or `#`, change it to something plain in MySQL Workbench first — special characters break the connection URL.

To change your MySQL root password:
```sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewPassword123';
FLUSH PRIVILEGES;
```

### Step 4 — Install dependencies

```bash
cd payroll-backend
pip install -r requirements.txt
```

### Step 5 — Run the app

```bash
python app.py
```

The app runs on `http://localhost:5000` by default.

---

## Project Structure

```
Payroll-Project/
├── payroll-backend/
│   ├── app.py              # Flask app entry point, security headers, server config
│   ├── config.py           # Database and session configuration
│   ├── models.py           # User model with is_admin() and is_locked() methods
│   ├── waf.py              # WAF middleware for request pattern filtering
│   ├── extensions.py       # SQLAlchemy and login manager setup
│   ├── routes/             # Blueprints: auth, admin, payroll
│   ├── static/             # CSS and frontend assets
│   └── tests/              # Penetration test scripts (T01–T10)
├── payroll-app.html        # Frontend interface
├── payroll-app.css         # Frontend styles
├── setup.sql               # Database schema and seed data
└── wordlist.txt            # Password list used in T10 brute force test
```

---

## Important

Do **not** commit `config.py` with a real password in it. Use environment variables in any deployment beyond local testing.
