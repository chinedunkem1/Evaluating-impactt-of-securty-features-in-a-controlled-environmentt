# Secure Payroll Web Application
**Final Year Project – TU Dublin**
Chinedu Nkem, Kyle McElroy, Sean Harmon Breen

A payroll management system built to demonstrate web application security features including 2FA, a honeypot, and role-based access control.

---

## What it does

- Employees can log in and view their payslips and profile
- Admins can manage employees, generate payslips, and view security logs
- Admin login requires a 2FA code (TOTP)
- There's a honeypot at `/admin-panel` that logs any bots or attackers who find it
- Visits to common scanner paths like `/wp-admin`, `/.env` etc are also logged

---

## Setup – Getting it running on your laptop

### What you need installed first

- Python 3.10 or higher
- MySQL (MySQL Community Server + MySQL Workbench)
- Git

---

### Step 1 – Clone the repo

Open a terminal (Command Prompt or PowerShell on Windows) and run:

```
git clone <your-repo-url>
cd <folder-name>
```

---

### Step 2 – Set up the database

1. Open **MySQL Workbench**
2. Connect to your local MySQL server
3. Open a new query tab and run the contents of `setup.sql` (just click the folder icon and open the file, then hit the lightning bolt to run it)
4. This creates an empty database called `payroll_db`

---

### Step 3 – Update the config with your MySQL password

Open `payroll-backend/config.py` and change this line:

```python
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'YOUR_MYSQL_PASSWORD_HERE')
```

Replace `YOUR_MYSQL_PASSWORD_HERE` with the password you use to log into MySQL Workbench. For example if your password is `root123`:

```python
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'root123')
```

> Note: if your password has special characters like `@` or `#` in it, change it to something plain in MySQL Workbench first. Special characters can break the connection URL.

To change your MySQL password, run this in MySQL Workbench:
```sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewPassword123';
FLUSH PRIVILEGES;
```

---

### Step 4 – Install Python packages

In the terminal, go into the backend folder:

```
cd payroll-backend
```

Then install the dependencies:

```
pip install -r requirements.txt
```

---

### Step 5 – Run the app

Make sure you're still in the `payroll-backend` folder, then run:

```
python app.py
```

The first time it runs it will automatically create all the database tables and add some demo data.

You should see something like:

```
Seeding database...
Done. Demo accounts created:
  Admin:    username=admin       password=Admin@1234
  Employee: username=johndoe     password=Employee@1234
 * Running on http://127.0.0.1:5000
```

---

### Step 6 – Open the app

Go to: **http://127.0.0.1:5000**

**Admin login:**
- Username: `admin`
- Password: `Admin@1234`
- 2FA code: `123456` (demo code, no authenticator app needed)

**Employee login:**
- Username: `johndoe`
- Password: `Employee@1234`
- No 2FA needed for employees

---

## Folder structure

```
Project/
├── payroll-app.html          <- the frontend (single HTML file)
├── setup.sql                 <- run this in MySQL Workbench first
├── README.md
├── .gitignore
└── payroll-backend/
    ├── app.py                <- main Flask app, also has the honeypot routes
    ├── config.py             <- database config (update your password here)
    ├── models.py             <- database models (User, Employee, Payslip, SecurityLog)
    ├── extensions.py         <- SQLAlchemy and LoginManager setup
    ├── requirements.txt      <- Python packages
    └── routes/
        ├── auth.py           <- login, logout, 2FA, register
        ├── admin.py          <- admin dashboard, employees, payslips, security logs
        └── employee.py       <- employee dashboard and payslips
```

---

## Common errors

**"Access denied for user root"**
Your MySQL password in `config.py` doesn't match your actual MySQL password. Double check Step 3.

**"Can't connect to MySQL server"**
MySQL isn't running. Open MySQL Workbench and start the connection, or check that the MySQL service is running on your machine.

**"No module named flask"**
You haven't installed the dependencies yet, or you're in the wrong folder. Run `pip install -r requirements.txt` from inside the `payroll-backend` folder.

**Port 5000 already in use**
Something else is running on port 5000. Either stop that process or change the port at the bottom of `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```
Then access the app at `http://127.0.0.1:5001`.

---

## Security features (for the demo)

| Feature | Where to see it |
|---|---|
| 2FA (TOTP) | Log in as admin – you'll be asked for a code |
| Honeypot | Visit `/admin-panel` in the browser, then check Security Logs in the admin dashboard |
| Role-based access | Try accessing `/api/admin/employees` without being logged in |
| Failed login logging | Enter a wrong password, then check Security Logs |
| Session management | Log out and try going back |
