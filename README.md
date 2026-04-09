
 Step 1 

Open a terminal and run:

git clone https://github.com/chinedunkem1/Payroll-Project
cd <folder-name>

Step 2 – Set up the database

1. Open MySQL 
2. Connect to your local MySQL server
3. Open a new query tab and run the contents of `setup.sql` (just click the folder icon and open the file, then hit the lightning bolt to run it)
4. This creates an empty database called `payroll_db`

---

### Step 3 – Update the config with your MySQL password

Open `payroll-backend/config.example.py`.so you need to find out the password of your MySQL(the way to test you password is Click MySQL , manage connections(top-right), test connections)

Once you have found your password , if you there is a way to change it using MySQL Query but when you find it , enter config.example.py and you will see

MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'YOUR_MYSQL_PASSWORD_HERE')

What your gonna do now is swap your password with the highlighted text that says 'YOUR_MYSQL_PASSWORD_HERE'

> Note: if your password has special characters like `@` or `#` in it, change it to something plain in MySQL Workbench first. Special characters can break the connection URL.

To change your MySQL password, run this in MySQL Workbench:
```sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewPassword123';
FLUSH PRIVILEGES;
```

Step 4 – Install Python packages

In the terminal, go into the backend folder:


Then install the dependencies:

pip install -r requirements.txt



Step 5 – Run the app

Make sure you're still in the `payroll-backend` folder, then run:

python app.py

important notice , when everything is setup and you want to push an update , make sure to uncheck the config.py because that will then change the password for everyone 