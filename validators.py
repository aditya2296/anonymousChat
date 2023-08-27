import re, sqlite3, secrets

def create_login_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def create_user_details_table():
    conn = sqlite3.connect('userDetails.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS userDetails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            position TEXT NOT NULL,
            manager TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def generate_secret_key():
    return secrets.token_hex(16)

def is_valid_password(password):
    # Implement your password validation logic here
    # Example: Password should have at least 8 characters
    return len(password) >= 8

def is_valid_email(email):
    # Implement your email validation logic here
    # Example: Use regex to validate email format
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(email_regex, email)

def email_exists(email):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user is not None
