import re
import sqlite3, secrets

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
