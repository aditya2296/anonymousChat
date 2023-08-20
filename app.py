from flask import Flask, render_template, request, jsonify, flash
import sqlite3
import secrets
import jwt
import datetime
from functools import wraps

def generate_secret_key():
    return secrets.token_hex(16)

def create_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()

app = Flask(__name__, template_folder="templates")
app.secret_key = generate_secret_key()
app.config['JWT_SECRET_KEY'] = "jwtproject"

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = decoded_token['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated
@app.route('/')
def home():
    return render_template('index.html')

users = {}

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']

    # Add the new user to the users dictionary.
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

    # Add code for successful sign-up (e.g., redirect to a success page).
    return f"Congratulations, {username}! You are now signed up!"


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        # Implement your user authentication logic here
        # For example, you could store the user ID in a session and redirect to a user dashboard
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           app.config['JWT_SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    else:
        flash('Invalid username or password.', 'error')
        return render_template('index.html', error='Invalid username or password.')

@app.route('/chat', methods=['GET'])
@token_required
def chat(current_user):
    return f'Welcome to the chat page, {current_user}!'

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_or_username = request.form['email_or_username']

        return "Password reset link sent to your email address."

    return render_template('forgotPassword.html')

if __name__ == '__main__':
    app.run(debug=True)
