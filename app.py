from flask import Flask, render_template, request, jsonify, flash
from validators import is_valid_password, is_valid_email, email_exists, generate_secret_key
import sqlite3, jwt, datetime
from functools import wraps
from flask_bcrypt import Bcrypt

def create_table():
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

create_table()

app = Flask(__name__, template_folder="templates")
app.secret_key = generate_secret_key()
app.config['JWT_SECRET_KEY'] = "jwtproject"
bcrypt = Bcrypt(app)

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

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['email']
    password = request.form['password']
    
    if not is_valid_email(email):
        flash('Invalid email format.', 'error')
        return render_template('signup.html', error='Invalid email format.')
    
    if not is_valid_password(password):
        flash('Password must have at least 8 characters.', 'error')
        return render_template('signup.html', error='Password must have at least 8 characters!')

    if (email_exists(email)):
       flash('Invalid username or password.', 'error')
       return render_template('signup.html', error='Username already exists!')
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    # Add the new user to the users dictionary.
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
    conn.commit()
    conn.close()

    # Add code for successful sign-up (e.g., redirect to a success page).
    return f"Congratulations, {email}! You are now signed up!"


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email=?', (email,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user[2], password):
        # Implement your user authentication logic here
        # For example, you could store the user ID in a session and redirect to a user dashboard
        token = jwt.encode({'username': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           app.config['JWT_SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    else:
        flash('Invalid username or password.', 'error')
        return render_template('index.html', error='Invalid username or password.')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        if (email_exists(email) == False):
            flash('Username does not exist', 'error')
            return render_template('forgotpassword.html', error='Username does not exist!')

        return "Password reset link sent to your email address."

    return render_template('forgotPassword.html')

if __name__ == '__main__':
    app.run(debug=True)
