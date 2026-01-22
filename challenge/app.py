from flask import Flask, request, jsonify, send_file
import jwt
import datetime
import sqlite3
from functools import wraps
import os
import secrets
from playwright.sync_api import sync_playwright

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-98765432346kjhfghjk78'
app.config['JWT_SECRET'] = 'jwt-secret-key-98765678954edfghjkfds'
DATABASE = 'users.db'

def generate_jwt_token(user_data):
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'email': user_data['email'],
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    

    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
    return token

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            flag TEXT DEFAULT ''
        )
    ''')
    
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        users = [
            (secrets.token_hex(8), 'Administrator', 'admin@example.com', 'password9876543458907654fgjhgfd', 'flag{cache_deception_with_cspt_gadget_thats_absolute_cinema}')
        ]
        
        c.executemany('''
            INSERT INTO users (id, username, email, password, flag)
            VALUES (?, ?, ?, ?, ?)
        ''', users)
        
        conn.commit()
    
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

def verify_credentials(username, password):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                       (username, password)).fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

init_db()

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token = request.headers.get('X-Auth-Token')
        
        if not auth_token:
            return jsonify({'error': 'Missing X-Auth-Token header'}), 401
        
        payload = verify_jwt_token(auth_token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user = get_user_by_id(payload.get('user_id'))
        
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        return f(user, *args, **kwargs)
    
    return decorated_function

@app.route('/')
def index():
    return send_file('templates/index.html')

@app.route('/register')
def register_page():
    return send_file('templates/register.html')

@app.route('/profile')
def profile():
    return send_file('templates/profile.html')

@app.route('/api/profile/<user_id>', methods=['GET'])
@require_auth
def get_token(user, user_id):

    response = jsonify({
        'user_id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'flag': user.get('flag', ''),
    })
    return response




def visit_url_with_browser(url, auth_token):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            
            page.goto(os.getenv('APP_URL'), wait_until='networkidle')
            page.evaluate(f"localStorage.setItem('authToken', '{auth_token}')")
            
            page.goto(url, wait_until='networkidle', timeout=10000)
            
            page.wait_for_timeout(2000)
            
            content = page.content()
            print(f"[Browser Visit] Successfully loaded: {url}")
            print(f"[Browser Visit] Page title: {page.title()}")
            
            browser.close()
            return True
    except Exception as e:
        print(f"[Browser Visit] Error visiting {url}: {str(e)}")
        return False

@app.route('/api/report', methods=['POST'])
@require_auth
def report_url(user):
    print(f"[Report] User {user['username']} reporting URL")
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'success': False, 'error': 'Missing URL'}), 400
    
    conn = get_db()
    admin = conn.execute('SELECT * FROM users WHERE username = ?', ('Administrator',)).fetchone()
    conn.close()
    
    if admin:
        admin_dict = dict(admin)
        admin_token = generate_jwt_token(admin_dict)
        
        success = visit_url_with_browser(url, admin_token)
        
        if success:
            return jsonify({'success': True, 'message': f'URL {url} visited by admin successfully.'})
        else:
            return jsonify({'success': False, 'error': 'Failed to visit URL'}), 500
    else:
        return jsonify({'success': False, 'error': 'Admin user not found'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = verify_credentials(username, password)
    
    if user:
        jwt_token = generate_jwt_token(user)
        
        return jsonify({
            'success': True,
            'auth_token': jwt_token,
            'username': user['username']
        })
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'success': False, 'error': 'Username already exists'}), 400
    
    user_id = secrets.token_hex(8)
    
    try:
        conn.execute('''
            INSERT INTO users (id, username, email, password, flag)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, username, email, password, ''))
        conn.commit()
        
        new_user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if new_user:
            user_dict = dict(new_user)
            jwt_token = generate_jwt_token(user_dict)
            
            return jsonify({
                'success': True,
                'auth_token': jwt_token,
                'username': user_dict['username']
            }), 201
        else:
            return jsonify({'success': False, 'error': 'Failed to create user'}), 500
            
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({'success': False, 'error': 'Database error: username or email already exists'}), 400
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': f'Registration failed: {str(e)}'}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
