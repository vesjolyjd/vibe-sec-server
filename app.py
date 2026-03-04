import os
import secrets
import hashlib
from flask import Flask, request, redirect, session, abort, render_template_string, make_response
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
DB_DSN = os.getenv('DB_DSN')

# Настройки безопасности сессий
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,       # Включить при HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,
)

# Хранилище сессий на сервере (для CSRF-токенов)
server_sessions = {}

def get_db_connection():
    return psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)

def hash_password(password):
    salt = os.urandom(32)
    iterations = 100_000
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    return salt.hex(), hash_bytes.hex()

def verify_password(password, salt_hex, hash_hex):
    salt = bytes.fromhex(salt_hex)
    original_hash = bytes.fromhex(hash_hex)
    iterations = 100_000
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    return hash_bytes == original_hash

@app.after_request
def add_security_headers(response):
    if 'Server' in response.headers:
        del response.headers['Server']
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

@app.route('/')
def index():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT comments.content, users.username
        FROM comments
        JOIN users ON comments.user_id = users.id
        ORDER BY comments.created_at DESC
    """)
    comments = cur.fetchall()
    cur.close()
    conn.close()

    csrf_token = ''
    if 'session_id' in request.cookies:
        sess_id = request.cookies.get('session_id')
        if sess_id in server_sessions:
            csrf_token = server_sessions[sess_id].get('csrf_token', '')

    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Безопасное приложение</title></head>
    <body>
        <h1>Добро пожаловать</h1>
        {% if 'user_id' in session %}
            <p>Вы вошли как {{ session.username }}. <a href="/logout">Выйти</a></p>
        {% else %}
            <p><a href="/login">Войти</a> или <a href="/register">зарегистрироваться</a></p>
        {% endif %}
        <h2>Комментарии</h2>
        <form method="POST" action="/comment">
            <textarea name="content" placeholder="Ваш комментарий"></textarea><br>
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button type="submit">Отправить</button>
        </form>
        <div>
            {% for c in comments %}
                <div><strong>{{ c.username }}</strong>: {{ c.content }}</div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    return render_template_string(html, comments=comments, csrf_token=csrf_token, session=session)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            abort(400)
        salt_hex, hash_hex = hash_password(password)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                (username, hash_hex, salt_hex)
            )
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            return "Пользователь уже существует", 400
        finally:
            cur.close()
            conn.close()
        return redirect('/login')
    return '''
        <form method="POST">
            <input type="text" name="username" placeholder="Логин"><br>
            <input type="password" name="password" placeholder="Пароль"><br>
            <button type="submit">Зарегистрироваться</button>
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, salt FROM users WHERE username = %s",
            (username,)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and verify_password(password, user['salt'], user['password_hash']):
            session_id = secrets.token_urlsafe(16)
            csrf_token = secrets.token_urlsafe(16)
            server_sessions[session_id] = {
                'user_id': user['id'],
                'username': user['username'],
                'csrf_token': csrf_token
            }
            resp = make_response(redirect('/'))
            resp.set_cookie('session_id', session_id, httponly=True, samesite='Lax')
            return resp
        else:
            return "Неверный логин или пароль", 401
    return '''
        <form method="POST">
            <input type="text" name="username" placeholder="Логин"><br>
            <input type="password" name="password" placeholder="Пароль"><br>
            <button type="submit">Войти</button>
        </form>
    '''

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/'))
    resp.delete_cookie('session_id')
    return resp

@app.route('/comment', methods=['POST'])
def add_comment():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in server_sessions:
        abort(403, 'Not authenticated')
    token = request.form.get('csrf_token')
    if token != server_sessions[session_id]['csrf_token']:
        abort(403, 'CSRF token mismatch')
    content = request.form.get('content')
    if not content:
        abort(400)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments (user_id, content) VALUES (%s, %s)",
        (server_sessions[session_id]['user_id'], content)
    )
    conn.commit()
    cur.close()
    conn.close()
    return redirect('/')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=1234, debug=False)