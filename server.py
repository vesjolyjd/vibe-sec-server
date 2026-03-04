#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
import json
import hashlib
import secrets

PORT = 1234

comments = []
users = {
    "admin": hashlib.sha256("secret".encode()).hexdigest()
}
sessions = {}   # session_id -> {"user": username, "csrf_token": token}

class MyHandler(http.server.SimpleHTTPRequestHandler):
    
    def send_security_headers(self):
        self.send_header('X-Frame-Options', 'DENY') # Запрет встраивания в iframe
        self.send_header('X-Content-Type-Options', 'nosniff') # Запрет MIME-сниффинга
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin') # Контроль реферера (другой origin - передаётся только сам origin, отмена http)
        self.send_header('Content-Security-Policy', "default-src 'self'") # Все ресурсы могут загружаться только с того же источника
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_security_headers()
            self.end_headers()
            with open('index.html', 'rb') as f:
                content = f.read()
            # Извлекаем сессию из куки
            cookies = self.headers.get('Cookie', '')
            session_id = None
            for cookie in cookies.split(';'):
                if cookie.strip().startswith('session='):
                    session_id = cookie.split('=')[1].strip()
                    break
            csrf_token = sessions.get(session_id, {}).get('csrf_token', '')
            # Вставляем CSRF-токен в страницу
            inject = f'<script>window.csrfToken = "{csrf_token}";</script>'
            content = content.replace(b'</body>', inject.encode() + b'</body>')
            self.wfile.write(content)
        elif self.path == '/comments':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps(comments).encode())
        else:
            super().do_GET()
    
    def do_POST(self):
        global comments
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)
        
        if self.path == '/login':
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if username in users and users[username] == password_hash:
                session_id = secrets.token_urlsafe(16)
                csrf_token = secrets.token_urlsafe(16)
                sessions[session_id] = {"user": username, "csrf_token": csrf_token}
                self.send_response(302)
                self.send_header('Set-Cookie', f'session={session_id}; HttpOnly; SameSite=Lax') # Кука недоступна через JavaScript, не будет отправляться при кросс-сайтовых POST-запросах
                self.send_header('Location', '/')
                self.send_security_headers()
                self.end_headers()
            else:
                self.send_response(401)
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(b'Login failed')
        elif self.path == '/comment':
            # Проверка сессии и CSRF-токена
            cookies = self.headers.get('Cookie', '')
            session_id = None
            for cookie in cookies.split(';'):
                if cookie.strip().startswith('session='):
                    session_id = cookie.split('=')[1].strip()
                    break
            if not session_id or session_id not in sessions:
                self.send_response(403)
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(b'Invalid session')
                return
            token_from_form = params.get('csrf_token', [''])[0]
            if token_from_form != sessions[session_id]['csrf_token']:
                self.send_response(403)
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(b'CSRF token mismatch')
                return
            comment = params.get('comment', [''])[0]
            comments.append(comment)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_security_headers()
            self.end_headers()
        else:
            self.send_response(404)
            self.send_security_headers()
            self.end_headers()

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        print(f"Сервер запущен на порту {PORT}. Откройте http://localhost:{PORT}")
        httpd.serve_forever()