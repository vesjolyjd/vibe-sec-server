#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
import json

PORT = 1234

# Список комментариев (все хранятся в памяти)
comments = []

# Простейшая база пользователей (логин:пароль в открытом виде)
users = {
    "admin": "secret"
}

class MyHandler(http.server.SimpleHTTPRequestHandler):
    """Обработчик HTTP-запросов"""
    
    def do_GET(self):
        """Обрабатываем GET-запросы"""
        if self.path == '/':
            # Отдаём главную страницу index.html
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('index.html', 'rb') as f:
                self.wfile.write(f.read())
        elif self.path == '/comments':
            # Отдаём список комментариев в формате JSON
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(comments).encode())
        else:
            # Для всех остальных путей пытаемся отдать статический файл (не используется)
            super().do_GET()

    def do_POST(self):
        """Обрабатываем POST-запросы (отправка форм)"""
        global comments
        # Читаем тело запроса (данные формы)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        # Разбираем параметры из строки запроса
        params = urllib.parse.parse_qs(post_data)

        if self.path == '/login':
            # Обработка формы входа
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            if username in users and users[username] == password:
                # Успешный вход: устанавливаем куку session
                self.send_response(302)  # 302 Redirect
                self.send_header('Set-Cookie', 'session=logged_in')
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'Login failed')
        elif self.path == '/comment':
            # Обработка добавления комментария
            comment = params.get('comment', [''])[0]
            # УЯЗВИМОСТЬ: сохраняем комментарий как есть, без проверок
            comments.append(comment)
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        print(f"Сервер запущен на порту {PORT}. Откройте http://localhost:{PORT}")
        httpd.serve_forever()