___
# vibe-sec-server

### Экранирование-вывода (от XSS)
Экранируем опасные символы: < > & " ' на их HTML-сущности
Вот как это добились

```JavaScript
let safe = c.replace(/&/g, '&amp;')
                            .replace(/</g, '&lt;')
                            .replace(/>/g, '&gt;')
                            .replace(/"/g, '&quot;')
                            .replace(/'/g, '&#039;');
```

### Заголовки-безопасности

#### X-Frame-Options
Запрещает встраивание страницы в <iframe> (защита от кликджекинга)

- `DENY` – запрет для любых сайтов
- `SAMEORIGIN` — разрешено только с того же источника
- `ALLOW-FROM uri` (устарела) — разрешено для указанного URI

#### X-Content-Type-Options
Отключает MIME-сниффинг (браузер не пытается угадать тип файла, строго следует Content-Type)

- `nosniff` — запрещает

#### Referrer-Policy
Управляет содержимым заголовка Referer (Отправитель) при переходах и запросах ресурсов

- `no-referrer` — не отправлять никогда
- `no-referrer`-when-downgrade (по умолчанию) – не отправлять при переходе с HTTPS на HTTP
- `same-origin` — отправлять только внутри своего источника
- `strict-origin` — отправлять только origin (без пути) при кросс-домене и при смене протокола не отправлять
- `strict-origin`-when-cross-origin — полный URL на своём источнике, только origin на чужом, не отправлять при смене протокола
- `unsafe-url` — отправлять полный URL всегда (опасно)

#### Content-Security-Policy(CSP)
Ограничивает источники загружаемых ресурсов (скриптов, стилей, изображений и т.д.) - предотвращает XSS и внедрение нежелательного кода

- `default-src` – источник по умолчанию для всех типов ресурсов.
- `script-src` – для скриптов.
- `style-src` – для стилей.
- `img-src` – для изображений.
- `connect-src` – для AJAX, WebSocket и т.п.
- `font-src`, `frame-src` и др.

Значения дирректив: 
    - `self` (свой источник)
    - `none` (запрет)
    - `unsafe-inline` (разрешить инлайн-код, небезопасно)
    - `unsafe-eval` (разрешить eval())
    - `домены` (example.com)
    - `протоколы` (https:)

#### Set-Cookie
Устанавливает cookie (куку) в браузере, которая будет отправляться серверу при последующих запросах

Флаги:
- `HttpOnly` – запрещает доступ к куке через JavaScript (document.cookie). Защита от кражи сессии при XSS-атаках
- `Secure` – кука передаётся только по HTTPS (не передаётся по незащищённому HTTP). Предотвращает перехват в открытых сетях
- `SameSite` – ограничивает отправку куки при кросс-сайтовых запросах. Защита от CSRF
    Параметры:
    - `Lax` – кука не отправляется при кросс-сайтовых POST-запросах, но отправляется при переходе по ссылке (например, при клике с другого сайта)
    - `Strict` – кука не отправляется ни при каких кросс-сайтовых запросах (даже при переходе по ссылке). Надёжнее, но может сломать переходы с внешних ссылок
    - `None` – кука отправляется при любых кросс-сайтовых запросах. Требует флага Secure (только HTTPS)
- `Expires / Max-Age` – устанавливают срок жизни cookie (определённая дата / промежуток времени). Без них cookie считается сессионной и удаляется при закрытии браузера
- `Path` – ограничивает путь на сервере, для которого отправляется cookie
- `Domain` – задаёт домен, для которого действует cookie (по умолчанию – только текущий)


### Хэширование-паролей
Хранить в открытом виде пароль плохо, кто угодно может прочитать код и спарсить конфиденциальную информацию.
Для обеспечения начальной защиты используем хэширование. Используем библиотеку `hashlib` c алгоритмом SHA-256

Немного про хэш :)

> Хеширование — это процесс преобразования данных любого размера в строку фиксированной длины (хеш), которая уникальна для исходных данных. 
> Необратимость: По значению хеша практически невозможно восстановить исходные данные
> Детерминированность: Для одних и тех же входных данных хеш всегда будет одинаковым
> Лавинный эффект: Малейшее изменение входных данных (например, изменение одного бита) приводит к полному изменению результирующего хеша

#### HASHLIB

Создание хеша SHA-256 для строки
```python
data = b"Hello, World!"  # Данные должны быть в байтовом формате
hash_object = hashlib.sha256(data)
```

Получение хеша в шестнадцатеричном формате (самый распространенный способ)
```python
hex_digest = hash_object.hexdigest()
```

Можем добавить данные
```python
hash_object.update(b" data")
```

- `digest()` возвращает как объект байтах
- `hash.hexdigest()` — возвращает хеш как строку в hex

Алгоритмы: 'blake2s', 'md5', 'sha3_256', 'sha384', 'sha256', 'sha512', 'md5', 'ripemd160', 'whirlpool' и другие

Использование соли:
1. Генерируем случайную соль (16-32 байта) `os.urandom(32)`
2. Вычисляем хеш 
```python
 hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',                      # Алгоритм HMAC
        password.encode('utf-8'),      # Пароль в байтах
        salt,                          # Соль
        iterations,                    # Количество итераций алгоритма хэширования
        dklen=32                        # Длина ключа (совпадает с digest_size SHA-256)
    )
```
3. Возвращаем соль и хеш для хранения (обычно хранят вместе) `salt.hex(), hash_bytes.hex()`

```python
def verify_password(password: str, salt_hex: str, hash_hex: str, iterations=100000):
    """Проверяет, соответствует ли пароль сохраненному хешу."""
    salt = bytes.fromhex(salt_hex)
    original_hash_bytes = bytes.fromhex(hash_hex)

    # Вычисляем хеш для предоставленного пароля с той же солью
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)

    # Сравниваем полученный хеш с сохраненным
    return hash_bytes == original_hash_bytes
```

### CSRF-tokens
Идея: при входе генерируем уникальный токен, храним его в сессии на сервере и отдаём в куку, а также вставляем в форму комментария как скрытое поле. При POST сравниваем токен из формы с токеном из сессии

1. Генерируем уникальный идентификатор сессии при входе
```python
import secrets
sessions = {}

session_id = secrets.token_urlsafe(16)
csrf_token = secrets.token_urlsafe(16)
```

2. В словарь sessions по этому ключу сохраняем информацию о пользователе и CSRF-токен `sessions[session_id] = {"user": username, "csrf_token": csrf_token}`
3. В куку кладём только идентификатор сессии `self.send_header('Set-Cookie', f'session={session_id}; HttpOnly; SameSite=Lax')`
4. В форму комментария добавляем скрытое поле с CSRF-токеном
```html
<form method="POST" action="/comment">
    <input type="text" name="comment" placeholder="Комментарий">
    <input type="hidden" name="csrf_token" id="csrf_token">
    <button type="submit">Отправить</button>
</form>
<script>
    document.getElementById('csrf_token').value = window.csrfToken || '';
</script>
```

5. При POST проверяем, что токен из формы совпадает с токеном в сессии
```python
    if not session_id or session_id not in sessions:
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b'Invalid session')
        return
    token_from_form = params.get('csrf_token', [''])[0]
    if token_from_form != sessions[session_id]['csrf_token']:
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b'CSRF token mismatch')
        return
```
