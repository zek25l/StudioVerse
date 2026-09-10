import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / 'data'
USERS_FILE = DATA_DIR / 'users.json'
SUBMISSIONS_FILE = DATA_DIR / 'submissions.json'
PORT = int(os.environ.get('PORT', '3000'))
SESSION_SECONDS = 60 * 60 * 24 * 30
ADMIN_SESSION_SECONDS = 60 * 60 * 8
OWNER_HASH = 'ad98f59a44425cfc03cd12554b893f26b98a73ef7435e5e01d75478559a6fe84'
SESSIONS = {}
ADMIN_SESSIONS = {}
USERS_LOCK = threading.Lock()


def ensure_store():
    DATA_DIR.mkdir(exist_ok=True)
    if not USERS_FILE.exists():
        USERS_FILE.write_text('[]\n', encoding='utf-8')
    if not SUBMISSIONS_FILE.exists():
        SUBMISSIONS_FILE.write_text('[]\n', encoding='utf-8')


def read_users():
    with USERS_LOCK:
        return json.loads(USERS_FILE.read_text(encoding='utf-8'))


def write_users(users):
    temporary_file = USERS_FILE.with_suffix('.tmp')
    with USERS_LOCK:
        temporary_file.write_text(json.dumps(users, indent=2) + '\n', encoding='utf-8')
        temporary_file.replace(USERS_FILE)


def read_submissions():
    with USERS_LOCK:
        return json.loads(SUBMISSIONS_FILE.read_text(encoding='utf-8'))


def write_submissions(submissions):
    temporary_file = SUBMISSIONS_FILE.with_suffix('.tmp')
    with USERS_LOCK:
        temporary_file.write_text(json.dumps(submissions, indent=2) + '\n', encoding='utf-8')
        temporary_file.replace(SUBMISSIONS_FILE)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64)
    return salt, hashed.hex()


def password_matches(password, user):
    _, supplied_hash = hash_password(password, user['passwordSalt'])
    return hmac.compare_digest(supplied_hash, user['passwordHash'])


def public_user(user):
    return {'id': user['id'], 'username': user['username'], 'createdAt': user['createdAt']}


def valid_credentials(username, password):
    return (isinstance(username, str) and 3 <= len(username) <= 24 and username.replace('_', '').isalnum()
            and username.isascii() and isinstance(password, str) and 8 <= len(password) <= 128)


class OrbitHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        print(f'{self.address_string()} - {format_string % args}')

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get('Content-Length', '0'))
        return json.loads(self.rfile.read(length) or '{}')

    def session_id(self):
        parsed = cookies.SimpleCookie(self.headers.get('Cookie', ''))
        return parsed.get('orbit_session').value if parsed.get('orbit_session') else None

    def session_user(self):
        session_id = self.session_id()
        session = SESSIONS.get(session_id)
        if not session or session['expiresAt'] < datetime.now(timezone.utc).timestamp():
            if session_id:
                SESSIONS.pop(session_id, None)
            return None
        return next((user for user in read_users() if user['id'] == session['userId']), None)

    def session_cookie(self, session_id, max_age=SESSION_SECONDS):
        cookie = cookies.SimpleCookie()
        cookie['orbit_session'] = session_id
        cookie['orbit_session']['httponly'] = True
        cookie['orbit_session']['samesite'] = 'Lax'
        cookie['orbit_session']['path'] = '/'
        cookie['orbit_session']['max-age'] = max_age
        return cookie['orbit_session'].OutputString()

    def admin_cookie(self, session_id):
        cookie = cookies.SimpleCookie()
        cookie['studioverse_admin'] = session_id
        cookie['studioverse_admin']['httponly'] = True
        cookie['studioverse_admin']['samesite'] = 'Lax'
        cookie['studioverse_admin']['path'] = '/'
        cookie['studioverse_admin']['max-age'] = ADMIN_SESSION_SECONDS
        return cookie['studioverse_admin'].OutputString()

    def is_admin(self):
        parsed = cookies.SimpleCookie(self.headers.get('Cookie', ''))
        session_id = parsed.get('studioverse_admin').value if parsed.get('studioverse_admin') else None
        session = ADMIN_SESSIONS.get(session_id)
        if not session or session['expiresAt'] < datetime.now(timezone.utc).timestamp():
            if session_id:
                ADMIN_SESSIONS.pop(session_id, None)
            return False
        return True

    def create_session(self, user):
        session_id = secrets.token_hex(32)
        SESSIONS[session_id] = {'userId': user['id'], 'expiresAt': datetime.now(timezone.utc).timestamp() + SESSION_SECONDS}
        return self.session_cookie(session_id)

    def do_GET(self):
        route = urlparse(self.path).path
        if route.startswith('/api/'):
            return self.send_json(404, {'error': 'API route not found.'})
        if route == '/api/submissions':
            if not self.is_admin():
                return self.send_json(401, {'error': 'Admin access required.'})
            return self.send_json(200, read_submissions())
        if route == '/api/session':
            user = self.session_user()
            if not user:
                return self.send_json(401, {'authenticated': False})
            return self.send_json(200, {'authenticated': True, 'user': public_user(user)})
        if route == '/' or route == '/index.html':
            return self.serve_file(ROOT / 'index.html', 'text/html; charset=utf-8')
        if route == '/server.py':
            return self.send_json(404, {'error': 'Not found'})
        if route.startswith(('/data/', '/server.', '/package.json', '/.env')):
            return self.send_json(404, {'error': 'Not found'})
        requested_file = (ROOT / route.lstrip('/')).resolve()
        if ROOT in requested_file.parents and requested_file.is_file():
            content_type = mimetypes.guess_type(str(requested_file))[0] or 'application/octet-stream'
            return self.serve_file(requested_file, content_type)
        return self.serve_file(ROOT / 'index.html', 'text/html; charset=utf-8')

    def do_POST(self):
        route = urlparse(self.path).path
        if route == '/api/admin/session':
            try:
                password = str(self.read_json().get('password', ''))
            except (ValueError, json.JSONDecodeError):
                return self.send_json(400, {'error': 'Invalid request.'})
            supplied_hash = hashlib.sha256(password.encode()).hexdigest()
            if not hmac.compare_digest(supplied_hash, OWNER_HASH):
                return self.send_json(401, {'error': 'That passcode is not correct.'})
            session_id = secrets.token_hex(32)
            ADMIN_SESSIONS[session_id] = {'expiresAt': datetime.now(timezone.utc).timestamp() + ADMIN_SESSION_SECONDS}
            return self.send_json(204, {}, {'Set-Cookie': self.admin_cookie(session_id)})
        if route == '/api/submissions':
            try:
                payload = self.read_json()
            except (ValueError, json.JSONDecodeError):
                return self.send_json(400, {'error': 'Please send valid submission details.'})
            email = str(payload.get('email', '')).strip()
            discord = str(payload.get('discord', '')).strip()
            details = str(payload.get('details', '')).strip()
            paypal = str(payload.get('paypal', '')).strip()
            if (not email and not discord) or not details or not paypal or payload.get('termsAccepted') is not True:
                return self.send_json(400, {'error': 'Email or Discord, sale details, PayPal, and TOS agreement are required.'})
            submissions = read_submissions()
            submission = {'id': str(uuid.uuid4()), 'ticketNumber': max([int(item.get('ticketNumber', 0)) for item in submissions] + [0]) + 1, 'email': email, 'discord': discord, 'details': details, 'paypal': paypal, 'additionalInfo': str(payload.get('additionalInfo', '')).strip(), 'status': 'pending', 'createdAt': datetime.now(timezone.utc).isoformat()}
            write_submissions([submission] + submissions)
            return self.send_json(201, {'id': submission['id'], 'ticketNumber': submission['ticketNumber']})
        if route == '/api/auth/logout':
            session_id = self.session_id()
            if session_id:
                SESSIONS.pop(session_id, None)
            return self.send_json(204, {}, {'Set-Cookie': self.session_cookie('', 0)})
        if route not in ('/api/auth/signup', '/api/auth/login'):
            return self.send_json(404, {'error': 'Not found'})

        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {'error': 'Please send valid account details.'})
        username = payload.get('username', '')
        password = payload.get('password', '')
        if route.endswith('signup') and not valid_credentials(username, password):
            return self.send_json(400, {'error': 'Use a username with 3–24 letters, numbers, or underscores and a password with at least 8 characters.'})
        username = str(username).lower()
        users = read_users()
        user = next((candidate for candidate in users if candidate['username'] == username), None)
        if route.endswith('signup'):
            if user:
                return self.send_json(409, {'error': 'That username is already taken.'})
            salt, password_hash = hash_password(password)
            user = {'id': str(uuid.uuid4()), 'username': username, 'passwordSalt': salt, 'passwordHash': password_hash, 'createdAt': datetime.now(timezone.utc).isoformat()}
            write_users(users + [user])
            return self.send_json(201, {'user': public_user(user)}, {'Set-Cookie': self.create_session(user)})
        if not user or not password_matches(str(password), user):
            return self.send_json(401, {'error': 'Username or password is incorrect.'})
        return self.send_json(200, {'user': public_user(user)}, {'Set-Cookie': self.create_session(user)})

    def serve_file(self, file_path, content_type):
        try:
            body = file_path.read_bytes()
        except FileNotFoundError:
            return self.send_json(404, {'error': 'Not found'})

        def do_PATCH(self):
            route = urlparse(self.path).path
            if not route.startswith('/api/submissions/') or not self.is_admin():
                return self.send_json(401 if route.startswith('/api/submissions/') else 404, {'error': 'Admin access required.' if route.startswith('/api/submissions/') else 'Not found'})
            try:
                status = self.read_json().get('status')
            except (ValueError, json.JSONDecodeError):
                return self.send_json(400, {'error': 'Invalid status.'})
            if status not in ('pending', 'approved', 'rejected'):
                return self.send_json(400, {'error': 'Invalid submission status.'})
            submissions = read_submissions()
            submission_id = route.rsplit('/', 1)[-1]
            index = next((i for i, item in enumerate(submissions) if item['id'] == submission_id), None)
            if index is None:
                return self.send_json(404, {'error': 'Submission not found.'})
            submissions[index]['status'] = status
            submissions[index]['reviewedAt'] = datetime.now(timezone.utc).isoformat()
            write_submissions(submissions)
            return self.send_json(200, submissions[index])
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    ensure_store()
    server = ThreadingHTTPServer(('127.0.0.1', PORT), OrbitHandler)
    print(f'Orbit is running at http://localhost:{PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nOrbit stopped.')
    finally:
        server.server_close()
