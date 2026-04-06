import os
import hashlib
import sqlite3
import zipfile
import shutil
import socket
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import flask
from werkzeug.utils import secure_filename
from typing import Optional

app = flask.Flask(__name__)
app.secret_key = "dev-secret-change-me"

BASE_DIR = Path(__file__).resolve().parent
_db_env = os.environ.get("DB_PATH")
if _db_env:
    _candidate = Path(_db_env)
    DB_PATH = _candidate if _candidate.is_absolute() else (BASE_DIR / _candidate)
else:
    DB_PATH = BASE_DIR / "app.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = BASE_DIR / "uploads"
PLUGIN_DIR = BASE_DIR / "plugins"
AVATAR_DIR = BASE_DIR / "static" / "uploads" / "avatars"

UPLOAD_DIR.mkdir(exist_ok=True)
PLUGIN_DIR.mkdir(exist_ok=True)
AVATAR_DIR.mkdir(parents=True, exist_ok=True)


def sniff_image_type(data: bytes) -> Optional[str]:
    if not data:
        return None

    # PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    # JPEG
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    # GIF
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    # WebP (RIFF....WEBP)
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          about TEXT DEFAULT '',
          avatar_local TEXT DEFAULT '',
          avatar_url TEXT DEFAULT ''
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL,
          content TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
        """
    )
    cur.execute("INSERT OR IGNORE INTO users(username) VALUES (?)", ("admin",))
    conn.commit()
    conn.close()


@app.before_request
def _boot():
    if not getattr(app, "_db_inited", False):
        init_db()
        app._db_inited = True


def is_logged_in() -> bool:
    return flask.request.cookies.get("visited") == "yes" and bool(flask.request.cookies.get("user"))


def login_required(view):
    def wrapped(*args, **kwargs):
        if not is_logged_in():
            next_url = flask.request.full_path if flask.request.query_string else flask.request.path
            return flask.redirect(flask.url_for("login", next=next_url))
        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__
    return wrapped


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> list[str]:
    dest_dir = dest_dir.resolve()
    extracted = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")

            if name.endswith("/"):
                continue

            if name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
                raise ValueError("Illegal path in zip")

            target = (dest_dir / name).resolve()
            if os.path.commonpath([str(dest_dir), str(target)]) != str(dest_dir):
                raise ValueError("ZipSlip blocked")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)

            extracted.append(str(target.relative_to(dest_dir)))

    return extracted



def safe_upload(zip_path: Path, dest_dir: Path) -> list[str]:
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            target = os.path.join(dest_dir, info.filename)  
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'wb') as f:
                    f.write(z.read(info.filename))  


def _host_is_public(hostname: str) -> bool:
    lowered = (hostname or "").lower()
    if lowered in {"localhost", "localhost.localdomain"}:
        return False

    try:
        addrinfos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False

    ips = {ai[4][0] for ai in addrinfos if ai and ai[4]}
    if not ips:
        return False

    for ip_str in ips:
        ip_obj = ipaddress.ip_address(ip_str)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        ):
            return False

    return True


def fetch_remote_avatar_info(url: str):
    if not url:
        return None

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None

    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "question-app/1.0"})
    

    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            content = resp.read()
            return {
                "content_snippet": content,
                "status": getattr(resp, "status", None),
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": resp.headers.get("Content-Length", ""),
            }
    except Exception:
        return None


@app.route('/')
def home():
    if is_logged_in():
        return flask.redirect(flask.url_for("dashboard"))
    return flask.redirect(flask.url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return flask.render_template("dashboard.html", user=flask.request.cookies.get("user"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        username = flask.request.form.get('username', '')
        password = flask.request.form.get('password', '')

        h1 = hashlib.md5(password.encode('utf-8')).hexdigest()
        h2 = hashlib.md5(h1.encode('utf-8')).hexdigest()
        next_url = flask.request.args.get("next") or flask.url_for("dashboard")

        if username == 'admin' and h2 == "7022cd14c42ff272619d6beacdc9ffde":
            resp = flask.make_response(flask.redirect(next_url))
            resp.set_cookie('visited', 'yes', httponly=True, samesite='Lax')
            resp.set_cookie('user', username, httponly=True, samesite='Lax')
            return resp

        return flask.render_template('login.html', error='用户名或密码错误', username=username), 401

    return flask.render_template('login.html', error=None, username='')


@app.route('/logout')
def logout():
    resp = flask.make_response(flask.redirect('/login'))
    resp.set_cookie('visited', '', expires=0)
    resp.set_cookie('user', '', expires=0)
    return resp

@app.route('/plugin/upload', methods=['GET', 'POST'])
@login_required
def upload_plugin():
    if flask.request.method == 'GET':
        return flask.render_template('plugin_upload.html', error=None, ok=None, files=None)

    file = flask.request.files.get('plugin')
    if not file or not file.filename:
        return flask.render_template('plugin_upload.html', error='请选择一个 zip 文件', ok=None, files=None), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.zip'):
        return flask.render_template('plugin_upload.html', error='仅支持 .zip 文件', ok=None, files=None), 400

    saved = UPLOAD_DIR / f"{uuid4().hex}-{filename}"
    file.save(saved)

    dest = PLUGIN_DIR / f"{Path(filename).stem}-{uuid4().hex[:8]}"
    dest.mkdir(parents=True, exist_ok=True)

    try:
        print(saved, dest)
        extracted = safe_upload(saved, dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        return flask.render_template('plugin_upload.html', error='解压失败：压缩包内容不合法', ok=None, files=None), 400

    return flask.render_template('plugin_upload.html', error=None, ok='上传并解压成功', files=extracted)



@app.route('/board', methods=['GET', 'POST'])
@login_required
def board():
    user = flask.request.cookies.get('user')

    if flask.request.method == 'POST':
        content = (flask.request.form.get('content') or '').strip()
        if content:
            conn = db()
            conn.execute(
                'INSERT INTO messages(username, content, created_at) VALUES (?,?,?)',
                (user, content, datetime.utcnow().isoformat(timespec='seconds') + 'Z'),
            )
            conn.commit()
            conn.close()
        return flask.redirect(flask.url_for('board'))

    conn = db()
    rows = conn.execute('SELECT * FROM messages ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return flask.render_template('board.html', user=user, messages=rows)


@app.route('/about', methods=['GET', 'POST'])
@login_required
def about():
    user = flask.request.cookies.get('user')

    conn = db()
    current = conn.execute('SELECT * FROM users WHERE username=?', (user,)).fetchone()
    about_text = current['about'] if current else ''
    avatar_local = current['avatar_local'] if current else ''
    avatar_url = current['avatar_url'] if current else ''

    if flask.request.method == 'POST':
        about_text = flask.request.form.get('about', '')
        avatar_url = flask.request.form.get('avatar_url', '')

        upload = flask.request.files.get('avatar_file')
        if upload and upload.filename:
            raw = upload.read()
            upload.seek(0)
            kind = sniff_image_type(raw)
            if kind not in {'png', 'jpeg', 'gif', 'webp'}:
                conn.close()
                return (
                    flask.render_template(
                        'about.html',
                        user=user,
                        about=about_text,
                        avatar_local=avatar_local,
                        avatar_url=avatar_url,
                        remote_info=fetch_remote_avatar_info(avatar_url),
                        error='头像文件必须是图片（png/jpg/gif/webp）',
                    ),
                    400,
                )

            fname = f"{uuid4().hex}.{ 'jpg' if kind == 'jpeg' else kind }"
            path = AVATAR_DIR / fname
            with open(path, 'wb') as f:
                f.write(raw)
            avatar_local = f"uploads/avatars/{fname}"

        conn.execute(
            'UPDATE users SET about=?, avatar_local=?, avatar_url=? WHERE username=?',
            (about_text, avatar_local, avatar_url, user),
        )
        conn.commit()

        current = conn.execute('SELECT * FROM users WHERE username=?', (user,)).fetchone()
        conn.close()

        return flask.render_template(
            'about.html',
            user=user,
            about=current['about'],
            avatar_local=current['avatar_local'],
            avatar_url=current['avatar_url'],
            remote_info=fetch_remote_avatar_info(current['avatar_url']),
            error=None,
        )

    conn.close()
    return flask.render_template(
        'about.html',
        user=user,
        about=about_text,
        avatar_local=avatar_local,
        avatar_url=avatar_url,
        remote_info=fetch_remote_avatar_info(avatar_url),
        error=None,
    )

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)
