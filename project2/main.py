import os
import secrets
import sqlite3
from pathlib import Path
from uuid import uuid4
from functools import wraps

from flask import Flask, g, request, session, redirect, url_for, render_template, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATA = Path(os.environ.get("FLASK_DATA_DIR", "/var/www/html/flaskapp"))
DATA.mkdir(parents=True, exist_ok=True)
UPLOADS = DATA / "uploads"
UPLOADS.mkdir(exist_ok=True)
keyfile = DATA / "secret.key"
try:
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    pass
else:
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32))
app.config.update(SECRET_KEY=keyfile.read_text().strip(), DATABASE=str(DATA / "users.db"),
                  MAX_CONTENT_LENGTH=10 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY") == "1")
if not app.secret_key:
    raise RuntimeError("secret.key is empty")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


with app.app_context():
    get_db().execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
        first_name TEXT NOT NULL, last_name TEXT NOT NULL,
        email TEXT NOT NULL, address TEXT NOT NULL,
        file_original_name TEXT, file_storage_name TEXT UNIQUE,
        word_count INTEGER CHECK(word_count >= 0),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    get_db().execute("""CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        original_name TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE,
        word_count INTEGER NOT NULL CHECK(word_count >= 0),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    get_db().execute("CREATE INDEX IF NOT EXISTS uploads_user ON uploads(user_id)")
    # Preserve earlier single-file records. Repeated startup does not duplicate them.
    get_db().execute("""INSERT OR IGNORE INTO uploads
        (user_id, original_name, storage_name, word_count)
        SELECT id, COALESCE(file_original_name, 'upload.txt'), file_storage_name,
               COALESCE(word_count, 0)
        FROM users WHERE file_storage_name IS NOT NULL""")
    get_db().commit()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def load_user_and_check_csrf():
    g.user = None
    if "user_id" in session:
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if request.method == "POST":
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(expected, request.form.get("csrf", "")):
            abort(400, "Invalid form token. Reload the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    if g.user is None:
        return render_template("landing.html")
    files = get_db().execute("SELECT * FROM uploads WHERE user_id=? ORDER BY id DESC",
                             (g.user["id"],)).fetchall()
    return render_template("dashboard.html", user=g.user, files=files)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        names = ("username", "first_name", "last_name", "email", "address")
        values = {name: request.form.get(name, "").strip() for name in names}
        password = request.form.get("password", "")
        error = None
        if any(not value or len(value) > 500 for value in values.values()):
            error = "Complete every field (maximum 500 characters each)."
        elif not 8 <= len(password) <= 128:
            error = "Use a password with 8 to 128 characters."
        elif "@" not in values["email"]:
            error = "Enter a valid email address."
        if error:
            flash(error)
        else:
            db = get_db()
            try:
                cursor = db.execute("""INSERT INTO users
                    (username,password_hash,first_name,last_name,email,address)
                    VALUES (?,?,?,?,?,?)""",
                    (values["username"], generate_password_hash(password), values["first_name"],
                     values["last_name"], values["email"], values["address"]))
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That username is already registered.")
            else:
                session.clear()
                session["user_id"] = cursor.lastrowid
                return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE username=?", (request.form.get("username", "").strip(),)).fetchone()
        password = request.form.get("password", "")
        if len(password) <= 128 and user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/profile")
@login_required
def profile():
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    incoming = [f for f in request.files.getlist("files") if f.filename]
    if not 1 <= len(incoming) <= 10:
        flash("Choose 1 to 10 text files.")
        return redirect(url_for("index"))
    prepared = []
    for f in incoming:
        original = f.filename.replace(chr(92), "/").rsplit("/", 1)[-1]
        if not original.lower().endswith(".txt"):
            flash("Only .txt files are accepted. No files were saved.")
            return redirect(url_for("index"))
        content = f.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            flash("Each file must be at most 2 MiB. No files were saved.")
            return redirect(url_for("index"))
        try:
            words = len(content.decode("utf-8-sig").split())
        except UnicodeDecodeError:
            flash("Use UTF-8 text files. No files were saved.")
            return redirect(url_for("index"))
        prepared.append((original, uuid4().hex + ".txt", words, content))
    written = []
    db = get_db()
    try:
        for original, stored, words, content in prepared:
            path = UPLOADS / stored
            written.append(path)
            path.write_bytes(content)
            db.execute("INSERT INTO uploads (user_id,original_name,storage_name,word_count) VALUES (?,?,?,?)",
                       (g.user["id"], original, stored, words))
        db.commit()
    except Exception:
        db.rollback()
        for path in written:
            path.unlink(missing_ok=True)
        raise
    flash(f"Uploaded {len(prepared)} file(s).")
    return redirect(url_for("index"))


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    record = get_db().execute("SELECT * FROM uploads WHERE id=? AND user_id=?",
                             (file_id, g.user["id"])).fetchone()
    if record is None:
        abort(404)
    stored = record["storage_name"]
    if Path(stored).name != stored:
        abort(404)
    path = UPLOADS / stored
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=record["original_name"], mimetype="text/plain")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(413)
def too_large(error):
    return "Upload too large. Keep the entire form under 10 MiB.", 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
