import os
import base64
import secrets
import sqlite3
import string
import hashlib

from flask import (
    Flask, request, session, redirect,
    render_template_string, jsonify
)
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vault.db")
SALT_PATH = os.path.join(BASE_DIR, "vault.salt")
HASH_PATH = os.path.join(BASE_DIR, "vault.hash")

# ---------- DATABASE ----------

def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted TEXT NOT NULL
        )
    """)
    return con

def make_key(master, salt):
    key = hashlib.pbkdf2_hmac(
        "sha256", master.encode(), salt, 600000, dklen=32
    )
    return base64.urlsafe_b64encode(key)

def cipher():
    key = session.get("vault_key")
    if not key:
        return None
    return Fernet(key.encode())

def vault_exists():
    return all(os.path.exists(p) for p in (SALT_PATH, HASH_PATH))

def unlock(master):
    if not vault_exists():
        salt = secrets.token_bytes(16)
        with open(SALT_PATH, "wb") as f:
            f.write(salt)
        with open(HASH_PATH, "w") as f:
            f.write(generate_password_hash(master))
    else:
        with open(SALT_PATH, "rb") as f:
            salt = f.read()
        with open(HASH_PATH) as f:
            saved_hash = f.read()
        if not check_password_hash(saved_hash, master):
            return False

    session.clear()
    session["vault_key"] = make_key(master, salt).decode()
    return True

# ---------- HTML + CSS IN ONE FILE ----------

PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VaultX — Password Manager</title>
<style>
:root {
    --bg:#0b1020; --panel:#121b2e; --card:#18243a;
    --border:#2a3852; --text:#edf2ff; --muted:#91a0bb;
    --accent:#8b7cff; --green:#57d6a0; --red:#ff7185;
}
* {box-sizing:border-box}
body {
    margin:0;background:var(--bg);color:var(--text);
    font-family:Inter,system-ui,Arial,sans-serif;
}
button,input {font:inherit}
button {cursor:pointer}
.topbar {
    padding:17px 5%;display:flex;justify-content:space-between;
    align-items:center;border-bottom:1px solid var(--border);
    background:#0e1628;gap:12px;
}
.logo {font-size:22px;font-weight:800;letter-spacing:-1px}
.logo span {color:var(--accent)}
.wrap {max-width:1050px;margin:auto;padding:34px 20px}
.eyebrow {
    color:var(--accent);font-size:11px;font-weight:800;
    letter-spacing:2px;margin-bottom:10px
}
h1 {font-size:clamp(26px,5vw,38px);margin:0 0 8px;letter-spacing:-1px}
h2 {font-size:19px;margin:0 0 6px}
p {line-height:1.6}
.muted {color:var(--muted);font-size:13px}
.panel {
    background:var(--panel);border:1px solid var(--border);
    border-radius:18px;padding:22px;margin:22px 0
}
.stats {display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-top:25px}
.stat {
    background:var(--panel);border:1px solid var(--border);
    padding:19px;border-radius:15px
}
.stat strong {display:block;font-size:28px;margin-top:8px}
.row {display:flex;gap:10px;align-items:center}
input {
    width:100%;min-width:0;background:#0c1425;color:var(--text);
    border:1px solid var(--border);padding:12px;border-radius:10px;
    outline:none;margin:5px 0 13px
}
input:focus {border-color:var(--accent)}
label {font-size:12px;font-weight:700}
.btn {
    padding:11px 15px;border:1px solid var(--border);
    background:#22314c;color:white;border-radius:10px;font-weight:650
}
.btn:hover {filter:brightness(1.18)}
.primary {background:var(--accent);border-color:var(--accent)}
.danger {background:#401f31;color:#ffb5c1}
.full {width:100%}
.search {display:flex;gap:8px;margin:20px 0}
.search input {margin:0}
.cards {display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}
.account {
    background:var(--card);border:1px solid var(--border);
    padding:17px;border-radius:14px;min-width:0
}
.account h3 {overflow-wrap:anywhere;margin:0 0 3px;font-size:16px}
.account .username {overflow-wrap:anywhere;color:var(--muted);font-size:12px}
.pill {font-size:10px;color:var(--green);background:#183a33;padding:5px 8px;border-radius:20px}
.secret {display:flex;gap:7px;margin:15px 0}
.secret input {margin:0;font-family:monospace}
.actions {display:flex;gap:7px;flex-wrap:wrap}
.actions .btn {font-size:12px;padding:9px 10px}
.edit {margin-top:14px;border-top:1px solid var(--border);padding-top:12px}
.edit summary {color:#c0b7ff;cursor:pointer;font-size:13px}
.notice {padding:12px;background:#1c2941;border:1px solid var(--border);border-radius:10px;margin:15px 0}
.auth {max-width:440px;margin:8vh auto;padding:22px}
.authbox {background:var(--panel);padding:30px;border:1px solid var(--border);border-radius:20px}
.footer {text-align:center;color:var(--muted);font-size:12px;padding:25px}
@media(max-width:650px) {
    .wrap {padding:25px 13px}
    .panel {padding:16px}
    .cards {grid-template-columns:1fr}
    .stats {gap:9px}
    .stat {padding:14px}
    .topbar {padding:14px}
    .logo {font-size:19px}
    .secret {flex-wrap:wrap}
    .secret input {flex-basis:100%}
    .authbox {padding:22px}
}
</style>
</head>
<body>

{% if not session.get('vault_key') %}
<div class="auth">
    <div class="authbox">
        <div class="logo">◆ Vault<span>X</span></div>
        <p class="eyebrow" style="margin-top:28px">YOUR PRIVATE VAULT</p>
        <h1>{{ 'Create your vault' if not exists else 'Welcome back' }}</h1>
        <p class="muted">
            {{ 'Create a strong master password to begin.' if not exists
               else 'Enter your master password to unlock your accounts.' }}
        </p>
        {% if error %}<div class="notice">{{ error }}</div>{% endif %}
        <form method="post" action="/unlock">
            <input type="hidden" name="csrf" value="{{ csrf }}">
            <label>Master password</label>
            <input type="password" name="master" minlength="12"
                   placeholder="At least 12 characters" required autofocus>
            {% if not exists %}
            <label>Confirm master password</label>
            <input type="password" name="confirm" minlength="12"
                   placeholder="Enter it again" required>
            {% endif %}
            <button class="btn primary full" type="submit">
                {{ 'Create secure vault' if not exists else 'Unlock vault' }}
            </button>
        </form>
        <p class="muted">Never share your master password.</p>
    </div>
</div>

{% else %}
<header class="topbar">
    <div class="logo">◆ Vault<span>X</span></div>
    <form method="post" action="/lock">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button class="btn" type="submit">Lock vault ↗</button>
    </form>
</header>

<main class="wrap">
    <p class="eyebrow">PERSONAL SECURITY</p>
    <h1>Your password vault.</h1>
    <p class="muted">All your accounts, organised in one place.</p>

    <div class="stats">
        <div class="stat"><span class="muted">Saved accounts</span>
            <strong>{{ entries|length }}</strong></div>
        <div class="stat"><span class="muted">Vault status</span>
            <strong style="color:var(--green);font-size:22px">● Protected</strong></div>
    </div>

    {% if message %}<div class="notice">{{ message }}</div>{% endif %}

    <section class="panel">
        <h2>Saved accounts</h2>
        <p class="muted">Search by website or username.</p>
        <form class="search" method="get">
            <input name="q" value="{{ q }}" placeholder="Search accounts...">
            <button class="btn" type="submit">Search</button>
        </form>

        {% if entries %}
        <div class="cards">
        {% for e in entries %}
            <article class="account">
                <div class="row" style="justify-content:space-between">
                    <div style="min-width:0">
                        <h3>{{ e.website }}</h3>
                        <div class="username">{{ e.username }}</div>
                    </div>
                    <span class="pill">ENCRYPTED</span>
                </div>

                <div class="secret">
                    <input id="pw{{ e.id }}" type="password" value="••••••••••"
                           readonly autocomplete="off">
                    <button class="btn" type="button"
                            onclick="reveal({{ e.id }},this)">Show</button>
                    <button class="btn" type="button"
                            onclick="copyPw({{ e.id }})">Copy</button>
                </div>

                <div class="actions">
                    <button class="btn" type="button"
                            onclick="editBox({{ e.id }})">Edit</button>
                    <form method="post" action="/delete/{{ e.id }}"
                          onsubmit="return confirm('Delete this account?')">
                        <input type="hidden" name="csrf" value="{{ csrf }}">
                        <button class="btn danger" type="submit">Delete</button>
                    </form>
                </div>

                <details class="edit" id="edit{{ e.id }}">
                    <summary>Edit account details</summary>
                    <form method="post" action="/edit/{{ e.id }}">
                        <input type="hidden" name="csrf" value="{{ csrf }}">
                        <label>Website</label>
                        <input name="website" value="{{ e.website }}" maxlength="150" required>
                        <label>Username</label>
                        <input name="username" value="{{ e.username }}" maxlength="150" required>
                        <label>New password (leave blank to keep current)</label>
                        <input name="password" type="password" autocomplete="new-password">
                        <button class="btn primary" type="submit">Save changes</button>
                    </form>
                </details>
            </article>
        {% endfor %}
        </div>
        {% else %}
        <div class="notice">No accounts found. Add one below.</div>
        {% endif %}
    </section>

    <section class="panel">
        <h2>Add a new account</h2>
        <p class="muted">Your password is encrypted before saving.</p>
        <form method="post" action="/add">
            <input type="hidden" name="csrf" value="{{ csrf }}">
            <label>Website or app</label>
            <input name="website" maxlength="150" placeholder="e.g. Google" required>
            <label>Username or email</label>
            <input name="username" maxlength="150" placeholder="you@example.com" required>
            <label>Password</label>
            <div class="row">
                <input id="newpw" name="password" type="password"
                       maxlength="1000" placeholder="Enter a password" required>
                <button class="btn" type="button"
                        onclick="toggleNew()">Show</button>
            </div>
            <div class="row" style="margin-bottom:12px">
                <button class="btn" type="button" onclick="generate()">Generate password</button>
                <span class="muted" id="genmsg"></span>
            </div>
            <button class="btn primary full" type="submit">+ Save account</button>
        </form>
    </section>
</main>
<div class="footer">VaultX · Local learning project</div>

<script>
async function reveal(id, button) {
    const input = document.getElementById('pw' + id);
    if (input.dataset.loaded === 'yes') {
        input.type = input.type === 'password' ? 'text' : 'password';
        button.textContent = input.type === 'password' ? 'Show' : 'Hide';
        return;
    }
    try {
        const r = await fetch('/secret/' + id, {cache:'no-store'});
        if (!r.ok) throw Error();
        const data = await r.json();
        input.value = data.password;
        input.dataset.loaded = 'yes';
        input.type = 'text';
        button.textContent = 'Hide';
    } catch {
        alert('Could not retrieve password.');
    }
}
async function copyPw(id) {
    try {
        const r = await fetch('/secret/' + id, {cache:'no-store'});
        if (!r.ok) throw Error();
        const data = await r.json();
        await navigator.clipboard.writeText(data.password);
        alert('Password copied.');
    } catch {
        alert('Copy failed. Use localhost and allow clipboard access.');
    }
}
function editBox(id) {
    const box = document.getElementById('edit' + id);
    box.open = !box.open;
}
function toggleNew() {
    const input = document.getElementById('newpw');
    input.type = input.type === 'password' ? 'text' : 'password';
}
async function generate() {
    try {
        const r = await fetch('/generate', {cache:'no-store'});
        const data = await r.json();
        if (!r.ok) throw Error();
        document.getElementById('newpw').value = data.password;
        document.getElementById('genmsg').textContent = 'Generated';
    } catch {
        alert('Password generation failed.');
    }
}
</script>
{% endif %}
</body>
</html>
"""

def render_page(message="", error=""):
    con = connect()
    entries = []
    q = request.args.get("q", "").strip()[:100]

    if session.get("vault_key"):
        rows = con.execute(
            "SELECT id, website, username FROM passwords ORDER BY website"
        ).fetchall()
        entries = [
            dict(r) for r in rows
            if q.lower() in r["website"].lower()
            or q.lower() in r["username"].lower()
        ]

    con.close()
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(24)
        session["csrf"] = token

    return render_template_string(
        PAGE, entries=entries, q=q, message=message, error=error,
        exists=vault_exists(), csrf=token
    )

def check_csrf():
    return secrets.compare_digest(
        session.get("csrf", ""),
        request.form.get("csrf", "")
    )

@app.route("/")
def home():
    return render_page()

@app.route("/unlock", methods=["POST"])
def do_unlock():
    if not check_csrf():
        return "Invalid request", 400

    master = request.form.get("master", "")
    if len(master) < 12:
        return render_page(error="Master password must be at least 12 characters.")

    if not vault_exists() and master != request.form.get("confirm", ""):
        return render_page(error="Master passwords do not match.")

    if unlock(master):
        return redirect("/")
    return render_page(error="Incorrect master password.")

@app.route("/lock", methods=["POST"])
def lock():
    if not check_csrf():
        return "Invalid request", 400
    session.clear()
    return redirect("/")

@app.route("/add", methods=["POST"])
def add():
    if not check_csrf() or not cipher():
        return "Session expired or invalid request", 403

    website = request.form.get("website", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not website or not username or not password:
        return render_page(message="All fields are required.")
    if len(website) > 150 or len(username) > 150 or len(password) > 1000:
        return render_page(message="One of the fields is too long.")

    encrypted = cipher().encrypt(password.encode()).decode()
    con = connect()
    con.execute(
        "INSERT INTO passwords(website,username,encrypted) VALUES(?,?,?)",
        (website, username, encrypted)
    )
    con.commit()
    con.close()
    return redirect("/")

@app.route("/edit/<int:item_id>", methods=["POST"])
def edit(item_id):
    if not check_csrf() or not cipher():
        return "Session expired or invalid request", 403

    website = request.form.get("website", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not website or not username or len(website) > 150 or len(username) > 150:
        return render_page(message="Invalid website or username.")

    con = connect()
    if password:
        if len(password) > 1000:
            con.close()
            return render_page(message="Password is too long.")
        encrypted = cipher().encrypt(password.encode()).decode()
        con.execute(
            "UPDATE passwords SET website=?,username=?,encrypted=? WHERE id=?",
            (website, username, encrypted, item_id)
        )
    else:
        con.execute(
            "UPDATE passwords SET website=?,username=? WHERE id=?",
            (website, username, item_id)
        )
    con.commit()
    con.close()
    return redirect("/")

@app.route("/delete/<int:item_id>", methods=["POST"])
def delete(item_id):
    if not check_csrf() or not cipher():
        return "Session expired or invalid request", 403

    con = connect()
    con.execute("DELETE FROM passwords WHERE id=?", (item_id,))
    con.commit()
    con.close()
    return redirect("/")

@app.route("/secret/<int:item_id>")
def secret(item_id):
    c = cipher()
    if not c:
        return jsonify(error="Vault locked"), 401

    con = connect()
    row = con.execute(
        "SELECT encrypted FROM passwords WHERE id=?", (item_id,)
    ).fetchone()
    con.close()

    if not row:
        return jsonify(error="Not found"), 404

    try:
        password = c.decrypt(row["encrypted"].encode()).decode()
    except Exception:
        return jsonify(error="Decryption failed"), 400

    response = jsonify(password=password)
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/generate")
def generate():
    if not cipher():
        return jsonify(error="Vault locked"), 401

    groups = [
        string.ascii_lowercase, string.ascii_uppercase,
        string.digits, "!@#$%^&*()-_=+"
    ]
    chars = [secrets.choice(g) for g in groups]
    all_chars = "".join(groups)
    chars.extend(secrets.choice(all_chars) for _ in range(16))
    secrets.SystemRandom().shuffle(chars)
    return jsonify(password="".join(chars))

if __name__ == "__main__":
    # Local machine only; don't expose this development server publicly.
    app.run(host="127.0.0.1", port=5000, debug=False)
