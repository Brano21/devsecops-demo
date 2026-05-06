"""
DevSecOps demo — INTENTIONALLY VULNERABLE Flask application.

WARNING: This code contains deliberate security vulnerabilities for
educational purposes. DO NOT deploy to production. DO NOT run on a
public network.

Vulnerabilities included:
  1. SQL Injection         (in /login)
  2. Reflected XSS         (in /search)
  3. Command Injection     (in /ping)
  4. Hardcoded secret      (SECRET_KEY)
  5. Vulnerable dependency (Jinja2 2.10 - CVE-2019-10906, CVE-2020-28493)

Run locally:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template, redirect, url_for, g

app = Flask(__name__)

# VULNERABILITY 4: hardcoded secret in source code
# In real life this MUST come from an environment variable or a secret manager.
app.secret_key = "super-secret-do-not-commit-12345"

DB_PATH = "demo.db"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Set up a tiny in-memory user table."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS notes")
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )
        """
    )
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "alicepass", "user"),
            ("bob", "bobpass", "user"),
            ("admin", "supersecretadminpassword", "admin"),
        ],
    )
    cur.executemany(
        "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
        [
            ("alice", "Shopping list", "Milk, bread, eggs"),
            ("alice", "Vacation ideas", "Croatia, Greece, Slovakia"),
            ("bob", "Work TODOs", "Finish report, email manager"),
            ("admin", "Server password", "P@ssw0rd123!"),
        ],
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABILITY 1: SQL Injection.

    User input is concatenated directly into the SQL string.
    An attacker can bypass authentication with payloads such as:
        username:  admin' --
        password:  anything

    A safe version would use parameterised queries:
        cur.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # !!! VULNERABLE: string concatenation !!!
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        cur = get_db().cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as exc:
            return render_template("login.html", error=f"DB error: {exc}", query=query)

        if row:
            return render_template(
                "welcome.html",
                username=row["username"],
                role=row["role"],
                query=query,
            )
        error = "Invalid credentials"
        return render_template("login.html", error=error, query=query)

    return render_template("login.html", error=error, query=None)


@app.route("/search")
def search():
    """
    VULNERABILITY 2: Reflected Cross-Site Scripting (XSS).

    The query parameter `q` is rendered without escaping using the
    `|safe` filter in templates/search.html, so a payload like
        /search?q=<script>alert('XSS')</script>
    will execute in the victim's browser.

    A safe version simply removes `|safe` and lets Jinja auto-escape.
    """
    query = request.args.get("q", "")
    cur = get_db().cursor()
    cur.execute(
        "SELECT title, body FROM notes WHERE title LIKE ? OR body LIKE ?",
        (f"%{query}%", f"%{query}%"),
    )
    notes = cur.fetchall()
    return render_template("search.html", q=query, notes=notes)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """
    VULNERABILITY 3: Command Injection.

    The `host` parameter is interpolated into a shell command. Payloads:
        host:  127.0.0.1; cat /etc/passwd
        host:  127.0.0.1 && whoami

    A safe version uses subprocess with a list of arguments and shell=False:
        subprocess.run(["ping", "-c", "1", host], capture_output=True)
    """
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # !!! VULNERABLE: shell=True with user input !!!
        try:
            result = subprocess.run(
                f"ping -c 1 {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = "Timeout"
    return render_template("ping.html", host=host, output=output)


@app.route("/notes")
def notes():
    """List all public notes — also a privilege issue: shows admin's notes."""
    cur = get_db().cursor()
    cur.execute("SELECT owner, title, body FROM notes")
    return render_template("notes.html", notes=cur.fetchall())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # Debug=True is also a security smell — leaks the Werkzeug debugger.
    # Host defaults to 127.0.0.1 (safe) but can be overridden via FLASK_HOST
    # so the GitHub Actions runner can expose the app to the ZAP process.
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=True)
