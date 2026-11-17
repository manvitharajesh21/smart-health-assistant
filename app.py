from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATABASE = "healthcare.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not password:
            flash("Please fill in all fields.")
        elif password != confirm:
            flash("Passwords do not match.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (email, password) VALUES (?, ?)",
                    (email, generate_password_hash(password))
                )
                conn.commit()
                flash("Registration successful. Please log in.")
                conn.close()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("This email is already registered.")
            finally:
                conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")

@app.route("/health")
def health():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("health.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    return render_template("dashboard.html", email=session["email"])


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            expiry = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

            conn.execute(
                "INSERT INTO reset_tokens VALUES (?, ?, ?)",
                (token_hash, email, expiry)
            )
            conn.commit()

            # Local demonstration only: display the reset link.
            # A deployed application must email this link to the user.
            reset_link = url_for("reset_password", token=token, _external=True)
            conn.close()
            return render_template("forgot_password.html", reset_link=reset_link)

        conn.close()
        flash("If that account exists, a reset link would be sent.")

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = get_db()
    record = conn.execute(
        "SELECT * FROM reset_tokens WHERE token_hash = ?",
        (token_hash,)
    ).fetchone()

    if not record:
        conn.close()
        flash("Invalid or expired reset link.")
        return redirect(url_for("forgot_password"))

    expiry = datetime.fromisoformat(record["expires_at"])

    if datetime.now(timezone.utc) > expiry:
        conn.execute("DELETE FROM reset_tokens WHERE token_hash = ?", (token_hash,))
        conn.commit()
        conn.close()
        flash("Reset link expired. Please request another.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
        elif password != confirm:
            flash("Passwords do not match.")
        else:
            conn.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (generate_password_hash(password), record["email"])
            )
            conn.execute(
                "DELETE FROM reset_tokens WHERE email = ?",
                (record["email"],)
            )
            conn.commit()
            conn.close()
            flash("Password reset successful. Please log in.")
            return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)