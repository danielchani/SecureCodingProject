import re
import hmac as py_hmac
from markupsafe import escape
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, flash

import security_utils

app = Flask(__name__)
app.secret_key = "super_secret_key_for_session_management"

# ---------- DB ----------
def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="com_ltd",
        use_pure=True,
    )

# ---------- Validators ----------
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def require_login():
    if "user_id" not in session:
        flash("Please login first.", "warning")
        return False
    return True


# ---------- Admin / Utility ----------
@app.route("/reset_db")
def reset_db():
    # NOTE: keep this for demo, not for production
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("DELETE FROM password_history")
    cursor.execute("DELETE FROM clients")
    cursor.execute("DELETE FROM users")

    cursor.execute("ALTER TABLE users AUTO_INCREMENT = 1")
    cursor.execute("ALTER TABLE password_history AUTO_INCREMENT = 1")
    cursor.execute("ALTER TABLE clients AUTO_INCREMENT = 1")

    conn.commit()
    cursor.close()
    conn.close()

    session.clear()
    flash("Database reset successfully!", "success")
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ---------- Auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Secure registration:
    - validates username/email
    - validates password policy (from config.json via security_utils)
    - stores HMAC hash + salt
    - uses parameterized SQL
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(username):
            flash("Invalid username format.", "danger")
            return redirect(url_for("register"))

        if not EMAIL_RE.match(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for("register"))

        ok, msg = security_utils.validate_password(password)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for("register"))

        password_hash, salt = security_utils.hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, salt, login_attempts)
                VALUES (%s, %s, %s, %s, 0)
                """,
                (username, email, password_hash, salt),
            )
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except mysql.connector.Error as e:
            # likely duplicate username
            flash(f"Registration failed: {e}", "danger")
            return redirect(url_for("register"))
        finally:
            cursor.close()
            conn.close()

    return render_template("register.html")


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Secure login:
    - parameterized SQL
    - username validation
    - correct handling of (hash, salt) returned by security_utils.hash_password
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(username):
            flash("Invalid username format.", "danger")
            return redirect(url_for("login"))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        stored_salt = user["salt"]
        stored_hash = user["password_hash"]

        entered_hash, _ = security_utils.hash_password(password, stored_salt)

        # constant-time compare
        if py_hmac.compare_digest(entered_hash, stored_hash):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful!", "success")
            cursor.close()
            conn.close()
            return redirect(url_for("dashboard"))

        cursor.close()
        conn.close()
        flash("Incorrect password.", "danger")
        return redirect(url_for("login"))

    # ✅ Use existing template
    return render_template("login.html")


# ---------- Secure dashboard + clients (uses the SAME templates as vulnerable) ----------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    """
    Secure dashboard:
    - stores clients safely (prevents SQLi)
    - escapes fields before storing (prevents stored XSS even if template uses |safe)
    - uses existing dashboard.html
    """
    if not require_login():
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        client_name = request.form.get("client_name", "").strip()
        description = request.form.get("description", "").strip()
        website_url = request.form.get("website_url", "").strip()

        # minimal validation (optional)
        if len(client_name) == 0:
            flash("Client name is required.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for("dashboard"))

        # ✅ Escape BEFORE storing => kills stored XSS even if template renders unsafe
        client_name_s = str(escape(client_name))
        description_s = str(escape(description))
        website_url_s = str(escape(website_url))

        cursor.execute(
            """
            INSERT INTO clients (client_name, description, website_url)
            VALUES (%s, %s, %s)
            """,
            (client_name_s, description_s, website_url_s),
        )
        conn.commit()
        flash("Client added (secure).", "success")

    cursor.execute("SELECT * FROM clients ORDER BY id DESC")
    clients = cursor.fetchall()

    cursor.close()
    conn.close()

    # ✅ Use existing template
    return render_template("dashboard.html", clients=clients)


@app.route("/delete_client/<int:client_id>", methods=["POST"])
def delete_client(client_id: int):
    """
    Secure delete:
    - parameterized SQL
    """
    if not require_login():
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("DELETE FROM clients WHERE id = %s", (client_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Client deleted (secure).", "info")
    return redirect(url_for("dashboard"))


# ---------- Secure search (reflected XSS protection) ----------
@app.route("/search", methods=["GET"])
def search():
    """
    Secure search:
    - reflected XSS: pass escaped query to template
    - uses existing search_results_secure.html
    """
    if not require_login():
        return redirect(url_for("login"))

    q = request.args.get("q", "")
    q_safe = str(escape(q))
    return render_template("search_results_secure.html", query=q_safe)


# ---------- Password reset + change password (secure + existing templates) ----------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    """
    Demo reset flow (still demo-level because no email sending):
    - generates token
    - stores in session
    """
    if request.method == "POST":
        token = security_utils.generate_reset_token()
        session["reset_token"] = token
        flash("Reset token generated. Check server console / demo flow.", "info")
        # In real world: email token link
        print(f"[SECURE DEMO] Reset Token: {token}")
        return redirect(url_for("reset_password_verify"))

    return render_template("forgot_password.html")


@app.route("/reset_verify", methods=["GET", "POST"])
def reset_password_verify():
    if request.method == "POST":
        user_token = request.form.get("token", "")
        stored = session.get("reset_token", "")

        # constant-time compare
        if stored and py_hmac.compare_digest(user_token, stored):
            session["reset_verified"] = True
            flash("Token verified.", "success")
            return redirect(url_for("change_password"))

        flash("Invalid token.", "danger")

    return render_template("verify_token.html")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    Secure password change:
    - requires login OR verified reset token
    - validates password policy
    - prevents reuse of last 3 passwords
    - parameterized SQL
    """
    can_change = ("user_id" in session) or session.get("reset_verified", False)
    if not can_change:
        flash("You must be logged in or verify reset token first.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        old_pass = request.form.get("old_password", "")
        new_pass = request.form.get("new_password", "")

        # If user isn't logged in (token flow), we can't know which user—so require login in this demo.
        if "user_id" not in session:
            flash("For this demo, please login to change password.", "warning")
            return redirect(url_for("login"))

        user_id = session["user_id"]

        ok, msg = security_utils.validate_password(new_pass)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for("change_password"))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        # verify old password
        old_hash, _ = security_utils.hash_password(old_pass, user["salt"])
        if not py_hmac.compare_digest(old_hash, user["password_hash"]):
            cursor.close()
            conn.close()
            flash("Old password incorrect.", "danger")
            return redirect(url_for("change_password"))

        # compute new hash (keep existing salt for compatibility with your current design)
        new_hash, _ = security_utils.hash_password(new_pass, user["salt"])

        # prevent reuse of last 3
        cursor.execute(
            """
            SELECT password_hash FROM password_history
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT 3
            """,
            (user_id,),
        )
        history = cursor.fetchall()
        for row in history:
            if py_hmac.compare_digest(row["password_hash"], new_hash):
                cursor.close()
                conn.close()
                flash("Cannot reuse one of the last 3 passwords.", "danger")
                return redirect(url_for("change_password"))

        # store current hash in history, then update
        cursor.execute(
            "INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)",
            (user_id, user["password_hash"]),
        )
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_hash, user_id),
        )

        conn.commit()
        cursor.close()
        conn.close()

        # clear reset flow if any
        session.pop("reset_verified", None)
        session.pop("reset_token", None)

        flash("Password changed successfully (secure).", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


if __name__ == "__main__":
    app.run(debug=True, port=5001)
