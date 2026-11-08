from encryption import encrypt_text, decrypt_text
from flask import Flask, request, jsonify,render_template
import bcrypt
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from database import get_db_connection, init_db


app = Flask(__name__)

# Initialize database
init_db()


# ==========================================
# SESSION VALIDATION FUNCTION
# ==========================================

def get_authenticated_user(conn):

    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    session_token = auth_header.split(" ", 1)[1].strip()

    if not session_token:
        return None

    token_hash = hashlib.sha256(
        session_token.encode("utf-8")
    ).hexdigest()

    session = conn.execute(
        """
        SELECT
            sessions.id AS session_id,
            sessions.expires_at,
            users.id,
            users.username,
            users.role
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE sessions.token_hash = ?
        """,
        (token_hash,)
    ).fetchone()

    if session is None:
        return None

    expiry = datetime.fromisoformat(session["expires_at"])

    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) >= expiry:

        conn.execute(
            "DELETE FROM sessions WHERE id = ?",
            (session["session_id"],)
        )

        conn.commit()
        return None

    return session

# ==========================================
# LOGIN WEBPAGE
# ==========================================



@app.route('/login-page')
def login_page():
    return render_template('login.html')


@app.route('/register-page')
def register_page():
    return render_template('register.html')

# ==========================================
# DASHBOARD AND RECORDS PAGE ROUTES
# ==========================================

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')


@app.route('/records-page')
def records_page():
    return render_template('records.html')

# ==========================================
# HOME API
# ==========================================

@app.route("/")
def home():

    return jsonify({
        "message": "Nestack Secure Records API is Running!"
    })


# ==========================================
# USER REGISTRATION API
# ==========================================

@app.route("/register", methods=["POST"])
def register():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON input"}), 400

    # Users cannot assign their own roles
    if "role" in data:
        return jsonify({
            "error": "Role assignment is not allowed"
        }), 403

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({
            "error": "Invalid username or password"
        }), 400

    username = username.strip()

    if not 3 <= len(username) <= 30:
        return jsonify({
            "error": "Username must be 3-30 characters"
        }), 400

    if len(password) < 8 or len(password.encode("utf-8")) > 72:
        return jsonify({
            "error": "Password must be at least 8 characters and at most 72 bytes"
        }), 400

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    conn = None

    try:

        conn = get_db_connection()

        conn.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (
                username,
                password_hash.decode("utf-8"),
                "user"
            )
        )

        conn.commit()

        return jsonify({
            "message": "User registered successfully"
        }), 201

    except sqlite3.IntegrityError:

        if conn:
            conn.rollback()

        return jsonify({
            "error": "Username already exists"
        }), 409

    except sqlite3.OperationalError:

        if conn:
            conn.rollback()

        return jsonify({
            "error": "Database temporarily unavailable"
        }), 503

    finally:

        if conn:
            conn.close()


# ==========================================
# USER LOGIN API WITH ACCOUNT LOCKOUT
# ==========================================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON input"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({
            "error": "Username and password required"
        }), 400

    username = username.strip()

    if len(password.encode("utf-8")) > 72:
        return jsonify({
            "error": "Password must not exceed 72 bytes"
        }), 400

    conn = None

    try:

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user is None:
            return jsonify({
                "error": "Invalid username or password"
            }), 401

        now = datetime.now(timezone.utc)

        # Check existing login attempts
        attempt = conn.execute(
            """
            SELECT failed_attempts, locked_until
            FROM login_attempts
            WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()

        # Check whether account is locked
        if attempt and attempt["locked_until"]:

            locked_until = datetime.fromisoformat(
                attempt["locked_until"]
            )

            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(
                    tzinfo=timezone.utc
                )

            if locked_until > now:

                return jsonify({
                    "error": "Account temporarily locked. Try again later.",
                    "locked_until": attempt["locked_until"]
                }), 429

            # Reset attempts after lockout expires
            conn.execute(
                """
                UPDATE login_attempts
                SET failed_attempts = 0,
                    locked_until = NULL
                WHERE user_id = ?
                """,
                (user["id"],)
            )

            conn.commit()

        # Verify password
        password_correct = bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        )

        # Handle incorrect password
        if not password_correct:

            conn.execute(
                """
                INSERT INTO login_attempts
                    (user_id, failed_attempts)
                VALUES (?, 1)
                ON CONFLICT(user_id)
                DO UPDATE SET
                    failed_attempts = failed_attempts + 1
                """,
                (user["id"],)
            )

            attempt = conn.execute(
                """
                SELECT failed_attempts
                FROM login_attempts
                WHERE user_id = ?
                """,
                (user["id"],)
            ).fetchone()

            failed_count = attempt["failed_attempts"]

            # Lock account after five failed attempts
            if failed_count >= 5:

                lock_expiry = now + timedelta(minutes=15)

                conn.execute(
                    """
                    UPDATE login_attempts
                    SET locked_until = ?
                    WHERE user_id = ?
                    """,
                    (lock_expiry.isoformat(), user["id"])
                )

                conn.commit()

                return jsonify({
                    "error": "Account locked after 5 failed attempts.",
                    "locked_until": lock_expiry.isoformat()
                }), 429

            conn.commit()

            return jsonify({
                "error": "Invalid username or password",
                "remaining_attempts": 5 - failed_count
            }), 401

        # Reset failed attempts after successful login
        conn.execute(
            """
            UPDATE login_attempts
            SET failed_attempts = 0,
                locked_until = NULL
            WHERE user_id = ?
            """,
            (user["id"],)
        )

        # Generate secure session token
        session_token = secrets.token_urlsafe(32)

        # Hash token before storing
        token_hash = hashlib.sha256(
            session_token.encode("utf-8")
        ).hexdigest()

        # Session expires after 30 minutes
        expiry = now + timedelta(minutes=30)

        conn.execute(
            """
            INSERT INTO sessions
                (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            """,
            (
                user["id"],
                token_hash,
                expiry.isoformat()
            )
        )

        conn.commit()

        return jsonify({
            "message": "Login successful",
            "username": user["username"],
            "role": user["role"],
            "session_token": session_token,
            "expires_at": expiry.isoformat()
        }), 200

    except sqlite3.OperationalError:

        if conn:
            conn.rollback()

        return jsonify({
            "error": "Database temporarily unavailable"
        }), 503

    finally:

        if conn:
            conn.close()


# ==========================================
# GET PROTECTED RECORDS API
# ==========================================

@app.route("/records", methods=["GET"])
def get_records():

    conn = get_db_connection()

    try:

        user = get_authenticated_user(conn)

        if user is None:
            return jsonify({
                "error": "Unauthorized. Please login."
            }), 401

        # Retrieve only this user's records
        records = conn.execute(
            """
            SELECT id, title, body, created_at
            FROM records
            WHERE owner_id = ?
            ORDER BY id DESC
            """,
            (user["id"],)
        ).fetchall()

        result = []
        migrated_legacy_records = False

        for record in records:

            stored_title = record["title"]
            stored_body = record["body"]

            # New encrypted fields use a version marker. Older plaintext
            # records are migrated only after ownership has been verified.
            try:
                if stored_title.startswith("fernet:v1:"):
                    plain_title = decrypt_text(stored_title[len("fernet:v1:"):])
                else:
                    plain_title = stored_title
                    stored_title = "fernet:v1:" + encrypt_text(plain_title)
                    migrated_legacy_records = True

                if stored_body.startswith("fernet:v1:"):
                    plain_body = decrypt_text(stored_body[len("fernet:v1:"):])
                else:
                    plain_body = stored_body
                    stored_body = "fernet:v1:" + encrypt_text(plain_body)
                    migrated_legacy_records = True

            except (ValueError, TypeError):
                app.logger.exception("Could not decrypt record id %s", record["id"])
                return jsonify({
                    "error": "A record could not be decrypted. Check the encryption key."
                }), 500

            if migrated_legacy_records:
                conn.execute(
                    """
                    UPDATE records
                    SET title = ?, body = ?
                    WHERE id = ? AND owner_id = ?
                    """,
                    (stored_title, stored_body, record["id"], user["id"])
                )

            result.append({
                "id": record["id"],
                "title": plain_title,
                "body": plain_body,
                "created_at": record["created_at"]
            })

        if migrated_legacy_records:
            conn.commit()

        return jsonify({
            "message": "Records retrieved successfully",
            "records": result
        }), 200

    finally:

        conn.close()


# ==========================================
# GET SINGLE PROTECTED RECORD API
# ==========================================

@app.route("/records/<int:record_id>", methods=["GET"])
def get_single_record(record_id):

    conn = get_db_connection()

    try:
        user = get_authenticated_user(conn)

        if user is None:
            return jsonify({
                "error": "Unauthorized. Please login."
            }), 401

        # Admins can read any record.
        # Normal users can read only their own records.
        if user["role"] == "admin":
            record = conn.execute(
                """
                SELECT id, title, body, owner_id, created_at
                FROM records
                WHERE id = ?
                """,
                (record_id,)
            ).fetchone()

        else:
            record = conn.execute(
                """
                SELECT id, title, body, owner_id, created_at
                FROM records
                WHERE id = ? AND owner_id = ?
                """,
                (record_id, user["id"])
            ).fetchone()

        if record is None:
            return jsonify({
                "error": "Record not found"
            }), 404

        title = record["title"]
        body = record["body"]

        try:
            if title.startswith("fernet:v1:"):
                title = decrypt_text(title[len("fernet:v1:"):])

            if body.startswith("fernet:v1:"):
                body = decrypt_text(body[len("fernet:v1:"):])

        except (ValueError, TypeError):
            app.logger.exception(
                "Record decryption failed for record %s",
                record_id
            )

            return jsonify({
                "error": "Unable to decrypt record"
            }), 500

        return jsonify({
            "message": "Record retrieved successfully",
            "record": {
                "id": record["id"],
                "title": title,
                "body": body,
                "owner_id": record["owner_id"],
                "created_at": record["created_at"]
            }
        }), 200

    finally:
        conn.close()

# ==========================================
# CREATE PROTECTED RECORD API
# ==========================================

@app.route("/records", methods=["POST"])
def create_record():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON input"
        }), 400

    title = data.get("title")
    body = data.get("body")

    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify({
            "error": "Title and body are required"
        }), 400

    title = title.strip()

    if not title or not body.strip() or len(title) > 150 or len(body) > 10000:
        return jsonify({
            "error": "Invalid record title or body"
        }), 400

    conn = get_db_connection()

    try:

        user = get_authenticated_user(conn)

        if user is None:
            return jsonify({
                "error": "Unauthorized. Please login."
            }), 401

        # Encrypt both the title and body before storing them in SQLite.
        encrypted_title = "fernet:v1:" + encrypt_text(title)
        encrypted_body = "fernet:v1:" + encrypt_text(body)

        cursor = conn.execute(
            """
            INSERT INTO records (title, body, owner_id)
            VALUES (?, ?, ?)
            """,
            (
                encrypted_title,
                encrypted_body,
                user["id"]
            )
        )

        conn.commit()

        return jsonify({
            "message": "Record created successfully",
            "record_id": cursor.lastrowid
        }), 201

    finally:

        conn.close()


# ==========================================
# DELETE PROTECTED RECORD API
# ==========================================

@app.route("/records/<int:record_id>", methods=["DELETE"])
def delete_record(record_id):

    conn = get_db_connection()

    try:

        user = get_authenticated_user(conn)

        if user is None:
            return jsonify({
                "error": "Unauthorized. Please login."
            }), 401

        # Delete only records owned by this user
        cursor = conn.execute(
            """
            DELETE FROM records
            WHERE id = ? AND owner_id = ?
            """,
            (
                record_id,
                user["id"]
            )
        )

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "error": "Record not found"
            }), 404

        return jsonify({
            "message": "Record deleted successfully"
        }), 200

    finally:

        conn.close()


# ==========================================
# LOGOUT API
# ==========================================

@app.route("/logout", methods=["POST"])
def logout():

    conn = get_db_connection()

    try:

        user = get_authenticated_user(conn)

        if user is None:
            return jsonify({
                "error": "Invalid or expired session"
            }), 401

        # Delete current session
        conn.execute(
            "DELETE FROM sessions WHERE id = ?",
            (user["session_id"],)
        )

        conn.commit()

        return jsonify({
            "message": "Logout successful"
        }), 200

    finally:

        conn.close()


# ==========================================
# RUN FLASK APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        use_reloader=False
    )
