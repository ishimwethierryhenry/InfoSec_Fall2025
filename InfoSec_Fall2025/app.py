"""
Information Security Fall 2025 Lab - Flask Application
-----------------------------------------------------
Short description: Minimal course-branded web app that supports registration
(Name, Andrew ID, Password), login, session-based greeting, and logout.
Includes a landing page and CMU-themed styling.
Lab 5: Added Two-Factor Authentication with OTPs (Hash Chains)

Routes:
- GET /          : Landing page with welcome message + Login/Register buttons.
- GET/POST /register : Register with name, Andrew ID, and password; on success redirect to /login.
- GET/POST /login    : Login with Andrew ID + password; on success redirect to /2fa.
- GET/POST /2fa      : Two-factor authentication page for OTP verification.
- GET /show-otp      : Debug route to show current OTP for testing.
- GET /dashboard     : Greets authenticated user (requires 2FA).
- GET /logout        : Clear session and return to landing page.
"""



from flask import Flask, request, redirect, render_template, session, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from functools import wraps
import sqlite3
import os
import io
import hashlib
import datetime

# Role Constants
ROLE_BASIC = "basic"
ROLE_USER_ADMIN = "user_admin"
ROLE_DATA_ADMIN = "data_admin"

# Flask App Setup
app = Flask(__name__)
app.secret_key = "my-secret-key-for-school-project"

# Upload Configuration
uploads_folder = 'uploads'
if not os.path.exists(uploads_folder):
    os.makedirs(uploads_folder)

# AES Key Management
AES_KEY_FILE = "secret_aes.key"

def load_aes_key():
    """Load the AES key from file"""
    try:
        with open(AES_KEY_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[!] AES key file '{AES_KEY_FILE}' not found!")
        print("[!] Run 'python generate_key.py' to create the key file.")
        exit(1)

AES_KEY = load_aes_key()

def encrypt_file_content(file_content):
    """Encrypt file content using AES-256 in CBC mode"""
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pad_length = 16 - (len(file_content) % 16)
    padded_content = file_content + bytes([pad_length] * pad_length)
    ciphertext = cipher.encrypt(padded_content)
    return iv + ciphertext

def decrypt_file_content(encrypted_content):
    """Decrypt file content that was encrypted with encrypt_file_content"""
    iv = encrypted_content[:16]
    ciphertext = encrypted_content[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_content = cipher.decrypt(ciphertext)
    pad_length = padded_content[-1]
    original_content = padded_content[:-pad_length]
    return original_content

# Database Functions
def get_database():
    db = sqlite3.connect("infosec_lab.db")
    db.row_factory = sqlite3.Row
    return db

def setup_database():
    with open("schema.sql", "r") as file:
        sql_commands = file.read()
    db = get_database()
    db.executescript(sql_commands)
    db.commit()
    db.close()

setup_database()

# OTP Functions (from Lab 5)
def generate_otp_chain(user_id, seed_value, db_connection):
    """Generate a hash chain of OTPs for 24 hours (1440 minutes)"""
    current_time = datetime.datetime.utcnow()
    start_time = current_time.replace(second=0, microsecond=0)
    current_hash = hashlib.sha256(seed_value.encode('utf-8')).hexdigest()
    
    for i in range(1440):
        otp_time = start_time + datetime.timedelta(minutes=i)
        timestamp = otp_time.strftime("%Y%m%d%H%M")
        hash_input = f"{current_hash}{timestamp}".encode('utf-8')
        current_hash = hashlib.sha256(hash_input).hexdigest()
        otp_code = str(int(current_hash[:8], 16))[-6:].zfill(6)
        db_connection.execute("INSERT INTO otp_chain (user_id, timestamp, otp_code) VALUES (?, ?, ?)", 
                  (user_id, timestamp, otp_code))

def get_current_otp(user_id):
    """Get the OTP for the current minute"""
    current_time = datetime.datetime.utcnow()
    current_timestamp = current_time.strftime("%Y%m%d%H%M")
    
    db = get_database()
    otp_row = db.execute("SELECT otp_code FROM otp_chain WHERE user_id = ? AND timestamp = ?", 
                        (user_id, current_timestamp)).fetchone()
    db.close()
    
    return otp_row["otp_code"] if otp_row else None

def verify_otp(user_id, entered_otp):
    """Verify OTP with ±2 minute tolerance"""
    current_time = datetime.datetime.utcnow()
    
    for offset in range(-2, 3):
        check_time = current_time + datetime.timedelta(minutes=offset)
        check_timestamp = check_time.strftime("%Y%m%d%H%M")
        
        db = get_database()
        otp_row = db.execute("SELECT otp_code FROM otp_chain WHERE user_id = ? AND timestamp = ?", 
                            (user_id, check_timestamp)).fetchone()
        db.close()
        
        if otp_row and otp_row["otp_code"] == entered_otp:
            return True
    
    return False

# Authentication Functions
def who_is_logged_in():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    
    db = get_database()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    return user

def require_2fa():
    """Check if user has completed 2FA"""
    return session.get("verified_2fa", False)

# Lab 6: Audit Logging
def log_audit(actor_id, action, target_pretty, outcome):
    """Log an admin action to the audit_logs table"""
    db = get_database()
    db.execute(
        "INSERT INTO audit_logs (actor_id, action, target_pretty, outcome) VALUES (?, ?, ?, ?)",
        (actor_id, action, target_pretty, outcome)
    )
    db.commit()
    db.close()

# Lab 6: Central Guard Function
def guard(action, target=None, forbid_self_delete=True):
    """
    Central authorization guard for all protected actions.
    Returns True if action is allowed, False otherwise.
    Automatically logs admin actions.
    """
    # Step 1: Require login + 2FA
    user = who_is_logged_in()
    if not user or not session.get("verified_2fa", False):
        return False
    
    # Step 2: Define policy
    policy = {
        "upload_own_file": ROLE_BASIC,
        "download_own_file": ROLE_BASIC,
        "delete_own_file": ROLE_BASIC,
        "change_password": ROLE_BASIC,
        "create_user": ROLE_USER_ADMIN,
        "delete_user": ROLE_USER_ADMIN,
        "assign_role": ROLE_USER_ADMIN,
        "change_username": ROLE_USER_ADMIN,
        "download_any_file": ROLE_DATA_ADMIN,
        "delete_any_file": ROLE_DATA_ADMIN,
        "read_log_file": ROLE_USER_ADMIN,  # Either admin role
    }
    
    # Step 3: Check if action exists
    if action not in policy:
        return False
    
    required_role = policy[action]
    user_role = user["role"]
    
    # Step 4: Define role hierarchy
    role_levels = {
        ROLE_BASIC: 0,
        ROLE_USER_ADMIN: 1,
        ROLE_DATA_ADMIN: 1,
    }
    
    # Check permission
    has_permission = role_levels.get(user_role, -1) >= role_levels.get(required_role, 999)
    
    # Special case: read_log_file allowed for EITHER admin role
    if action == "read_log_file" and user_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        has_permission = True
    
    # Step 5: Prevent user_admin from deleting themselves
    if action == "delete_user" and forbid_self_delete and user_role == ROLE_USER_ADMIN:
        if target:
            if target.lower() == user["andrew_id"].lower():
                log_audit(user["id"], action, target, "denied")
                return False
    
    # Step 6: Log admin actions
    is_admin_action = required_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]
    if is_admin_action:
        outcome = "allowed" if has_permission else "denied"
        log_audit(user["id"], action, target or "N/A", outcome)
    
    return has_permission

# Lab 6: Decorators
def require_login_and_2fa(f):
    """Decorator to require login and 2FA"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = who_is_logged_in()
        if not user:
            flash("Please log in first!", "error")
            return redirect(url_for("login"))
        if not require_2fa():
            return redirect(url_for("two_factor_auth"))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = who_is_logged_in()
        if not user or user["role"] not in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
            flash("You don't have admin permissions!", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

# Routes - Public Pages
@app.route("/")
def index():
    return render_template("index.html", title="My Security Lab", user=who_is_logged_in())

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not andrew_id or not password:
            flash("Please fill all fields!", "error")
            return render_template("register.html", title="Register")

        password_hash = generate_password_hash(password)

        db = get_database()
        try:
            cursor = db.execute(
                "INSERT INTO users (name, andrew_id, password, role) VALUES (?, ?, ?, ?)", 
                (name, andrew_id, password_hash, ROLE_BASIC)
            )
            user_id = cursor.lastrowid
            
            seed_value = andrew_id + password
            generate_otp_chain(user_id, seed_value, db)
            
            db.commit()
            flash("You registered successfully! Your OTP system is ready. Now you can login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            db.rollback()
            if "andrew_id" in str(e).lower():
                flash("This Andrew ID is already taken!", "error")
            else:
                flash(f"Registration failed: {str(e)}", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        finally:
            db.close()
    
    return render_template("register.html", title="Register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        db = get_database()
        user = db.execute("SELECT * FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()
        db.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["verified_2fa"] = False
            return redirect(url_for("two_factor_auth"))
        else:
            flash("Wrong Andrew ID or password!", "error")
    
    return render_template("login.html", title="Login")

@app.route("/2fa", methods=["GET", "POST"])
def two_factor_auth():
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        
        if not entered_otp:
            flash("Please enter your OTP!", "error")
            return render_template("2fa.html", title="Two-Factor Authentication")
        
        if verify_otp(user["id"], entered_otp):
            session["verified_2fa"] = True
            flash("2FA verification successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP! Please try again.", "error")
    
    return render_template("2fa.html", title="Two-Factor Authentication")

@app.route("/show-otp")
def show_otp():
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    current_otp = get_current_otp(user["id"])
    current_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    return render_template("show_otp.html", 
                         title="Current OTP", 
                         otp=current_otp, 
                         current_time=current_time)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# Routes - Basic User Dashboard
@app.route("/dashboard")
def dashboard():
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    if not require_2fa():
        return redirect(url_for("two_factor_auth"))
    
    # Lab 6: Only show user's own files
    db = get_database()
    user_files = db.execute(
        "SELECT * FROM files WHERE uploader_id = ? ORDER BY upload_timestamp DESC", 
        (user["id"],)
    ).fetchall()
    db.close()
    
    welcome_message = f"Hello {user['name']}, Welcome to Lab 6 with Role-Based Access Control!"
    return render_template("dashboard.html", title="Dashboard", greeting=welcome_message, user=user, files=user_files)

@app.route("/upload", methods=["POST"])
def upload_file():
    user = who_is_logged_in()
    if not user or not require_2fa():
        return redirect(url_for("login"))
    
    if not guard("upload_own_file"):
        flash("You don't have permission to upload files!", "error")
        return redirect(url_for("dashboard"))
    
    if 'file' not in request.files:
        flash('You did not choose a file!', 'error')
        return redirect(url_for('dashboard'))
    
    my_file = request.files['file']
    if my_file.filename == '':
        flash('You did not choose a file!', 'error')
        return redirect(url_for('dashboard'))
    
    file_content = my_file.read()
    encrypted_content = encrypt_file_content(file_content)
    
    file_name = my_file.filename
    file_path = os.path.join(uploads_folder, file_name)
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)
    
    db = get_database()
    db.execute(
        "INSERT INTO files (filename, uploader_andrewid, uploader_id) VALUES (?, ?, ?)", 
        (file_name, user['andrew_id'], user['id'])
    )
    db.commit()
    db.close()
    
    flash('Your file was uploaded and encrypted!', 'success')
    return redirect(url_for('dashboard'))

@app.route("/uploads/<filename>")
def download_file(filename):
    user = who_is_logged_in()
    if not user or not require_2fa():
        return redirect(url_for("login"))
    
    db = get_database()
    file_record = db.execute("SELECT * FROM files WHERE filename = ?", (filename,)).fetchone()
    db.close()
    
    if not file_record:
        flash("File not found!", "error")
        return redirect(url_for("dashboard"))
    
    # Lab 6: Check ownership
    if file_record["uploader_id"] != user["id"]:
        flash("You don't have permission to download this file!", "error")
        return redirect(url_for("dashboard"))
    
    if not guard("download_own_file", filename):
        flash("You don't have permission to download files!", "error")
        return redirect(url_for("dashboard"))
    
    file_path = os.path.join(uploads_folder, filename)
    
    if not os.path.exists(file_path):
        flash("File not found!", "error")
        return redirect(url_for("dashboard"))
    
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()
    
    try:
        decrypted_content = decrypt_file_content(encrypted_content)
    except Exception as e:
        flash("Error decrypting file!", "error")
        return redirect(url_for("dashboard"))
    
    file_obj = io.BytesIO(decrypted_content)
    
    return send_file(
        file_obj,
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    user = who_is_logged_in()
    if not user or not require_2fa():
        return redirect(url_for("login"))
    
    db = get_database()
    file_record = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    
    if not file_record:
        flash("File not found!", "error")
        db.close()
        return redirect(url_for("dashboard"))
    
    # Lab 6: Check ownership
    if file_record["uploader_id"] != user["id"]:
        flash("You don't have permission to delete this file!", "error")
        db.close()
        return redirect(url_for("dashboard"))
    
    if not guard("delete_own_file", file_record["filename"]):
        flash("You don't have permission to delete files!", "error")
        db.close()
        return redirect(url_for("dashboard"))
    
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    db.close()
    
    file_path = os.path.join(uploads_folder, file_record["filename"])
    if os.path.exists(file_path):
        os.remove(file_path)
    
    flash('File deleted!', 'success')
    return redirect(url_for('dashboard'))

# Lab 6: Admin Routes
@app.route("/admin/users")
@require_login_and_2fa
@require_admin
def admin_users():
    user = who_is_logged_in()
    
    if user["role"] == ROLE_USER_ADMIN:
        # Show user management
        db = get_database()
        all_users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
        db.close()
        return render_template("admin_users.html", title="Manage Users", user=user, users=all_users)
    
    elif user["role"] == ROLE_DATA_ADMIN:
        # Show file management
        db = get_database()
        all_files = db.execute("""
            SELECT f.*, u.andrew_id as owner_andrew_id 
            FROM files f
            JOIN users u ON f.uploader_id = u.id
            ORDER BY f.upload_timestamp DESC
        """).fetchall()
        db.close()
        return render_template("admin_users.html", title="Manage Files", user=user, all_files=all_files)
    
    else:
        flash("Access denied!", "error")
        return redirect(url_for("dashboard"))

@app.route("/admin/create-user", methods=["POST"])
@require_login_and_2fa
@require_admin
def admin_create_user():
    user = who_is_logged_in()
    
    name = request.form.get("name", "").strip()
    andrew_id = request.form.get("andrew_id", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", ROLE_BASIC)
    
    # Check permission first (will log the attempt)
    if not guard("create_user", andrew_id):
        flash("You don't have permission to create users!", "error")
        return redirect(url_for("admin_users"))
    
    if not name or not andrew_id or not password:
        flash("Please fill all fields!", "error")
        return redirect(url_for("admin_users"))
    
    if role not in [ROLE_BASIC, ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        flash("Invalid role!", "error")
        return redirect(url_for("admin_users"))
    
    password_hash = generate_password_hash(password)
    
    db = get_database()
    try:
        cursor = db.execute(
            "INSERT INTO users (name, andrew_id, password, role) VALUES (?, ?, ?, ?)",
            (name, andrew_id, password_hash, role)
        )
        new_user_id = cursor.lastrowid
        
        seed_value = andrew_id + password
        generate_otp_chain(new_user_id, seed_value, db)
        
        db.commit()
        flash(f"User '{andrew_id}' created successfully with role '{role}'!", "success")
    except sqlite3.IntegrityError:
        db.rollback()
        flash("Andrew ID already exists!", "error")
    finally:
        db.close()
    
    return redirect(url_for("admin_users"))

@app.route("/admin/assign-role", methods=["POST"])
@require_login_and_2fa
@require_admin
def admin_assign_role():
    user_id = request.form.get("user_id")
    new_role = request.form.get("role")
    
    if not user_id or not new_role:
        flash("Missing required fields!", "error")
        return redirect(url_for("admin_users"))
    
    db = get_database()
    target_user = db.execute("SELECT andrew_id FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not target_user:
        flash("User not found!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    target_andrew_id = target_user["andrew_id"]
    
    if not guard("assign_role", target_andrew_id):
        flash("You don't have permission to assign roles!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    if new_role not in [ROLE_BASIC, ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        flash("Invalid role!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    db.close()
    
    flash(f"Role updated to '{new_role}' for user '{target_andrew_id}'!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/change-username", methods=["POST"])
@require_login_and_2fa
@require_admin
def admin_change_username():
    user_id = request.form.get("user_id")
    new_name = request.form.get("new_name", "").strip()
    
    if not user_id or not new_name:
        flash("Missing required fields!", "error")
        return redirect(url_for("admin_users"))
    
    db = get_database()
    target_user = db.execute("SELECT andrew_id FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not target_user:
        flash("User not found!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    target_andrew_id = target_user["andrew_id"]
    
    if not guard("change_username", target_andrew_id):
        flash("You don't have permission to change usernames!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    db.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, user_id))
    db.commit()
    db.close()
    
    flash(f"Username updated to '{new_name}' for user '{target_andrew_id}'!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/delete-user", methods=["POST"])
@require_login_and_2fa
@require_admin
def admin_delete_user():
    user_id = request.form.get("user_id")
    
    if not user_id:
        flash("Missing user ID!", "error")
        return redirect(url_for("admin_users"))
    
    db = get_database()
    target_user = db.execute("SELECT andrew_id FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not target_user:
        flash("User not found!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    target_andrew_id = target_user["andrew_id"]
    
    # Guard will prevent self-delete
    if not guard("delete_user", target_andrew_id):
        flash("You cannot delete this user!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    db.execute("DELETE FROM otp_chain WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM files WHERE uploader_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    
    flash(f"User '{target_andrew_id}' deleted successfully!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/download/<int:file_id>")
@require_login_and_2fa
@require_admin
def admin_download_file(file_id):
    db = get_database()
    file_record = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    db.close()
    
    if not file_record:
        flash("File not found!", "error")
        return redirect(url_for("admin_users"))
    
    if not guard("download_any_file", file_record["filename"]):
        flash("You don't have permission to download files!", "error")
        return redirect(url_for("admin_users"))
    
    file_path = os.path.join(uploads_folder, file_record["filename"])
    
    if not os.path.exists(file_path):
        flash("File not found on disk!", "error")
        return redirect(url_for("admin_users"))
    
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()
    
    try:
        decrypted_content = decrypt_file_content(encrypted_content)
    except Exception as e:
        flash("Error decrypting file!", "error")
        return redirect(url_for("admin_users"))
    
    file_obj = io.BytesIO(decrypted_content)
    return send_file(
        file_obj,
        as_attachment=True,
        download_name=file_record["filename"],
        mimetype='application/octet-stream'
    )

@app.route("/admin/delete-file/<int:file_id>", methods=["POST"])
@require_login_and_2fa
@require_admin
def admin_delete_file(file_id):
    db = get_database()
    file_record = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    
    if not file_record:
        flash("File not found!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    if not guard("delete_any_file", file_record["filename"]):
        flash("You don't have permission to delete files!", "error")
        db.close()
        return redirect(url_for("admin_users"))
    
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    db.close()
    
    file_path = os.path.join(uploads_folder, file_record["filename"])
    if os.path.exists(file_path):
        os.remove(file_path)
    
    flash(f"File '{file_record['filename']}' deleted successfully!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/logs")
@require_login_and_2fa
@require_admin
def admin_logs():
    user = who_is_logged_in()
    
    if not guard("read_log_file"):
        flash("You don't have permission to view audit logs!", "error")
        return redirect(url_for("dashboard"))
    
    db = get_database()
    logs = db.execute("""
        SELECT created_at, actor_andrew_id, action, target, outcome
        FROM audit_logs_pretty
        ORDER BY id DESC
        LIMIT 200
    """).fetchall()
    db.close()
    
    return render_template("admin_logs.html", title="Audit Logs", user=user, logs=logs)

# Run the app
if __name__ == "__main__":
    print("Starting Flask app for Lab 6 - RBAC with Audit Logging...")
    app.run(host="0.0.0.0", port=5000, debug=True)