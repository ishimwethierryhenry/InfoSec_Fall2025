"""
Information Security Fall 2025 Lab - Flask Application
-----------------------------------------------------
Short description: Minimal course-branded web app that supports registration
(Name, Andrew ID, Password), login, session-based greeting, and logout.
Includes a landing page and CMU-themed styling.

Routes:
- GET /          : Landing page with welcome message + Login/Register buttons.
- GET/POST /register : Register with name, Andrew ID, and password; on success redirect to /login.
- GET/POST /login    : Login with Andrew ID + password; on success redirect to /dashboard.
- GET /dashboard     : Greets authenticated user: "Hello {Name}, Welcome to Lab 0 of Information Security course. Enjoy!!!"
- GET /logout        : Clear session and return to landing page.
"""

from flask import Flask, request, redirect, render_template, session, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3
import os
import io

# Make a new Flask app
app = Flask(__name__)
app.secret_key = "my-secret-key-for-school-project"

# Where to put files
uploads_folder = 'uploads'

# Make the uploads folder if it doesn't exist
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

# Load AES key at startup
AES_KEY = load_aes_key()

def encrypt_file_content(file_content):
    """
    Encrypt file content using AES-256 in CBC mode.
    Prepends the IV to the ciphertext for later decryption.
    
    Args:
        file_content (bytes): Raw file content to encrypt
        
    Returns:
        bytes: IV + encrypted content
    """
    # Generate a random 16-byte IV for this file
    iv = get_random_bytes(16)
    
    # Create AES cipher in CBC mode
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    
    # Pad the content to be multiple of 16 bytes (AES block size)
    # PKCS7 padding
    pad_length = 16 - (len(file_content) % 16)
    padded_content = file_content + bytes([pad_length] * pad_length)
    
    # Encrypt the content
    ciphertext = cipher.encrypt(padded_content)
    
    # Return IV + ciphertext (IV needed for decryption)
    return iv + ciphertext

def decrypt_file_content(encrypted_content):
    """
    Decrypt file content that was encrypted with encrypt_file_content.
    Expects IV to be prepended to the ciphertext.
    
    Args:
        encrypted_content (bytes): IV + encrypted content
        
    Returns:
        bytes: Original file content
    """
    # Extract IV (first 16 bytes) and ciphertext (rest)
    iv = encrypted_content[:16]
    ciphertext = encrypted_content[16:]
    
    # Create AES cipher in CBC mode with extracted IV
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    
    # Decrypt
    padded_content = cipher.decrypt(ciphertext)
    
    # Remove PKCS7 padding
    pad_length = padded_content[-1]
    original_content = padded_content[:-pad_length]
    
    return original_content

# Database stuff
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

# Setup database when app starts
setup_database()

# Check who is logged in
def who_is_logged_in():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    
    db = get_database()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    return user

# Home page
@app.route("/")
def index():
    return render_template("index.html", title="My Security Lab", user=who_is_logged_in())

# Register new user - UPDATED FOR LAB 3 SECURITY
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get form data
        name = request.form.get("name", "").strip()
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        # Check if all fields filled
        if not name or not andrew_id or not password:
            flash("Please fill all fields!", "error")
            return render_template("register.html", title="Register")

        # SECURITY IMPROVEMENT: Hash the password with automatic salt generation
        password_hash = generate_password_hash(password)

        # Save to database
        db = get_database()
        try:
            # Store the hashed password instead of plaintext
            db.execute("INSERT INTO users (name, andrew_id, password) VALUES (?, ?, ?)", 
                      (name, andrew_id, password_hash))
            db.commit()
            flash("You registered successfully! Now you can login.", "success")
            return redirect(url_for("login"))
        except:
            flash("This Andrew ID is already taken!", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        finally:
            db.close()
    
    return render_template("register.html", title="Register")

# Login user - UPDATED FOR LAB 3 SECURITY
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get login info
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        # Get user from database by andrew_id only
        db = get_database()
        user = db.execute("SELECT * FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()
        db.close()

        # SECURITY IMPROVEMENT: Use check_password_hash for secure password verification
        if user and check_password_hash(user["password"], password):
            # Login successful
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("dashboard"))
        else:
            flash("Wrong Andrew ID or password!", "error")
    
    return render_template("login.html", title="Login")

# User dashboard
@app.route("/dashboard")
def dashboard():
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    # Get all files
    db = get_database()
    all_files = db.execute("SELECT * FROM files ORDER BY upload_timestamp DESC").fetchall()
    db.close()
    
    welcome_message = f"Hello {user['name']}, Welcome to Lab 4 of Information Security course. Enjoy your learning journey!!!"
    return render_template("dashboard.html", title="Dashboard", greeting=welcome_message, user=user, files=all_files)

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# Upload file - UPDATED FOR LAB 4 ENCRYPTION
@app.route("/upload", methods=["POST"])
def upload_file():
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    # Check if file exists
    if 'file' not in request.files:
        flash('You did not choose a file!', 'error')
        return redirect(url_for('dashboard'))
    
    my_file = request.files['file']
    if my_file.filename == '':
        flash('You did not choose a file!', 'error')
        return redirect(url_for('dashboard'))
    
    # Read file content into memory
    file_content = my_file.read()
    
    # LAB 4: Encrypt the file content
    encrypted_content = encrypt_file_content(file_content)
    
    # Save the encrypted content to disk
    file_name = my_file.filename
    file_path = os.path.join(uploads_folder, file_name)
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)
    
    # Save info to database
    db = get_database()
    db.execute("INSERT INTO files (filename, uploader_andrewid) VALUES (?, ?)", 
              (file_name, user['andrew_id']))
    db.commit()
    db.close()
    
    flash('Your file was uploaded and encrypted!', 'success')
    return redirect(url_for('dashboard'))

# Download file - UPDATED FOR LAB 4 DECRYPTION
@app.route("/download/<filename>")
def download_file(filename):
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    file_path = os.path.join(uploads_folder, filename)
    
    if not os.path.exists(file_path):
        flash("File not found!", "error")
        return redirect(url_for("dashboard"))
    
    # LAB 4: Read encrypted file and decrypt it
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()
    
    # Decrypt the content
    try:
        decrypted_content = decrypt_file_content(encrypted_content)
    except Exception as e:
        flash("Error decrypting file!", "error")
        print(f"Decryption error: {e}")
        return redirect(url_for("dashboard"))
    
    # Create a file-like object from decrypted content
    file_obj = io.BytesIO(decrypted_content)
    
    # Send the decrypted file to user
    return send_file(
        file_obj,
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

# Delete file
@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    # Remove from database
    db = get_database()
    db.execute("DELETE FROM files WHERE filename = ?", (filename,))
    db.commit()
    db.close()
    
    # Remove actual file
    file_path = os.path.join(uploads_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    flash('File deleted!', 'success')
    return redirect(url_for('dashboard'))

# Run the app
if __name__ == "__main__":
    print("Starting my secure Flask app for Lab 4...")
    app.run(host="0.0.0.0", port=5000, debug=True)