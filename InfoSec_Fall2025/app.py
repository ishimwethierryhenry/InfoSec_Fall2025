"""
Information Security Fall 2025 Lab - Flask Application
-----------------------------------------------------
Short description: Course-branded web app that supports registration
(Name, Andrew ID, Password), login, session-based greeting, logout,
and file sharing functionality for Lab 2.
Includes a landing page, CMU-themed styling, and basic file operations.

Lab 3 Update: Added secure password hashing with werkzeug.security

Routes:
- GET /          : Landing page with welcome message + Login/Register buttons.
- GET/POST /register : Register with name, Andrew ID, and password; on success redirect to /login.
- GET/POST /login    : Login with Andrew ID + password; on success redirect to /dashboard.
- GET /dashboard     : Dashboard with greeting, file upload form, and list of all uploaded files.
- GET /logout        : Clear session and return to landing page.
- POST /upload       : Handle file uploads; save file to uploads/ folder and metadata to database.
- GET /download/<filename> : Download a file from the uploads/ folder.
- POST /delete/<filename>  : Delete a file from both database and uploads/ folder.

Lab 2 Features:
- File upload functionality with form on dashboard
- File listing showing filename, uploader, and upload timestamp
- File download capability for any logged-in user
- File deletion capability for any logged-in user
- All files visible to all logged-in users (no ownership restrictions)

Lab 3 Security Features:
- Secure password hashing using PBKDF2-SHA256
- Automatic salt generation for each password
- Secure password verification during login
"""  


from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

# Make a new Flask app
app = Flask(__name__)
app.secret_key = "my-secret-key-for-school-project"

# Where to put files
uploads_folder = 'uploads'

# Make the uploads folder if it doesn't exist
if not os.path.exists(uploads_folder):
    os.makedirs(uploads_folder)

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
    
    welcome_message = f"Hello {user['name']}, Welcome to Lab 3 of Information Security course. Enjoy your learning journey!!!"
    return render_template("dashboard.html", title="Dashboard", greeting=welcome_message, user=user, files=all_files)

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# Upload file
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
    
    # Save the file
    file_name = my_file.filename
    file_path = os.path.join(uploads_folder, file_name)
    my_file.save(file_path)
    
    # Save info to database
    db = get_database()
    db.execute("INSERT INTO files (filename, uploader_andrewid) VALUES (?, ?)", 
              (file_name, user['andrew_id']))
    db.commit()
    db.close()
    
    flash('Your file was uploaded!', 'success')
    return redirect(url_for('dashboard'))

# Download file
@app.route("/download/<filename>")
def download_file(filename):
    user = who_is_logged_in()
    if not user:
        return redirect(url_for("login"))
    
    return send_from_directory(uploads_folder, filename)

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
    print("Starting my secure Flask app for Lab 3...")
    app.run(host="0.0.0.0", port=5000, debug=True)