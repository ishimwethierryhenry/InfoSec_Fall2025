# This script is used for resetting the database contents

import sqlite3
import os

DB_FILE = "infosec_lab.db"

def reset_db():
    # Check if we're in scripts folder, adjust path accordingly
    if os.path.basename(os.getcwd()) == 'scripts':
        db_path = f"../{DB_FILE}"
    else:
        db_path = DB_FILE
    
    if not os.path.exists(db_path):
        print(f"[!] Database file '{db_path}' not found.")
        print(f"[!] Current directory: {os.getcwd()}")
        print(f"[!] Run this script from the main project directory")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Delete all records from all tables
    cursor.execute("DELETE FROM otp_chain;")
    cursor.execute("DELETE FROM files;")
    cursor.execute("DELETE FROM users;")
    
    # Reset auto-increment counters
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='users';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='files';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='otp_chain';")
    
    conn.commit()
    conn.close()
    
    # Run VACUUM in separate connection (outside transaction)
    conn = sqlite3.connect(db_path)
    conn.execute("VACUUM;")
    conn.close()

    print("[*] All tables have been cleared and auto-increment counters reset.")
    print("[*] Cleared: users, files, and otp_chain tables")
    print("[*] Database completely clean for fresh start.")

if __name__ == "__main__":
    reset_db()