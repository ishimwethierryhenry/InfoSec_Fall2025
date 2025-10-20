#!/usr/bin/env python3
"""
Helper script to create admin users for testing Lab 6
Run this after setting up the database to create test admin accounts
"""

import sqlite3
import hashlib
import datetime
from werkzeug.security import generate_password_hash

def generate_otp_chain(user_id, seed_value, db_connection):
    """Generate a hash chain of OTPs for 24 hours"""
    current_time = datetime.datetime.utcnow()
    start_time = current_time.replace(second=0, microsecond=0)
    current_hash = hashlib.sha256(seed_value.encode('utf-8')).hexdigest()
    
    for i in range(1440):
        otp_time = start_time + datetime.timedelta(minutes=i)
        timestamp = otp_time.strftime("%Y%m%d%H%M")
        hash_input = f"{current_hash}{timestamp}".encode('utf-8')
        current_hash = hashlib.sha256(hash_input).hexdigest()
        otp_code = str(int(current_hash[:8], 16))[-6:].zfill(6)
        db_connection.execute(
            "INSERT INTO otp_chain (user_id, timestamp, otp_code) VALUES (?, ?, ?)", 
            (user_id, timestamp, otp_code)
        )

def create_admin_users():
    """Create test admin users"""
    conn = sqlite3.connect("infosec_lab.db")
    cursor = conn.cursor()
    
    # Admin users to create
    admins = [
        {
            "name": "Henry ISHIMWE",
            "andrew_id": "ithierry",
            "password": "Henry123",
            "role": "user_admin"
        },
        {
            "name": "Aline Bobo",
            "andrew_id": "abobo",
            "password": "Henry123",
            "role": "data_admin"
        },
        {
            "name": "Hirwa Maxime",
            "andrew_id": "hmaxime",
            "password": "Henry123",
            "role": "basic"
        }
    ]
    
    print("Creating admin users for Lab 6 testing...")
    print("-" * 50)
    
    created_users = []  # Track successfully created users
    
    for admin in admins:
        try:
            # Check if user already exists
            existing = cursor.execute(
                "SELECT id FROM users WHERE andrew_id = ?", 
                (admin["andrew_id"],)
            ).fetchone()
            
            if existing:
                print(f"⚠️  User '{admin['andrew_id']}' already exists, skipping.")
                continue
            
            # Hash password
            password_hash = generate_password_hash(admin["password"])
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (name, andrew_id, password, role) VALUES (?, ?, ?, ?)",
                (admin["name"], admin["andrew_id"], password_hash, admin["role"])
            )
            user_id = cursor.lastrowid
            
            # Generate OTP chain
            seed_value = admin["andrew_id"] + admin["password"]
            generate_otp_chain(user_id, seed_value, conn)
            
            conn.commit()
            
            print(f"✅ Created: {admin['name']}")
            print(f"   Andrew ID: {admin['andrew_id']}")
            print(f"   Password: {admin['password']}")
            print(f"   Role: {admin['role']}")
            print()
            
            # Track created user
            created_users.append(admin)
            
        except Exception as e:
            print(f"❌ Error creating {admin['andrew_id']}: {e}")
            conn.rollback()
    
    conn.close()
    
    print("-" * 50)
    print("Admin seeding complete!")
    
    if created_users:
        print("\nTest accounts created:")
        for idx, user in enumerate(created_users, 1):
            print(f"{idx}. {user['andrew_id']} / {user['password']} ({user['role']})")
        print("\nYou can now log in with these credentials.")
    else:
        print("\nNo new users created (all already exist).")

if __name__ == "__main__":
    create_admin_users()