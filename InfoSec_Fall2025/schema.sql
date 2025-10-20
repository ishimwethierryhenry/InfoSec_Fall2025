-- Information Security Fall 2025 Lab - Database Schema (Lab 6)
-- Central place for schema so you can add future tables here.

-- Users table with role support
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'basic' -- NEW role field is added for lab 6 because the system needs to know what permissions each user has.
);

-- Files table with uploader_id for ownership tracking
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    uploader_andrewid TEXT NOT NULL,
    uploader_id INTEGER NOT NULL,
    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploader_id) REFERENCES users (id)
);

-- Lab 5: OTP Chain table for Two-Factor Authentication
CREATE TABLE IF NOT EXISTS otp_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Lab 6: Audit logging table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    actor_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    target_pretty TEXT,
    outcome TEXT NOT NULL,
    FOREIGN KEY (actor_id) REFERENCES users (id)
);

-- Lab 6: View for readable audit logs
CREATE VIEW IF NOT EXISTS audit_logs_pretty AS
SELECT 
    al.id,
    al.created_at,
    u.andrew_id AS actor_andrew_id,
    al.action,
    al.target_pretty AS target,
    al.outcome
FROM audit_logs al
JOIN users u ON al.actor_id = u.id;