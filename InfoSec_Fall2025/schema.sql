-- Information Security Fall 2025 Lab - Database Schema
-- Central place for schema so you can add future tables here.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

-- Lab 2: Files table... basically I'm going to create the table which is going to keep records of the files uploaded.
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    uploader_andrewid TEXT NOT NULL,
    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Lab 5: OTP Chain table for Two-Factor Authentication
CREATE TABLE IF NOT EXISTS otp_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);