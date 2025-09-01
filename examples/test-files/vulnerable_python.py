#!/usr/bin/env python3
"""
Sample Python code with intentional security vulnerabilities for testing Semgrep scanner
"""

import os
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SQL Injection vulnerability
def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: Using string formatting for SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection vulnerability  
def execute_system_command(filename):
    # Vulnerable: Using user input directly in system command
    command = f"cat {filename}"
    result = os.system(command)
    return result

# XSS vulnerability (Flask)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable: Direct output without escaping
    return f"<h1>Search results for: {query}</h1>"

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

# Weak cryptography
import hashlib

def hash_password(password):
    # Vulnerable: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# Path traversal vulnerability
def read_file(filename):
    # Vulnerable: No path validation
    with open(filename, 'r') as f:
        return f.read()

# Unsafe deserialization
import pickle

def load_data(data):
    # Vulnerable: Unsafe pickle deserialization
    return pickle.loads(data)

if __name__ == '__main__':
    app.run(debug=True)  # Vulnerable: Debug mode in production