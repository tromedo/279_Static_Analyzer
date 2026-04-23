# vuln_db.py - Sample script with SQL injection vulnerabilities
# WARNING: This file is intentionally vulnerable for demonstration purposes

import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY: Raw string formatting in SQL query (SQL Injection)
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def get_user_by_id(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY: f-string used directly in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def delete_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY: % formatting in SQL query
    query = "DELETE FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    conn.commit()

def safe_get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
# demo run
# demo run
# demo run
