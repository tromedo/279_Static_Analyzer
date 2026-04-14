# vuln_auth.py - Sample script with hardcoded secrets vulnerabilities
# WARNING: This file is intentionally vulnerable for demonstration purposes

import requests
import hashlib

# VULNERABILITY: Hardcoded API key
API_KEY = "sk-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"

# VULNERABILITY: Hardcoded password
DB_PASSWORD = "admin1234"

# VULNERABILITY: Hardcoded secret token
SECRET_TOKEN = "hardcoded_jwt_secret_do_not_use"

# VULNERABILITY: Hardcoded AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def authenticate(password):
    # VULNERABILITY: MD5 used for password hashing (weak algorithm)
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed == DB_PASSWORD

def fetch_data(endpoint):
    # VULNERABILITY: API key hardcoded in headers
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(endpoint, headers=headers)
    return response.json()

def safe_authenticate(password, stored_hash):
    # SAFE: Use bcrypt or similar (placeholder)
    import hashlib, os
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key
