# vuln_input.py - Sample script with input validation vulnerabilities
# WARNING: This file is intentionally vulnerable for demonstration purposes

import os
import subprocess
import pickle

def run_command(user_input):
    # VULNERABILITY: Shell injection via unsanitized user input
    os.system("ping " + user_input)

def run_command_v2(user_input):
    # VULNERABILITY: subprocess with shell=True and unsanitized input
    subprocess.call("ls " + user_input, shell=True)

def load_data(filename):
    # VULNERABILITY: Unsafe deserialization using pickle
    with open(filename, "rb") as f:
        return pickle.load(f)

def read_file(filename):
    # VULNERABILITY: Path traversal - no validation on filename
    with open(filename, "r") as f:
        return f.read()

def evaluate_expression(expr):
    # VULNERABILITY: eval() on user-supplied input
    return eval(expr)

def safe_run_command(user_input):
    # SAFE: Use subprocess with a list (no shell=True)
    allowed = ["ls", "pwd", "whoami"]
    if user_input not in allowed:
        raise ValueError("Command not allowed")
    subprocess.call([user_input])
