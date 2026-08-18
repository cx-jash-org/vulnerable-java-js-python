import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

# VULNERABLE: Hardcoded secret
SECRET_KEY = "django-insecure-abc123xyz456secret"
DATABASE_PASSWORD = "admin123"


@app.route("/user")
def get_user():
    # VULNERABLE: SQL Injection
    user_id = request.args.get("id")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # String concatenation - SAST will flag this
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

    return str(cursor.fetchall())


@app.route("/exec")
def run_command():
    # VULNERABLE: Command Injection
    cmd = request.args.get("cmd")
    result = os.system("ls " + cmd)
    return str(result)


@app.route("/run")
def run_subprocess():
    # VULNERABLE: Command Injection via subprocess with shell=True
    user_input = request.args.get("input")
    output = subprocess.check_output("echo " + user_input, shell=True)
    return output.decode()


if __name__ == "__main__":
    # VULNERABLE: Debug mode enabled
    app.run(debug=True, host="0.0.0.0")
