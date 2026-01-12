import os
import sqlite3
import subprocess
import logging
import hashlib
from flask import Flask, request, jsonify, abort
from werkzeug.security import check_password_hash

app = Flask(__name__)

API_KEY = os.environ.get("API_KEY")
SAFE_DIRECTORY = os.path.abspath("safe_files")

logging.basicConfig(level=logging.INFO)

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/auth", methods=["POST"])
def auth():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        return jsonify({"status": "authenticated"})
    return jsonify({"status": "denied"}), 401

@app.route("/exec", methods=["POST"])
def exec_cmd():
    cmd_key = request.json.get("cmd")
    allowed_commands = {
        "uptime": ["/usr/bin/uptime"],
        "df": ["/bin/df", "-h"]
    }
    
    if cmd_key not in allowed_commands:
        abort(403)

    output = subprocess.check_output(allowed_commands[cmd_key], shell=False)
    return jsonify({"output": output.decode()})

@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.get_json()
    return jsonify({"status": "received", "data": data})

@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.json.get("text", "")
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return jsonify({"hash": hashed})

@app.route("/file", methods=["POST"])
def read_file():
    filename = request.json.get("filename")
    if not filename:
        abort(400)
        
    target_path = os.path.abspath(os.path.join(SAFE_DIRECTORY, filename))
    
    if not target_path.startswith(SAFE_DIRECTORY):
        abort(403)
        
    if not os.path.exists(target_path):
        abort(404)

    with open(target_path, "r") as f:
        return jsonify({"content": f.read()})

@app.route("/log", methods=["POST"])
def log_data():
    data = request.json.get("data", "")
    sanitized = str(data).replace('\n', '').replace('\r', '')
    logging.info(f"User log entry: {sanitized}")
    return jsonify({"status": "logged"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)