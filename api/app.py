from flask import Flask, request, abort
import sqlite3
import pickle
import subprocess
import hashlib
import os
import logging
import json

app = Flask(__name__)

# SECRET HARDCODÉ (mauvaise pratique)
#API_KEY = "API-KEY-123456"
API_KEY = os.environ.get("API_KEY")


# Logging non sécurisé
#logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.INFO)



@app.route("/auth", methods=["POST"])
def auth():
    username = request.json.get("username")
    password = request.json.get("password")

    # SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    #query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(
    "SELECT * FROM users WHERE username=? AND password=?",
    (username, password)
)


    if cursor.fetchone():
        return {"status": "authenticated"}
    return {"status": "denied"}


@app.route("/exec", methods=["POST"])
def exec_cmd():
    #cmd = request.json.get("cmd")
    # Command Injection
    #output = subprocess.check_output(cmd, shell=True)
    #return {"output": output.decode()}
    return {"error": "Command execution disabled"}, 403



@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.data
    # Désérialisation dangereuse
    #obj = pickle.loads(data)
    obj = json.loads(data)
    return {"object": str(obj)}
    


@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.json.get("text", "")
    # Chiffrement faible
    #hashed = hashlib.md5(text.encode()).hexdigest()
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return {"hash": hashed}


@app.route("/file", methods=["POST"])
def read_file():
    filename = request.json.get("filename")
    # Path Traversal
    #with open(filename, "r") as f:
     #   return {"content": f.read()}
    BASE_DIR = "/safe/files"

    path = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not path.startswith(BASE_DIR):
       abort(403)

    with open(path, "r") as f:
        return f.read()



@app.route("/debug", methods=["GET"])
def debug():
    # Divulgation d'informations sensibles
    #return {
     #   "api_key": API_KEY,
      #  "env": dict(os.environ),
       # "cwd": os.getcwd()
    #}
    return {"status": "debug disabled"}, 403



@app.route("/log", methods=["POST"])
def log_data():
    data = request.json
    # Log Injection
    #logging.info(f"User input: {data}")
    logging.info("User input received")

    return {"status": "logged"}


if __name__ == "__main__":
    #app.run(host="0.0.0.0", port=5000, debug=True)
    app.run(host="0.0.0.0", port=5000, debug=False)
