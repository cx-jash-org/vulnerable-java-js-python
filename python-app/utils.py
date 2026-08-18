import pickle
import os
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/download")
def download_file():
    # VULNERABLE: Path Traversal
    filename = request.args.get("file")
    filepath = os.path.join("/var/data", filename)
    return send_file(filepath)


@app.route("/load")
def load_data():
    # VULNERABLE: Insecure Deserialization
    data = request.args.get("data")
    obj = pickle.loads(bytes.fromhex(data))
    return str(obj)


@app.route("/read")
def read_file():
    # VULNERABLE: Path Traversal
    file = request.args.get("name")
    with open("/uploads/" + file, "r") as f:
        return f.read()
