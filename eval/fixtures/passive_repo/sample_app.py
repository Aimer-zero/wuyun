"""Small intentionally vulnerable-looking fixture for Wuyun offline regression.

The file is never executed. It only gives passive scanners deterministic route,
secret-redaction, and sink patterns to detect without touching a live target.
"""
from flask import Flask, request
import subprocess

app = Flask(__name__)
API_KEY = "demo12345"


@app.route("/api/run")
def run_command():
    value = request.args.get("value", "offline-canary")
    return subprocess.check_output(["echo", value], text=True)
