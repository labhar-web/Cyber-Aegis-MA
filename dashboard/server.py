"""
Cyber-Aegis MA — Dashboard API Server
=======================================
Serves the professional web UI and provides real-time data endpoints.
"""

import json
import os
import time
import threading
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# ─── Config ───────────────────────────────────────────────────────────────────
CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")
with open(CFG_PATH, "r") as f:
    CONFIG = json.load(f)

DASHBOARD_PORT = CONFIG["dashboard_port"]
INTEL_FILE     = CONFIG["paths"]["intel_file"]
BANNED_FILE    = CONFIG["paths"]["banned_file"]
LOG_FILE       = CONFIG["paths"]["log_file"]
STATIC_DIR     = os.path.join(os.path.dirname(__file__), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
CORS(app)

# ─── Helpers ──────────────────────────────────────────────────────────────────
def load_json(path: str, default=None):
    if default is None:
        default = {}
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def parse_log_stats(path: str) -> dict:
    stats = {"sqli": 0, "xss": 0, "cmd": 0, "dir": 0, "brute": 0, "honeypot": 0}
    if not os.path.exists(path):
        return stats
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            l = line.upper()
            if "AI_BLOCKED" in line or "BLOCKED" in line:
                if "SQLI" in l:     stats["sqli"] += 1
                elif "XSS" in l:    stats["xss"] += 1
                elif "CMD" in l:    stats["cmd"] += 1
                elif "DIR" in l:    stats["dir"] += 1
                elif "BRUTE" in l:  stats["brute"] += 1
                elif "HONEY" in l:  stats["honeypot"] += 1
    return stats

# ─── API Routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/api/stats")
def api_stats():
    intel     = load_json(INTEL_FILE)
    banned    = load_json(BANNED_FILE).get("banned_ips", {})
    log_stats = parse_log_stats(LOG_FILE)
    config    = load_json(CFG_PATH)
    return jsonify({
        "intel":      intel,
        "banned_ips": banned,
        "log_stats":  log_stats,
        "config":     {
            "target_url":    config.get("target_url"),
            "waf_port":      config.get("waf_port"),
            "ban_threshold": config.get("ban_threshold")
        },
        "server_time": time.strftime("%H:%M:%S")
    })

@app.route("/api/unban", methods=["POST"])
def api_unban():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    data = load_json(BANNED_FILE, {"banned_ips": {}})
    if ip in data.get("banned_ips", {}):
        del data["banned_ips"][ip]
        with open(BANNED_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return jsonify({"success": True, "message": f"IP {ip} unbanned."})
    return jsonify({"error": "IP not found in ban list"}), 404

@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        return jsonify(load_json(CFG_PATH))
    data = load_json(CFG_PATH)
    updates = request.json or {}
    data.update(updates)
    with open(CFG_PATH, "w") as f:
        json.dump(data, f, indent=2)
    return jsonify({"success": True})

@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 50))
    if not os.path.exists(LOG_FILE):
        return jsonify({"lines": []})
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return jsonify({"lines": [l.strip() for l in lines[-limit:] if l.strip()]})

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  CYBER-AEGIS DASHBOARD")
    print(f"  Open in browser: http://localhost:{DASHBOARD_PORT}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, threaded=True)
