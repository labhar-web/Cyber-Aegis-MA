"""
Cyber-Aegis MA — Reverse Proxy WAF Engine
==========================================
This script acts as a transparent reverse proxy in front of any HTTP/HTTPS
website. All incoming traffic is inspected by multiple security layers before
being forwarded to the real target.

Usage:
  Edit config.json → Set "target_url" → Run this script.
  Traffic to http://localhost:8080 is now protected.
"""

import json
import os
import re
import sys
import time
import queue
import logging
import threading
import requests
from flask import Flask, request, jsonify, Response

# ─── Add defender/ to path for imports ───────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "defender"))
from rate_limiter     import RateLimiter
from anomaly_detector import AnomalyDetector
from system_state     import SystemState

# ─── Load Config ──────────────────────────────────────────────────────────────
CFG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
with open(CFG_PATH, "r") as f:
    CONFIG = json.load(f)

TARGET_URL      = CONFIG["target_url"].rstrip("/")
WAF_PORT        = CONFIG["waf_port"]
API_KEY         = CONFIG["gemini_api_key"]
LOG_FILE        = CONFIG["paths"]["log_file"]
INTEL_FILE      = CONFIG["paths"]["intel_file"]
BANNED_FILE     = CONFIG["paths"]["banned_file"]
BAN_THRESHOLD   = CONFIG["ban_threshold"]
SCORING         = CONFIG["scoring"]
GEM_COOLDOWN    = CONFIG.get("gemini_cooldown_seconds", 20)
RL_CFG          = CONFIG.get("rate_limit",  {"max_rps": 20, "burst": 40, "ban_after": 5})

# ─── Initialize Security Engines ─────────────────────────────────────────────
rate_limiter = RateLimiter(
    max_rps  = RL_CFG.get("max_rps",  20),
    burst    = RL_CFG.get("burst",    40),
    ban_after= RL_CFG.get("ban_after", 5),
    ban_file = BANNED_FILE
)
anomaly_detector = AnomalyDetector()
system_state     = SystemState(
    intel_file  = BANNED_FILE.replace("banned_ips.json", "") + "/../threat_intel.json",
    banned_file = BANNED_FILE
)
system_state.inject_anomaly_detector(anomaly_detector)

# ─── Logging ──────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - WAF - %(levelname)s - %(message)s"
)
logger = logging.getLogger("CyberAegisWAF")

app = Flask(__name__)

# ─── CORS — allow cross-origin fetch from Attack Lab / Dashboard ───────────────
@app.after_request
def add_cors(response):
    """Allow any localhost origin to call WAF endpoints (Dashboard + Attack Lab)."""
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Forwarded-For"
    return response


# ─── WAF Patterns ─────────────────────────────────────────────────────────────
SQLI_PATTERNS = [
    r"('\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+)",
    r"('\s*--|'\s*#)",
    r"(UNION\s+SELECT)",
    r"(;\s*DROP|;\s*DELETE|;\s*INSERT)",
    r"('\s*OR\s+\d+=\d+)",
    r"(LIMIT\s+\d+\s*--)",
]
XSS_PATTERNS  = [r"<script[\s\S]*?>", r"javascript\s*:", r"on\w+\s*="]
CMD_PATTERNS  = [r";\s*(cat|ls|dir|wget|curl|nc|bash|sh|cmd|powershell)\b",
                 r"\|\|?\s*(cat|ls|dir|wget|curl|nc|bash|sh|cmd|powershell)\b",
                 r"&\s*(cat|ls|dir|wget|curl|nc|bash|sh|cmd|powershell)\b"]
DIR_PATTERNS  = [r"\.\./", r"\.\.\\", r"file://"]

SQLI_RE = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)
XSS_RE  = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)
CMD_RE  = re.compile("|".join(CMD_PATTERNS), re.IGNORECASE)
DIR_RE  = re.compile("|".join(DIR_PATTERNS), re.IGNORECASE)

HONEYPOT_PATHS = {
    "/api/admin/backup", "/hidden/passwords.txt",
    "/admin/backup.sql", "/.env", "/wp-admin/install.php",
    "/admin", "/admin/", "/phpmyadmin", "/phpmyadmin/",
    "/shell", "/config", "/setup", "/install",
    "/.git", "/.htaccess", "/server-status", "/xmlrpc.php",
}

# ─── Brute Force Tracking ─────────────────────────────────────────────────────
_brute_lock = threading.Lock()
_failed_logins: dict = {}   # {ip: {"count": int, "first": timestamp}}
BRUTE_MAX_FAILS   = 5       # block after 5 failures
BRUTE_WINDOW_SECS = 120     # within 2 minutes

def record_failed_login(ip: str) -> bool:
    """Returns True if IP should be banned for brute force."""
    now = time.time()
    with _brute_lock:
        entry = _failed_logins.get(ip, {"count": 0, "first": now})
        # Reset window if expired
        if now - entry["first"] > BRUTE_WINDOW_SECS:
            entry = {"count": 0, "first": now}
        entry["count"] += 1
        _failed_logins[ip] = entry
        return entry["count"] >= BRUTE_MAX_FAILS

def local_classify(combined: str) -> dict:
    if SQLI_RE.search(combined):
        return {"threat": "SQLi",          "confidence": 95, "source": "local"}
    if XSS_RE.search(combined):
        return {"threat": "XSS",           "confidence": 95, "source": "local"}
    if CMD_RE.search(combined):
        return {"threat": "CMD_INJECTION",  "confidence": 90, "source": "local"}
    if DIR_RE.search(combined):
        return {"threat": "DIR_TRAVERSAL",  "confidence": 85, "source": "local"}
    return {"threat": "SAFE",              "confidence": 90, "source": "local"}

# ─── Gemini Async Worker ──────────────────────────────────────────────────────
GEMINI_AVAILABLE = False
gemini_queue = queue.Queue(maxsize=10)
_last_gemini_call = 0
_genai_client = None

try:
    from google import genai
    from google.genai import types
    _genai_client = genai.Client(api_key=API_KEY)
    GEMINI_AVAILABLE = True
except Exception:
    pass

CLASSIFIER_PROMPT = """You are a Web Application Firewall.
Classify the request payload and reply with ONLY valid JSON:
{"threat": "SAFE|SQLi|XSS|CMD_INJECTION|DIR_TRAVERSAL|FUZZING|AUTH_BYPASS", "confidence": 0-100, "type": "description"}"""

def gemini_worker():
    global _last_gemini_call
    while True:
        try:
            req_id, payload = gemini_queue.get(timeout=5)
            now = time.time()
            if now - _last_gemini_call < GEM_COOLDOWN:
                gemini_queue.task_done()
                continue
            _last_gemini_call = now
            response = _genai_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=f"Analyze this request payload:\n{payload[:500]}",
                config=types.GenerateContentConfig(
                    system_instruction=CLASSIFIER_PROMPT, temperature=0.1)
            )
            raw = response.text.strip()
            # Strip markdown code fences if Gemini wraps in ```json ... ```
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()
            if not raw:
                gemini_queue.task_done()
                continue
            result = json.loads(raw)
            print(f"[GEMINI-ASYNC] {result.get('threat')} ({result.get('confidence')}%) | {result.get('type','')}")
            gemini_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[GEMINI-ASYNC] Error: {e}")
            try:
                gemini_queue.task_done()
            except Exception:
                pass

if GEMINI_AVAILABLE:
    threading.Thread(target=gemini_worker, daemon=True).start()

# ─── IP Firewall helpers ──────────────────────────────────────────────────────
_ban_lock = threading.Lock()
_score_map: dict = {}

def get_ip(req) -> str:
    xff = req.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else req.remote_addr

def load_banned() -> dict:
    if not os.path.exists(BANNED_FILE):
        return {}
    try:
        with open(BANNED_FILE) as f:
            return json.load(f).get("banned_ips", {})
    except Exception:
        return {}

def ban_ip(ip: str, reason: str):
    with _ban_lock:
        data = {"banned_ips": load_banned()}
        data["banned_ips"][ip] = {
            "reason": reason,
            "blocked_at": time.time(),
            "expires_at": time.time() + 3600
        }
        os.makedirs(os.path.dirname(BANNED_FILE), exist_ok=True)
        with open(BANNED_FILE, "w") as f:
            json.dump(data, f, indent=2)
    logger.warning(f"IP_BANNED | ip='{ip}' | reason='{reason}'")
    print(f"[FIREWALL] BANNED: {ip} — {reason}")
    _update_intel("ip_banned", ip)

def score_ip(ip: str, threat: str) -> bool:
    with _ban_lock:
        pts = SCORING.get(threat.upper(), 5)
        _score_map[ip] = _score_map.get(ip, 0) + pts
        print(f"[SCORER] {ip} score={_score_map[ip]}/{BAN_THRESHOLD} (+{pts} for {threat})")
        return _score_map[ip] >= BAN_THRESHOLD

# ─── Intel file helpers ───────────────────────────────────────────────────────
_intel_lock = threading.Lock()
_intel = {
    "total_requests": 0, "blocked_by_ai": 0, "blocked_by_rules": 0,
    "attacks_succeeded": 0, "patches_applied": 0,
    "recent_threats": [], "status": "MONITORING"
}

def _update_intel(event: str, detail: str = ""):
    with _intel_lock:
        if event == "request":
            _intel["total_requests"] += 1
        elif event == "blocked":
            _intel["blocked_by_ai"] += 1
            _intel["recent_threats"].append({
                "time": time.strftime("%H:%M:%S"), "layer": "WAF", "event": detail
            })
            _intel["recent_threats"] = _intel["recent_threats"][-30:]
        elif event == "ip_banned":
            _intel["recent_threats"].append({
                "time": time.strftime("%H:%M:%S"), "layer": "Firewall", "event": f"Banned IP {detail}"
            })
        os.makedirs(os.path.dirname(INTEL_FILE), exist_ok=True)
        with open(INTEL_FILE, "w") as f:
            json.dump(_intel, f, indent=2)

# ─── Main Proxy Handler ───────────────────────────────────────────────────────
# IPs that are never banned (local machine, trusted network)
TRUSTED_IPS = {"127.0.0.1", "::1", "localhost"}

@app.before_request
def firewall_gate():
    # Handle CORS preflight early — before any WAF logic
    if request.method == "OPTIONS":
        from flask import Response
        return Response(status=204, headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Forwarded-For",
        })
    ip = get_ip(request)
    if ip in TRUSTED_IPS:
        return  # Never block trusted local IPs
    if ip in load_banned():
        logger.warning(f"FIREWALL_BLOCK | ip='{ip}' | path='{request.path}'")
        return jsonify({"error": "Your IP has been blocked by Cyber-Aegis WAF."}), 403

@app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
@app.route("/<path:path>",             methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
def proxy(path):
    ip = get_ip(request)
    _update_intel("request")
    system_state.record_request()  # signal: normal request

    # ── Layer 0.5: Rate Limiter ──────────────────────────────────
    allowed, rl_info = rate_limiter.is_allowed(ip)
    if not allowed:
        violations = rl_info.get("violations", 0)
        logger.warning(f"RATE_LIMIT | ip='{ip}' | violations={violations}")
        _update_intel("blocked", f"Rate limit exceeded by {ip} (v={violations})")
        print(f"[RATE-LIMIT] {ip} — violation #{violations}")
        system_state.record_request(blocked=True)
        return jsonify({
            "error": "Too many requests. Slow down.",
            "retry_after": "1s"
        }), 429

    # ── Honeypot check ──
    if "/" + path in HONEYPOT_PATHS or request.path in HONEYPOT_PATHS:
        logger.critical(f"HONEYPOT_TRIGGER | ip='{ip}' | path='{request.path}'")
        print(f"[HONEYPOT] TRAP TRIGGERED by {ip} → {request.path}")
        system_state.record_request(blocked=True, honeypot=True)
        if score_ip(ip, "HONEYPOT_TRIGGER"):
            ban_ip(ip, f"Touched honeypot: {request.path}")
        return jsonify({"error": "Forbidden"}), 403

    # ── Collect payload (URL-decode everything so %27 etc. don't bypass) ─
    from urllib.parse import unquote_plus
    body_text  = request.get_data(as_text=True)
    body_decoded = unquote_plus(body_text)          # decode %27 → '  etc.
    qs           = unquote_plus(request.query_string.decode(errors="ignore"))
    # Also grab form field values directly (handles multipart)
    form_vals  = " ".join(str(v) for v in request.form.values())
    args_vals  = " ".join(str(v) for v in request.args.values())
    combined   = f"{request.path} {qs} {args_vals} {body_decoded} {form_vals}"

    # ── Layer 1: Local WAF ──
    clf = local_classify(combined)
    threat     = clf["threat"]
    confidence = clf["confidence"]
    source     = clf["source"]

    logger.info(f"AI_CLASSIFY [{source}] | ip='{ip}' | path='{request.path}' | threat={threat} | conf={confidence}%")
    print(f"[WAF] {threat} ({confidence}%) | ip='{ip}' | {request.method} /{path}")

    if threat != "SAFE" and confidence >= 70:
        logger.warning(f"AI_BLOCKED | ip='{ip}' | threat='{threat}'")
        _update_intel("blocked", f"{threat} from {ip}")
        system_state.record_request(blocked=True)
        if score_ip(ip, threat):
            ban_ip(ip, f"Accumulated threat score exceeded ({threat})")
        return jsonify({
            "status": "blocked",
            "message": "Request blocked by Cyber-Aegis AI Security.",
            "threat": threat
        }), 403

    # ── Layer 1.5: Anomaly Detection ─────────────────────────────
    ua          = request.headers.get("User-Agent", "")
    is_threat   = (threat != "SAFE")
    anomaly_score = anomaly_detector.record_request(
        ip, request.path, request.method, ua, is_threat, False
    )
    if anomaly_score > 0.80:
        logger.warning(f"ANOMALY_BLOCK | ip='{ip}' | score={anomaly_score:.2f}")
        _update_intel("blocked", f"Behavioral anomaly ({anomaly_score:.0%}) from {ip}")
        print(f"[ANOMALY] BLOCKED {ip} — score={anomaly_score:.2f}")
        if score_ip(ip, "FUZZING"):
            ban_ip(ip, f"Anomalous behavior detected (score={anomaly_score:.2f})")
        return jsonify({
            "status":  "blocked",
            "message": "Anomalous behavior detected by Cyber-Aegis AI.",
            "score":   round(anomaly_score, 3)
        }), 403

    # ── Layer 2: Queue for Gemini async ──
    if GEMINI_AVAILABLE:
        try:
            gemini_queue.put_nowait((id(request), combined))
        except queue.Full:
            pass

    # ── Forward to real target ──
    try:
        target = f"{TARGET_URL}/{path}"
        headers = {k: v for k, v in request.headers if k.lower() != "host"}
        headers["X-Forwarded-For"] = ip
        headers["X-Protected-By"]  = "Cyber-Aegis-WAF"

        resp = requests.request(
            method=request.method,
            url=target,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15
        )

        excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        response_headers = [(k, v) for k, v in resp.raw.headers.items()
                            if k.lower() not in excluded]

        # ── Brute Force: track failed logins ──────────────────────────────────
        is_login = request.path.rstrip("/") in ("/login", "/api/login")
        if is_login and request.method == "POST" and ip not in TRUSTED_IPS:
            resp_text = resp.text
            login_failed = resp.status_code == 200 and (
                "Invalid credentials" in resp_text or
                "Login failed"        in resp_text or
                "Incorrect"           in resp_text
            )
            if login_failed:
                should_ban = record_failed_login(ip)
                logger.warning(f"BRUTE_ATTEMPT | ip='{ip}' | count={_failed_logins.get(ip, {}).get('count', '?')}")
                if should_ban:
                    ban_ip(ip, "Brute force — too many failed logins")
                    system_state.record_request(blocked=True)
                    return jsonify({
                        "status":  "blocked",
                        "message": "Too many failed login attempts. IP banned.",
                        "threat":  "BRUTE_FORCE"
                    }), 403

        return Response(resp.content, status=resp.status_code, headers=response_headers)

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Target website is unreachable."}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Anomaly & Rate Limit API ─────────────────────────────────────────────────
@app.route("/waf/api/anomalies")
def waf_anomalies():
    return jsonify({
        "scores":  anomaly_detector.get_all_scores(),
        "stats":   anomaly_detector.get_stats(),
        "events":  anomaly_detector.get_events(30)
    })

@app.route("/waf/api/rate-limits")
def waf_rate_limits():
    return jsonify(rate_limiter.get_stats())

@app.route("/waf/api/learning")
def waf_learning():
    return jsonify(anomaly_detector.get_learning_status())

@app.route("/waf/api/state")
def waf_state():
    return jsonify(system_state.get_state())

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  CYBER-AEGIS WAF — Reverse Proxy Engine")
    print(f"  Protecting: {TARGET_URL}")
    print(f"  WAF listening on: http://0.0.0.0:{WAF_PORT}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=WAF_PORT, debug=False, threaded=True)
