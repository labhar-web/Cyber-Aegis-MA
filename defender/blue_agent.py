"""
Cyber-Aegis MA — Blue Agent (AI Defender)
==========================================
Reads paths and keys from config.json.
Monitors the WAF security log and runs the Gemini Threat Analyst.
"""

import time
import os
import re
import json
import sys
import threading

# ─── Load Central Config ─────────────────────────────────────────────────────
CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")
try:
    with open(CFG_PATH, "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    print(f"[ERROR] config.json not found at: {CFG_PATH}")
    sys.exit(1)

LOG_FILE   = CONFIG["paths"]["log_file"]
INTEL_FILE = CONFIG["paths"]["intel_file"]
API_KEY    = CONFIG["gemini_api_key"]

# ─── Gemini Client ────────────────────────────────────────────────────────────
try:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=API_KEY)
    GEMINI_AVAILABLE = True
except Exception as e:
    print(f"[BLUE AGENT] Gemini unavailable: {e}")
    GEMINI_AVAILABLE = False

# ─── IP Firewall & Threat Scorer ─────────────────────────────────────────────
try:
    from ip_firewall import IPFirewall
    from threat_scorer import ThreatScorer
    firewall = IPFirewall()
    scorer   = ThreatScorer(ban_threshold=CONFIG.get("ban_threshold", 100))
except ImportError:
    # Running from different directory — adjust sys.path
    sys.path.insert(0, os.path.dirname(__file__))
    from ip_firewall import IPFirewall
    from threat_scorer import ThreatScorer
    firewall = IPFirewall()
    scorer   = ThreatScorer(ban_threshold=CONFIG.get("ban_threshold", 100))

# ─── Shared Intel State ───────────────────────────────────────────────────────
_intel_lock = threading.Lock()

def _load_intel() -> dict:
    """Load existing intel from file (written by proxy_waf.py) or return defaults."""
    if os.path.exists(INTEL_FILE):
        try:
            with open(INTEL_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "total_requests": 0, "blocked_by_ai": 0, "blocked_by_rules": 0,
        "attacks_succeeded": 0, "patches_applied": 0,
        "recent_threats": [], "status": "MONITORING"
    }

def _save_intel(data: dict):
    os.makedirs(os.path.dirname(INTEL_FILE), exist_ok=True)
    with open(INTEL_FILE, "w") as f:
        json.dump(data, f, indent=2)

def _update_intel(key: str = None, value=None, threat_event: dict = None):
    """Thread-safe merge of an update into the intel file."""
    with _intel_lock:
        data = _load_intel()
        if key:
            data[key] = data.get(key, 0) + value if isinstance(value, int) else value
        if threat_event:
            data.setdefault("recent_threats", []).append(threat_event)
            data["recent_threats"] = data["recent_threats"][-30:]
        _save_intel(data)

# ======================================================
# THREAD 1: Log Monitor (Layer 2 — Rule-Based Watcher)
# ======================================================
def log_monitor():
    print("[LAYER 2] Log monitor started...")

    # Create log file if it doesn't exist yet
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a", encoding="utf-8").close()

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)  # Start from end — only watch NEW lines
        print("[LAYER 2] Tailing WAF security log...")

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue

            line = line.strip()

            # ── Count every classified request ──
            if "AI_CLASSIFY" in line:
                ip     = _extract(r"ip='([^']+)'", line, "0.0.0.0")
                threat = _extract(r"threat=(\S+)", line, "SAFE")
                threat = threat.rstrip("%").rstrip(",")

                # Score this IP and auto-ban if threshold exceeded
                if threat != "SAFE":
                    should_ban = scorer.add_score(ip, threat)
                    if should_ban and not firewall.is_blocked(ip):
                        firewall.block_ip(ip, f"Threat score exceeded ({threat})")
                        _update_intel(threat_event={
                            "time":  time.strftime("%H:%M:%S"),
                            "layer": "Firewall",
                            "event": f"AUTO-BANNED IP {ip} (score>={CONFIG.get('ban_threshold',100)})"
                        })
                        print(f"[FIREWALL] Auto-banned {ip}")

            # ── AI/WAF blocked a request ──
            if "AI_BLOCKED" in line:
                _update_intel("blocked_by_ai", 1, threat_event={
                    "time":  time.strftime("%H:%M:%S"),
                    "layer": "AI-WAF",
                    "event": line.split("|")[-1].strip()[:100]
                })

            # ── Honeypot triggered ──
            if "HONEYPOT_TRIGGER" in line:
                ip       = _extract(r"ip='([^']+)'",   line, "?")
                hp_path  = _extract(r"path='([^']+)'", line, "?")
                _update_intel(threat_event={
                    "time":  time.strftime("%H:%M:%S"),
                    "layer": "Honeypot",
                    "event": f"TRAP triggered by {ip} -> {hp_path}"
                })

            # ── IP ban recorded ──
            if "IP_BANNED" in line:
                ip = _extract(r"ip='([^']+)'", line, "?")
                _update_intel(threat_event={
                    "time":  time.strftime("%H:%M:%S"),
                    "layer": "Firewall",
                    "event": f"Banned IP {ip}"
                })

def _extract(pattern: str, text: str, default: str = "") -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else default

# ======================================================
# THREAD 2: Gemini Threat Intelligence Analyst
# ======================================================
ANALYST_PROMPT = """You are a cybersecurity threat intelligence analyst.
Read the recent security log lines and produce a JSON threat report.
Reply with ONLY this JSON (no markdown, no code blocks):
{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "active_attack_types": ["list", "of", "types"],
  "summary": "One sentence summary",
  "recommendation": "One sentence recommendation"
}"""

def threat_analyst():
    if not GEMINI_AVAILABLE:
        print("[ANALYST] Gemini not available, skipping.")
        return

    print("[ANALYST] Gemini Threat Intelligence Engine started...")
    interval = CONFIG.get("analyst_interval_seconds", 60)
    time.sleep(15)

    while True:
        try:
            if not os.path.exists(LOG_FILE):
                time.sleep(interval)
                continue

            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            recent = "".join(lines[-40:])
            if not recent.strip():
                time.sleep(interval)
                continue

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=f"Analyze these WAF security logs:\n\n{recent}",
                config=types.GenerateContentConfig(
                    system_instruction=ANALYST_PROMPT,
                    temperature=0.2
                )
            )

            raw = response.text.strip()
            # Strip any accidental markdown fences
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            report = json.loads(raw)
            print(f"[ANALYST] Threat Level: {report.get('threat_level')} | {report.get('summary')}")

            # Merge into intel
            with _intel_lock:
                data = _load_intel()
                data["ai_report"] = report
                _save_intel(data)

        except json.JSONDecodeError:
            print(f"[ANALYST] Could not parse Gemini response as JSON.")
        except Exception as e:
            print(f"[ANALYST] Error: {e}")

        time.sleep(interval)

# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  CYBER-AEGIS BLUE AGENT")
    print(f"  Monitoring: {LOG_FILE}")
    print(f"  Intel file: {INTEL_FILE}")
    print("=" * 60)

    t1 = threading.Thread(target=log_monitor,  daemon=True, name="LogMonitor")
    t2 = threading.Thread(target=threat_analyst, daemon=True, name="ThreatAnalyst")
    t1.start()
    t2.start()

    print("[BLUE AGENT] All defense layers active. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[BLUE AGENT] Stopped.")
