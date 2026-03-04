import requests
import time
import random
import sys

TARGET_BASE = "http://127.0.0.1:5000"
TARGET_LOGIN = f"{TARGET_BASE}/api/login"
TARGET_SEARCH = f"{TARGET_BASE}/api/search"

NORMAL_USERS = [
    ("user1", "pass123"),
    ("admin", "wrong_pass"),
    ("guest", "guest"),
]

# Simulate a botnet of 5 IPs
BOTNET_IPS = [
    f"{random.randint(11, 200)}.{random.randint(1, 200)}.{random.randint(1, 200)}.100"
    for _ in range(5)
]

# Attack payloads grouped by type
SQLI_PAYLOADS = [
    ("' OR '1'='1",        "SQLi - OR bypass"),
    ("admin' --",          "SQLi - comment bypass"),
    ("' OR 1=1 LIMIT 1 --","SQLi - LIMIT bypass"),
    ("admin' #",           "SQLi - hash comment"),
    ("' UNION SELECT 1,2,3,4,5 --", "SQLi - UNION probe"),
]

XSS_PAYLOADS = [
    ("<script>alert('XSS')</script>", "XSS - script tag"),
    ("javascript:alert(1)",           "XSS - javascript URI"),
    ("<img src=x onerror=alert(1)>",  "XSS - img onerror"),
    ("<svg onload=alert(1)>",         "XSS - svg onload"),
]

BRUTE_FORCE_PASSWORDS = [
    "123456", "password", "admin", "letmein", "qwerty",
    "abc123", "monkey", "master", "dragon", "111111",
]

ATTACK_TYPES = ["sqli", "xss", "brute_force", "normal"]

stats = {"blocked": 0, "succeeded": 0, "errors": 0, "total": 0}

def send(url, data, label, attack_type, ip):
    stats["total"] += 1
    headers = {"X-Forwarded-For": ip}
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=5)
        code = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:100]}

        if code == 403:
            stats["blocked"] += 1
            ai = body.get('ai_analysis', {})
            print(f"[BLOCKED-{code}] {label} -> {ai.get('threat','?')} ({ai.get('confidence','?')}%)")
        elif code == 200:
            stats["succeeded"] += 1
            role = body.get("role", "?")
            print(f"[SUCCESS-{code}] {label} -> role={role} | data={body.get('sensitive_data', '-')}")
        elif code == 401:
            print(f"[DENIED-{code}]  {label}")
        elif code == 403 and "blocked" in body.get("message", "").lower():
             print(f"[FIREWALL-{code}] IP {ip} is banned!")
        elif code == 403 and body.get("error") == "Access Denied.":
             print(f"[HONEYPOT-{code}] Trap triggered by {ip}!")
        elif code == 500:
            stats["errors"] += 1
            print(f"[VULN-{code}]   SQL Error! {label}")
        else:
            stats["errors"] += 1
            print(f"[ERROR-{code}]   {label} -> {body}")
    except requests.exceptions.ConnectionError:
        print(f"[DOWN]  Target App is down. Waiting...")
        time.sleep(3)
    except requests.exceptions.Timeout:
        print(f"[TIMEOUT] {label}")
    except Exception as e:
        print(f"[EXCEPTION] {label}: {e}")

def run_attack():
    print("[RED AGENT] Cyber-Aegis MA Attacker Starting...")
    print(f"[RED AGENT] Target: {TARGET_BASE}")
    print("[RED AGENT] Press Ctrl+C to stop.\n")

    round_num = 0
    while True:
        round_num += 1
        current_ip = random.choice(BOTNET_IPS)
        attack_type = random.choices(
            ATTACK_TYPES, weights=[15, 10, 10, 10, 10, 10, 5, 30]
        )[0]

        if attack_type == "normal":
            user, pw = random.choice(NORMAL_USERS)
            send(TARGET_LOGIN, {"username": user, "password": pw},
                 f"NORMAL | user={user}", "normal", current_ip)

        elif attack_type == "sqli":
            payload, desc = random.choice(SQLI_PAYLOADS)
            send(TARGET_LOGIN, {"username": payload, "password": "any"},
                 f"SQLI   | {desc}", "sqli", current_ip)

        elif attack_type == "xss":
            payload, desc = random.choice(XSS_PAYLOADS)
            send(TARGET_LOGIN, {"username": payload, "password": "x"},
                 f"XSS    | {desc}", "xss", current_ip)

        elif attack_type == "cmd":
            payload, desc = random.choice(CMD_PAYLOADS)
            send(TARGET_LOGIN, {"username": payload, "password": "x"},
                 f"CMD    | {desc}", "cmd", current_ip)

        elif attack_type == "dir":
            payload, desc = random.choice(DIR_PAYLOADS)
            send(TARGET_LOGIN, {"username": payload, "password": "x"},
                 f"DIR    | {desc}", "dir", current_ip)

        elif attack_type == "brute_force":
            pw = random.choice(BRUTE_FORCE_PASSWORDS)
            send(TARGET_LOGIN, {"username": "admin", "password": pw},
                 f"BRUTE  | admin:{pw}", "brute", current_ip)

        elif attack_type == "honeypot":
            url = random.choice(HONEYPOT_URLS)
            send(url, {"info": "probe"},
                 f"PROBE  | {url}", "honeypot", current_ip)
                 
        elif attack_type == "canary":
            send(TARGET_LOGIN, {"username": "admin", "password": CANARY_TOKEN},
                 f"CANARY | used stolen token", "canary", current_ip)

        # Print stats every 20 rounds
        if round_num % 20 == 0:
            total = stats["total"]
            rate = (stats["blocked"] / total * 100) if total else 0
            print(f"\n[STATS] Total={total} | Blocked={stats['blocked']} ({rate:.0f}%) | Succeeded={stats['succeeded']} | Errors={stats['errors']}\n")

        time.sleep(1.2)

if __name__ == "__main__":
    try:
        run_attack()
    except KeyboardInterrupt:
        print("\n[RED AGENT] Stopped by user.")
        total = stats["total"]
        if total:
            rate = (stats["blocked"] / total * 100)
            print(f"[STATS] Final: Total={total} | Blocked={stats['blocked']} ({rate:.0f}%) | Succeeded={stats['succeeded']}")
        sys.exit(0)
