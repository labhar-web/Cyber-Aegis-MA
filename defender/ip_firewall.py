import os
import json
import time

class IPFirewall:
    def __init__(self, db_path=r"c:\Cyber-Aegis MA\target_app\banned_ips.json"):
        self.db_path = db_path
        self._ensure_db()

    def _ensure_db(self):
        if not os.path.exists(self.db_path):
            with open(self.db_path, "w") as f:
                json.dump({"banned_ips": {}}, f)

    def is_blocked(self, ip: str) -> bool:
        with open(self.db_path, "r") as f:
            data = json.load(f)
        return ip in data.get("banned_ips", {})

    def block_ip(self, ip: str, reason: str, duration_sec: int = 3600):
        with open(self.db_path, "r") as f:
            data = json.load(f)
        
        data.setdefault("banned_ips", {})[ip] = {
            "reason": reason,
            "blocked_at": time.time(),
            "expires_at": time.time() + duration_sec
        }
        
        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=4)
        
        print(f"[FIREWALL] IP Blocked: {ip} | Reason: {reason}")
