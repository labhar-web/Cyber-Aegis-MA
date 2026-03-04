"""
Cyber-Aegis — Real Rate Limiter
================================
Token-bucket algorithm: each IP gets a bucket of N tokens.
Every request consumes 1 token. Tokens refill at rate R/second.
If a bucket is empty → the request is rate-limited.
Repeated violations → automatic IP ban.
"""

import time
import threading
import json
import os

class RateLimiter:
    """
    Token-Bucket Rate Limiter with automatic ban escalation.
    
    Args:
        max_rps      : max requests per second per IP  (default 20)
        burst        : max burst size                  (default 40)
        ban_after    : violations before auto-ban      (default 5)
        ban_file     : path to banned_ips.json
    """

    def __init__(self, max_rps: int = 20, burst: int = 40,
                 ban_after: int = 5, ban_file: str = None):
        self.max_rps   = max_rps
        self.burst     = burst
        self.ban_after = ban_after
        self.ban_file  = ban_file

        self._lock      = threading.Lock()
        self._buckets   = {}   # ip → {"tokens": float, "last": float}
        self._violations= {}   # ip → int count
        self._events    = []   # recent rate-limit events (for dashboard)

    # ── Public API ──────────────────────────────────────────────
    def is_allowed(self, ip: str) -> tuple[bool, dict]:
        """
        Returns (allowed: bool, info: dict).
        If allowed=False the request must be rejected with 429.
        """
        with self._lock:
            now = time.time()
            bucket = self._buckets.get(ip)

            if bucket is None:
                bucket = {"tokens": self.burst, "last": now}
                self._buckets[ip] = bucket

            # Refill tokens since last call
            elapsed = now - bucket["last"]
            bucket["tokens"] = min(
                self.burst,
                bucket["tokens"] + elapsed * self.max_rps
            )
            bucket["last"] = now

            # Consume 1 token
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return True, {"tokens_left": int(bucket["tokens"])}

            # Rate-limit triggered
            self._violations[ip] = self._violations.get(ip, 0) + 1
            violations = self._violations[ip]

            event = {
                "time":       time.strftime("%H:%M:%S"),
                "ip":         ip,
                "violations": violations
            }
            self._events.append(event)
            self._events = self._events[-50:]

            info = {"violated": True, "violations": violations}

            # Auto-ban after repeated violations
            if violations >= self.ban_after and self.ban_file:
                self._ban_ip(ip, f"Rate limit exceeded ({violations} violations)")
                info["banned"] = True

            return False, info

    def get_events(self, limit: int = 20) -> list:
        with self._lock:
            return list(self._events[-limit:])

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "tracked_ips":   len(self._buckets),
                "violations":    sum(self._violations.values()),
                "recent_events": self._events[-10:]
            }

    def reset_ip(self, ip: str):
        with self._lock:
            self._buckets.pop(ip, None)
            self._violations.pop(ip, None)

    # ── Internal ────────────────────────────────────────────────
    def _ban_ip(self, ip: str, reason: str):
        if not self.ban_file:
            return
        try:
            data = {"banned_ips": {}}
            if os.path.exists(self.ban_file):
                with open(self.ban_file) as f:
                    data = json.load(f)
            data.setdefault("banned_ips", {})[ip] = {
                "reason":     reason,
                "blocked_at": time.time(),
                "expires_at": time.time() + 3600
            }
            os.makedirs(os.path.dirname(self.ban_file), exist_ok=True)
            with open(self.ban_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"[RATE-LIMITER] Auto-banned {ip}: {reason}")
        except Exception as e:
            print(f"[RATE-LIMITER] Could not write ban file: {e}")
