"""
Cyber-Aegis — System State Engine
===================================
Computes the overall operational threat level of the WAF system
by aggregating multiple risk signals into a single composite score.

Threat Levels:
  GREEN  — Normal / No significant activity
  YELLOW — Elevated / Suspicious activity detected
  ORANGE — High / Active attack in progress
  RED    — Critical / System under heavy attack

Called by proxy_waf.py and exposed via /waf/api/state
"""

import math
import time
import os
import json
import threading
from collections import deque


class SystemState:
    """
    Computes a composite Global Threat Level from live WAF telemetry.

    Signals used:
      1. blocked_ratio     → % of requests that were blocked
      2. attack_frequency  → attacks per minute (rolling 60s window)
      3. avg_anomaly_score → mean anomaly score of active IPs
      4. banned_ip_growth  → rate of new IP bans
      5. honeypot_hits     → any honeypot trigger = instant escalation
    """

    LEVELS = ["GREEN", "YELLOW", "ORANGE", "RED"]

    LEVEL_COLORS = {
        "GREEN":  "#3fb950",
        "YELLOW": "#d29922",
        "ORANGE": "#f0883e",
        "RED":    "#f85149",
    }

    def __init__(self, intel_file: str, banned_file: str):
        self._intel_file  = intel_file
        self._banned_file = banned_file
        self._lock        = threading.Lock()

        # Rolling windows
        self._request_ts  = deque()  # timestamps of all requests (60s window)
        self._blocked_ts  = deque()  # timestamps of blocked requests
        self._honeypot_ts = deque()  # honeypot hits in last 60s

        # Cached state
        self._state = {
            "level":           "GREEN",
            "color":           self.LEVEL_COLORS["GREEN"],
            "score":           0.0,
            "signals": {
                "blocked_ratio":    0.0,
                "attack_frequency": 0.0,
                "avg_anomaly":      0.0,
                "banned_growth":    0,
                "honeypot_hits":    0,
            },
            "summary":    "System nominal — no significant activity.",
            "updated_at": time.strftime("%H:%M:%S"),
        }

        self._prev_banned_count = 0

        # Start background refresh
        threading.Thread(target=self._refresh_loop,
                         daemon=True, name="SystemState").start()

    # ── Public API ────────────────────────────────────────────────
    def record_request(self, blocked: bool = False, honeypot: bool = False):
        """Call this for every incoming request."""
        now = time.time()
        with self._lock:
            self._request_ts.append(now)
            if blocked:   self._blocked_ts.append(now)
            if honeypot:  self._honeypot_ts.append(now)
            self._prune(now)

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)

    # ── Background Refresh ────────────────────────────────────────
    def _refresh_loop(self):
        while True:
            try:
                self._compute()
            except Exception as e:
                print(f"[STATE] compute error: {e}")
            time.sleep(5)

    def _compute(self):
        now = time.time()
        with self._lock:
            self._prune(now)
            n_req     = len(self._request_ts)
            n_blocked = len(self._blocked_ts)
            n_honey   = len(self._honeypot_ts)

        # ── Signal 1: Blocked ratio (0..1) ──
        blocked_ratio = n_blocked / max(n_req, 1)

        # ── Signal 2: Attack frequency (attacks/min) ──
        attack_freq = n_blocked * (60 / 60)   # in 60s window

        # ── Signal 3: Avg anomaly from scores ──
        avg_anomaly = self._read_avg_anomaly()

        # ── Signal 4: Banned IP growth rate ──
        banned_count = self._read_banned_count()
        with self._lock:
            growth = max(0, banned_count - self._prev_banned_count)
            self._prev_banned_count = banned_count

        # ── Composite score (weighted) ──
        score = (
            blocked_ratio   * 0.35 +
            min(1.0, attack_freq / 30) * 0.25 +
            avg_anomaly     * 0.25 +
            min(1.0, growth / 5) * 0.10 +
            min(1.0, n_honey / 2) * 0.05
        )

        # Honeypot = always at least ORANGE
        if n_honey > 0 and score < 0.5:
            score = max(score, 0.5)

        # Map score → level
        if score < 0.20:
            level = "GREEN"
            summary = "System nominal — traffic is within normal parameters."
        elif score < 0.45:
            level = "YELLOW"
            summary = f"Elevated activity — {n_blocked} requests blocked in the last 60s."
        elif score < 0.70:
            level = "ORANGE"
            summary = f"Active attack detected — blocking {int(blocked_ratio*100)}% of traffic."
        else:
            level = "RED"
            summary = f"CRITICAL — system under heavy attack. {n_blocked} blocked, {banned_count} IPs banned!"

        with self._lock:
            self._state = {
                "level":  level,
                "color":  self.LEVEL_COLORS[level],
                "score":  round(score, 3),
                "signals": {
                    "blocked_ratio":    round(blocked_ratio, 3),
                    "attack_frequency": round(attack_freq, 1),
                    "avg_anomaly":      round(avg_anomaly, 3),
                    "banned_growth":    growth,
                    "honeypot_hits":    n_honey,
                },
                "summary":    summary,
                "updated_at": time.strftime("%H:%M:%S"),
            }

    # ── Helpers ───────────────────────────────────────────────────
    def _prune(self, now: float, window: float = 60.0):
        for dq in (self._request_ts, self._blocked_ts, self._honeypot_ts):
            while dq and now - dq[0] > window:
                dq.popleft()

    def _read_avg_anomaly(self) -> float:
        """Read current anomaly scores from the WAF (shared via module ref)."""
        # The detector reference is injected by proxy_waf
        if hasattr(self, "_anomaly_ref") and self._anomaly_ref is not None:
            scores = self._anomaly_ref.get_all_scores()
            if scores:
                return sum(scores.values()) / len(scores)
        return 0.0

    def _read_banned_count(self) -> int:
        if not os.path.exists(self._banned_file):
            return 0
        try:
            with open(self._banned_file) as f:
                data = json.load(f)
            return len(data.get("banned_ips", {}))
        except Exception:
            return 0

    def inject_anomaly_detector(self, detector):
        """Inject the anomaly detector instance for direct score reading."""
        self._anomaly_ref = detector
