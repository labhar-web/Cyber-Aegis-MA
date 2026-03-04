"""
Cyber-Aegis — Behavioral Anomaly Detector
==========================================
Learns the "normal" baseline behavior of each IP and flags deviations.

Two engines run simultaneously:
  1. Statistical Z-Score Engine  — fast, no dependencies, always on.
  2. Isolation Forest ML Engine  — scikit-learn based, flags outliers.

The combined score (0.0–1.0) is stored per IP and served to the dashboard.
"""

import time
import threading
import math
import json
from collections import defaultdict, deque

# ─── Optional ML imports ──────────────────────────────────────
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[ANOMALY] scikit-learn not found — using Z-Score engine only.")

# ─────────────────────────────────────────────────────────────
class BehaviorProfile:
    """Tracks a sliding window of metrics for one IP."""
    WINDOW = 120  # seconds to keep data

    def __init__(self):
        self.requests     = deque()    # timestamps
        self.error_count  = 0
        self.path_set     = set()
        self.user_agents  = set()
        self.post_count   = 0
        self.threat_count = 0

    def record(self, ts: float, path: str, method: str,
               ua: str, is_threat: bool, is_error: bool):
        now = time.time()
        # Prune old entries
        while self.requests and now - self.requests[0] > self.WINDOW:
            self.requests.popleft()
        self.requests.append(ts)
        self.path_set.add(path)
        self.user_agents.add(ua)
        if method == "POST": self.post_count += 1
        if is_threat:        self.threat_count += 1
        if is_error:         self.error_count  += 1

    def feature_vector(self) -> list:
        """Return a numeric feature vector for ML."""
        rps = len(self.requests) / max(1, BehaviorProfile.WINDOW)
        return [
            rps,                        # requests per second
            len(self.path_set),         # unique paths visited
            len(self.user_agents),      # unique user agents used
            self.post_count,            # POST requests count
            self.threat_count,          # threats triggered
            self.error_count,           # errors caused
        ]


class AnomalyDetector:
    """
    Combines Z-Score + Isolation Forest to score each IP.
    Score 0.0 = perfectly normal. Score 1.0 = highly anomalous.
    """
    RETRAIN_INTERVAL = 300   # seconds between model retrains

    def __init__(self):
        self._lock       = threading.Lock()
        self._profiles   : dict[str, BehaviorProfile] = defaultdict(BehaviorProfile)
        self._scores     : dict[str, float] = {}
        self._events     : list  = []

        # Statistical baseline
        self._baseline_history : deque = deque(maxlen=1000)

        # ML model
        self._model      = None
        self._last_train = 0

        if ML_AVAILABLE:
            threading.Thread(target=self._retrain_loop,
                             daemon=True, name="IsoForestTrainer").start()

    # ── Public API ──────────────────────────────────────────────
    def record_request(self, ip: str, path: str, method: str = "GET",
                       ua: str = "", is_threat: bool = False,
                       is_error: bool = False):
        with self._lock:
            prof = self._profiles[ip]
            prof.record(time.time(), path, method, ua, is_threat, is_error)
            vec  = prof.feature_vector()
            self._baseline_history.append(vec)

        # Score this IP
        score = self._compute_score(ip, vec)
        with self._lock:
            prev  = self._scores.get(ip, 0.0)
            self._scores[ip] = round(score, 3)

            if score > 0.65 and score > prev + 0.1:
                event = {
                    "time":  time.strftime("%H:%M:%S"),
                    "ip":    ip,
                    "score": round(score, 2),
                    "label": self._label(score)
                }
                self._events.append(event)
                self._events = self._events[-50:]

        return score

    def get_score(self, ip: str) -> float:
        with self._lock:
            return self._scores.get(ip, 0.0)

    def get_all_scores(self) -> dict:
        with self._lock:
            return dict(sorted(self._scores.items(),
                               key=lambda x: x[1], reverse=True))

    def get_events(self, limit: int = 20) -> list:
        with self._lock:
            return list(self._events[-limit:])

    def get_stats(self) -> dict:
        with self._lock:
            scores = list(self._scores.values())
            high   = sum(1 for s in scores if s > 0.65)
            return {
                "tracked_ips":    len(self._profiles),
                "high_anomalies": high,
                "ml_active":      ML_AVAILABLE and self._model is not None,
                "recent_events":  self._events[-10:]
            }

    def get_learning_status(self) -> dict:
        """Return the current adaptive baseline for UI visualization."""
        with self._lock:
            n = len(self._baseline_history)
            FEATURE_NAMES = ["Req/s", "Unique Paths", "User Agents",
                             "POST Count", "Threats", "Errors"]
            if n < 5:
                return {
                    "samples": n,
                    "ready":   False,
                    "threshold": 0.8,
                    "features": [{"name": f, "mean": 0, "std": 0}
                                 for f in FEATURE_NAMES]
                }
            history = list(self._baseline_history)
            means   = [sum(h[i] for h in history) / n for i in range(6)]
            stds    = [
                math.sqrt(sum((h[i] - means[i])**2 for h in history) / n)
                for i in range(6)
            ]
            # Adaptive threshold: tighten as more samples are collected
            adaptive_t = max(0.65, 0.95 - (n / 2000))
            return {
                "samples":   n,
                "ready":     n >= 30,
                "threshold": round(adaptive_t, 3),
                "features": [
                    {"name": FEATURE_NAMES[i],
                     "mean": round(means[i], 4),
                     "std":  round(stds[i], 4)}
                    for i in range(6)
                ]
            }

    # ── Internal scoring ─────────────────────────────────────────
    def _compute_score(self, ip: str, vec: list) -> float:
        scores = []

        # 1. Z-Score engine
        z = self._zscore_score(vec)
        scores.append(z)

        # 2. Isolation Forest
        if ML_AVAILABLE and self._model is not None:
            try:
                import numpy as np
                pred = self._model.decision_function([vec])[0]
                # decision_function: negative = anomalous, positive = normal
                # Map to 0..1 (higher = more anomalous)
                iso = max(0.0, min(1.0, -pred + 0.5))
                scores.append(iso)
            except Exception:
                pass

        return sum(scores) / len(scores) if scores else 0.0

    def _zscore_score(self, vec: list) -> float:
        """Z-Score: how far is this vector from the population mean?"""
        if len(self._baseline_history) < 10:
            return 0.0
        try:
            # compute per-feature mean and std
            n      = len(self._baseline_history)
            means  = [sum(h[i] for h in self._baseline_history) / n
                      for i in range(len(vec))]
            stds   = [
                math.sqrt(sum((h[i] - means[i]) ** 2
                              for h in self._baseline_history) / n) + 1e-6
                for i in range(len(vec))
            ]
            zscores = [abs((vec[i] - means[i]) / stds[i]) for i in range(len(vec))]
            avg_z   = sum(zscores) / len(zscores)
            # Sigmoid-like mapping: z=2 → 0.7, z=3 → 0.9
            return max(0.0, min(1.0, avg_z / (avg_z + 1.5)))
        except Exception:
            return 0.0

    def _retrain_loop(self):
        """Periodically retrain the Isolation Forest model."""
        while True:
            time.sleep(self.RETRAIN_INTERVAL)
            self._retrain()

    def _retrain(self):
        with self._lock:
            data = list(self._baseline_history)
        if len(data) < 30:
            return
        try:
            import numpy as np
            X = np.array(data, dtype=float)
            model = IsolationForest(n_estimators=50, contamination=0.15,
                                    random_state=42)
            model.fit(X)
            with self._lock:
                self._model = model
            print(f"[ANOMALY] Isolation Forest retrained on {len(data)} samples.")
        except Exception as e:
            print(f"[ANOMALY] Retrain error: {e}")

    @staticmethod
    def _label(score: float) -> str:
        if score < 0.40: return "NORMAL"
        if score < 0.65: return "SUSPICIOUS"
        if score < 0.85: return "HIGH"
        return "CRITICAL"
