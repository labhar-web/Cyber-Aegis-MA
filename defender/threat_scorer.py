from collections import defaultdict
import time

class ThreatScorer:
    def __init__(self, ban_threshold: int = 100):
        self.scores = defaultdict(int)
        self.ban_threshold = ban_threshold

    def add_score(self, ip: str, threat_type: str) -> bool:
        """
        Adds score to an IP based on the threat type.
        Returns True if the IP crossed the ban threshold.
        """
        if threat_type.upper() == "SQLI":
            self.scores[ip] += 50
        elif threat_type.upper() == "XSS":
            self.scores[ip] += 40
        elif threat_type.upper() in ["BRUTE_FORCE", "AUTH_FAIL"]:
            self.scores[ip] += 10
        elif threat_type.upper() == "FUZZING":
            self.scores[ip] += 20
        elif threat_type.upper() in ["HONEYPOT_TRIGGER", "CANARY_USE"]:
            self.scores[ip] += 100 # Instant Ban
        elif threat_type.upper() in ["CMD_INJECTION", "DIR_TRAVERSAL"]:
            self.scores[ip] += 60
        else:
            self.scores[ip] += 5

        print(f"[SCORER] IP={ip} added score for {threat_type}. Total={self.scores[ip]}/{self.ban_threshold}")

        if self.scores[ip] >= self.ban_threshold:
            return True
        return False
