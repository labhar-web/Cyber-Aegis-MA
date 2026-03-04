# 🛡️ Cyber-Aegis MA

> **AI-Powered Web Application Firewall** — نظام جدار حماية تطبيقات الويب المعزز بالذكاء الاصطناعي

![Version](https://img.shields.io/badge/version-1.0--PoC-6366f1)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Status](https://img.shields.io/badge/status-Proof%20of%20Concept-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 📌 What is Cyber-Aegis MA?

Cyber-Aegis MA is a smart Reverse Proxy that sits between users and your web application, inspecting every HTTP request through **5 cascading defense layers** — from instant IP banning to deep Gemini AI analysis — to detect and block web attacks in real time.

---

## 🏗️ Architecture

```
🌐 Client / Attacker
        │
        ▼
┌────────────────────────────────────┐
│       Cyber-Aegis WAF :8080        │
│                                    │
│  L0   → IP Firewall   (<0.1ms)     │
│  L0.5 → Rate Limiter  (Token Bucket│
│  L1   → Regex WAF     (SQLi/XSS..) │
│  L1.5 → ML Anomaly    (IsoForest)  │
│  L2   → Gemini AI     (async)      │
└────────────────────────────────────┘
        │
        ▼ (if safe)
🏪 Target App :3000

📊 SOC Dashboard :5050  (real-time monitoring)
```

---

## 🔒 Defense Layers

| Layer | Name | Technology | Latency |
|-------|------|-----------|---------|
| 0 | IP Firewall | JSON Blacklist | < 0.1ms |
| 0.5 | Rate Limiter | Token Bucket (20 req/s) | < 1ms |
| 1 | Regex WAF | SQLi, XSS, CMD, Dir Traversal | ~1ms |
| 1.5 | ML Anomaly | Isolation Forest + Z-Score | ~5ms |
| 2 | Gemini AI | Gemini 2.5 Flash (async) | non-blocking |

---

## 📁 Project Structure

```
Cyber-Aegis MA/
├── proxy_waf.py          # WAF core — Reverse Proxy engine
├── config.json           # Configuration (target URL, thresholds)
├── requirements.txt      # Python dependencies
├── run_demo.cmd          # One-click full launch (with demo guide)
├── run_all.cmd           # Quick launch (no guide)
│
├── attacker/
│   └── red_agent.py      # Automated attack simulator (Red Team)
│
├── defender/
│   ├── anomaly_detector.py  # ML anomaly detection
│   ├── blue_agent.py        # Nightly AI security analyst
│   ├── ip_firewall.py       # IP ban/whitelist management
│   ├── rate_limiter.py      # Token Bucket rate limiting
│   ├── system_state.py      # Global threat level (GREEN→RED)
│   └── threat_scorer.py     # Per-IP threat scoring
│
├── dashboard/
│   ├── server.py         # Dashboard API server
│   └── static/
│       └── index.html    # SOC Dashboard UI
│
└── shopdemo/
    └── app.py            # Intentionally vulnerable demo app
```

---

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Launch Everything
```cmd
run_demo.cmd
```

This starts:
| Service | URL | Purpose |
|---------|-----|---------|
| ShopDemo (victim app) | http://localhost:3000 | Vulnerable target |
| Cyber-Aegis WAF | http://localhost:8080 | Protected proxy |
| SOC Dashboard | http://localhost:5050 | Real-time monitoring |

---

## 🎬 Demo Scenario

### Step 1 — Show the Vulnerability (No WAF)
```
URL: http://localhost:3000/login
Username: ' OR '1'='1' --
Password: anything
→ Result: Login bypassed! 🔓
```

### Step 2 — Enable Protection (WAF Active)
```
URL: http://localhost:8080/login
Username: ' OR '1'='1' --
Password: anything
→ Result: 403 Forbidden — Blocked! 🛡️
```

### Step 3 — Auto Attack Lab
```
URL: http://localhost:3000/attack → Auto Attack → ▶ Start
→ 12 attacks fired → 9+ blocked (75%+ block rate) 🎯
```

---

## 🤖 Agents

### 🔵 Blue Agent (`defender/blue_agent.py`)
- Runs nightly analysis of all security logs
- Uses Gemini AI to generate a human-readable threat report
- Identifies attack patterns, top offending IPs, and trends

### 🔴 Red Agent (`attacker/red_agent.py`)
- Simulates a botnet of 5 IPs
- Fires SQLi, XSS, Brute Force, and directory traversal attacks
- Reports block/pass statistics to validate WAF effectiveness

---

## ⚙️ Configuration (`config.json`)

```json
{
  "target_url": "http://localhost:3000",
  "rate_limit": { "max_requests": 20, "window_seconds": 1 },
  "brute_force": { "max_fails": 5, "window_seconds": 120 },
  "gemini_api_key": "YOUR_KEY_HERE"
}
```

---

## 🗺️ Roadmap

| Phase | Status | Features |
|-------|--------|----------|
| v1.0 — PoC | ✅ Done | 5-layer WAF, ML anomaly, Gemini AI, SOC Dashboard, Attack Lab |
| v2.0 | ⏭️ Next | HTTPS/TLS, GeoIP blocking, Email/Telegram alerts |
| v3.0 | 🔭 Future | Custom AI model (CICIDS2017), Zero-Day detection, Federated Learning, SaaS deployment |

---

## 📋 Requirements

```
flask
requests
flask-cors
google-generativeai
scikit-learn
numpy
```

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

<div align="center">
  <strong>Cyber-Aegis MA</strong> — Built with 🛡️ for a safer web
</div>
