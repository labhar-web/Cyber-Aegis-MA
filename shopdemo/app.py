"""
ShopDemo — Deliberately Vulnerable E-commerce Demo
====================================================
Used to demonstrate Cyber-Aegis WAF protection.
Run alongside proxy_waf.py:
  - Direct (vulnerable):  http://localhost:3000
  - Protected (via WAF):  http://localhost:8080
"""

import sqlite3, os, html
from flask import Flask, request, render_template_string, redirect, session, g

app = Flask(__name__)
app.secret_key = "shopdemo_secret"

DB_PATH = os.path.join(os.path.dirname(__file__), "shop.db")

# ─── DB Setup ──────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'customer'
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT,
            image TEXT
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY,
            product_id INTEGER,
            author TEXT,
            content TEXT
        );
        DELETE FROM users;
        INSERT OR IGNORE INTO users VALUES (1,'admin','SuperSecret123','admin');
        INSERT OR IGNORE INTO users VALUES (2,'alice','alice2024','customer');
        INSERT OR IGNORE INTO users VALUES (3,'bob','bob1234','customer');
        DELETE FROM products;
        INSERT OR IGNORE INTO products VALUES (1,'AirPods Pro Max',299.99,'Premium wireless headphones','🎧');
        INSERT OR IGNORE INTO products VALUES (2,'UltraBook X15',1299.99,'High-performance laptop','💻');
        INSERT OR IGNORE INTO products VALUES (3,'SmartWatch Ultra',499.99,'Health-tracking smartwatch','⌚');
        INSERT OR IGNORE INTO products VALUES (4,'Gaming Mouse Pro',79.99,'3000 DPI optical mouse','🖱️');
    """)
    db.commit()
    db.close()

# ─── Base Template ─────────────────────────────────────────────────────────────
BASE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShopDemo — {{page_title}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0;
  --primary: #6366f1; --primary-d: #4f46e5;
  --danger: #ef4444; --success: #22c55e;
  --text: #1e293b; --muted: #64748b;
  --radius: 12px; --shadow: 0 4px 24px rgba(0,0,0,.08);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }

/* ── WAF Toggle Bar ── */
.waf-bar {
  position: sticky; top: 0; z-index: 1000;
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 32px;
  font-size: .82rem; font-weight: 600;
  transition: background .4s, color .4s;
}
.waf-bar.vulnerable { background: #7f1d1d; color: #fca5a5; border-bottom: 2px solid #ef4444; }
.waf-bar.protected  { background: #14532d; color: #86efac; border-bottom: 2px solid #22c55e; }

.waf-bar-left { display: flex; align-items: center; gap: 12px; }
.waf-indicator { display: flex; align-items: center; gap: 6px; font-size: .78rem; }
.waf-dot { width: 8px; height: 8px; border-radius: 50%; animation: blink 1.5s ease infinite; }
.vulnerable .waf-dot { background: #ef4444; }
.protected  .waf-dot { background: #22c55e; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.4} }

.waf-mode-label { font-size: .95rem; font-weight: 700; letter-spacing: .5px; }
.vulnerable .waf-mode-label { color: #fef2f2; }
.protected  .waf-mode-label { color: #f0fdf4; }
.waf-desc { font-size: .72rem; opacity: .8; }

.toggle-btn {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 20px; border-radius: 999px; border: none;
  font-family: 'Inter', sans-serif; font-weight: 700; font-size: .82rem;
  cursor: pointer; transition: all .25s;
}
.vulnerable .toggle-btn { background: #22c55e; color: #14532d; }
.vulnerable .toggle-btn:hover { background: #16a34a; color: white; transform: scale(1.04); }
.protected  .toggle-btn { background: #ef4444; color: #fff; }
.protected  .toggle-btn:hover { background: #dc2626; transform: scale(1.04); }

/* ── Navbar ── */
nav {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 32px;
  background: var(--surface); border-bottom: 1px solid var(--border);
  box-shadow: 0 1px 8px rgba(0,0,0,.05);
}
.nav-brand { font-size: 1.4rem; font-weight: 700; color: var(--primary); letter-spacing: -1px; }
.nav-brand span { color: var(--text); }
.nav-links { display: flex; gap: 24px; }
.nav-links a { text-decoration: none; color: var(--muted); font-weight: 500; font-size: .9rem; transition: color .2s; }
.nav-links a:hover { color: var(--primary); }
.nav-user { display: flex; align-items: center; gap: 10px; font-size: .85rem; color: var(--muted); }
.nav-user a { color: var(--primary); text-decoration: none; font-weight: 600; }

/* ── Layout ── */
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
.page-title { font-size: 1.8rem; font-weight: 700; margin-bottom: 6px; }
.page-sub { color: var(--muted); font-size: .9rem; margin-bottom: 28px; }

/* ── Cards ── */
.card {
  background: var(--surface); border-radius: var(--radius);
  border: 1px solid var(--border); box-shadow: var(--shadow);
  padding: 28px;
}

/* ── Forms ── */
.form-group { margin-bottom: 18px; }
label { display: block; font-size: .82rem; font-weight: 600; color: var(--muted); margin-bottom: 6px; letter-spacing: .3px; }
input[type=text],input[type=password],input[type=search],textarea {
  width: 100%; padding: 10px 14px;
  border: 1.5px solid var(--border); border-radius: 8px;
  font-family: 'Inter', sans-serif; font-size: .9rem; color: var(--text);
  background: var(--bg); outline: none; transition: border-color .2s;
}
input:focus, textarea:focus { border-color: var(--primary); }
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 10px 24px; border-radius: 8px; border: none;
  font-family: 'Inter', sans-serif; font-weight: 600; font-size: .9rem;
  cursor: pointer; transition: all .2s; text-decoration: none;
}
.btn-primary { background: var(--primary); color: white; }
.btn-primary:hover { background: var(--primary-d); transform: translateY(-1px); }
.btn-danger  { background: var(--danger);  color: white; }
.btn-success { background: var(--success); color: white; }

/* ── Alerts ── */
.alert { padding: 12px 16px; border-radius: 8px; font-size: .88rem; margin-top: 14px; }
.alert-danger  { background: #fef2f2; border: 1px solid #fca5a5; color: #991b1b; }
.alert-success { background: #f0fdf4; border: 1px solid #86efac; color: #166534; }
.alert-info    { background: #eff6ff; border: 1px solid #93c5fd; color: #1e40af; }

/* ── Products ── */
.products-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 20px; }
.product-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 20px 18px; text-align: center;
  transition: transform .2s, box-shadow .2s;
}
.product-card:hover { transform: translateY(-4px); box-shadow: 0 12px 32px rgba(0,0,0,.1); }
.product-emoji { font-size: 3rem; margin-bottom: 12px; }
.product-name { font-weight: 700; font-size: 1rem; margin-bottom: 4px; }
.product-price { color: var(--primary); font-weight: 700; font-size: 1.1rem; }
.product-desc { color: var(--muted); font-size: .8rem; margin: 6px 0 14px; }
.btn-cart { width: 100%; padding: 8px; background: var(--primary); color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }
.btn-cart:hover { background: var(--primary-d); }

/* ── Vuln hint ── */
.vuln-hint {
  background: #fffbeb; border: 1px dashed #f59e0b;
  border-radius: 8px; padding: 10px 14px; margin-bottom: 14px;
  font-size: .78rem; color: #92400e; font-family: monospace;
}
.protected-notice {
  background: #f0fdf4; border: 1px solid #86efac;
  border-radius: 8px; padding: 10px 14px; margin-bottom: 14px;
  font-size: .78rem; color: #166534;
}

/* ── Reviews ── */
.review { padding: 12px 0; border-bottom: 1px solid var(--border); }
.review-author { font-weight: 600; font-size: .85rem; }
.review-content { font-size: .88rem; color: var(--muted); margin-top: 4px; }
</style>
</head>
<body>

<!-- ═══ WAF Toggle Bar ═══════════════════════════════════════ -->
<div class="waf-bar {{waf_class}}" id="waf-bar">
  <div class="waf-bar-left">
    <div class="waf-indicator">
      <span class="waf-dot"></span>
      <span class="waf-mode-label" id="waf-mode-label">
        {{waf_mode_label}}
      </span>
    </div>
    <span class="waf-desc" id="waf-desc">{{waf_desc}}</span>
  </div>
  <div style="display:flex;align-items:center;gap:16px;">
    <span style="opacity:.7;font-size:.75rem;">Cyber-Aegis WAF</span>
    <button class="toggle-btn" onclick="toggleWAF()">
      {{toggle_icon}} {{toggle_label}}
    </button>
  </div>
</div>

<!-- ═══ Navbar ═══════════════════════════════════════════════ -->
<nav>
  <div class="nav-brand">Shop<span>Demo</span></div>
  <div class="nav-links">
    <a href="{{base}}/">🏠 Home</a>
    <a href="{{base}}/search">🔍 Search</a>
    <a href="{{base}}/products">🛍️ Products</a>
    <a href="{{base}}/attack" style="color:#ef4444;font-weight:700;">⚔️ Attack Lab</a>
    {% if session.get('user') %}
    <a href="{{base}}/account">👤 {{session.user}}</a>
    <a href="{{base}}/logout">Logout</a>
    {% else %}
    <a href="{{base}}/login">Login</a>
    {% endif %}
  </div>
</nav>

<!-- ═══ Content ═══════════════════════════════════════════════ -->
{% block content %}{% endblock %}

<script>
// Read current mode from localStorage
const PROTECTED_BASE = "http://localhost:8080";
const VULNERABLE_BASE = "http://localhost:3000";
let protected_mode = localStorage.getItem("waf_mode") === "protected";

function applyMode() {
  const bar   = document.getElementById("waf-bar");
  const label = document.getElementById("waf-mode-label");
  const desc  = document.getElementById("waf-desc");
  if (protected_mode) {
    bar.className   = "waf-bar protected";
    label.textContent = "🟢 WAF PROTECTED";
    desc.textContent  = "All traffic filtered by Cyber-Aegis AI";
  } else {
    bar.className   = "waf-bar vulnerable";
    label.textContent = "🔴 VULNERABLE MODE";
    desc.textContent  = "Direct access — no protection active";
  }
}

function toggleWAF() {
  protected_mode = !protected_mode;
  localStorage.setItem("waf_mode", protected_mode ? "protected" : "vulnerable");
  // Redirect to same path on the correct base URL
  const path = window.location.pathname + window.location.search;
  const newBase = protected_mode ? PROTECTED_BASE : VULNERABLE_BASE;
  window.location.href = newBase + path;
}

// On load, sync bar state
applyMode();

// Fix all links to use correct base
document.querySelectorAll("a[href]").forEach(a => {
  const href = a.getAttribute("href");
  if (href && href.startsWith("/")) {
    const base = protected_mode ? PROTECTED_BASE : VULNERABLE_BASE;
    a.href = base + href;
  }
});
// Fix all forms
document.querySelectorAll("form[action]").forEach(form => {
  const action = form.getAttribute("action");
  if (action && action.startsWith("/")) {
    const base = protected_mode ? PROTECTED_BASE : VULNERABLE_BASE;
    form.action = base + action;
  }
});
</script>
</body>
</html>
"""

# ─── Home Page ─────────────────────────────────────────────────────────────────
HOME_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<div class="container">
  <div class="page-title">🛍️ Welcome to ShopDemo</div>
  <p class="page-sub">Your favorite online store — featuring the latest tech gadgets.</p>

  <div class="products-grid">
    {% for p in products %}
    <div class="product-card">
      <div class="product-emoji">{{p['image']}}</div>
      <div class="product-name">{{p['name']}}</div>
      <div class="product-desc">{{p['description']}}</div>
      <div class="product-price">${{p['price']}}</div>
      <button class="btn-cart" style="margin-top:10px;">Add to Cart 🛒</button>
    </div>
    {% endfor %}
  </div>
</div>
""")

# ─── Login Page ────────────────────────────────────────────────────────────────
LOGIN_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<div class="container" style="max-width:440px;">
  <div class="card">
    <h2 style="margin-bottom:4px;">Account Login</h2>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:20px;">Sign in to your ShopDemo account</p>

    <div class="vuln-hint">
      ⚠️ <b>VULNERABLE:</b> Try: username = <code>' OR '1'='1' --</code>  password = <code>anything</code>
    </div>

    {% if error %}
    <div class="alert alert-danger">{{error}}</div>
    {% endif %}
    {% if success %}
    <div class="alert alert-success">{{success}}</div>
    {% endif %}

    {% if result %}
    <div class="alert alert-info" style="font-family:monospace;font-size:.8rem;">
      <b>SQL Result:</b> {{result}}
    </div>
    {% endif %}

    <form method="POST" action="/login">
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter username" value="{{username}}">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password">
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;">Login →</button>
    </form>

    <p style="margin-top:16px;font-size:.8rem;color:var(--muted);">
      Test accounts: <code>admin / SuperSecret123</code> · <code>alice / alice2024</code>
    </p>
  </div>
</div>
""")

# ─── Search Page ───────────────────────────────────────────────────────────────
SEARCH_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<div class="container">
  <div class="page-title">🔍 Search Products</div>
  <p class="page-sub">Find what you're looking for.</p>

  <div class="vuln-hint">
    ⚠️ <b>VULNERABLE (XSS):</b> Try: <code>&lt;img src=x onerror="alert('XSS Hacked!')"&gt;</code>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <form method="GET" action="/search">
      <div style="display:flex;gap:10px;">
        <input type="search" name="q" value="{{query}}" placeholder="Search products..." style="flex:1;">
        <button type="submit" class="btn btn-primary">Search</button>
      </div>
    </form>
  </div>

  {% if query %}
  <div style="margin-bottom:14px;color:var(--muted);font-size:.9rem;">
    Results for: <b>{{query_raw|safe}}</b>
  </div>
  {% if results %}
  <div class="products-grid">
    {% for p in results %}
    <div class="product-card">
      <div class="product-emoji">{{p['image']}}</div>
      <div class="product-name">{{p['name']}}</div>
      <div class="product-price">${{p['price']}}</div>
      <button class="btn-cart">Add to Cart 🛒</button>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="alert alert-info">No products found for "{{query}}"</div>
  {% endif %}
  {% endif %}
</div>
""")

# ─── Attack Control Panel ─────────────────────────────────────────────────────
ATTACK_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<style>
.attack-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:0}
.attack-log{background:#0f172a;border-radius:10px;padding:16px;min-height:220px;max-height:340px;
  overflow-y:auto;font-family:monospace;font-size:.8rem;color:#94a3b8;}
.log-line{padding:3px 0;border-bottom:1px solid #1e293b;}
.log-blocked{color:#f87171;} .log-pass{color:#4ade80;} .log-info{color:#60a5fa;}
.attack-type-btn{padding:8px 16px;border:2px solid var(--border);border-radius:8px;
  background:white;cursor:pointer;font-weight:600;font-size:.82rem;transition:all .2s;}
.attack-type-btn.active,.attack-type-btn:hover{border-color:var(--primary);background:var(--primary);color:white;}
.progress-bar{height:6px;background:#e2e8f0;border-radius:4px;margin-top:8px;overflow:hidden;}
.progress-fill{height:100%;background:var(--primary);border-radius:4px;width:0%;transition:width .3s;}
</style>

<div class="container">
  <div class="page-title">⚔️ Attack Control Panel</div>
  <p class="page-sub">Switch between Manual and Automated attack modes to test the WAF.</p>

  <!-- Mode Toggle -->
  <div style="display:flex;gap:10px;margin-bottom:24px;">
    <button class="attack-type-btn active" id="btn-manual" onclick="setMode('manual')">👤 Manual Attack</button>
    <button class="attack-type-btn" id="btn-auto" onclick="setMode('auto')">🤖 Auto Attack</button>
  </div>

  <!-- ─── MANUAL MODE ─── -->
  <div id="panel-manual">
    <div class="attack-grid">
      <!-- SQLi -->
      <div class="card">
        <h3 style="margin-bottom:4px;">💉 SQL Injection</h3>
        <p style="font-size:.8rem;color:var(--muted);margin-bottom:16px;">Inject into the login form username field</p>
        <div class="vuln-hint" style="margin-bottom:12px;">Target: <b id="sqli-target">localhost:3000/login</b></div>
        <div class="form-group">
          <label>SQLi Payload</label>
          <input type="text" id="sqli-payload" value="' OR '1'='1' --" style="font-family:monospace;">
        </div>
        <div class="form-group">
          <label>Password (any)</label>
          <input type="text" id="sqli-pass" value="anything123">
        </div>
        <button class="btn btn-danger" onclick="runManualSQLi()">💥 Send SQLi</button>
        <div id="sqli-result" style="margin-top:12px;"></div>
      </div>

      <!-- XSS -->
      <div class="card">
        <h3 style="margin-bottom:4px;">🎭 XSS Injection</h3>
        <p style="font-size:.8rem;color:var(--muted);margin-bottom:16px;">Inject script into the search field</p>
        <div class="vuln-hint" style="margin-bottom:12px;">Target: <b id="xss-target">localhost:3000/search</b></div>
        <div class="form-group">
          <label>XSS Payload</label>
          <input type="text" id="xss-payload" value='<img src=x onerror="alert(\"XSS!\")">'
            style="font-family:monospace;">
        </div>
        <button class="btn btn-danger" onclick="runManualXSS()">💥 Send XSS</button>
        <div id="xss-result" style="margin-top:12px;"></div>
      </div>
    </div>
  </div>

  <!-- ─── AUTO MODE ─── -->
  <div id="panel-auto" style="display:none;">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <h3>🤖 Automated Attack Storm</h3>
          <p style="font-size:.8rem;color:var(--muted);">Fires all payloads automatically — watch Dashboard react</p>
        </div>
        <div style="display:flex;gap:10px;">
          <button class="btn btn-danger" id="auto-btn" onclick="runAutoAttack()">▶ Start Auto Attack</button>
          <button class="btn" style="background:#64748b;color:white;" onclick="clearLog()">🗑 Clear</button>
        </div>
      </div>

      <div style="display:flex;gap:16px;margin-bottom:12px;font-size:.82rem;">
        <span>Total: <b id="stat-total">0</b></span>
        <span style="color:#f87171;">Blocked: <b id="stat-blocked">0</b></span>
        <span style="color:#4ade80;">Passed: <b id="stat-passed">0</b></span>
      </div>
      <div class="progress-bar"><div class="progress-fill" id="auto-progress"></div></div>

      <div class="attack-log" id="auto-log" style="margin-top:12px;">
        <span class="log-info">↑ Click Start to begin automated attacks...</span>
      </div>
    </div>
  </div>
</div>

<script>
const WAF_BASE  = "http://localhost:8080";
const VULN_BASE = "http://localhost:3000";
const protected_mode = localStorage.getItem("waf_mode") === "protected";
const BASE_URL = protected_mode ? WAF_BASE : VULN_BASE;

// Update target labels
document.getElementById("sqli-target").textContent =
  (protected_mode ? "localhost:8080" : "localhost:3000") + "/login";
document.getElementById("xss-target").textContent =
  (protected_mode ? "localhost:8080" : "localhost:3000") + "/search?q=payload";

function setMode(mode) {
  document.getElementById("panel-manual").style.display = mode==="manual"?"":"none";
  document.getElementById("panel-auto").style.display   = mode==="auto"?"":"none";
  document.getElementById("btn-manual").className = "attack-type-btn" + (mode==="manual"?" active":"");
  document.getElementById("btn-auto").className   = "attack-type-btn" + (mode==="auto"?" active":"");
}

function showResult(elId, status, msg) {
  const el = document.getElementById(elId);
  const cls = status===403?"alert-danger":status===200?"alert-success":"alert-info";
  const icon = status===403?"🛡️ BLOCKED":status===200?"💥 PASSED":"⚠️ ";
  el.innerHTML = `<div class="alert ${cls}">${icon} (${status}) — ${msg}</div>`;
}

async function runManualSQLi() {
  const payload  = document.getElementById("sqli-payload").value;
  const password = document.getElementById("sqli-pass").value;
  showResult("sqli-result",0,"Sending...");
  try {
    const r = await fetch(BASE_URL+"/login", {
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:`username=${encodeURIComponent(payload)}&password=${encodeURIComponent(password)}`
    });
    const txt = await r.text();
    const summary = txt.includes("Logged in")? "Login bypassed! Admin access gained 💀" :
                    txt.includes("blocked")   ? "WAF blocked the attack"               :
                                                "Login failed (credentials wrong)";
    showResult("sqli-result", r.status, summary);
  } catch(e) { showResult("sqli-result",0,"Error: "+e.message); }
}

async function runManualXSS() {
  const payload = document.getElementById("xss-payload").value;
  showResult("xss-result",0,"Sending...");
  try {
    const r = await fetch(BASE_URL+"/search?q="+encodeURIComponent(payload));
    const txt = await r.text();
    const reflected = txt.includes(payload.substring(1,10));
    const summary = r.status===403? "WAF blocked the XSS" :
                    reflected      ? "XSS reflected in page! (popup would fire in browser)" :
                                     "Response received";
    showResult("xss-result", r.status, summary);
  } catch(e) { showResult("xss-result",0,"Error: "+e.message); }
}

// ─── AUTO ATTACK ───────────────────────────────────────────────────────────────
const AUTO_PAYLOADS = [
  {type:"SQLi",  url:"/login", method:"POST",
   body:"username=%27+OR+%271%27%3D%271%27+--&password=anything"},
  {type:"SQLi",  url:"/login", method:"POST",
   body:"username=admin%27+--&password=x"},
  {type:"SQLi",  url:"/login", method:"POST",
   body:"username=%27+UNION+SELECT+1%2C2%2C3+--&password=x"},
  {type:"XSS",   url:"/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", method:"GET", body:null},
  {type:"XSS",   url:"/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", method:"GET", body:null},
  {type:"XSS",   url:"/search?q=javascript%3Aalert(1)", method:"GET", body:null},
  {type:"Honeypot", url:"/admin",              method:"GET", body:null},
  {type:"Honeypot", url:"/.env",               method:"GET", body:null},
  {type:"CMD",   url:"/search?q=%3Bcat+%2Fetc%2Fpasswd", method:"GET", body:null},
  {type:"DIR",   url:"/search?q=..%2F..%2Fetc%2Fpasswd", method:"GET", body:null},
  {type:"Brute", url:"/login", method:"POST", body:"username=admin&password=123456"},
  {type:"Brute", url:"/login", method:"POST", body:"username=admin&password=password"},
];

let autoRunning = false;
let stats = {total:0, blocked:0, passed:0};

function logLine(cls, msg) {
  const log = document.getElementById("auto-log");
  const d = document.createElement("div");
  d.className = "log-line " + cls;
  d.textContent = new Date().toLocaleTimeString() + " " + msg;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

function updateStats() {
  document.getElementById("stat-total").textContent   = stats.total;
  document.getElementById("stat-blocked").textContent = stats.blocked;
  document.getElementById("stat-passed").textContent  = stats.passed;
  const pct = stats.total ? Math.round(stats.total / AUTO_PAYLOADS.length*100) : 0;
  document.getElementById("auto-progress").style.width = pct+"%";
}

function clearLog() {
  document.getElementById("auto-log").innerHTML = "";
  stats = {total:0, blocked:0, passed:0};
  updateStats();
}

async function runAutoAttack() {
  if (autoRunning) return;
  autoRunning = true;
  clearLog();
  const btn = document.getElementById("auto-btn");
  btn.textContent = "⏳ Running...";
  btn.disabled = true;

  logLine("log-info", `Target: ${BASE_URL} | Mode: ${protected_mode ? "PROTECTED":"VULNERABLE"}`);
  logLine("log-info", `Firing ${AUTO_PAYLOADS.length} attack payloads...`);

  for (const p of AUTO_PAYLOADS) {
    await new Promise(r => setTimeout(r, 400));
    try {
      const opts = {method: p.method};
      if (p.body) {
        opts.headers = {"Content-Type":"application/x-www-form-urlencoded"};
        opts.body = p.body;
      }
      const r = await fetch(BASE_URL + p.url, opts);
      stats.total++;
      if (r.status === 403) {
        stats.blocked++;
        logLine("log-blocked", `🛡️ BLOCKED [${p.type}] ${p.url} → 403`);
      } else {
        stats.passed++;
        logLine("log-pass", `💥 PASSED  [${p.type}] ${p.url} → ${r.status}`);
      }
    } catch(e) {
      stats.total++;
      logLine("log-info", `⚠ ERROR [${p.type}] ${e.message.substring(0,50)}`);
    }
    updateStats();
  }

  const rate = Math.round(stats.blocked/stats.total*100);
  logLine("log-info",
    `✅ Done! Blocked ${stats.blocked}/${stats.total} (${rate}% block rate)`);
  btn.textContent = "▶ Start Auto Attack";
  btn.disabled = false;
  autoRunning = false;
}
</script>
""")

# ─── Routes ────────────────────────────────────────────────────────────────────
def render(tmpl, **kw):
    mode = request.cookies.get("waf_mode", "vulnerable")
    protected = mode == "protected"
    base = "http://localhost:8080" if protected else "http://localhost:3000"
    kw.update(
        waf_class      = "protected" if protected else "vulnerable",
        waf_mode_label = "🟢 WAF PROTECTED" if protected else "🔴 VULNERABLE MODE",
        waf_desc       = "Traffic filtered by Cyber-Aegis AI" if protected else "Direct — no WAF active",
        toggle_icon    = "🔓" if protected else "🛡️",
        toggle_label   = "Disable WAF" if protected else "Enable WAF",
        base           = base,
        page_title     = kw.get("page_title", "ShopDemo"),
    )
    return render_template_string(tmpl, **kw)

@app.route("/")
def home():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render(HOME_TMPL, products=products, page_title="Home")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # ⚠️ INTENTIONALLY VULNERABLE — SQLi
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            row = db.execute(query).fetchone()
            if row:
                session["user"] = row["username"]
                session["role"] = row["role"]
                return render(LOGIN_TMPL,
                    page_title="Login",
                    success=f"✅ Logged in as [{row['username']}] — Role: {row['role']}",
                    result=f"Query: {query}",
                    username=username,
                    error=None)
            else:
                return render(LOGIN_TMPL,
                    page_title="Login",
                    error="Invalid credentials.",
                    result=f"Query: {query}",
                    username=username,
                    success=None)
        except Exception as e:
            return render(LOGIN_TMPL,
                page_title="Login",
                error=f"DB Error: {e}",
                result=f"Query: {query}",
                username=username,
                success=None)

    return render(LOGIN_TMPL, page_title="Login", error=None, success=None, result=None, username="")

@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        db = get_db()
        results = db.execute(
            "SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)
        ).fetchall()
    # ⚠️ INTENTIONALLY VULNERABLE — XSS: query reflected without escaping
    query_raw = q   # rendered with |safe in template
    return render(SEARCH_TMPL, page_title="Search", query=html.escape(q),
                  query_raw=query_raw, results=results)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/products")
def products():
    db = get_db()
    prods = db.execute("SELECT * FROM products").fetchall()
    return render(HOME_TMPL, products=prods, page_title="Products")

@app.route("/attack")
def attack():
    return render(ATTACK_TMPL, page_title="Attack Lab")

# ─── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 55)
    print("  ShopDemo — Vulnerable E-commerce Demo")
    print("  Direct (vulnerable):  http://localhost:3000")
    print("  Protected (via WAF):  http://localhost:8080")
    print("=" * 55)
    app.run(host="0.0.0.0", port=3000, debug=False)
