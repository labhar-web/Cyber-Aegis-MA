/**
 * Cyber-Aegis WAF — Dashboard JS
 * Premium real-time dashboard for the WAF Command Center.
 */

const API = "";          // dashboard API (same origin)
const WAF = "http://localhost:8080"; // WAF proxy API

let allLogs = [];
let currentConfig = {};
let prevBanned = 0;
let prevBlocked = 0;
let prevTotal = 0;

// Training samples history for threshold chart
const thresholdHistory = [];

// ─── Chart.js Instances ──────────────────────────────────────────────────────
let timelineChart = null;
let donutChart = null;
let threshChart = null;

const TIMELINE_MAX_POINTS = 30;
const timelineData = {
    labels: [],
    total: [],
    blocked: []
};

// Attack colors for donut
const ATTACK_COLORS = {
    SQLi: "#388bfd",
    XSS: "#f85149",
    CMD: "#bc8cff",
    DIR: "#d29922",
    Brute: "#39d0d8",
    Honeypot: "#3fb950"
};

// ─── Tab Navigation ──────────────────────────────────────────────────────────
document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
        const tab = item.dataset.tab;
        document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
        item.classList.add("active");
        document.getElementById(`tab-${tab}`)?.classList.add("active");

        const title = item.textContent.trim().replace(/^./, "").trim();
        document.getElementById("page-title").textContent = title;

        if (tab === "logs") loadLogs();
        if (tab === "settings") loadSettings();
    });
});

// ─── Chart Initialization ────────────────────────────────────────────────────
function initCharts() {
    // ── Timeline Chart ──
    const tlCtx = document.getElementById("chart-timeline")?.getContext("2d");
    if (tlCtx) {
        timelineChart = new Chart(tlCtx, {
            type: "line",
            data: {
                labels: timelineData.labels,
                datasets: [
                    {
                        label: "Requests",
                        data: timelineData.total,
                        borderColor: "#388bfd",
                        backgroundColor: "rgba(56,139,253,.08)",
                        pointRadius: 2,
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: "Blocked",
                        data: timelineData.blocked,
                        borderColor: "#f85149",
                        backgroundColor: "rgba(248,81,73,.08)",
                        pointRadius: 2,
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: "#8b949e", font: { size: 10 } } } },
                scales: {
                    x: {
                        ticks: { color: "#484f58", font: { size: 9 } },
                        grid: { color: "rgba(255,255,255,0.04)" }
                    },
                    y: {
                        ticks: { color: "#484f58", font: { size: 9 } },
                        grid: { color: "rgba(255,255,255,0.04)" },
                        beginAtZero: true
                    }
                },
                animation: { duration: 300 }
            }
        });
    }

    // ── Donut Chart ──
    const dCtx = document.getElementById("chart-donut")?.getContext("2d");
    if (dCtx) {
        donutChart = new Chart(dCtx, {
            type: "doughnut",
            data: {
                labels: Object.keys(ATTACK_COLORS),
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: Object.values(ATTACK_COLORS),
                    borderWidth: 1,
                    borderColor: "#161b22",
                    hoverBorderColor: "#388bfd"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "72%",
                plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw}` } }
                },
                animation: { duration: 600 }
            }
        });
        renderDonutLegend();
    }

    // ── Threshold Chart ──
    const thCtx = document.getElementById("chart-threshold")?.getContext("2d");
    if (thCtx) {
        threshChart = new Chart(thCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Adaptive Threshold",
                    data: [],
                    borderColor: "#d29922",
                    backgroundColor: "rgba(210,153,34,.1)",
                    pointRadius: 2,
                    tension: 0.3,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: "#484f58", font: { size: 8 } }, grid: { color: "rgba(255,255,255,0.04)" } },
                    y: {
                        min: 0.5, max: 1.0,
                        ticks: { color: "#484f58", font: { size: 8 } },
                        grid: { color: "rgba(255,255,255,0.04)" }
                    }
                },
                animation: { duration: 400 }
            }
        });
    }
}

function renderDonutLegend() {
    const el = document.getElementById("donut-legend");
    if (!el) return;
    el.innerHTML = Object.entries(ATTACK_COLORS).map(([k, c]) =>
        `<div class="donut-legend-item">
          <div class="legend-dot" style="background:${c}"></div>${k}
        </div>`
    ).join("");
}

// ─── Stats Polling ───────────────────────────────────────────────────────────
async function fetchStats() {
    try {
        const res = await fetch(`${API}/api/stats`);
        if (!res.ok) return;
        const data = await res.json();
        renderStats(data);
    } catch (e) { }
}

function renderStats(data) {
    const intel = data.intel || {};
    const banned = data.banned_ips || {};
    const ls = data.log_stats || {};
    const cfg = data.config || {};
    const threats = intel.recent_threats || [];

    const total = intel.total_requests || 0;
    const blocked = intel.blocked_by_ai || 0;
    const bannedN = Object.keys(banned).length;
    const clean = Math.max(0, total - blocked);

    // KPI values
    setKPI("kpi-total", total, "trend-total", total - prevTotal, "kbar-total", total, total);
    setKPI("kpi-blocked", blocked, "trend-blocked", blocked - prevBlocked, "kbar-blocked", blocked, total || 1);
    setKPI("kpi-banned", bannedN, "trend-banned", bannedN - prevBanned, "kbar-banned", bannedN, 20);
    setKPI("kpi-clean", clean, "trend-clean", clean - (prevTotal - prevBlocked), "kbar-clean", clean, total || 1);
    setKPI("kpi-sqli", ls.sqli || 0, null, 0, "kbar-sqli", ls.sqli || 0, total || 1);
    setKPI("kpi-xss", ls.xss || 0, null, 0, "kbar-xss", ls.xss || 0, total || 1);

    prevTotal = total;
    prevBlocked = blocked;
    prevBanned = bannedN;

    // Target host
    const url = cfg.target_url || "-";
    currentConfig = cfg;
    const host = url.replace(/https?:\/\//, "").split("/")[0].substring(0, 28);
    const el = document.getElementById("target-host");
    if (el) el.textContent = host || "-";

    // Attack breakdown donut
    if (donutChart) {
        const vals = [ls.sqli || 0, ls.xss || 0, ls.cmd || 0, ls.dir || 0, ls.brute || 0, ls.honeypot || 0];
        donutChart.data.datasets[0].data = vals;
        donutChart.update("none");
    }

    // Timeline
    const now = new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    timelineData.labels.push(now);
    timelineData.total.push(total);
    timelineData.blocked.push(blocked);
    if (timelineData.labels.length > TIMELINE_MAX_POINTS) {
        timelineData.labels.shift();
        timelineData.total.shift();
        timelineData.blocked.shift();
    }
    if (timelineChart) timelineChart.update("none");

    // AI report
    const ai = intel.ai_report;
    if (ai) {
        const lvl = ai.threat_level || "?";
        const badge = document.getElementById("global-threat-badge");
        if (badge) { badge.textContent = lvl; badge.className = `threat-badge ${lvl}`; }
        const el2 = document.getElementById("ai-threat-level");
        if (el2) { el2.textContent = `THREAT LEVEL: ${lvl}`; el2.className = `ai-level-display ${lvl}`; }
        const s = document.getElementById("ai-summary");
        if (s) s.textContent = ai.summary || "";
        const r = document.getElementById("ai-rec");
        if (r) r.textContent = ai.recommendation || "";
        const tags = document.getElementById("ai-tags");
        if (tags && ai.active_attack_types) {
            tags.innerHTML = ai.active_attack_types.map(t => `<span class="ai-tag">${t}</span>`).join("");
        }
    }

    // Feeds
    renderFeed("threat-feed", threats.slice(-10).reverse(), 10);

    // Ban table
    renderBanTable(banned);
    const bc = document.getElementById("ban-count-badge");
    if (bc) bc.textContent = `${bannedN} Banned`;

    // Server time
    document.getElementById("server-time").textContent = data.server_time || "";
}

function setKPI(id, val, trendId, delta, barId, barVal, barMax) {
    const el = document.getElementById(id);
    if (el) {
        const prev = parseInt(el.textContent) || 0;
        if (prev !== val) {
            el.textContent = val;
            el.style.transform = "scale(1.08)";
            setTimeout(() => { el.style.transform = ""; }, 250);
        }
    }
    if (trendId) {
        const te = document.getElementById(trendId);
        if (te) {
            const sign = delta > 0 ? "+" : "";
            te.textContent = `${sign}${delta}`;
            te.style.color = delta > 0 && id.includes("blocked") ? "var(--accent-red)"
                : delta > 0 ? "var(--accent-blue)"
                    : "var(--text-muted)";
        }
    }
    if (barId) {
        const be = document.getElementById(barId);
        const pct = barMax ? Math.min(100, (barVal / barMax) * 100) : 0;
        if (be) be.style.width = pct + "%";
    }
}

// ─── Feeds & Tables ──────────────────────────────────────────────────────────
function renderFeed(id, threats, limit) {
    const container = document.getElementById(id);
    if (!container) return;
    const slice = (threats || []).slice(0, limit);
    if (!slice.length) {
        container.innerHTML = `<span style="color:var(--text-muted);font-size:.75rem;">No threat events yet.</span>`;
        return;
    }
    container.innerHTML = slice.map(t => {
        const layer = (t.layer || "").toLowerCase();
        let cls = "";
        if (layer.includes("waf") || layer.includes("ai")) cls = "waf";
        else if (layer.includes("fire")) cls = "firewall";
        else if (layer.includes("honey")) cls = "honey";
        return `<div class="threat-event ${cls}"><b>${t.time || ""}</b> [${t.layer || "?"}] ${t.event || ""}</div>`;
    }).join("");
}

function renderBanTable(banned) {
    const tbody = document.getElementById("ban-table-body");
    if (!tbody) return;
    const ips = Object.entries(banned);
    if (!ips.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-msg">No IPs are currently banned.</td></tr>`;
        return;
    }
    tbody.innerHTML = ips.map(([ip, info]) => {
        const t = new Date(info.blocked_at * 1000).toLocaleTimeString();
        return `<tr>
          <td style="font-family:var(--font-mono);color:var(--accent-red);">${ip}</td>
          <td>${info.reason || "-"}</td>
          <td>${t}</td>
          <td><button class="btn-unban" onclick="unbanIP('${ip}')">Unban</button></td>
        </tr>`;
    }).join("");
}

// ─── Unban ───────────────────────────────────────────────────────────────────
async function unbanIP(ip) {
    try {
        const res = await fetch(`${API}/api/unban`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (data.success) { flashNotify(`✓ IP ${ip} unbanned`); fetchStats(); }
    } catch (e) { }
}

// ─── Logs ────────────────────────────────────────────────────────────────────
async function loadLogs() {
    try {
        const res = await fetch(`${API}/api/logs?limit=200`);
        const data = await res.json();
        allLogs = data.lines || [];
        renderLogs(allLogs);
    } catch (e) { }
}

function renderLogs(lines) {
    const container = document.getElementById("log-view");
    if (!container) return;
    container.innerHTML = lines.map(line => {
        let cls = "log-line";
        const u = line.toUpperCase();
        if (u.includes("BLOCKED") || u.includes("AI_BLOCKED")) cls += " blocked";
        else if (u.includes("BANNED") || u.includes("IP_BANNED")) cls += " banned";
        else if (u.includes("HONEYPOT")) cls += " honey";
        return `<div class="${cls}">${escapeHtml(line)}</div>`;
    }).join("");
    container.scrollTop = container.scrollHeight;
}

function filterLogs() {
    const q = document.getElementById("log-search").value.toLowerCase();
    renderLogs(allLogs.filter(l => l.toLowerCase().includes(q)));
}

// ─── Settings ────────────────────────────────────────────────────────────────
async function loadSettings() {
    try {
        const res = await fetch(`${API}/api/config`);
        const cfg = await res.json();
        document.getElementById("cfg-target").value = cfg.target_url || "";
        document.getElementById("cfg-waf-port").value = cfg.waf_port || 8080;
        document.getElementById("cfg-threshold").value = cfg.ban_threshold || 100;
        document.getElementById("cfg-rps").value = cfg.rate_limit?.max_rps || 20;

        const scoringForm = document.getElementById("scoring-form");
        const scoring = cfg.scoring || {};
        scoringForm.innerHTML = Object.entries(scoring).map(([k, v]) =>
            `<div class="scoring-row"><span>${k}</span><input type="number" id="score-${k}" value="${v}"></div>`
        ).join("");
    } catch (e) { }
}

async function saveConfig() {
    const target = document.getElementById("cfg-target").value;
    const wafPort = parseInt(document.getElementById("cfg-waf-port").value);
    const threshold = parseInt(document.getElementById("cfg-threshold").value);
    const updates = { target_url: target, waf_port: wafPort, ban_threshold: threshold };
    try {
        const res = await fetch(`${API}/api/config`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(updates)
        });
        const data = await res.json();
        const msg = document.getElementById("save-msg");
        if (data.success) { msg.textContent = "✓ Config saved!"; setTimeout(() => msg.textContent = "", 3000); }
        else { msg.textContent = "Error saving."; msg.style.color = "var(--accent-red)"; }
    } catch (e) { }
}

// ─── Anomaly + Rate Limit Polling ────────────────────────────────────────────
async function fetchAnomalies() {
    try {
        const res = await fetch(`${WAF}/waf/api/anomalies`);
        if (!res.ok) return;
        const data = await res.json();
        renderAnomalyTable(data.scores || {});
        renderMLStatus(data.stats || {});
    } catch (e) { }
}

async function fetchRateLimits() {
    try {
        const res = await fetch(`${WAF}/waf/api/rate-limits`);
        if (!res.ok) return;
        const data = await res.json();
        renderRateLimitStats(data);
    } catch (e) { }
}

async function fetchLearning() {
    try {
        const res = await fetch(`${WAF}/waf/api/learning`);
        if (!res.ok) return;
        const data = await res.json();
        renderLearningTab(data);
    } catch (e) { }
}

// ─── Anomaly Rendering ───────────────────────────────────────────────────────
function renderAnomalyTable(scores) {
    const tbody = document.getElementById("anomaly-table-body");
    if (!tbody) return;
    const entries = Object.entries(scores).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-msg">Scores appear after the first requests.</td></tr>`;
        return;
    }
    tbody.innerHTML = entries.map(([ip, score]) => {
        const pct = Math.round(score * 100);
        const label = anomalyLabel(score);
        const color = anomalyColor(score);
        const bar = `<div style="height:5px;background:${color};border-radius:3px;width:${pct}%;transition:width .6s;"></div>`;
        return `<tr>
          <td style="font-family:var(--font-mono);color:${color};">${ip}</td>
          <td>
            <div style="display:flex;align-items:center;gap:10px;">
              <div style="flex:1;background:var(--surface2);border-radius:3px;height:5px;overflow:hidden;">${bar}</div>
              <span style="font-family:var(--font-mono);font-size:0.72rem;">${pct}%</span>
            </div>
          </td>
          <td><span style="color:${color};font-weight:700;">${label}</span></td>
          <td style="font-size:0.75rem;color:var(--text-muted);">${score > 0.8 ? "⚠️ Blocked" : "Monitoring"}</td>
        </tr>`;
    }).join("");
}

function renderMLStatus(stats) {
    const el = document.getElementById("ml-status-label");
    const desc = document.getElementById("ml-status-desc");
    const dotIF = document.getElementById("dot-isoforest");
    const mlDot = document.getElementById("ml-dot");
    if (!el) return;
    const mlOn = stats.ml_active;
    el.textContent = mlOn ? "ISOLATION FOREST ACTIVE" : "Z-SCORE ENGINE ACTIVE";
    el.className = `ai-level-display ${mlOn ? "LOW" : "MEDIUM"}`;
    if (desc) desc.textContent = `Tracking ${stats.tracked_ips || 0} IPs · ${stats.high_anomalies || 0} high-risk anomalies`;
    if (dotIF) dotIF.style.background = mlOn ? "var(--accent-green)" : "var(--text-muted)";
    if (mlDot) mlDot.className = mlOn ? "layer-status green-dot" : "layer-status blue-dot";
}

function renderRateLimitStats(data) {
    const statsEl = document.getElementById("rate-stats");
    const eventsEl = document.getElementById("rate-events");
    if (statsEl) {
        statsEl.innerHTML = `
          <span style="color:var(--text-muted);">IPs Tracked:</span> <b>${data.tracked_ips || 0}</b>
          &nbsp;|&nbsp;
          <span style="color:var(--accent-red);">Total Violations:</span> <b>${data.violations || 0}</b>`;
    }
    if (eventsEl) {
        const events = (data.recent_events || []).slice().reverse();
        if (!events.length) {
            eventsEl.innerHTML = `<span style="color:var(--text-muted);font-size:.75rem;">No rate-limit violations yet.</span>`;
            return;
        }
        eventsEl.innerHTML = events.map(e =>
            `<div class="threat-event waf">[${e.time || "?"}] ${e.ip || "?"} — violation #${e.violations || "?"}</div>`
        ).join("");
    }
}

// ─── AI Learning Tab ─────────────────────────────────────────────────────────
function renderLearningTab(data) {
    const samples = data.samples || 0;
    const ready = data.ready || false;
    const threshold = data.threshold || 0.80;
    const features = data.features || [];

    // Header
    const badge = document.getElementById("ai-learn-badge");
    const sl = document.getElementById("ai-learn-status");
    const sc = document.getElementById("ai-sample-count");
    const tv = document.getElementById("ai-threshold-val");
    if (badge) badge.className = `ai-learn-badge${ready ? " ready" : ""}`;
    if (sl) sl.textContent = ready ? "BASELINE READY — Learning" : `Building baseline (${samples}/30)...`;
    if (sc) sc.textContent = `${samples} / ${ready ? "1000" : "30"}`;
    if (tv) tv.textContent = threshold.toFixed(3);

    // Feature baseline table
    const container = document.getElementById("feature-baselines");
    if (container && features.length) {
        const maxMean = Math.max(...features.map(f => f.mean), 1);
        container.innerHTML = features.map(f => {
            const pct = Math.min(100, (f.mean / maxMean) * 100);
            return `<div class="feature-row">
              <div class="feat-name">${f.name}</div>
              <div class="feat-bar-bg"><div class="feat-bar-fill" style="width:${pct}%"></div></div>
              <div class="feat-mean">${f.mean.toFixed(3)}</div>
              <div class="feat-std">±${f.std.toFixed(3)}</div>
            </div>`;
        }).join("");
    }

    // Threshold history chart
    if (threshChart) {
        const now = new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        threshChart.data.labels.push(now);
        threshChart.data.datasets[0].data.push(threshold);
        if (threshChart.data.labels.length > 20) {
            threshChart.data.labels.shift();
            threshChart.data.datasets[0].data.shift();
        }
        threshChart.update("none");
    }

    // Anomaly events feed on AI tab
    renderFeed("anomaly-events-feed",
        (data.events || []).slice().reverse(), 30);
}

// ─── Report Download ──────────────────────────────────────────────────────────
async function downloadReport() {
    const res = await fetch(`${API}/api/stats`);
    const data = await res.json();
    const intel = data.intel || {};
    const banned = data.banned_ips || {};
    const ls = data.log_stats || {};
    const cfg = data.config || {};
    const now = new Date().toLocaleString();
    const ai = intel.ai_report || {};

    let html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Cyber-Aegis Incident Report</title>
<style>
  body{font-family:Arial,sans-serif;padding:30px;background:#f6f8fa;}
  h1{color:#c62828;border-bottom:2px solid #c62828;padding-bottom:10px;}
  h2{color:#1a237e;margin-top:24px;}
  table{border-collapse:collapse;width:100%;margin-top:10px;}
  th{background:#1a237e;color:white;padding:10px;text-align:left;}
  td{padding:8px 10px;border:1px solid #dee2e6;}
  tr:nth-child(even){background:#f0f4ff;}
  .stat{display:inline-block;background:white;border:1px solid #dee2e6;border-radius:8px;padding:12px 20px;margin:8px;text-align:center;}
  .stat-val{font-size:2rem;font-weight:bold;color:#1a237e;}
  .ai-box{background:#e8f5e9;border:1px solid #a5d6a7;border-radius:6px;padding:14px;margin-top:10px;}
  footer{margin-top:40px;color:#666;font-size:.85rem;border-top:1px solid #dee2e6;padding-top:10px;}
</style></head><body>
<h1>🛡️ Cyber-Aegis WAF — Security Incident Report</h1>
<p><b>Generated:</b> ${now} &nbsp;|&nbsp; <b>Target:</b> ${cfg.target_url || "-"}</p>
<h2>System Summary</h2>
<div>
  <div class="stat"><div class="stat-val">${intel.total_requests || 0}</div>Total Requests</div>
  <div class="stat"><div class="stat-val" style="color:#c62828;">${intel.blocked_by_ai || 0}</div>Threats Blocked</div>
  <div class="stat"><div class="stat-val" style="color:#e65100;">${Object.keys(banned).length}</div>IPs Banned</div>
</div>
<h2>AI Threat Assessment</h2>
<div class="ai-box">
  <b>Threat Level:</b> ${ai.threat_level || "N/A"}<br>
  <b>Summary:</b> ${ai.summary || "-"}<br>
  <b>Recommendation:</b> ${ai.recommendation || "-"}<br>
  <b>Attack Types:</b> ${(ai.active_attack_types || []).join(", ") || "-"}
</div>
<h2>Attack Breakdown</h2>
<table><tr><th>Attack Type</th><th>Count</th></tr>
  <tr><td>SQL Injection</td><td>${ls.sqli || 0}</td></tr>
  <tr><td>XSS</td><td>${ls.xss || 0}</td></tr>
  <tr><td>CMD Injection</td><td>${ls.cmd || 0}</td></tr>
  <tr><td>Directory Traversal</td><td>${ls.dir || 0}</td></tr>
  <tr><td>Brute Force</td><td>${ls.brute || 0}</td></tr>
  <tr><td>Honeypot Triggered</td><td>${ls.honeypot || 0}</td></tr>
</table>
<h2>Banned IPs</h2>
<table><tr><th>IP</th><th>Reason</th><th>Banned At</th></tr>`;
    Object.entries(banned).forEach(([ip, info]) => {
        const t = new Date(info.blocked_at * 1000).toLocaleString();
        html += `<tr><td>${ip}</td><td>${info.reason || "-"}</td><td>${t}</td></tr>`;
    });
    html += `</table>
<footer>Generated by Cyber-Aegis WAF — AI-Powered Web Application Firewall.</footer>
</body></html>`;

    const blob = new Blob([html], { type: "text/html" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cyber_aegis_report_${Date.now()}.html`;
    a.click();
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function flashNotify(msg) {
    const div = document.createElement("div");
    div.style.cssText = "position:fixed;bottom:24px;right:24px;background:#1f6feb;color:#fff;padding:12px 20px;border-radius:8px;font-family:'Rajdhani',sans-serif;font-size:.9rem;z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,.4);";
    div.textContent = msg;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 3000);
}

function anomalyLabel(score) {
    if (score < .40) return "NORMAL";
    if (score < .65) return "SUSPICIOUS";
    if (score < .85) return "HIGH";
    return "CRITICAL";
}

function anomalyColor(score) {
    if (score < .40) return "var(--accent-green)";
    if (score < .65) return "var(--accent-yell)";
    if (score < .85) return "#f0883e";
    return "var(--accent-red)";
}

// ─── Global Threat Level Beacon ───────────────────────────────────────────────
const LEVEL_COLORS = {
    GREEN: "#3fb950",
    YELLOW: "#d29922",
    ORANGE: "#f0883e",
    RED: "#f85149"
};

async function fetchState() {
    try {
        const res = await fetch(`${WAF}/waf/api/state`);
        if (!res.ok) return;
        const data = await res.json();
        renderBeacon(data);
    } catch (e) { /* WAF may not be running yet */ }
}

function renderBeacon(data) {
    const level = data.level || "GREEN";
    const score = data.score || 0;
    const summary = data.summary || "";
    const color = LEVEL_COLORS[level] || LEVEL_COLORS.GREEN;
    const sigs = data.signals || {};

    // Update CSS custom property so beacon-dot, beacon-text, ::before all change color
    const beacon = document.getElementById("threat-beacon");
    if (beacon) beacon.style.setProperty("--beacon-color", color);

    const textEl = document.getElementById("beacon-text");
    if (textEl) textEl.textContent = level;

    const scoreEl = document.getElementById("beacon-score");
    if (scoreEl) scoreEl.textContent = `Risk Score: ${Math.round(score * 100)}%`;

    const summaryEl = document.getElementById("beacon-summary");
    if (summaryEl) summaryEl.textContent = summary;

    // Update the top-header global threat badge too
    const badge = document.getElementById("global-threat-badge");
    if (badge) {
        // Map system state level → Gemini threat level (they can coexist)
        badge.style.borderColor = color;
        badge.style.color = color;
    }

    // Build or refresh the 5-segment signal bar
    let barRow = beacon?.querySelector(".beacon-bar-row");
    if (beacon && !barRow) {
        barRow = document.createElement("div");
        barRow.className = "beacon-bar-row";
        barRow.innerHTML = Array.from({ length: 5 }, (_, i) =>
            `<div class="beacon-bar-seg" id="bseg-${i}"></div>`
        ).join("");
        beacon.appendChild(barRow);
    }
    if (barRow) {
        const filled = Math.ceil(score * 5);
        for (let i = 0; i < 5; i++) {
            const seg = document.getElementById(`bseg-${i}`);
            if (seg) seg.style.background = i < filled ? color : "var(--surface3)";
        }
    }
}

// ─── Start ────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    fetchStats();
    fetchAnomalies();
    fetchRateLimits();
    fetchLearning();
    fetchState();

    setInterval(fetchStats, 2000);
    setInterval(fetchAnomalies, 3000);
    setInterval(fetchRateLimits, 3000);
    setInterval(fetchLearning, 4000);
    setInterval(fetchState, 3000);
});
