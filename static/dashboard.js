// ═══════════════════════════════════════════════════════
//  DoS Sentinel v4 — dashboard.js
// ═══════════════════════════════════════════════════════

const socket = io();

let normalCount  = 0;
let anomalyCount = 0;
let chartMode    = "syn";
let lastData     = null;
let _autoBlockEnabled = true;

let trafficChart, distributionChart, multiChart, bytesChart;

const gaugeCpuCtx = document.getElementById("gaugeCpu");
const gaugeMemCtx = document.getElementById("gaugeMem");
const gaugeNetCtx = document.getElementById("gaugeNet");

// ═══════════════════════════════════════════════════════
//  Init Charts
// ═══════════════════════════════════════════════════════

function initCharts() {

    trafficChart = new Chart(document.getElementById("trafficChart"), {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "SYN_RECV",
                data: [],
                borderColor: "#248dff",
                backgroundColor: "rgba(36,141,255,0.08)",
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointRadius: 3,
                pointBackgroundColor: []
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#536e8b", maxTicksLimit: 8 }, grid: { color: "rgba(70,100,130,.12)" } },
                y: { beginAtZero: true, suggestedMax: 10, ticks: { color: "#536e8b" }, grid: { color: "rgba(70,100,130,.12)" } }
            }
        }
    });

    distributionChart = new Chart(document.getElementById("distributionChart"), {
        type: "doughnut",
        data: {
            labels: ["Normal", "Anomaly"],
            datasets: [{ data: [1, 0], backgroundColor: ["#1689ff", "#ff4355"], borderWidth: 0 }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "72%",
            animation: { duration: 400 },
            plugins: { legend: { display: false } }
        }
    });

    multiChart = new Chart(document.getElementById("multiChart"), {
        type: "line",
        data: {
            labels: [],
            datasets: [
                makeDataset("SYN_RECV",    "#ff4355", "rgba(255,67,85,0.07)"),
                makeDataset("Established", "#248dff", "rgba(36,141,255,0.07)"),
                makeDataset("Total Conns", "#914eff", "rgba(145,78,255,0.07)"),
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { display: true, labels: { color: "#8299b6", boxWidth: 12 } } },
            scales: {
                x: { ticks: { color: "#536e8b", maxTicksLimit: 8 }, grid: { color: "rgba(70,100,130,.12)" } },
                y: { beginAtZero: true, suggestedMax: 10, ticks: { color: "#536e8b" }, grid: { color: "rgba(70,100,130,.12)" } }
            }
        }
    });

    bytesChart = new Chart(document.getElementById("bytesChart"), {
        type: "bar",
        data: {
            labels: [],
            datasets: [
                { label: "Sent KB/s",     data: [], backgroundColor: "rgba(32,219,130,0.6)" },
                { label: "Received KB/s", data: [], backgroundColor: "rgba(255,158,37,0.6)" },
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { labels: { color: "#8299b6" } } },
            scales: {
                x: { ticks: { color: "#536e8b", maxTicksLimit: 10 }, grid: { color: "rgba(70,100,130,.1)" } },
                y: { beginAtZero: true, suggestedMax: 1, ticks: { color: "#536e8b" }, grid: { color: "rgba(70,100,130,.1)" } }
            }
        }
    });
}

function makeDataset(label, color, bg) {
    return { label, data: [], borderColor: color, backgroundColor: bg, borderWidth: 2, fill: true, tension: 0.35, pointRadius: 2, pointBackgroundColor: color };
}

// ═══════════════════════════════════════════════════════
//  Arc Gauge
// ═══════════════════════════════════════════════════════

function drawGauge(canvas, pct, color) {
    const ctx = canvas.getContext("2d");
    const cx = canvas.width / 2, cy = canvas.height / 2, r = 70;
    const start = Math.PI * 0.75, end = Math.PI * 2.25;
    const val = start + (end - start) * (Math.min(pct, 100) / 100);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.beginPath(); ctx.arc(cx, cy, r, start, end);
    ctx.strokeStyle = "#0d2036"; ctx.lineWidth = 12; ctx.lineCap = "round"; ctx.stroke();
    ctx.beginPath(); ctx.arc(cx, cy, r, start, val);
    ctx.strokeStyle = color; ctx.lineWidth = 12; ctx.lineCap = "round"; ctx.stroke();
}

function updateGauges(cpu, mem, net) {
    drawGauge(gaugeCpuCtx, cpu, cpu > 80 ? "#ff4355" : "#1bdc84");
    drawGauge(gaugeMemCtx, mem, mem > 80 ? "#ff9e25" : "#258eff");
    drawGauge(gaugeNetCtx, net, "#ffad37");
    setText("gaugeCpuLabel", cpu + "%");
    setText("gaugeMemLabel", mem + "%");
    setText("gaugeNetLabel", net + "%");
}

// ═══════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.innerText = val;
}

function formatBytes(b) {
    if (b < 1024)    return b.toFixed(0) + " B/s";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB/s";
    return (b / 1048576).toFixed(1) + " MB/s";
}

function pushAndTrim(chart, label, maxPoints, ...values) {
    chart.data.labels.push(label);
    values.forEach((v, i) => { if (chart.data.datasets[i]) chart.data.datasets[i].data.push(Number(v)); });
    while (chart.data.labels.length > maxPoints) {
        chart.data.labels.shift();
        chart.data.datasets.forEach(d => d.data.shift());
    }
    const allVals = chart.data.datasets.flatMap(d => d.data).filter(v => v != null && !isNaN(v));
    const maxVal  = allVals.length ? Math.max(...allVals) : 0;
    chart.options.scales.y.suggestedMax = Math.max(Math.ceil(maxVal * 1.4), 10);
    chart.update("none");
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseFloat(el.innerText) || 0;
    const diff = target - current;
    if (Math.abs(diff) < 0.5) { el.innerText = target; return; }
    el.innerText = (current + diff * 0.4).toFixed(Number.isInteger(target) ? 0 : 3);
}

function attackTypePill(type) {
    if (!type || type === "-") return "—";
    const span = document.createElement("span");
    span.className = "attack-type-pill";
    span.textContent = type;
    return span.outerHTML;
}

function riskBadge(risk) {
    const cls = risk === "HIGH" ? "risk-high" : risk === "MEDIUM" ? "risk-medium" : "risk-low";
    return `<span class="status-pill ${cls}">${risk || "—"}</span>`;
}

function confBadge(conf) {
    const cls = conf === "HIGH" ? "status-anomaly" : conf === "MEDIUM" ? "status-suspicious" : "status-normal";
    return `<span class="status-pill ${cls}">${conf || "—"}</span>`;
}

// ═══════════════════════════════════════════════════════
//  HTTP Telemetry
// ═══════════════════════════════════════════════════════

function updateHttpTelemetry(tel) {
    const unavail = document.getElementById("httpUnavailable");
    const metrics = document.getElementById("httpMetrics");
    const badge   = document.getElementById("httpAvailBadge");
    if (!tel || tel.available === false) {
        if (unavail) unavail.style.display = "flex";
        if (metrics) metrics.style.display = "none";
        if (badge)   { badge.textContent = "● OFFLINE"; badge.style.color = "#ff5360"; badge.style.borderColor = "rgba(255,83,96,.3)"; badge.style.background = "rgba(255,83,96,.08)"; }
        return;
    }
    if (unavail) unavail.style.display = "none";
    if (metrics) metrics.style.display = "";
    if (badge)   { badge.textContent = "● LIVE"; badge.style.color = ""; badge.style.borderColor = ""; badge.style.background = ""; }

    setText("httpTotal",   tel.total_requests ?? 0);
    setText("httpRps",     (tel.requests_per_sec ?? 0).toFixed(1));
    setText("httpSuccess", tel.successful_responses ?? 0);
    setText("httpErrors",  tel.error_responses ?? 0);
    setText("httpAvgRt",   (tel.avg_response_time_ms ?? 0).toFixed(1) + " ms");

    const sc  = tel.status_codes || {};
    const el  = document.getElementById("httpStatusCodes");
    if (el) el.textContent = `2xx:${sc["2xx"]??0}  3xx:${sc["3xx"]??0}  4xx:${sc["4xx"]??0}  5xx:${sc["5xx"]??0}`;
}

// ═══════════════════════════════════════════════════════
//  Attack Log
// ═══════════════════════════════════════════════════════

function renderAttackLog(log) {
    const atbody = document.getElementById("attackTable");
    if (!atbody) return;
    atbody.innerHTML = "";
    if (!log || log.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 7;
        td.style.cssText = "text-align:center;color:#4f6984;padding:30px";
        td.textContent = "No attacks detected yet";
        tr.appendChild(td);
        atbody.appendChild(tr);
        return;
    }
    [...log].forEach(ev => {
        const tr = document.createElement("tr");
        tr.classList.add("row-anomaly");

        const tdTime = document.createElement("td"); tdTime.textContent = ev.ts || ev.time || "-";
        const tdDet  = document.createElement("td"); tdDet.innerHTML  = `<span class="status-pill status-anomaly">${ev.detection || ev.status || "ANOMALY"}</span>`;
        const tdAt   = document.createElement("td"); tdAt.innerHTML   = attackTypePill(ev.attack_type);
        const tdConf = document.createElement("td"); tdConf.innerHTML = confBadge(ev.confidence);
        const tdRisk = document.createElement("td"); tdRisk.innerHTML = riskBadge(ev.risk);
        const tdSc   = document.createElement("td"); tdSc.textContent = ev.score != null ? Number(ev.score).toFixed(4) : "-";
        const tdIp   = document.createElement("td"); tdIp.textContent = ev.source_ip || "-";

        tr.append(tdTime, tdDet, tdAt, tdConf, tdRisk, tdSc, tdIp);
        atbody.appendChild(tr);
    });
}

async function loadFullAttackLog() {
    try {
        const res = await fetch("/api/attack_log");
        const log = await res.json();
        renderAttackLog(log);
    } catch (e) {
        console.error("Failed to load attack log:", e);
    }
}

// ═══════════════════════════════════════════════════════
//  Main Update
// ═══════════════════════════════════════════════════════

function applyUpdate(data) {
    lastData = data;
    const t  = data.traffic;
    const ts = data.timestamp;

    setText("clock", new Date().toLocaleTimeString());

    animateNumber("synRecv",          t.syn_recv);
    animateNumber("established",      t.established);
    animateNumber("totalConnections", t.total_connections);
    setText("bytesSent",     formatBytes(t.bytes_sent_per_sec));
    setText("bytesReceived", formatBytes(t.bytes_recv_per_sec));
    setText("velocityCard",  t.conn_velocity + "/s");
    setText("connVelocity",  t.conn_velocity);

    const card      = document.getElementById("threatCard");
    const isAnomaly  = data.detection === "ANOMALY";
    const isCooldown = data.detection === "COOLDOWN";

    card.className = "threat-card" + (isAnomaly ? " anomaly" : isCooldown ? " cooldown" : "");
    setText("threatStatus",   data.detection);
    setText("threatMessage",  isAnomaly  ? "⚠ Possible DoS-related anomaly detected!"
                            : isCooldown ? "⏳ Cooling down after anomaly…"
                            : "Server traffic appears normal");
    setText("shieldIcon",     isAnomaly ? "!" : isCooldown ? "⏳" : "✓");
    animateNumber("anomalyScore", data.anomaly_score);
    setText("riskLevel",       data.risk);
    setText("confidenceLevel", data.confidence || "—");
    setText("totalAnomalies",  data.stats.total_anomalies);
    setText("attackType",      isAnomaly ? (data.attack_type || "Unknown DoS") : "—");
    setText("attackTypeSource", isAnomaly ? (data.attack_type_source || "—") : "—");
    setText("modelVersion",    data.model_version || "—");
    setText("modelStatus",     data.system && data.system.model === "ERROR" ? "error" : "loaded");
    const modelStatusEl = document.getElementById("modelStatus");
    if (modelStatusEl) modelStatusEl.style.color = (data.system && data.system.model === "ERROR") ? "#ff5360" : "#42f398";

    // System section model fields
    setText("statModelVersion", data.model_version || "—");
    const statModelStatusEl = document.getElementById("statModelStatus");
    if (statModelStatusEl) {
        if (data.system && data.system.model === "ERROR") {
            statModelStatusEl.textContent = "● ERROR";
            statModelStatusEl.style.color = "#ff5360";
        } else {
            statModelStatusEl.textContent = "● ACTIVE";
            statModelStatusEl.style.color = "#42f398";
        }
    }

    if (isAnomaly) {
        const banner = document.getElementById("alertBanner");
        banner.classList.add("visible");
        setText("alertText", `🚨 ${data.attack_type || "DoS Anomaly"} — Score: ${data.anomaly_score} | Risk: ${data.risk} | Confidence: ${data.confidence} | SYN_RECV: ${t.syn_recv}`);
    }

    setText("attackBadge", data.stats.total_anomalies);

    // HTTP telemetry
    updateHttpTelemetry(data.http_telemetry);

    const ds       = trafficChart.data.datasets[0];
    const colorArr = Array.isArray(ds.pointBackgroundColor) ? ds.pointBackgroundColor : [];
    colorArr.push(isAnomaly ? "#ff4355" : "#248dff");
    if (colorArr.length > 60) colorArr.shift();
    ds.pointBackgroundColor = colorArr;
    ds.borderColor     = isAnomaly ? "#ff4355" : "#248dff";
    ds.backgroundColor = isAnomaly ? "rgba(255,67,85,0.10)" : "rgba(36,141,255,0.08)";

    const synVal = chartMode === "syn" ? t.syn_recv
                 : chartMode === "est" ? t.established
                 : t.total_connections;
    pushAndTrim(trafficChart, ts, 60, synVal);
    pushAndTrim(multiChart,   ts, 60, t.syn_recv, t.established, t.total_connections);
    pushAndTrim(bytesChart,   ts, 40, (t.bytes_sent_per_sec / 1024).toFixed(2), (t.bytes_recv_per_sec / 1024).toFixed(2));

    if (isAnomaly) anomalyCount++; else normalCount++;
    const total = normalCount + anomalyCount;
    const nPct  = total === 0 ? 100 : Math.round(normalCount / total * 100);
    setText("donutTotal",    total);
    setText("normalPercent",  nPct + "%");
    setText("anomalyPercent", (100 - nPct) + "%");
    distributionChart.data.datasets[0].data = [normalCount, anomalyCount];
    distributionChart.update();

    // Events table
    const tbody = document.getElementById("eventsTable");
    tbody.innerHTML = "";
    [...data.events].reverse().forEach(ev => {
        const det = ev.status || ev.detection || "NORMAL";
        const cls = det === "ANOMALY" ? "status-anomaly" : (ev.score < 0 ? "status-suspicious" : "status-normal");
        const tr  = document.createElement("tr");
        if (det === "ANOMALY") tr.classList.add("row-anomaly");

        const tdTime  = document.createElement("td"); tdTime.textContent  = ev.time || "-";
        const tdMsg   = document.createElement("td"); tdMsg.textContent   = ev.message || "-";
        const tdSyn   = document.createElement("td"); tdSyn.textContent   = ev.syn_recv ?? "-";
        const tdConns = document.createElement("td"); tdConns.textContent = ev.connections ?? "-";
        const tdSc    = document.createElement("td"); tdSc.textContent    = ev.score != null ? Number(ev.score).toFixed(4) : "-";
        const tdAt    = document.createElement("td"); tdAt.innerHTML      = attackTypePill(ev.attack_type);
        const tdConf  = document.createElement("td"); tdConf.innerHTML    = confBadge(ev.confidence);
        const tdSt    = document.createElement("td"); tdSt.innerHTML      = `<span class="status-pill ${cls}">${det}</span>`;

        tr.append(tdTime, tdMsg, tdSyn, tdConns, tdSc, tdAt, tdConf, tdSt);
        tbody.appendChild(tr);
    });

    // Attack log — only refresh if tab active
    const attackSec = document.getElementById("sec-attacks");
    if (attackSec && attackSec.classList.contains("active")) {
        renderAttackLog(data.attack_log);
    }

    // IP Manager
    const ipTable = document.getElementById("ipTable");
    ipTable.innerHTML = `
        <div class="source-row header">
            <div>IP ADDRESS</div><div>CONNECTIONS</div><div>TREND</div><div>ACTION</div>
        </div>`;

    if (!data.sources || data.sources.length === 0) {
        const empty = document.createElement("div");
        empty.style.cssText = "padding:24px 18px;color:#4f6984;font-size:12px";
        empty.textContent = "No active source IPs detected";
        ipTable.appendChild(empty);
    } else {
        data.sources.forEach(src => {
            if (!src || !src.ip) return;
            const row = document.createElement("div");
            row.className = "source-row" + (src.blocked ? " blocked-row" : "");

            const divIp    = document.createElement("div"); divIp.className = "ip-addr"; divIp.textContent = src.ip;
            const divConns = document.createElement("div"); divConns.textContent = src.connections ?? 0;

            const divTrend = document.createElement("div"); divTrend.className = "trend-mini";
            (src.trend || []).forEach(v => {
                const bar = document.createElement("span");
                bar.className = "trend-bar";
                bar.style.height = Math.min(v * 4, 20) + "px";
                divTrend.appendChild(bar);
            });

            const divAct = document.createElement("div");
            const btn    = document.createElement("button");
            if (src.blocked) {
                btn.className   = "btn-unblock";
                btn.textContent = "Unblock";
                btn.addEventListener("click", () => unblockIp(src.ip));
            } else {
                btn.className   = "btn-block";
                btn.textContent = "Block";
                btn.addEventListener("click", () => blockIp(src.ip));
            }
            divAct.appendChild(btn);
            row.append(divIp, divConns, divTrend, divAct);
            ipTable.appendChild(row);
        });
    }
    setText("blockedCount", data.stats.blocked_count + " Blocked");

    updateGauges(Math.round(data.system.cpu), Math.round(data.system.memory), Math.round(data.system.network));

    setText("statUptime",    data.stats.uptime);
    setText("statEvents",    data.stats.total_events);
    setText("statAnomalies", data.stats.total_anomalies);
    setText("statBlocked",   data.stats.blocked_count);
    setText("sidebarUptime", "◷ " + data.stats.uptime);

    // Auto-block panel
    const ab = data.stats;
    _autoBlockEnabled = ab.auto_block !== false;
    setText("abStatus",    _autoBlockEnabled ? "ENABLED" : "DISABLED");
    const abEl = document.getElementById("abStatus");
    if (abEl) abEl.style.color = _autoBlockEnabled ? "#42f398" : "#ff5360";
    setText("abThreshold", (ab.auto_block_threshold || 3) + " anomalies");
    setText("abBlocked",   ab.blocked_count + " IPs");
    const toggle = document.getElementById("autoBlockToggle");
    if (toggle) toggle.innerText = "Auto-Block: " + (_autoBlockEnabled ? "ON" : "OFF");
}

// ═══════════════════════════════════════════════════════
//  Simulator
// ═══════════════════════════════════════════════════════

let _simResetTimer = null;

function setSimStatus(text, color) {
    const el = document.getElementById("simStatus");
    if (!el) return;
    el.textContent = text;
    el.style.color = color;
}

async function launchSim(attack, intensity) {
    setSimStatus(`LAUNCHING ${attack.toUpperCase()}…`, "#ffb63e");
    if (_simResetTimer) { clearTimeout(_simResetTimer); _simResetTimer = null; }
    try {
        const res  = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack, intensity })
        });
        const data = await res.json();
        if (data.ok) {
            setSimStatus(`RUNNING: ${attack.toUpperCase()} (${intensity})`, "#ff6572");
            // Auto-reset after 130 s (default simulator timeout is 120 s)
            _simResetTimer = setTimeout(() => setSimStatus("IDLE", "#b180ff"), 130_000);
        } else {
            setSimStatus("ERROR: " + (data.error || "failed"), "#ff9e25");
        }
    } catch (e) {
        setSimStatus("LAUNCH FAILED", "#ff5360");
    }
}

// ═══════════════════════════════════════════════════════
//  Auto-Block Controls
// ═══════════════════════════════════════════════════════

async function toggleAutoBlock() {
    _autoBlockEnabled = !_autoBlockEnabled;
    await fetch("/api/auto_block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: _autoBlockEnabled })
    });
}

async function saveAutoBlock() {
    const threshold = parseInt(document.getElementById("thresholdInput").value) || 3;
    await fetch("/api/auto_block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threshold })
    });
}

// ═══════════════════════════════════════════════════════
//  IP Block / Unblock
// ═══════════════════════════════════════════════════════

async function blockIp(ip) {
    await fetch("/api/block", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
}

async function unblockIp(ip) {
    await fetch("/api/unblock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
}

// ═══════════════════════════════════════════════════════
//  Alert Banner
// ═══════════════════════════════════════════════════════

function dismissAlert() {
    document.getElementById("alertBanner").classList.remove("visible");
}

// ═══════════════════════════════════════════════════════
//  Chart Mode Toggle
// ═══════════════════════════════════════════════════════

function setChartMode(mode) {
    chartMode = mode;
    trafficChart.data.labels = [];
    trafficChart.data.datasets[0].data = [];
    trafficChart.data.datasets[0].pointBackgroundColor = [];
    trafficChart.update("none");
    document.querySelectorAll(".chart-controls button").forEach((b, i) => {
        b.classList.toggle("selected", ["syn", "est", "all"][i] === mode);
    });
}

// ═══════════════════════════════════════════════════════
//  Section Navigation
// ═══════════════════════════════════════════════════════

document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
        const sec = item.dataset.section;
        document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
        document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
        item.classList.add("active");
        const target = document.getElementById("sec-" + sec);
        if (target) target.classList.add("active");
        if (sec === "attacks") loadFullAttackLog();
        if (sec === "traffic") {
            setTimeout(() => { multiChart && multiChart.resize(); bytesChart && bytesChart.resize(); }, 50);
        }
    });
});

// ═══════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════

socket.on("connect", () => {
    document.getElementById("wsDot").className   = "dot green pulse";
    document.getElementById("wsLabel").innerText = "Live";
});

socket.on("disconnect", () => {
    document.getElementById("wsDot").className   = "dot red-dot";
    document.getElementById("wsLabel").innerText = "Disconnected";
});

socket.on("update",          data => applyUpdate(data));
socket.on("ip_blocked",      d    => console.log("Blocked:",      d.ip));
socket.on("ip_unblocked",    d    => console.log("Unblocked:",    d.ip));
socket.on("ip_auto_blocked", d    => {
    console.log("Auto-blocked:", d.ip);
    const banner = document.getElementById("alertBanner");
    banner.classList.add("visible");
    setText("alertText", `🔒 Auto-blocked IP: ${d.ip} — repeated anomaly trigger`);
});

// ═══════════════════════════════════════════════════════
//  Boot
// ═══════════════════════════════════════════════════════

initCharts();
