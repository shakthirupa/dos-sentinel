// ═══════════════════════════════════════════════════════
//  DoS Sentinel v3 — dashboard.js
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
    return `<span class="attack-type-pill">${type}</span>`;
}

// ═══════════════════════════════════════════════════════
//  Attack Log
// ═══════════════════════════════════════════════════════

function renderAttackLog(log) {
    const atbody = document.getElementById("attackTable");
    if (!atbody) return;
    atbody.innerHTML = "";
    if (!log || log.length === 0) {
        atbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#4f6984;padding:30px">No attacks detected yet</td></tr>`;
        return;
    }
    [...log].reverse().forEach(ev => {
        const riskCls = ev.risk === "HIGH" ? "status-anomaly" : "status-suspicious";
        const tr = document.createElement("tr");
        tr.classList.add("row-anomaly");
        tr.innerHTML = `
            <td>${ev.time || ev.ts || "-"}</td>
            <td>${ev.syn_recv}</td>
            <td>${ev.connections || ev.conns}</td>
            <td>${ev.velocity ?? "-"}</td>
            <td>${ev.score}</td>
            <td>${attackTypePill(ev.attack_type)}</td>
            <td><span class="status-pill ${riskCls}">${ev.risk ?? ev.status}</span></td>`;
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
    const isAnomaly = data.detection === "ANOMALY";

    card.className = "threat-card" + (isAnomaly ? " anomaly" : "");
    setText("threatStatus",   data.detection);
    setText("threatMessage",  isAnomaly ? "⚠ Possible DoS-related anomaly detected!" : "Server traffic appears normal");
    setText("shieldIcon",     isAnomaly ? "!" : "✓");
    animateNumber("anomalyScore", data.anomaly_score);
    setText("riskLevel",      data.risk);
    setText("totalAnomalies", data.stats.total_anomalies);
    setText("attackType",     isAnomaly ? (data.attack_type || "Unknown DoS") : "—");

    if (isAnomaly) {
        const banner = document.getElementById("alertBanner");
        banner.classList.add("visible");
        setText("alertText", `🚨 ${data.attack_type || "DoS Anomaly"} — Score: ${data.anomaly_score} | Risk: ${data.risk} | SYN_RECV: ${t.syn_recv}`);
    }

    setText("attackBadge", data.stats.total_anomalies);

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
        const cls = ev.status === "ANOMALY" ? "status-anomaly" : ev.score < 0 ? "status-suspicious" : "status-normal";
        const tr  = document.createElement("tr");
        if (ev.status === "ANOMALY") tr.classList.add("row-anomaly");
        tr.innerHTML = `
            <td>${ev.time}</td>
            <td>${ev.message}</td>
            <td>${ev.syn_recv}</td>
            <td>${ev.connections}</td>
            <td>${ev.velocity ?? "-"}</td>
            <td>${ev.score}</td>
            <td>${attackTypePill(ev.attack_type)}</td>
            <td><span class="status-pill ${cls}">${ev.status}</span></td>`;
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
    data.sources.forEach(src => {
        const row = document.createElement("div");
        row.className = "source-row" + (src.blocked ? " blocked-row" : "");
        const trendHtml = (src.trend || []).map(v =>
            `<span class="trend-bar" style="height:${Math.min(v * 4, 20)}px"></span>`
        ).join("");
        row.innerHTML = `
            <div class="ip-addr">${src.ip}</div>
            <div>${src.connections}</div>
            <div class="trend-mini">${trendHtml}</div>
            <div>${src.blocked
                ? `<button class="btn-unblock" onclick="unblockIp('${src.ip}')">Unblock</button>`
                : `<button class="btn-block" onclick="blockIp('${src.ip}')">Block</button>`
            }</div>`;
        ipTable.appendChild(row);
    });
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

async function launchSim(attack, intensity) {
    const simStatus = document.getElementById("simStatus");
    if (simStatus) { simStatus.innerText = `LAUNCHING ${attack.toUpperCase()}…`; simStatus.style.color = "#ffb63e"; }
    try {
        const res  = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack, intensity })
        });
        const data = await res.json();
        if (simStatus) {
            if (data.ok) {
                simStatus.innerText = `RUNNING: ${attack.toUpperCase()} (${intensity})`;
                simStatus.style.color = "#ff6572";
            } else {
                simStatus.innerText = "ERROR: " + (data.error || "failed");
                simStatus.style.color = "#ff9e25";
            }
        }
    } catch (e) {
        if (simStatus) { simStatus.innerText = "LAUNCH FAILED"; simStatus.style.color = "#ff5360"; }
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
