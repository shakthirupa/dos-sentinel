// ═══════════════════════════════════════════════════════
//  DoS Sentinel v4 — dashboard.js
// ═══════════════════════════════════════════════════════

const socket = io();

let normalCount  = 0;
let anomalyCount = 0;
let chartMode    = "syn";
let lastData     = null;
let _autoBlockEnabled = true;
let _simResetTimer    = null;   // auto-reset simulator status badge

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
    if (el) el.textContent = val;
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
    const current = parseFloat(el.textContent) || 0;
    const diff = target - current;
    if (Math.abs(diff) < 0.5) { el.textContent = target; return; }
    el.textContent = (current + diff * 0.4).toFixed(Number.isInteger(target) ? 0 : 3);
}

// Safe pill builder — never uses raw network values as HTML
function attackTypePill(type) {
    if (!type || type === "-") return "—";
    const span = document.createElement("span");
    span.className = "attack-type-pill";
    span.textContent = type;
    return span.outerHTML;
}

function confidencePill(conf) {
    if (!conf) return "—";
    const cls = conf === "HIGH" ? "conf-high" : conf === "MEDIUM" ? "conf-medium" : "conf-low";
    const span = document.createElement("span");
    span.className = "confidence-pill " + cls;
    span.textContent = conf;
    return span.outerHTML;
}

function riskPill(risk) {
    if (!risk) return "—";
    const cls = risk === "HIGH" ? "status-anomaly" : risk === "MEDIUM" ? "status-suspicious" : "status-normal";
    const span = document.createElement("span");
    span.className = "status-pill " + cls;
    span.textContent = risk;
    return span.outerHTML;
}

// ═══════════════════════════════════════════════════════
//  HTTP Telemetry
// ═══════════════════════════════════════════════════════

function updateHttpTelemetry(tel) {
    const available   = tel && tel.available !== false;
    const unavailDiv  = document.getElementById("httpUnavailable");
    const metricsDiv  = document.getElementById("httpMetrics");
    const availBadge  = document.getElementById("httpAvailBadge");

    if (!available) {
        if (unavailDiv)  unavailDiv.style.display  = "flex";
        if (metricsDiv)  metricsDiv.style.display  = "none";
        if (availBadge) {
            availBadge.textContent = "● OFFLINE";
            availBadge.style.color = "#ff5360";
            availBadge.style.background = "rgba(255,83,96,.1)";
            availBadge.style.borderColor = "rgba(255,83,96,.3)";
        }
        return;
    }

    if (unavailDiv)  unavailDiv.style.display  = "none";
    if (metricsDiv)  metricsDiv.style.display  = "grid";
    if (availBadge) {
        availBadge.textContent = "● LIVE";
        availBadge.style.color = "";
        availBadge.style.background = "";
        availBadge.style.borderColor = "";
    }

    setText("httpTotal",   tel.total_requests   ?? 0);
    setText("httpRps",     tel.requests_per_sec ?? 0);
    setText("httpSuccess", tel.successful_responses ?? 0);
    setText("httpErrors",  tel.error_responses  ?? 0);
    setText("httpAvgRt",   (tel.avg_response_time_ms ?? 0).toFixed(2) + " ms");

    const sc = tel.status_codes || {};
    setText("httpStatusCodes",
        "2xx: " + (sc["2xx"] ?? 0) +
        "  3xx: " + (sc["3xx"] ?? 0) +
        "  4xx: " + (sc["4xx"] ?? 0) +
        "  5xx: " + (sc["5xx"] ?? 0)
    );
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
        td.colSpan = 8;
        td.style.cssText = "text-align:center;color:#4f6984;padding:30px";
        td.textContent = "No attacks detected yet";
        tr.appendChild(td);
        atbody.appendChild(tr);
        return;
    }
    [...log].reverse().forEach(ev => {
        const tr = document.createElement("tr");
        tr.classList.add("row-anomaly");

        const cells = [
            ev.time || ev.ts || "-",
            ev.syn_recv ?? "-",
            ev.connections ?? ev.conns ?? "-",
            ev.score ?? "-",
            null,   // attack type pill — set below
            null,   // confidence pill
            null,   // risk pill
            ev.source_ip || "-",
        ];

        cells.forEach((val, i) => {
            const td = document.createElement("td");
            if (i === 4) td.innerHTML = attackTypePill(ev.attack_type);
            else if (i === 5) td.innerHTML = confidencePill(ev.confidence);
            else if (i === 6) td.innerHTML = riskPill(ev.risk);
            else td.textContent = val;
            tr.appendChild(td);
        });

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
    const t  = data.traffic || {};
    const ts = data.timestamp || "";

    setText("clock", new Date().toLocaleTimeString());

    // Network metrics
    animateNumber("synRecv",          t.syn_recv          ?? 0);
    animateNumber("established",      t.established       ?? 0);
    animateNumber("totalConnections", t.total_connections ?? 0);
    setText("bytesSent",     formatBytes(t.bytes_sent_per_sec ?? 0));
    setText("bytesReceived", formatBytes(t.bytes_recv_per_sec ?? 0));
    setText("velocityCard",  (t.conn_velocity ?? 0) + "/s");

    // Detection state
    const detection = data.detection || "NORMAL";
    const isAnomaly  = detection === "ANOMALY";
    const isCooldown = detection === "COOLDOWN";

    const card = document.getElementById("threatCard");
    card.className = "threat-card" +
        (isAnomaly  ? " anomaly"  : "") +
        (isCooldown ? " cooldown" : "");

    setText("threatStatus", detection);
    setText("threatMessage",
        isAnomaly  ? "Possible DoS-related anomaly detected!" :
        isCooldown ? "Cooling down — monitoring for recurrence..." :
                     "Server traffic appears normal"
    );
    setText("shieldIcon", isAnomaly ? "!" : isCooldown ? "~" : "✓");

    animateNumber("anomalyScore", data.anomaly_score ?? 0);
    setText("riskLevel",       data.risk        || "LOW");
    setText("confidenceLevel", data.confidence  || "LOW");
    setText("totalAnomalies",  (data.stats || {}).total_anomalies ?? 0);

    // Attack type + source
    const atkType   = isAnomaly ? (data.attack_type || "Unclassified Anomaly") : "—";
    const atkSource = isAnomaly ? (data.attack_type_source === "rule_based" ? "Rule-based" : "—") : "—";
    setText("attackType",       atkType);
    setText("attackTypeSource", atkSource);

    // Model version + status
    const modelVer    = data.model_version || "—";
    const modelStatus = (data.system || {}).model || "—";
    setText("modelVersion",     modelVer);
    setText("modelStatus",      modelStatus);
    setText("statModelVersion", modelVer);
    const statStatusEl = document.getElementById("statModelStatus");
    if (statStatusEl) {
        statStatusEl.textContent = modelStatus === "ACTIVE" ? "● ACTIVE" : "● " + modelStatus;
        statStatusEl.style.color = modelStatus === "ACTIVE" ? "#42f398" : "#ff5360";
    }

    // Alert banner
    if (isAnomaly) {
        const banner = document.getElementById("alertBanner");
        banner.classList.add("visible");
        setText("alertText",
            (data.attack_type || "DoS Anomaly") +
            " — Score: " + (data.anomaly_score ?? 0) +
            " | Risk: " + (data.risk || "?") +
            " | Confidence: " + (data.confidence || "?") +
            " | SYN_RECV: " + (t.syn_recv ?? 0)
        );
    }

    setText("attackBadge", (data.stats || {}).total_anomalies ?? 0);

    // Traffic chart coloring
    const ds       = trafficChart.data.datasets[0];
    const colorArr = Array.isArray(ds.pointBackgroundColor) ? ds.pointBackgroundColor : [];
    colorArr.push(isAnomaly ? "#ff4355" : isCooldown ? "#ffb63e" : "#248dff");
    if (colorArr.length > 60) colorArr.shift();
    ds.pointBackgroundColor = colorArr;
    ds.borderColor     = isAnomaly ? "#ff4355" : isCooldown ? "#ffb63e" : "#248dff";
    ds.backgroundColor = isAnomaly ? "rgba(255,67,85,0.10)" : isCooldown ? "rgba(255,182,62,0.08)" : "rgba(36,141,255,0.08)";

    const synVal = chartMode === "syn" ? (t.syn_recv ?? 0)
                 : chartMode === "est" ? (t.established ?? 0)
                 : (t.total_connections ?? 0);
    pushAndTrim(trafficChart, ts, 60, synVal);
    pushAndTrim(multiChart,   ts, 60, t.syn_recv ?? 0, t.established ?? 0, t.total_connections ?? 0);
    pushAndTrim(bytesChart,   ts, 40,
        ((t.bytes_sent_per_sec ?? 0) / 1024).toFixed(2),
        ((t.bytes_recv_per_sec ?? 0) / 1024).toFixed(2)
    );

    // Distribution donut
    if (isAnomaly) anomalyCount++; else normalCount++;
    const total = normalCount + anomalyCount;
    const nPct  = total === 0 ? 100 : Math.round(normalCount / total * 100);
    setText("donutTotal",    total);
    setText("normalPercent",  nPct + "%");
    setText("anomalyPercent", (100 - nPct) + "%");
    distributionChart.data.datasets[0].data = [normalCount, anomalyCount];
    distributionChart.update();

    // Recent events table
    const tbody = document.getElementById("eventsTable");
    tbody.innerHTML = "";
    [...(data.events || [])].reverse().forEach(ev => {
        const det = ev.status || "NORMAL";
        const cls = det === "ANOMALY" ? "status-anomaly"
                  : det === "COOLDOWN" ? "status-suspicious"
                  : (ev.score < 0 ? "status-suspicious" : "status-normal");
        const tr = document.createElement("tr");
        if (det === "ANOMALY") tr.classList.add("row-anomaly");

        const cols = [
            ev.time,
            ev.message,
            ev.syn_recv ?? "-",
            ev.connections ?? "-",
            ev.score ?? "-",
            null,   // attack type pill
            null,   // confidence pill
            null,   // status pill
        ];
        cols.forEach((val, i) => {
            const td = document.createElement("td");
            if (i === 5) td.innerHTML = attackTypePill(ev.attack_type);
            else if (i === 6) td.innerHTML = confidencePill(ev.confidence);
            else if (i === 7) {
                const sp = document.createElement("span");
                sp.className = "status-pill " + cls;
                sp.textContent = det;
                td.appendChild(sp);
            } else {
                td.textContent = val ?? "-";
            }
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });

    // Attack log — only refresh if tab active
    const attackSec = document.getElementById("sec-attacks");
    if (attackSec && attackSec.classList.contains("active")) {
        renderAttackLog(data.attack_log);
    }

    // IP Manager
    const ipTable = document.getElementById("ipTable");
    const header  = document.createElement("div");
    header.className = "source-row header";
    ["IP ADDRESS", "CONNECTIONS", "TREND", "ACTION"].forEach(h => {
        const d = document.createElement("div");
        d.textContent = h;
        header.appendChild(d);
    });
    ipTable.innerHTML = "";
    ipTable.appendChild(header);

    const sources = data.sources || [];
    if (sources.length === 0) {
        const empty = document.createElement("div");
        empty.style.cssText = "padding:20px 18px;color:#4f6984;font-size:12px";
        empty.textContent = "No active source IPs";
        ipTable.appendChild(empty);
    } else {
        sources.forEach(src => {
            const row = document.createElement("div");
            row.className = "source-row" + (src.blocked ? " blocked-row" : "");

            const ipDiv = document.createElement("div");
            ipDiv.className = "ip-addr";
            ipDiv.textContent = src.ip || "—";

            const connDiv = document.createElement("div");
            connDiv.textContent = src.connections ?? 0;

            const trendDiv = document.createElement("div");
            trendDiv.className = "trend-mini";
            (src.trend || []).forEach(v => {
                const bar = document.createElement("span");
                bar.className = "trend-bar";
                bar.style.height = Math.min(v * 4, 20) + "px";
                trendDiv.appendChild(bar);
            });

            const actDiv = document.createElement("div");
            const btn = document.createElement("button");
            btn.className = src.blocked ? "btn-unblock" : "btn-block";
            btn.textContent = src.blocked ? "Unblock" : "Block";
            const ipVal = src.ip;
            btn.addEventListener("click", () => src.blocked ? unblockIp(ipVal) : blockIp(ipVal));
            actDiv.appendChild(btn);

            row.appendChild(ipDiv);
            row.appendChild(connDiv);
            row.appendChild(trendDiv);
            row.appendChild(actDiv);
            ipTable.appendChild(row);
        });
    }

    setText("blockedCount", (data.stats || {}).blocked_count + " Blocked");

    // System gauges
    const sys = data.system || {};
    updateGauges(Math.round(sys.cpu || 0), Math.round(sys.memory || 0), Math.round(sys.network || 0));

    // Session stats
    const st = data.stats || {};
    setText("statUptime",    st.uptime    || "00:00:00");
    setText("statEvents",    st.total_events    ?? 0);
    setText("statAnomalies", st.total_anomalies ?? 0);
    setText("statBlocked",   st.blocked_count   ?? 0);
    setText("sidebarUptime", "◷ " + (st.uptime || "00:00:00"));

    // Auto-block panel
    _autoBlockEnabled = st.auto_block !== false;
    setText("abStatus",    _autoBlockEnabled ? "ENABLED" : "DISABLED");
    const abEl = document.getElementById("abStatus");
    if (abEl) abEl.style.color = _autoBlockEnabled ? "#42f398" : "#ff5360";
    setText("abThreshold", (st.auto_block_threshold || 3) + " anomalies");
    setText("abBlocked",   (st.blocked_count ?? 0) + " IPs");
    const toggle = document.getElementById("autoBlockToggle");
    if (toggle) toggle.textContent = "Auto-Block: " + (_autoBlockEnabled ? "ON" : "OFF");

    // HTTP telemetry
    updateHttpTelemetry(data.http_telemetry);
}

// ═══════════════════════════════════════════════════════
//  Simulator
// ═══════════════════════════════════════════════════════

async function launchSim(attack, intensity) {
    const simStatus = document.getElementById("simStatus");
    if (simStatus) {
        simStatus.textContent = "LAUNCHING " + attack.toUpperCase() + "...";
        simStatus.style.color = "#ffb63e";
    }
    try {
        const res  = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack, intensity })
        });
        const data = await res.json();
        if (simStatus) {
            if (data.ok) {
                simStatus.textContent = "RUNNING: " + attack.toUpperCase() + " (" + intensity + ")";
                simStatus.style.color = "#ff6572";
                // Auto-reset after simulator default timeout (120s) + buffer
                clearTimeout(_simResetTimer);
                _simResetTimer = setTimeout(() => {
                    simStatus.textContent = "IDLE";
                    simStatus.style.color = "#b180ff";
                }, 130000);
            } else {
                simStatus.textContent = "ERROR: " + (data.error || "failed");
                simStatus.style.color = "#ff9e25";
            }
        }
    } catch (e) {
        if (simStatus) {
            simStatus.textContent = "LAUNCH FAILED";
            simStatus.style.color = "#ff5360";
        }
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
    await fetch("/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
    });
}

async function unblockIp(ip) {
    await fetch("/api/unblock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
    });
}

// ═══════════════════════════════════════════════════════
//  URL Probe
// ═══════════════════════════════════════════════════════

function setProbeStatus(text, color) {
    const el = document.getElementById("probeStatus");
    if (!el) return;
    el.textContent = text;
    el.style.color = color || "";
}

async function probeUrl() {
    const input = document.getElementById("probeUrlInput");
    const btn   = document.getElementById("probeBtn");
    const url   = input ? input.value.trim() : "";

    if (!url) {
        setProbeStatus("Enter a URL first.", "#ff9e25");
        return;
    }

    if (btn) { btn.disabled = true; btn.textContent = "Probing…"; }
    setProbeStatus("PROBING", "#ffb63e");

    const resultEl = document.getElementById("probeResult");
    const errEl    = document.getElementById("probeError");
    if (resultEl) resultEl.style.display = "none";
    if (errEl)    errEl.style.display    = "none";

    let data;
    try {
        const res = await fetch("/api/probe", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url }),
        });
        data = await res.json();
    } catch (e) {
        setProbeStatus("ERROR", "#ff5360");
        if (errEl) {
            errEl.style.display = "flex";
            const errTx = document.getElementById("probeErrorText");
            if (errTx) errTx.textContent = "Network error — could not reach the server.";
        }
        return;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Probe"; }
    }

    // Determine status from HTTP response semantics
    if (!data.ok && data.error && data.error.toLowerCase().includes("rate limit")) {
        setProbeStatus("RATE LIMITED", "#ff9e25");
    } else if (data.ok) {
        setProbeStatus("SUCCESS", "#42f398");
    } else {
        setProbeStatus("ERROR", "#ff5360");
    }

    // Populate the 6 result fields regardless of ok/error — textContent only
    const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val ?? "—"; };
    set("prURL",      data.url);
    set("prHostname", data.hostname);
    set("prIP",       data.resolved_ip);
    set("prStatus",   data.status_code != null ? String(data.status_code) : "—");
    set("prTime",     data.response_time_ms != null ? data.response_time_ms + " ms" : "—");
    set("prTS",       data.timestamp);

    // #probeError is a child of #probeResult — show the outer container first,
    // then toggle the inner error panel based on whether the probe succeeded.
    if (resultEl) resultEl.style.display = "block";
    if (data.ok) {
        if (errEl) errEl.style.display = "none";
    } else {
        if (errEl) {
            errEl.style.display = "flex";
            const errTx = document.getElementById("probeErrorText");
            if (errTx) errTx.textContent = data.error || "Unknown error.";
        }
    }
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
            setTimeout(() => {
                multiChart && multiChart.resize();
                bytesChart && bytesChart.resize();
            }, 50);
        }
    });
});

// ═══════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════

socket.on("connect", () => {
    document.getElementById("wsDot").className   = "dot green pulse";
    document.getElementById("wsLabel").textContent = "Live";
});

socket.on("disconnect", () => {
    document.getElementById("wsDot").className   = "dot red-dot";
    document.getElementById("wsLabel").textContent = "Disconnected";
});

socket.on("update",          data => applyUpdate(data));
socket.on("ip_blocked",      d    => console.log("Blocked:",      d.ip));
socket.on("ip_unblocked",    d    => console.log("Unblocked:",    d.ip));
socket.on("ip_auto_blocked", d    => {
    console.log("Auto-blocked:", d.ip);
    const banner = document.getElementById("alertBanner");
    banner.classList.add("visible");
    setText("alertText", "Auto-blocked IP: " + d.ip + " — repeated anomaly trigger");
});

// ═══════════════════════════════════════════════════════
//  Boot
// ═══════════════════════════════════════════════════════

initCharts();
