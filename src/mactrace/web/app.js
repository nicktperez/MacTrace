const state = {
  mode: "live",
  events: [],
  alerts: [],
  processes: [],
  network: [],
  suppressions: [],
  cases: [],
  inventory: { executables: [], persistence: [] },
  sensors: [],
  rules: [],
  allowlists: [],
  baseline: null,
  assessment: null,
  paused: false,
  selectedAlert: null,
  selectedProcess: null,
  socket: null,
  charts: {},
  chartSignatures: {},
  eventChartDirty: false,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = (value = "") => String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const time = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateTime = (iso) => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });
const labelType = (type) => type.replaceAll("_", " ");
const eventIcon = (type) => ({ process_start: "▶", process_stop: "■", executable_trust: "✓", network_connection: "⇄", network_listen: "◉", file_change: "✦" })[type] || "·";
const eventDetail = (event) => {
  if (event.file_path) return `${event.action || "changed"} · ${event.file_path}`;
  if (event.remote_address) return `${event.local_address || "*"}:${event.local_port || "—"} → ${event.remote_address}:${event.remote_port || "—"}`;
  return event.executable || event.command_line || `PID ${event.pid ?? "—"}`;
};

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || `Request failed (${response.status})`);
  if (response.status === 204) return null;
  return response.json();
}

function toast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = message;
  $("#toast-region").append(node);
  setTimeout(() => node.remove(), 3500);
}

function setView(view) {
  $$(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.view === view));
  $$(".view").forEach(panel => panel.classList.toggle("active", panel.id === `view-${view}`));
  const headings = {
    overview: ["Security overview", "Endpoint posture"],
    events: ["Telemetry", "Live event stream"],
    processes: ["Process explorer", "Execution ancestry"],
    network: ["Network activity", "Connections & listeners"],
    detections: ["Detection center", "Investigation queue"],
    cases: ["Case management", "Correlated investigations"],
    inventory: ["Asset visibility", "Executable & persistence inventory"],
    investigation: ["Investigation view", "Evidence timeline"],
    health: ["System configuration", "Sensor health & tuning"],
  };
  $("#page-context").textContent = headings[view][0];
  $("#page-title").textContent = headings[view][1];
  history.replaceState(null, "", `#${view}`);
  if (view === "overview" && state.eventChartDirty) scheduleEventChartRefresh();
  if (view === "cases") loadCases();
  if (view === "inventory") loadInventory();
  if (view === "health") loadHealth();
}

function renderMode(mode) {
  state.mode = mode;
  const pill = $("#mode-pill");
  pill.textContent = mode === "demo" ? "Synthetic demo" : "Live collection";
  pill.classList.toggle("demo", mode === "demo");
  $("#demo-banner").classList.toggle("hidden", mode !== "demo");
}

function renderStats(stats) {
  $("#risk-score").textContent = stats.risk_score || 0;
  $("#risk-dial").style.setProperty("--risk", `${Math.min(stats.risk_score || 0, 100) * 3.6}deg`);
  $("#risk-label").textContent = stats.risk_score >= 70 ? "Elevated observed risk" : stats.risk_score >= 30 ? "Review recommended" : "Minimal observed risk";
  $("#metric-alerts").textContent = stats.alerts_today || 0;
  $("#metric-processes").textContent = stats.processes || 0;
  $("#metric-network").textContent = stats.connections || 0;
  $("#metric-events").textContent = stats.total_events || 0;
  $("#alert-badge").textContent = stats.alerts_today || 0;
  renderSeverity(stats.severities || {});
}

function renderAssessment(assessment) {
  state.assessment = assessment;
  const root = $("#assessment-brief");
  root.className = `assessment-brief ${assessment.status}`;
  const findingButtons = assessment.findings.slice(0, 2).map(finding => `
    <button class="assessment-finding ${finding.priority}" data-assessment-alert="${finding.alert_ids[0]}">
      <i aria-hidden="true"></i><span><strong>${esc(finding.headline)}</strong><small>${esc(finding.recommendation)} · ${finding.confidence} confidence</small></span><span>Open →</span>
    </button>`).join("");
  root.innerHTML = `
    <div class="assessment-lead"><span class="assessment-mark">${assessment.status === "quiet" ? "✓" : "⌁"}</span><div>
      <div class="assessment-heading"><span>Activity assessment</span><span class="assessment-method">Local correlation · ${assessment.window_hours}h</span></div>
      <h2>${esc(assessment.headline)}</h2><p>${esc(assessment.summary)}</p>
    </div></div>
    <div class="assessment-findings">${findingButtons || `<div class="assessment-empty">No active finding needs investigation. New detections will be correlated automatically.</div>`}</div>`;
  $$("[data-assessment-alert]", root).forEach(button => button.addEventListener("click", () => openAlert(Number(button.dataset.assessmentAlert))));
}

let assessmentRefreshTimer = null;
function scheduleAssessmentRefresh() {
  clearTimeout(assessmentRefreshTimer);
  assessmentRefreshTimer = setTimeout(async () => {
    try { renderAssessment(await api("/api/assessment")); } catch (error) { toast(error.message); }
  }, 250);
}

function chartColors() {
  const css = getComputedStyle(document.documentElement);
  return {
    primary: css.getPropertyValue("--primary").trim(),
    accent: css.getPropertyValue("--accent").trim(),
    green: css.getPropertyValue("--green").trim(),
    yellow: css.getPropertyValue("--yellow").trim(),
    critical: css.getPropertyValue("--critical").trim(),
    muted: css.getPropertyValue("--muted").trim(),
    line: css.getPropertyValue("--line").trim(),
  };
}

function renderSeverity(severities) {
  const keys = ["critical", "high", "medium", "low"];
  const values = keys.map(key => severities[key] || 0);
  const total = values.reduce((sum, value) => sum + value, 0);
  $("#severity-total").firstChild.textContent = total;
  const colors = chartColors();
  const palette = [colors.critical, colors.primary, colors.yellow, colors.accent];
  $("#severity-legend").innerHTML = keys.map((key, index) => `<div class="legend-row"><i style="background:${palette[index]}"></i><span>${key}</span><b>${values[index]}</b></div>`).join("");
  if (!window.Chart) return drawFallback($("#severity-chart"), values, palette, true);
  const signature = JSON.stringify(values);
  if (state.chartSignatures.severity === signature) return;
  state.chartSignatures.severity = signature;
  if (state.charts.severity) {
    state.charts.severity.data.datasets[0].data = total ? values : [1];
    state.charts.severity.data.datasets[0].backgroundColor = total ? palette : [colors.line];
    state.charts.severity.update("none");
    return;
  }
  state.charts.severity = new Chart($("#severity-chart"), {
    type: "doughnut",
    data: { labels: keys, datasets: [{ data: total ? values : [1], backgroundColor: total ? palette : [colors.line], borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false, cutout: "78%", plugins: { legend: { display: false }, tooltip: { enabled: total > 0 } } },
  });
}

function renderEventChart() {
  state.eventChartDirty = false;
  const recent = [...state.events].reverse().slice(-60);
  const buckets = Array.from({ length: 10 }, (_, index) => ({ label: `${index + 1}`, process: 0, network: 0, file: 0 }));
  recent.forEach((event, index) => {
    const bucket = buckets[Math.min(9, Math.floor(index / Math.max(1, Math.ceil(recent.length / 10))))];
    if (event.event_type.startsWith("process")) bucket.process += 1;
    else if (event.event_type.startsWith("network")) bucket.network += 1;
    else bucket.file += 1;
  });
  const colors = chartColors();
  if (!window.Chart) return drawFallback($("#events-chart"), buckets.map(b => b.process + b.network + b.file), [colors.accent], false);
  const labels = buckets.map((_, i) => i % 2 ? "" : `T-${10 - i}`);
  const values = [
    buckets.map(bucket => bucket.process),
    buckets.map(bucket => bucket.network),
    buckets.map(bucket => bucket.file),
  ];
  if (state.charts.events) {
    state.charts.events.data.labels = labels;
    state.charts.events.data.datasets.forEach((dataset, index) => {
      dataset.data = values[index];
    });
    state.charts.events.update("none");
    return;
  }
  state.charts.events = new Chart($("#events-chart"), {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Processes", data: values[0], borderColor: colors.accent, backgroundColor: "transparent", tension: .35, pointRadius: 0, borderWidth: 1.5 },
        { label: "Network", data: values[1], borderColor: colors.primary, backgroundColor: "transparent", tension: .35, pointRadius: 0, borderWidth: 1.5 },
        { label: "Files", data: values[2], borderColor: colors.yellow, backgroundColor: "transparent", tension: .35, pointRadius: 0, borderWidth: 1.5 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, interaction: { intersect: false, mode: "index" },
      scales: { x: { grid: { display: false }, ticks: { color: colors.muted, font: { size: 8 } } }, y: { beginAtZero: true, grid: { color: colors.line }, ticks: { color: colors.muted, font: { size: 8 }, precision: 0 } } },
      plugins: { legend: { labels: { color: colors.muted, usePointStyle: true, boxWidth: 6, font: { size: 9 } }, position: "bottom", align: "start" } },
    },
  });
}

let eventChartRefreshTimer = null;
function scheduleEventChartRefresh() {
  state.eventChartDirty = true;
  if (!$("#view-overview").classList.contains("active")) return;
  if (eventChartRefreshTimer !== null) return;
  eventChartRefreshTimer = setTimeout(() => {
    eventChartRefreshTimer = null;
    renderEventChart();
  }, 650);
}

function drawFallback(canvas, values, colors, donut) {
  const ctx = canvas.getContext("2d");
  const width = canvas.clientWidth || 240, height = canvas.clientHeight || 120;
  canvas.width = width * devicePixelRatio; canvas.height = height * devicePixelRatio; ctx.scale(devicePixelRatio, devicePixelRatio);
  ctx.clearRect(0, 0, width, height);
  if (donut) {
    const total = values.reduce((a, b) => a + b, 0) || 1; let start = -Math.PI / 2;
    values.forEach((value, index) => { const angle = value / total * Math.PI * 2; ctx.beginPath(); ctx.strokeStyle = colors[index]; ctx.lineWidth = 12; ctx.arc(width / 2, height / 2, Math.min(width, height) / 2 - 10, start, start + angle); ctx.stroke(); start += angle; });
  } else {
    const max = Math.max(...values, 1); ctx.strokeStyle = colors[0]; ctx.lineWidth = 2; ctx.beginPath();
    values.forEach((value, index) => { const x = index / Math.max(1, values.length - 1) * width; const y = height - 10 - value / max * (height - 20); index ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.stroke();
  }
}

function renderRecentAlerts() {
  const root = $("#recent-alerts");
  const alerts = state.alerts.slice(0, 4);
  root.innerHTML = alerts.length ? alerts.map(alert => `
    <div class="alert-row" data-alert="${alert.id}">
      <span class="alert-icon">◇</span>
      <span class="alert-copy"><strong>${esc(alert.rule_name)}</strong><small>${esc(alert.process_name || alert.rule_id)} · ${time(alert.timestamp)}</small></span>
      <span class="severity ${alert.severity}">${alert.severity}</span><span class="status ${alert.status}">${alert.status}</span>
    </div>`).join("") : `<div class="empty-inline">No detections yet. Live observations will appear here when a rule matches.</div>`;
  $$("[data-alert]", root).forEach(node => node.addEventListener("click", () => openAlert(Number(node.dataset.alert))));
}

function filteredEvents() {
  const query = $("#event-search").value.trim().toLowerCase();
  const type = $("#event-type-filter").value;
  return state.events.filter(event => (!type || event.event_type === type) && (!query || JSON.stringify(event).toLowerCase().includes(query)));
}

function renderEvents() {
  const root = $("#event-stream");
  const events = filteredEvents().slice(0, 300);
  $("#visible-events").textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;
  $("#event-badge").textContent = Math.min(state.events.length, 999);
  root.innerHTML = events.length ? events.map(event => `
    <div class="event-row ${event.synthetic ? "synthetic" : ""}">
      <time class="event-time">${time(event.timestamp)}</time><span class="event-kind-icon">${eventIcon(event.event_type)}</span>
      <span class="event-type">${labelType(event.event_type)}</span><span class="event-process">${esc(event.process_name || event.file_path?.split("/").pop() || "System")}</span>
      <span class="event-detail" title="${esc(eventDetail(event))}">${esc(eventDetail(event))}</span>
    </div>`).join("") : `<div class="empty-inline">No events match these filters.</div>`;
}

function renderProcesses() {
  const latest = new Map();
  state.events.filter(e => e.event_type === "process_start" && e.pid != null).forEach(e => { if (!latest.has(e.pid)) latest.set(e.pid, e); });
  state.processes = [...latest.values()];
  $("#process-tree").innerHTML = state.processes.length ? state.processes.map(process => `
    <div class="process-node ${state.selectedProcess === process.pid ? "selected" : ""}" data-pid="${process.pid}">
      <span class="process-node-icon">▶</span><span><strong>${esc(process.process_name || "Unknown")}</strong><small>${esc(process.executable || "Path unavailable")}</small></span><small>${process.pid}</small>
    </div>`).join("") : `<div class="empty-inline">No process starts observed yet.</div>`;
  $$("[data-pid]", $("#process-tree")).forEach(node => node.addEventListener("click", () => openProcess(Number(node.dataset.pid))));
}

async function openProcess(pid) {
  state.selectedProcess = pid; renderProcesses();
  try {
    const data = await api(`/api/processes/${pid}`);
    const process = data.process;
    $("#process-detail").classList.remove("empty-state");
    $("#process-detail").innerHTML = `
      <div class="detail-header"><div class="title-line"><span class="process-node-icon">▶</span><h2>${esc(process.process_name || "Unknown")}</h2></div><p>${esc(process.executable || "Executable path unavailable")}</p></div>
      <section class="detail-section"><h3>PROCESS METADATA</h3><dl class="metadata-grid"><div><dt>PID</dt><dd>${process.pid}</dd></div><div><dt>Parent PID</dt><dd>${process.ppid ?? "—"}</dd></div><div><dt>First observed</dt><dd>${dateTime(process.timestamp)}</dd></div><div><dt>Signing</dt><dd>${esc(process.metadata?.signing || "unavailable")}</dd></div><div><dt>First executable sighting</dt><dd>${process.metadata?.newly_observed_executable ? "Yes" : "Previously observed"}</dd></div><div><dt>Quarantine provenance</dt><dd>${process.metadata?.quarantine?.status === "pending" ? "Inspection pending" : process.metadata?.quarantine?.present ? esc(process.metadata.quarantine.agent || "Present") : "Not present"}</dd></div></dl></section>
      <section class="detail-section"><h3>SANITIZED COMMAND</h3><p class="explanation"><code>${esc(process.command_line || "Unavailable")}</code></p></section>
      <section class="detail-section"><h3>ANCESTRY · CHILD → ROOT</h3><div class="ancestry-line"><span>${esc(process.process_name)}</span>${(process.ancestry || []).map(parent => `<i>←</i><span>${esc(parent.name)} <small>${parent.pid}</small></span>`).join("")}</div></section>
      <section class="detail-section"><h3>RELATED ACTIVITY</h3><p class="explanation">${data.events.length} event(s) · ${data.alerts.length} detection(s)</p></section>`;
  } catch (error) { toast(error.message); }
}

function renderNetwork() {
  const query = $("#network-search").value.trim().toLowerCase();
  const rows = state.network.filter(row => !query || JSON.stringify(row).toLowerCase().includes(query));
  $("#network-table").innerHTML = `<div class="table-head"><span>Process</span><span>Local</span><span>Remote</span><span>State</span><span>First / last observed</span></div>` + (rows.length ? rows.map(row => `
    <div class="table-row"><strong>${esc(row.process_name || "Restricted")}</strong><code>${esc(row.local_address || "*")}:${row.local_port || "—"}</code><code>${esc(row.remote_address || "—")}:${row.remote_port || "—"}</code><span class="connection-state">${esc(row.connection_state || labelType(row.event_type))}</span><span class="observed-range">${time(row.first_observed)} → ${time(row.last_observed)}<small>${row.observation_count} observation${row.observation_count === 1 ? "" : "s"}</small></span></div>`).join("") : `<div class="empty-inline">No network observations match.</div>`);
}

function filteredAlerts() {
  const severity = $("#severity-filter").value, status = $("#status-filter").value;
  return state.alerts.filter(alert => (!severity || alert.severity === severity) && (!status || alert.status === status));
}

function renderDetections() {
  const alerts = filteredAlerts();
  $("#detection-list").innerHTML = alerts.length ? alerts.map(alert => `
    <div class="detection-item ${state.selectedAlert === alert.id ? "selected" : ""}" data-detection="${alert.id}">
      <div class="detection-item-top"><strong>${esc(alert.rule_name)}</strong><span class="severity ${alert.severity}">${alert.severity}</span></div>
      <p>${esc(alert.description)}</p><small>${esc(alert.rule_id)} · ${time(alert.timestamp)} · ${esc(alert.status)}</small>
    </div>`).join("") : `<div class="empty-inline">No detections match these filters.</div>`;
  $$("[data-detection]", $("#detection-list")).forEach(node => node.addEventListener("click", () => openAlert(Number(node.dataset.detection), false)));
}

async function openAlert(id, switchView = true) {
  state.selectedAlert = id;
  if (switchView) setView("detections");
  renderDetections();
  try {
    const alert = await api(`/api/alerts/${id}`);
    const finding = state.assessment?.findings.find(item => item.alert_ids.includes(id));
    const assessmentContext = finding ? `<section class="detail-section"><h3>ACTIVITY ASSESSMENT</h3><div class="assessment-context"><div class="assessment-context-top"><strong>${esc(finding.recommendation)}</strong><span class="priority-label ${finding.priority}">${finding.priority} · ${finding.confidence} confidence</span></div><p>${esc(finding.summary)}</p></div><p class="explanation">${esc(finding.why.join(" · "))}</p></section>` : "";
    const root = $("#detection-detail");
    root.classList.remove("empty-state");
    root.innerHTML = `
      <div class="detail-header"><div class="title-line"><span class="alert-icon">◇</span><h2>${esc(alert.rule_name)}</h2><span class="severity ${alert.severity}">${alert.severity}</span></div><p>${esc(alert.rule_id)} · ${dateTime(alert.timestamp)}</p></div>
      <section class="detail-section"><h3>WHY THIS FIRED</h3><p class="explanation">${esc(alert.explanation)}</p></section>
      ${assessmentContext}
      <section class="detail-section"><h3>SUPPORTING EVIDENCE</h3>${alert.supporting_event_ids.map(eventId => `<span class="evidence-chip">Event #${eventId}</span>`).join("") || `<p class="explanation">No persisted event references.</p>`}</section>
      <section class="detail-section"><h3>RECOMMENDED INVESTIGATION</h3><ol class="step-list">${alert.recommended_steps.map(step => `<li>${esc(step)}</li>`).join("")}</ol></section>
      <section class="detail-section"><h3>ANALYST DISPOSITION</h3><form id="analyst-form" class="analyst-form"><select id="alert-status"><option>new</option><option>investigating</option><option>benign</option><option>resolved</option></select><textarea id="analyst-note" placeholder="Add a local analyst note…">${esc(alert.analyst_note)}</textarea><div class="analyst-actions"><button class="primary-button" type="submit">Save disposition</button><button id="build-timeline" class="secondary-button compact" type="button">Build timeline</button><button id="suppress-rule" class="secondary-button compact" type="button">Suppress rule · 1h</button></div></form></section>`;
    $("#alert-status").value = alert.status;
    $("#analyst-form").addEventListener("submit", saveDisposition);
    $("#build-timeline").addEventListener("click", () => openInvestigation(id));
    $("#suppress-rule").addEventListener("click", () => suppressRule(alert.rule_id));
  } catch (error) { toast(error.message); }
}

async function suppressRule(ruleId) {
  try {
    const suppression = await api(`/api/suppressions/${encodeURIComponent(ruleId)}`, {
      method: "PUT",
      body: JSON.stringify({ hours: 1, reason: "Suppressed from Detection Center" }),
    });
    state.suppressions = state.suppressions.filter(item => item.rule_id !== ruleId);
    state.suppressions.push(suppression);
    toast(`${ruleId} suppressed for one hour. Existing alerts are unchanged.`);
  } catch (error) { toast(error.message); }
}

async function saveDisposition(event) {
  event.preventDefault();
  try {
    const updated = await api(`/api/alerts/${state.selectedAlert}`, { method: "PATCH", body: JSON.stringify({ status: $("#alert-status").value, analyst_note: $("#analyst-note").value }) });
    const index = state.alerts.findIndex(alert => alert.id === updated.id);
    if (index >= 0) state.alerts[index] = updated;
    renderDetections(); renderRecentAlerts(); scheduleAssessmentRefresh(); toast("Disposition saved locally.");
  } catch (error) { toast(error.message); }
}

async function openInvestigation(id) {
  try {
    const report = await api(`/api/investigations/${id}`);
    setView("investigation");
    const root = $("#investigation-content");
    root.classList.remove("empty-state");
    root.innerHTML = `
      <div class="investigation-header"><div><h2>${esc(report.alert.rule_name)}</h2><p>${esc(report.alert.rule_id)} · ${report.timeline.length} correlated event(s) · Sanitized ${report.mode} report</p></div><div class="export-actions"><a class="secondary-button compact" href="/api/investigations/${id}/export?format=json">Export JSON</a><a class="secondary-button compact" href="/api/investigations/${id}/export?format=html">Export HTML</a></div></div>
      <div class="timeline">${report.timeline.length ? report.timeline.map(event => `<article class="timeline-event"><time>${dateTime(event.timestamp)}</time><h3>${eventIcon(event.event_type)} ${esc(labelType(event.event_type))} · ${esc(event.process_name || "System")}</h3><p>${esc(eventDetail(event))}</p></article>`).join("") : `<div class="empty-inline">No correlated evidence is available.</div>`}</div>`;
  } catch (error) { toast(error.message); }
}

async function loadCases() {
  try {
    state.cases = await api("/api/cases");
    renderCases();
  } catch (error) { toast(error.message); }
}

function renderCases() {
  const root = $("#case-list");
  root.innerHTML = state.cases.length ? state.cases.map(item => `
    <button class="case-item" data-case="${esc(item.id)}">
      <span class="case-item-top"><strong>${esc(item.title)}</strong><span class="priority-label ${item.priority}">${item.priority}</span></span>
      <span>${esc(item.summary)}</span>
      <small>${item.alert_count} detection${item.alert_count === 1 ? "" : "s"} · ${esc(item.confidence)} confidence · ${esc(item.status)}</small>
    </button>`).join("") : `<div class="empty-inline">No correlated cases yet. Cases are created when detections form a meaningful activity chain.</div>`;
  $$("[data-case]", root).forEach(node => node.addEventListener("click", () => openCase(node.dataset.case)));
}

async function openCase(id) {
  try {
    const item = await api(`/api/cases/${encodeURIComponent(id)}`);
    const root = $("#case-detail");
    root.classList.remove("empty-state");
    root.innerHTML = `
      <div class="detail-header"><div class="title-line"><span class="alert-icon">▣</span><h2>${esc(item.title)}</h2><span class="priority-label ${item.priority}">${item.priority}</span></div><p>${esc(item.id)} · ${esc(item.confidence)} confidence</p></div>
      <section class="detail-section"><h3>CASE ASSESSMENT</h3><p class="explanation">${esc(item.summary)}</p></section>
      <section class="detail-section"><h3>LINKED DETECTIONS</h3><div class="case-alerts">${item.alerts.map(alert => `<button data-case-alert="${alert.id}"><span>${esc(alert.rule_name)}</span><span class="severity ${alert.severity}">${alert.severity}</span></button>`).join("")}</div></section>
      <section class="detail-section"><h3>EVIDENCE TIMELINE · ${item.timeline.length} EVENTS</h3><div class="mini-timeline">${item.timeline.slice(-10).map(event => `<div><time>${time(event.timestamp)}</time><strong>${esc(labelType(event.event_type))}</strong><span>${esc(event.process_name || event.file_path || "System")}</span></div>`).join("")}</div></section>
      <section class="detail-section"><h3>CASE DISPOSITION</h3><form id="case-form" class="analyst-form"><select id="case-status"><option>new</option><option>investigating</option><option>contained</option><option>resolved</option><option>benign</option></select><textarea id="case-note" placeholder="Document findings, actions, and rationale…">${esc(item.analyst_note)}</textarea><button class="primary-button" type="submit">Save case</button></form></section>`;
    $("#case-status").value = item.status;
    $$("[data-case-alert]", root).forEach(node => node.addEventListener("click", () => openAlert(Number(node.dataset.caseAlert))));
    $("#case-form").addEventListener("submit", async event => {
      event.preventDefault();
      try {
        await api(`/api/cases/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status: $("#case-status").value, analyst_note: $("#case-note").value }) });
        await loadCases(); toast("Case saved locally.");
      } catch (error) { toast(error.message); }
    });
  } catch (error) { toast(error.message); }
}

async function loadInventory() {
  const kind = $("#inventory-kind").value;
  try {
    state.inventory[kind] = await api(`/api/inventory/${kind}`);
    renderInventory();
  } catch (error) { toast(error.message); }
}

function renderInventory() {
  const kind = $("#inventory-kind").value;
  const query = $("#inventory-search").value.trim().toLowerCase();
  const rows = state.inventory[kind].filter(item => !query || JSON.stringify(item).toLowerCase().includes(query));
  $("#inventory-summary").innerHTML = `<strong>${rows.length}</strong><span>${kind === "executables" ? "observed executables" : "persistence entries"} shown</span>`;
  if (kind === "executables") {
    $("#inventory-table").innerHTML = `<div class="inventory-head"><span>Executable</span><span>Trust</span><span>Launches</span><span>First / last observed</span></div>` + (rows.length ? rows.map(item => `<div class="inventory-row"><span><strong>${esc(item.process_name || "Unknown")}</strong><code>${esc(item.path)}</code></span><span class="trust ${esc(item.signing)}">${esc(item.signing)}</span><strong>${item.launch_count}</strong><span class="observed-range">${dateTime(item.first_observed)}<small>${dateTime(item.last_observed)}</small></span></div>`).join("") : `<div class="empty-inline">No executable observations match.</div>`);
  } else {
    $("#inventory-table").innerHTML = `<div class="inventory-head"><span>Persistence item</span><span>Type</span><span>Changes</span><span>Last observed</span></div>` + (rows.length ? rows.map(item => `<div class="inventory-row"><span><strong>${esc(item.path.split("/").pop())}</strong><code>${esc(item.path)}</code></span><span>${esc(item.persistence_type)}</span><strong>${item.change_count}</strong><span class="observed-range">${dateTime(item.last_observed)}<small>${esc(item.last_action || "observed")}</small></span></div>`).join("") : `<div class="empty-inline">No persistence metadata match.</div>`);
  }
}

async function loadHealth() {
  try {
    [state.sensors, state.baseline, state.rules, state.allowlists] = await Promise.all([
      api("/api/sensors"), api("/api/baseline"), api("/api/rules"), api("/api/allowlists"),
    ]);
    renderHealth();
  } catch (error) { toast(error.message); }
}

function renderHealth() {
  $("#sensor-grid").innerHTML = state.sensors.map(sensor => `
    <article class="panel sensor-card"><div><span class="health-dot ${sensor.status}"></span><strong>${esc(sensor.name)}</strong></div><b>${esc(sensor.status)}</b><p>${esc(sensor.detail)}</p><small>${sensor.events_observed == null ? "Continuous monitor" : `${sensor.events_observed} events observed`}${sensor.last_poll ? ` · ${time(sensor.last_poll)}` : ""}</small></article>`).join("");
  const baseline = state.baseline;
  $("#baseline-panel").innerHTML = `<div class="baseline-top"><strong>${baseline.progress}%</strong><span>${baseline.learning ? "Learning normal activity" : "Baseline active"}</span></div><div class="progress-track"><i style="width:${baseline.progress}%"></i></div><p>${baseline.observations} observations across ${Object.keys(baseline.categories).length} behavior categories. New executables, parent relationships, remote destinations, and listeners receive explainable novelty scores.</p><div class="category-chips">${Object.entries(baseline.categories).map(([key, count]) => `<span>${esc(labelType(key))} · ${count}</span>`).join("")}</div>`;
  $("#allowlist-rule").innerHTML = `<option value="">All rules</option>` + state.rules.map(rule => `<option value="${esc(rule.rule_id)}">${esc(rule.rule_id)}</option>`).join("");
  $("#allowlist-list").innerHTML = state.allowlists.length ? state.allowlists.map(item => `<div class="allowlist-item"><span><strong>${esc(labelType(item.kind))}</strong><code>${esc(item.value)}</code><small>${item.rule_id ? `Only ${esc(item.rule_id)}` : "All rules"}</small></span><button data-remove-allowlist="${item.id}" class="text-button">Remove</button></div>`).join("") : `<div class="empty-inline">No custom exceptions.</div>`;
  $$("[data-remove-allowlist]").forEach(button => button.addEventListener("click", async () => {
    try { await api(`/api/allowlists/${button.dataset.removeAllowlist}`, { method: "DELETE" }); await loadHealth(); toast("Exception removed."); } catch (error) { toast(error.message); }
  }));
  $("#rules-list").innerHTML = state.rules.map(rule => `<div class="rule-row"><div><strong>${esc(rule.name)}</strong><p>${esc(rule.description)}</p><small>${esc(rule.rule_id)} · default ${esc(rule.default_severity)}</small></div><label class="switch"><input type="checkbox" data-rule-enabled="${esc(rule.rule_id)}" ${rule.enabled ? "checked" : ""}><span></span><em>${rule.enabled ? "On" : "Off"}</em></label><select data-rule-severity="${esc(rule.rule_id)}"><option value="">Default</option>${["low","medium","high","critical"].map(level => `<option ${rule.severity_override === level ? "selected" : ""}>${level}</option>`).join("")}</select></div>`).join("");
  $$("[data-rule-enabled], [data-rule-severity]").forEach(control => control.addEventListener("change", async () => {
    const ruleId = control.dataset.ruleEnabled || control.dataset.ruleSeverity;
    const enabled = $(`[data-rule-enabled="${ruleId}"]`).checked;
    const severity = $(`[data-rule-severity="${ruleId}"]`).value || null;
    try { await api(`/api/rules/${encodeURIComponent(ruleId)}`, { method: "PUT", body: JSON.stringify({ enabled, severity_override: severity }) }); await loadHealth(); toast(`${ruleId} updated.`); } catch (error) { toast(error.message); }
  }));
}

async function loadInitial() {
  try {
    const [health, stats, events, alerts, network, suppressions, assessment] = await Promise.all([api("/api/health"), api("/api/stats"), api("/api/events?limit=500"), api("/api/alerts?limit=500"), api("/api/network"), api("/api/suppressions"), api("/api/assessment")]);
    renderMode(health.mode); state.events = events; state.alerts = alerts; state.network = network; state.suppressions = suppressions;
    renderStats(stats); renderAssessment(assessment); renderEvents(); renderEventChart(); renderRecentAlerts(); renderProcesses(); renderNetwork(); renderDetections();
  } catch (error) { toast(`Could not load MacTrace: ${error.message}`); }
}

function connectSocket() {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  state.socket = socket;
  socket.addEventListener("open", () => { $("#socket-state").classList.add("online"); $("#socket-state").lastChild.textContent = " Live"; socket.send("ready"); });
  socket.addEventListener("close", () => { $("#socket-state").classList.remove("online"); $("#socket-state").lastChild.textContent = " Reconnecting"; setTimeout(connectSocket, 1600); });
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (message.kind === "connected") { renderMode(message.data.mode); renderStats(message.data.stats); }
    if (message.kind === "event") {
      state.events.unshift(message.data); state.events = state.events.slice(0, 2000);
      if (!state.paused) {
        renderEvents(); scheduleEventChartRefresh(); renderProcesses();
        if (message.data.event_type === "executable_trust" && state.selectedProcess === message.data.pid) {
          openProcess(message.data.pid);
        }
        if (message.data.event_type.startsWith("network_")) {
          api("/api/network").then(rows => { state.network = rows; renderNetwork(); });
        }
      }
    }
    if (message.kind === "alert") {
      state.alerts.unshift(message.data); renderRecentAlerts(); renderDetections();
      scheduleAssessmentRefresh();
      toast(`${message.data.severity.toUpperCase()} · ${message.data.rule_name}`);
    }
    if (message.kind === "alert_update") {
      const index = state.alerts.findIndex(alert => alert.id === message.data.id);
      if (index >= 0) state.alerts[index] = message.data;
      renderRecentAlerts(); renderDetections(); scheduleAssessmentRefresh();
    }
    if (message.kind === "stats") renderStats(message.data);
  });
}

function bind() {
  $$(".nav-item").forEach(button => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-go]").forEach(button => button.addEventListener("click", () => setView(button.dataset.go)));
  ["event-search", "event-type-filter"].forEach(id => $(`#${id}`).addEventListener("input", renderEvents));
  $("#network-search").addEventListener("input", renderNetwork);
  ["severity-filter", "status-filter"].forEach(id => $(`#${id}`).addEventListener("input", renderDetections));
  $("#inventory-search").addEventListener("input", renderInventory);
  $("#inventory-kind").addEventListener("change", loadInventory);
  $("#allowlist-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      await api("/api/allowlists", { method: "POST", body: JSON.stringify({ kind: $("#allowlist-kind").value, value: $("#allowlist-value").value, rule_id: $("#allowlist-rule").value || null }) });
      $("#allowlist-value").value = ""; await loadHealth(); toast("Exception added.");
    } catch (error) { toast(error.message); }
  });
  $("#pause-stream").addEventListener("click", event => {
    state.paused = !state.paused;
    event.currentTarget.textContent = state.paused ? "▶ Resume" : "Ⅱ Pause";
    if (state.paused && eventChartRefreshTimer !== null) {
      clearTimeout(eventChartRefreshTimer);
      eventChartRefreshTimer = null;
    }
    if (!state.paused) { renderEvents(); renderEventChart(); renderProcesses(); renderNetwork(); }
  });
  const initial = location.hash.slice(1);
  if (["overview", "events", "processes", "network", "detections", "cases", "inventory", "investigation", "health"].includes(initial)) setView(initial);
}

bind();
loadInitial();
connectSocket();
