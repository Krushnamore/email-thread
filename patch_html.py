import re

with open("frontend/index.html", "r") as f:
    html = f.read()

# Add toast container before script
if '<div id="toastContainer" class="toast-container"></div>' not in html:
    html = html.replace("</body>", '<div id="toastContainer" class="toast-container"></div>\n</body>')

# Add showToast function
if 'function showToast(' not in html:
    toast_func = """
// ---------- real-time alerts ----------
function showToast(verdict, score, subject) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  const level = (verdict || 'low').toLowerCase();
  toast.className = `toast toast-${level}`;
  let title = "Real-Time Alert";
  if (verdict === 'HIGH' || verdict === 'CRITICAL') {
    title = `High-Risk Email Blocked! (${score}/100)`;
  } else {
    title = `Email Analyzed (${verdict})`;
  }
  toast.innerHTML = `<div class="toast-title">${title}</div><div class="toast-msg">Subject: ${escapeHtml(subject)}</div>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease-in forwards';
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}
"""
    html = html.replace("// ---------- rendering ----------", toast_func + "\n// ---------- rendering ----------")

# Trigger toast at end of runAnalysis
if 'showToast(data.scoring.verdict, data.scoring.score, data.subject)' not in html:
    # Need to find runAnalysis logic where renderResults is called
    html = html.replace("renderResults(data);\n    loadCases(); // refresh case history table", 
        "renderResults(data);\n    loadCases(); // refresh case history table\n    showToast(data.scoring.verdict, data.scoring.score, data.subject);")

# Update Relay Chain HTML logic
relay_logic_old = """  const relayWrap = document.getElementById("relayChain");
  if (hops.length) {
    relayWrap.innerHTML = hops.map(h => `
      <div class="hop">
        <span class="idx">${h.hop_index}</span>
        <div style="flex:1;">
          <div style="font-weight: 500;">${escapeHtml(h.from_host || "unknown")} → ${escapeHtml(h.by_host || "unknown")} ${h.ip ? "<span style='color:#93c5fd;'>(" + escapeHtml(h.ip) + ")</span>" : ""}</div>
          ${h.resolved_from_host ? `<div class="muted" style="font-size:0.8em; color: #60a5fa; margin-top:2px;">⚡ Resolved host IP via DNS: ${escapeHtml(h.resolved_from_host)}</div>` : ""}
          ${h.geoip && h.geoip.country ? `<div class="muted" style="font-size:0.85em; margin-top:2px; color: #4ade80;">📍 ${escapeHtml(h.geoip.city || "Unknown")}, ${escapeHtml(h.geoip.country)} (${escapeHtml(h.geoip.isp || "")})</div>` : ""}
          ${!h.geoip && h.network_type ? `<div class="muted" style="font-size:0.82em; margin-top:2px; color: #94a3b8;">🔒 ${escapeHtml(h.network_type)}</div>` : ""}
          ${h.label ? `<div class="label">${escapeHtml(h.label)}</div>` : ""}
        </div>
      </div>`).join("");
  } else {
    relayWrap.innerHTML = '<div class="muted">No relay chain available for this input mode.</div>';
  }"""

relay_logic_new = """  const relayWrap = document.getElementById("relayChain");
  if (hops.length) {
    relayWrap.innerHTML = `<div class="relay-graph">` + hops.map(h => {
      const isExternal = h.network_type !== 'Internal' && h.network_type !== 'Private';
      const dotClass = isExternal ? 'external' : 'internal';
      return `
      <div class="relay-node">
        <div class="relay-dot ${dotClass}"></div>
        <div class="relay-content">
          <div class="relay-title">
            <span>${escapeHtml(h.from_host || "unknown")} → ${escapeHtml(h.by_host || "unknown")}</span>
            <span style="color:var(--muted); font-size:11px;">Hop ${h.hop_index}</span>
          </div>
          <div class="relay-subtitle">
            ${h.ip ? `IP: <span style="color:#93c5fd;">${escapeHtml(h.ip)}</span>` : ""}
            ${h.resolved_from_host ? `<br/>⚡ DNS Resolved: ${escapeHtml(h.resolved_from_host)}` : ""}
            ${h.geoip && h.geoip.country ? `<br/>📍 ${escapeHtml(h.geoip.city || "Unknown")}, ${escapeHtml(h.geoip.country)} (${escapeHtml(h.geoip.isp || "")})` : ""}
            ${!h.geoip && h.network_type ? `<br/>🔒 ${escapeHtml(h.network_type)}` : ""}
            ${h.label ? `<br/><span style="color:var(--accent);">${escapeHtml(h.label)}</span>` : ""}
          </div>
        </div>
      </div>`;
    }).join("") + `</div>`;
  } else {
    relayWrap.innerHTML = '<div class="muted">No relay chain available for this input mode.</div>';
  }"""

html = html.replace(relay_logic_old, relay_logic_new)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("HTML patched")
