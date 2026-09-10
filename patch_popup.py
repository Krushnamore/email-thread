import re

with open("frontend/index.html", "r") as f:
    html = f.read()

# Replace the popup HTML
html = html.replace(
    'bindPopup(`<b>Hop ${h.hop_index}</b><br/>From: ${escapeHtml(h.from_host || "unknown")}<br/>By: ${escapeHtml(h.by_host || "unknown")}`)',
    'bindPopup(`<div style="font-family:sans-serif;"><b>Hop ${h.hop_index}</b><br/><b>IP:</b> ${escapeHtml(h.ip || "unknown")}<br/><b>Host:</b> ${escapeHtml(h.from_host !== "unknown" ? h.from_host : h.by_host)}<br/><b>Network:</b> ${escapeHtml(h.network_type || "Public")}</div>`)'
)

with open("frontend/index.html", "w") as f:
    f.write(html)

print("Popup patched")
