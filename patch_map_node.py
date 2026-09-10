import re

with open("frontend/index.html", "r") as f:
    html = f.read()

# Fix htmlNode for hops
html = html.replace(
    '`<div class="node-badge">Hop ${h.hop_index}</div><div class="node-ip">${escapeHtml(h.ip || "unknown")}</div><div class="node-city">${escapeHtml(h.geoip.city || "Unknown")}</div>`',
    '`<div class="node-badge">Hop ${h.hop_index}</div><div class="node-host">${escapeHtml(h.from_host && h.from_host !== "unknown" ? h.from_host : (h.by_host || "unknown"))}</div><div class="node-ip">${escapeHtml(h.ip || "unknown")}</div><div class="node-city">${escapeHtml(h.geoip.city || "Unknown")}</div>`'
)

# Fix htmlNode for earliest IP fallback
html = html.replace(
    '`<div class="node-badge">Earliest IP</div><div class="node-ip">${escapeHtml(geo.ip || "unknown")}</div><div class="node-city">${escapeHtml(geo.city || "Unknown")}</div>`',
    '`<div class="node-badge">Earliest IP</div><div class="node-host">Origin</div><div class="node-ip">${escapeHtml(geo.ip || "unknown")}</div><div class="node-city">${escapeHtml(geo.city || "Unknown")}</div>`'
)

# Update sizes
html = html.replace("iconSize: [170, 70]", "iconSize: [200, 90]")
html = html.replace("iconAnchor: [85, 35]", "iconAnchor: [100, 45]")
html = html.replace("iconSize: [120, 58]", "iconSize: [200, 90]")
html = html.replace("iconAnchor: [60, 29]", "iconAnchor: [100, 45]")


with open("frontend/index.html", "w") as f:
    f.write(html)

with open("frontend/index.css", "r") as f:
    css = f.read()

if ".node-host" not in css:
    host_css = """
.custom-graph-node .node-host {
  font-size: 10px;
  color: #a0aec0;
  margin-bottom: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 95%;
}
"""
    css = css.replace(".custom-graph-node .node-ip {", host_css + "\n.custom-graph-node .node-ip {")
    with open("frontend/index.css", "w") as f:
        f.write(css)

print("Map nodes updated with hostnames and larger sizes")
