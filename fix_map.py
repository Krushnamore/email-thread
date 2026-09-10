with open("frontend/index.css", "r") as f:
    css = f.read()

# Remove background, border, etc. from custom-graph-node
# and apply it to an inner container
css = css.replace("""
.custom-graph-node {
  background: var(--panel-2);
  border: 1px solid var(--accent);
  border-radius: 8px;
  color: var(--text);
  text-align: center;
  box-shadow: 0 4px 12px rgba(0,0,0,0.8);
  padding: 8px 10px; width: 100%; height: 100%; box-sizing: border-box;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  animation: nodePopIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
}""", """
.custom-graph-node {
  /* Leaflet uses transform for positioning. We must not override it here! */
}
.custom-graph-node .node-content {
  background: var(--panel-2);
  border: 1px solid var(--accent);
  border-radius: 8px;
  color: var(--text);
  text-align: center;
  box-shadow: 0 4px 12px rgba(0,0,0,0.8);
  padding: 8px 10px; width: 100%; height: 100%; box-sizing: border-box;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  animation: nodePopIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
}
""")

css = css.replace(".custom-graph-node.is-external {", ".custom-graph-node.is-external .node-content {")

with open("frontend/index.css", "w") as f:
    f.write(css)


with open("frontend/index.html", "r") as f:
    html = f.read()

# Wrap htmlNode contents in .node-content
html = html.replace(
    'const htmlNode = `<div class="node-badge">Hop ${h.hop_index}</div><div class="node-host">${escapeHtml(h.from_host && h.from_host !== "unknown" ? h.from_host : (h.by_host || "unknown"))}</div><div class="node-ip">${escapeHtml(h.ip || "unknown")}</div><div class="node-city">${escapeHtml(h.geoip.city || "Unknown")}</div>`;',
    'const htmlNode = `<div class="node-content"><div class="node-badge">Hop ${h.hop_index}</div><div class="node-host">${escapeHtml(h.from_host && h.from_host !== "unknown" ? h.from_host : (h.by_host || "unknown"))}</div><div class="node-ip">${escapeHtml(h.ip || "unknown")}</div><div class="node-city">${escapeHtml(h.geoip.city || "Unknown")}</div></div>`;'
)

html = html.replace(
    'html: `<div class="node-badge">Earliest IP</div><div class="node-host">Origin</div><div class="node-ip">${escapeHtml(geo.ip || "unknown")}</div><div class="node-city">${escapeHtml(geo.city || "Unknown")}</div>`,',
    'html: `<div class="node-content"><div class="node-badge">Earliest IP</div><div class="node-host">Origin</div><div class="node-ip">${escapeHtml(geo.ip || "unknown")}</div><div class="node-city">${escapeHtml(geo.city || "Unknown")}</div></div>`,'
)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("Map node animation bug fixed")
