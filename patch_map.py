import re

with open("frontend/index.html", "r") as f:
    html = f.read()

# Add CSS for custom graph nodes on the map
css_ext = """
.custom-graph-node {
  background: var(--panel-2);
  border: 1px solid #5b8cff;
  border-radius: 8px;
  color: var(--text);
  text-align: center;
  box-shadow: 0 4px 12px rgba(0,0,0,0.8);
  padding: 4px 6px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}
.custom-graph-node.is-external {
  border-color: #ff8a4c;
}
.custom-graph-node .node-badge {
  background: #5b8cff;
  color: #1a1a1a;
  font-size: 10px;
  font-weight: 700;
  border-radius: 4px;
  padding: 2px 6px;
  margin-bottom: 3px;
  text-transform: uppercase;
}
.custom-graph-node.is-external .node-badge {
  background: #ff8a4c;
}
.custom-graph-node .node-ip {
  font-size: 11px;
  font-family: monospace;
  color: #e2e8f0;
  margin-bottom: 2px;
}
.custom-graph-node .node-city {
  font-size: 9px;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}
.trace-path-animated {
  animation: traceDash 30s linear infinite;
}
@keyframes traceDash {
  to { stroke-dashoffset: -1000; }
}
"""

if "custom-graph-node" not in html:
    html = html.replace("</style>", css_ext + "</style>")

# Replace standard map markers with custom graph nodes and animated polylines
map_logic_old = """        // Add markers
        hops.forEach(h => {
          if (h.geoip && h.geoip.lat && h.geoip.lon) {
            const m = L.marker([h.geoip.lat, h.geoip.lon]).addTo(window.mapInstance)
              .bindPopup(`<b>Hop ${h.hop_index}</b><br/>${escapeHtml(h.geoip.city || "Unknown")}, ${escapeHtml(h.geoip.country || "")}<br/>IP: ${h.ip}`);
            window.mapMarkers.push(m);
          }
        });

        if (hops.length === 0 && geo.lat && geo.lon) {
          const m = L.marker([geo.lat, geo.lon]).addTo(window.mapInstance)
            .bindPopup(`<b>Earliest IP</b><br/>${escapeHtml(geo.city || "Unknown")}, ${escapeHtml(geo.country || "")}`);
          window.mapMarkers.push(m);
        }
        
        if (latlngs.length > 1) {
          window.mapPolyline = L.polyline(latlngs, {color: '#3b82f6', weight: 3, dashArray: '5, 10'}).addTo(window.mapInstance);
          window.mapInstance.fitBounds(window.mapPolyline.getBounds(), { padding: [30, 30], maxZoom: 5 });
        } else {"""

map_logic_new = """        // Add markers (Graph Nodes)
        hops.forEach(h => {
          if (h.geoip && h.geoip.lat && h.geoip.lon) {
            const isExternal = h.network_type !== 'Internal' && h.network_type !== 'Private';
            const htmlNode = `<div class="node-badge">Hop ${h.hop_index}</div><div class="node-ip">${escapeHtml(h.ip || "unknown")}</div><div class="node-city">${escapeHtml(h.geoip.city || "Unknown")}</div>`;
            const icon = L.divIcon({
              className: isExternal ? 'custom-graph-node is-external' : 'custom-graph-node',
              html: htmlNode,
              iconSize: [120, 58],
              iconAnchor: [60, 29]
            });
            const m = L.marker([h.geoip.lat, h.geoip.lon], {icon}).addTo(window.mapInstance)
              .bindPopup(`<b>Hop ${h.hop_index}</b><br/>From: ${escapeHtml(h.from_host || "unknown")}<br/>By: ${escapeHtml(h.by_host || "unknown")}`);
            window.mapMarkers.push(m);
          }
        });

        if (hops.length === 0 && geo.lat && geo.lon) {
          const icon = L.divIcon({
            className: 'custom-graph-node is-external',
            html: `<div class="node-badge">Earliest IP</div><div class="node-ip">${escapeHtml(geo.ip || "unknown")}</div><div class="node-city">${escapeHtml(geo.city || "Unknown")}</div>`,
            iconSize: [120, 58],
            iconAnchor: [60, 29]
          });
          const m = L.marker([geo.lat, geo.lon], {icon}).addTo(window.mapInstance);
          window.mapMarkers.push(m);
        }
        
        if (latlngs.length > 1) {
          window.mapPolyline = L.polyline(latlngs, {
            color: '#ff8a4c', 
            weight: 3, 
            dashArray: '8, 12',
            className: 'trace-path-animated'
          }).addTo(window.mapInstance);
          
          window.mapInstance.fitBounds(window.mapPolyline.getBounds(), { padding: [80, 80], maxZoom: 5 });
        } else {"""

html = html.replace(map_logic_old, map_logic_new)

# Make map larger to fit nodes
html = html.replace('id="intelMap" style="height: 250px;', 'id="intelMap" style="height: 400px;')

with open("frontend/index.html", "w") as f:
    f.write(html)

print("Map patched")
