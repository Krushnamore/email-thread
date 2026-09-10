import re

with open("frontend/index.html", "r") as f:
    html = f.read()

# Add CSS for animation
anim_css = """
@keyframes nodePopIn {
  0% { transform: scale(0.5); opacity: 0; }
  70% { transform: scale(1.1); opacity: 1; }
  100% { transform: scale(1); opacity: 1; }
}
.custom-graph-node {
  animation: nodePopIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
}
"""
if "nodePopIn" not in html:
    html = html.replace("</style>", anim_css + "\n</style>")

old_map_logic = """      if (latlngs.length > 0) {
        mapEl.style.display = "block";
        if (!window.mapInstance) {
          window.mapInstance = L.map('intelMap');
          window.mapTileLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap &copy; CARTO',
            subdomains: 'abcd',
            maxZoom: 20
          }).addTo(window.mapInstance);
        }

        // Add markers (Graph Nodes)
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
        } else {
          window.mapInstance.setView(latlngs[0], 5);
        }
        
        setTimeout(() => {
          if (window.mapInstance) window.mapInstance.invalidateSize();
        }, 150);"""

new_map_logic = """      if (latlngs.length > 0) {
        mapEl.style.display = "block";
        if (!window.mapInstance) {
          window.mapInstance = L.map('intelMap', { scrollWheelZoom: false });
          window.mapTileLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap &copy; CARTO',
            subdomains: 'abcd',
            maxZoom: 20
          }).addTo(window.mapInstance);
        }

        // Set bounds immediately so the map doesn't jump
        if (latlngs.length > 1) {
          const tempBounds = L.polyline(latlngs).getBounds();
          window.mapInstance.fitBounds(tempBounds, { padding: [80, 80], maxZoom: 5 });
        } else {
          window.mapInstance.setView(latlngs[0], 5);
        }
        
        setTimeout(() => {
          if (window.mapInstance) window.mapInstance.invalidateSize();
        }, 150);

        window.mapPolyline = L.polyline([], {
          color: '#ff8a4c', 
          weight: 3, 
          dashArray: '8, 12',
          className: 'trace-path-animated'
        }).addTo(window.mapInstance);

        // Animate sequence
        (async () => {
          const drawnLatLngs = [];
          for (const h of hops) {
            if (h.geoip && h.geoip.lat && h.geoip.lon) {
              await new Promise(r => setTimeout(r, 600)); // Delay between hops
              
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
              
              drawnLatLngs.push([h.geoip.lat, h.geoip.lon]);
              window.mapPolyline.setLatLngs(drawnLatLngs);
              
              // Move map smoothly if we want, or just let the fitBounds hold it.
              // Since we fitBounds ahead of time, it stays steady.
            }
          }
          
          if (hops.length === 0 && geo.lat && geo.lon) {
            await new Promise(r => setTimeout(r, 600));
            const icon = L.divIcon({
              className: 'custom-graph-node is-external',
              html: `<div class="node-badge">Earliest IP</div><div class="node-ip">${escapeHtml(geo.ip || "unknown")}</div><div class="node-city">${escapeHtml(geo.city || "Unknown")}</div>`,
              iconSize: [120, 58],
              iconAnchor: [60, 29]
            });
            const m = L.marker([geo.lat, geo.lon], {icon}).addTo(window.mapInstance);
            window.mapMarkers.push(m);
          }
        })();"""

html = html.replace(old_map_logic, new_map_logic)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("Map animation patched")
