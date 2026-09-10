import re

with open("frontend/index.html", "r") as f:
    html = f.read()

html = html.replace(
    'const m = L.marker([geo.lat, geo.lon], {icon}).addTo(window.mapInstance);',
    'const m = L.marker([geo.lat, geo.lon], {icon}).addTo(window.mapInstance).bindPopup(`<div style="font-family:sans-serif;"><b>Earliest IP</b><br/><b>IP:</b> ${escapeHtml(geo.ip || "unknown")}</div>`);'
)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("Fallback popup patched")
