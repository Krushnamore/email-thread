import re

with open("frontend/index.html", "r") as f:
    html = f.read()

old_logic = """        // Animate sequence
        (async () => {
          const drawnLatLngs = [];
          for (const h of hops) {
            if (h.geoip && h.geoip.lat && h.geoip.lon) {
              await new Promise(r => setTimeout(r, 600)); // Delay between hops
              
              const isExternal = h.network_type !== 'Internal' && h.network_type !== 'Private';"""

new_logic = """        // Animate sequence
        window.mapAnimId = (window.mapAnimId || 0) + 1;
        const currentAnimId = window.mapAnimId;
        
        (async () => {
          const drawnLatLngs = [];
          for (const h of hops) {
            if (h.geoip && h.geoip.lat && h.geoip.lon) {
              await new Promise(r => setTimeout(r, 800)); // Delay between hops for visual impact
              if (currentAnimId !== window.mapAnimId) return; // abort if new analysis started
              
              const isExternal = h.network_type !== 'Internal' && h.network_type !== 'Private';"""

html = html.replace(old_logic, new_logic)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("Map animation abort logic patched")
