import re

with open("frontend/index.html", "r") as f:
    html = f.read()

old_logic = """          if (hops.length === 0 && geo.lat && geo.lon) {
            await new Promise(r => setTimeout(r, 600));"""

new_logic = """          if (hops.length === 0 && geo.lat && geo.lon) {
            await new Promise(r => setTimeout(r, 800));
            if (currentAnimId !== window.mapAnimId) return;"""

html = html.replace(old_logic, new_logic)

with open("frontend/index.html", "w") as f:
    f.write(html)
