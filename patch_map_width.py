with open("frontend/index.html", "r") as f:
    html_code = f.read()

html_code = html_code.replace("iconSize: [140, 65]", "iconSize: [170, 70]")
html_code = html_code.replace("iconAnchor: [70, 32]", "iconAnchor: [85, 35]")

with open("frontend/index.html", "w") as f:
    f.write(html_code)

print("Map width increased further")
