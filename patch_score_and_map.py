with open("server.js", "r") as f:
    server_code = f.read()

# Fix the score capping
server_code = server_code.replace(
    """  const analysisResult = {""",
    """  score = Math.min(100, score);
  const analysisResult = {"""
)

with open("server.js", "w") as f:
    f.write(server_code)

# Fix the map node width
with open("frontend/index.html", "r") as f:
    html_code = f.read()

html_code = html_code.replace("iconSize: [120, 58]", "iconSize: [140, 65]")
html_code = html_code.replace("iconAnchor: [60, 29]", "iconAnchor: [70, 32]")

with open("frontend/index.html", "w") as f:
    f.write(html_code)

print("Score and Map fixed")
