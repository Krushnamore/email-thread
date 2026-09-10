with open("server.js", "r") as f:
    code = f.read()

code = code.replace(
    'const receivedRegex = /^Received:\\s+([^]*?)(?=\\n[^\\s]|$)/gmi;',
    'const receivedRegex = /^Received:\\s+([^]*?)(?=\\r?\\n[^\\s\\r\\n]|$(?![\\r\\n]))/gmi;'
)

with open("server.js", "w") as f:
    f.write(code)
print("Patched regex")
