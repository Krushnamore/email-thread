with open("frontend/index.html", "r") as f:
    html = f.read()

load_old = """  try {
    const url = verdict ? `${API_BASE}/api/cases?verdict=${verdict}` : `${API_BASE}/api/cases`;
    const resp = await fetch(url);
    const data = await resp.json();
    allCases = data.cases || [];"""

load_new = """  try {
    const url = verdict ? `${API_BASE}/api/cases?verdict=${verdict}` : `${API_BASE}/api/cases`;
    const resp = await fetch(url);
    const contentType = resp.headers.get("content-type") || "";
    if (!resp.ok || !contentType.includes("application/json")) {
       const text = await resp.text();
       throw new Error(`Failed to load cases. Status: ${resp.status}. Content: ${text.substring(0, 50)}...`);
    }
    const data = await resp.json();
    allCases = data.cases || [];"""

html = html.replace(load_old, load_new)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("Load cases patched")
