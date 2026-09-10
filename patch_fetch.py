with open("frontend/index.html", "r") as f:
    html = f.read()

# Add a check for content-type before parsing JSON
fetch_logic_old = """  try {
    const data = await resp.json();
    renderResults(data);
    loadCases(); // refresh case history table
    showToast(data.scoring.verdict, data.scoring.score, data.subject);
  } catch (renderErr) {"""

fetch_logic_new = """  try {
    const contentType = resp.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      const text = await resp.text();
      throw new Error(`Expected JSON but received ${contentType}. Content: ${text.substring(0, 50)}...`);
    }
    const data = await resp.json();
    renderResults(data);
    loadCases(); // refresh case history table
    showToast(data.scoring.verdict, data.scoring.score, data.subject);
  } catch (renderErr) {"""

html = html.replace(fetch_logic_old, fetch_logic_new)

with open("frontend/index.html", "w") as f:
    f.write(html)

print("Fetch patched")
