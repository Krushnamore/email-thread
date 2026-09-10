import re

with open("frontend/index.html", "r") as f:
    html = f.read()

old_error = """    if (!contentType.includes("application/json")) {
      const text = await resp.text();
      throw new Error(`Expected JSON but received ${contentType}. Content: ${text.substring(0, 50)}...`);
    }"""

new_error = """    if (!contentType.includes("application/json")) {
      const text = await resp.text();
      if (text.includes("Cookie check") || text.includes("__cookie_check") || resp.redirected) {
        throw new Error("Your session has expired or third-party cookies are blocked. Please refresh the page or open the app in a new tab to re-authenticate.");
      }
      throw new Error(`Server returned an invalid non-JSON response. Please check if the backend is running properly. (Response snippet: ${text.substring(0, 40)}...)`);
    }"""

html = html.replace(old_error, new_error)

with open("frontend/index.html", "w") as f:
    f.write(html)
print("Error handling patched")
