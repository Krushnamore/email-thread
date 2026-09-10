import re

with open("server.js", "r") as f:
    code = f.read()

# Add Date extraction
date_ext = """  // Extract Date header
  let emailDate = 'Unknown';
  const dateMatch = headersPart.match(/^Date:\\s*([^\\r\\n]+(?:\\r?\\n[ \\t]+[^\\r\\n]+)*)/mi);
  if (dateMatch) {
    emailDate = dateMatch[1].replace(/\\r?\\n[ \\t]+/g, ' ').trim();
  }
"""

if "let emailDate =" not in code:
    code = code.replace("  // 3. Extract Authentication Status", date_ext + "\n  // 3. Extract Authentication Status")

if "email_date: emailDate" not in code:
    code = code.replace("subject: subject,", "subject: subject,\n    email_date: emailDate,")

with open("server.js", "w") as f:
    f.write(code)


with open("pdf_helper.js", "r") as f:
    pdf_code = f.read()

if "caseData.email_date" not in pdf_code:
    pdf_code = pdf_code.replace("['Date', '\\u2014']", "['Date', caseData.email_date || '\\u2014']")

with open("pdf_helper.js", "w") as f:
    f.write(pdf_code)

with open("frontend/index.html", "r") as f:
    html = f.read()

if '<td id="emailDate">' not in html:
    html = html.replace('<tr><td>From</td><td id="senderFrom">—</td></tr>', 
                        '<tr><td>Date</td><td id="emailDate">—</td></tr>\n            <tr><td>From</td><td id="senderFrom">—</td></tr>')

if 'document.getElementById("emailDate").textContent' not in html:
    html = html.replace('document.getElementById("senderFrom").textContent = data.from_address || "—";',
                        'document.getElementById("emailDate").textContent = data.email_date || "—";\n  document.getElementById("senderFrom").textContent = data.from_address || "—";')

with open("frontend/index.html", "w") as f:
    f.write(html)

print("Date patched")
