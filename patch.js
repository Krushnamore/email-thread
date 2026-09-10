const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');
const start = code.indexOf("app.get('/api/cases/:case_id/report', async (req, res) => {");
const endStr = "});\n\napp.delete('/api/cases/:case_id', (req, res) => {";
const end = code.indexOf(endStr);
if (start !== -1 && end !== -1) {
  const newRoute = `app.get('/api/cases/:case_id/report', async (req, res) => {
  const caseData = cases.get(req.params.case_id);
  if (!caseData) {
    return res.status(404).json({ detail: 'Case not found' });
  }

  const doc = new PDFDocument({ margin: 50, bufferPages: true });
  const filename = \`Report_\${caseData.id}.pdf\`;

  res.setHeader('Content-disposition', \`attachment; filename="\${filename}"\`);
  res.setHeader('Content-type', 'application/pdf');

  doc.pipe(res);
  generatePdf(doc, caseData);
`;
  code = code.substring(0, start) + newRoute + code.substring(end);
  fs.writeFileSync('server.js', code);
  console.log('Patched');
} else {
  console.log('Not found', start, end);
}
