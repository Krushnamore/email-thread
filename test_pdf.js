import PDFDocument from 'pdfkit-table';
import fs from 'fs';
const doc = new PDFDocument({ margin: 50 });
doc.pipe(fs.createWriteStream('test.pdf'));
const table = {
  title: "Title",
  headers: ["H1", "H2"],
  rows: [
    ["R1", "R2"]
  ],
};
doc.table(table, { width: 300 });
doc.end();
