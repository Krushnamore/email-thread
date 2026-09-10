const fs = require('fs');
const headersPart = fs.readFileSync('demo_hops.eml', 'utf8').split(/\r?\n\r?\n/)[0];
const receivedRegex = /^Received:\s+([^]*?)(?=\n[^\s]|$)/gmi;
let match;
while ((match = receivedRegex.exec(headersPart)) !== null) {
  const block = match[1];
  console.log("BLOCK:", JSON.stringify(block));
  const fromM = block.match(/from\s+([^\s\(\[]+)/i);
  const byM = block.match(/by\s+([^\s\(\[;]+)/i);
  console.log("  from:", fromM ? fromM[1] : null);
  console.log("  by:", byM ? byM[1] : null);
}
