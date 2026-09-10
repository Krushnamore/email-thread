const headersPart = "Received: " + "a\n ".repeat(10000) + "b";
const start = Date.now();
const receivedRegex = /^Received:\s+([^]*?)(?=\n[^\s]|$)/gmi;
let match;
while ((match = receivedRegex.exec(headersPart)) !== null) { }
console.log("Received match took", Date.now() - start, "ms");
