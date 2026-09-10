const headersPart = "From: " + "a".repeat(100000) + "\n ";
const start = Date.now();
const fromMatch = headersPart.match(/^From:\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)/mi);
console.log("From match took", Date.now() - start, "ms");
