function isPrivate() { return false; }
function findIps() { return []; }
function extractEarliestPublicIp(text) {
  if (!text) return null;
  const headersPart = text.split(/\r?\n\r?\n/)[0] || '';
  const leakHeaders = [ /X-Originating-IP:\s*\[?([a-fA-F0-9\.:]+)\]?/i ];
  for (const regex of leakHeaders) {
    const match = headersPart.match(regex);
    if (match && !isPrivate(match[1])) return match[1];
  }
  const receivedRegex = /^Received:\s+([^]*?)(?=\n[^\s]|$)/gmi;
  let match;
  const receivedBlocks = [];
  while ((match = receivedRegex.exec(headersPart)) !== null) {
    receivedBlocks.push(match[1]);
  }
  return null;
}

const largeText = "Received: from foo\n".repeat(100000) + "\n\nBody";
console.log("Starting extract...");
extractEarliestPublicIp(largeText);
console.log("Done.");
