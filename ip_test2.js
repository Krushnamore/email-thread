const email = `
Received: from client (unknown [5.5.5.5]) by mail.com
Received: from [192.168.1.1] (unknown [8.8.8.8]) by client
Message-ID: <foo@1.1.1.1>
`;
function extractEarliestPublicIp(text) {
  function isPrivate(ip) {
    const partsStr = ip.split('.');
    for (const p of partsStr) {
      if (p.length > 1 && p.startsWith('0')) return true;
    }
    const parts = partsStr.map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
    return false;
  }
  
  const xOriginating = text.match(/X-Originating-IP:\s*\[?([\d\.]+)\]?/i);
  if (xOriginating && !isPrivate(xOriginating[1])) {
    return xOriginating[1];
  }
  
  const receivedRegex = /^Received:\s+([^]*?)(?=\n[^\s]|$)/gmi;
  let match;
  const receivedBlocks = [];
  while ((match = receivedRegex.exec(text)) !== null) {
    receivedBlocks.push(match[1]);
  }
  
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  
  for (let i = receivedBlocks.length - 1; i >= 0; i--) {
    const ips = receivedBlocks[i].match(ipRegex) || [];
    // The IP representing the sender in a Received header is usually the FIRST IP in that header block,
    // e.g. Received: from [123.123.123.123] by ...
    // Let's just find the first public IP in the oldest Received block.
    for (let j = 0; j < ips.length; j++) {
      if (!isPrivate(ips[j])) {
        return ips[j];
      }
    }
  }
  return null;
}
console.log(extractEarliestPublicIp(email));
