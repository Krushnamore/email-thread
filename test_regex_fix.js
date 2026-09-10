const text = 'Received: from A\n        by B\nTest: C\nReceived: from X\n by Y';
const regex = /^Received:\s+([^]*?)(?=\r?\n[^\s\r\n]|$(?![\r\n]))/gmi;
let m;
while((m = regex.exec(text))) {
  console.log(JSON.stringify(m[1]));
}
