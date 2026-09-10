const http = require('http');

let payload = "From: a@b.com\nSubject: Test\n";
for (let i = 0; i < 2000; i++) {
  payload += `Received: from host${i}.com by mx.google.com;\n`;
}

const req = http.request('http://localhost:3000/analyze/paste', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, (res) => {
  let data = '';
  res.on('data', d => data += d);
  res.on('end', () => console.log(res.statusCode, data.substring(0, 100)));
});

req.on('error', console.error);
req.write(JSON.stringify({ raw_text: payload }));
req.end();
