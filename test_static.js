const express = require('express');
const app = express();
app.use(express.static('frontend'));
app.post('/api/test', (req, res) => res.json({ok: true}));
app.listen(3001, () => {
  const http = require('http');
  const req = http.request({
    method: 'POST',
    host: 'localhost',
    port: 3001,
    path: '/index.html'
  }, (res) => {
    console.log(res.statusCode);
    process.exit(0);
  });
  req.end();
});
