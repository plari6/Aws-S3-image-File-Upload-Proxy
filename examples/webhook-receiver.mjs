// Receive and verify s3proxy events (e.g. inside your own service, or as a
// pattern for an n8n Code node). Run: WEBHOOK_SECRET=... node examples/webhook-receiver.mjs
import http from 'node:http';
import crypto from 'node:crypto';

const secret = process.env.WEBHOOK_SECRET;
http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const m = String(req.headers['x-s3proxy-signature'] || '').match(/^t=(\d+),v1=([0-9a-f]{64})$/);
    const fresh = m && Math.abs(Date.now() / 1000 - Number(m[1])) < 300;
    const expected = m && crypto.createHmac('sha256', secret).update(`${m[1]}.${body}`).digest('hex');
    if (!fresh || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(m[2]))) {
      res.writeHead(401).end('bad signature');
      return;
    }
    const event = JSON.parse(body);
    // event.event: file.uploaded | file.malware | file.deleted
    console.log(event.event, event.data.tenant, event.data.name, event.data.size, event.data.sha256);
    res.end('ok');
  });
}).listen(3000, () => console.log('listening on :3000'));
