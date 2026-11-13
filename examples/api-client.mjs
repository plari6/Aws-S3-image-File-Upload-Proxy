// Use the proxy from your own back office / CRM integration.
// S3PROXY_URL=https://upload.example.com S3PROXY_KEY=s3p_... node examples/api-client.mjs ./contract.pdf
import fs from 'node:fs';
import path from 'node:path';

const base = process.env.S3PROXY_URL || 'http://localhost:8080';
const headers = { authorization: `Bearer ${process.env.S3PROXY_KEY}` };
const file = process.argv[2];

// 1) Upload through the proxy (all checks, streamed to S3)
const form = new FormData();
form.append('file', new Blob([fs.readFileSync(file)]), path.basename(file));
const up = await (await fetch(`${base}/api/files?tenant=acme`, { method: 'POST', headers, body: form })).json();
console.log('upload:', JSON.stringify(up.results[0]));

// 2) Ask for a 10-minute download link to put in an email / CRM note
if (up.results[0].ok) {
  const dl = await (await fetch(`${base}/api/files/${up.results[0].file.id}/download?ttl=10m`, { headers })).json();
  console.log('download URL (valid 10 min):', dl.url);
}

// 3) Create an upload link to send to the client
const link = await (await fetch(`${base}/api/links`, {
  method: 'POST', headers: { ...headers, 'content-type': 'application/json' },
  body: JSON.stringify({ tenant: 'acme', label: 'KYC documents', expiresIn: '3d', maxFiles: 5, allowedTypes: ['pdf', 'jpg'] }),
})).json();
console.log('client upload link:', link.link.url);
