// @ts-check
// Offline end-to-end demo: starts the proxy on a random port with the local
// storage driver and plays real client + attacker scenarios over HTTP.
// Every scenario must pass; the same run is used as an integration test.
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { loadConfig } from '../config.js';
import { createProxy } from '../index.js';
import { createApiKey } from '../security/apikeys.js';
import { makePdf, makePng, makeExe, makeSvg, makeHtml, makeDocx, makeJpegWithGps, hasGps, hasOrientation } from './fixtures.js';

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

/**
 * @param {{ log?: (line: string) => void, keep?: boolean, port?: number, env?: Record<string, string> }} [opts]
 */
export async function runDemo({ log = console.log, keep = false, port = 0, env = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's3proxy-demo-'));
  const server = http.createServer();
  await new Promise((r) => server.listen(port, '127.0.0.1', () => r(null)));
  const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
  const base = `http://127.0.0.1:${addr.port}`;
  const config = loadConfig({
    APP_SECRET: crypto.randomBytes(32).toString('base64url'), STORAGE_DRIVER: 'local', DATA_DIR: dir, PUBLIC_URL: base,
    MAX_FILE_SIZE: '2mb', RATE_LIMIT_MAX: '1000', ...env,
  });
  const proxy = createProxy({ config, log: () => {} });
  server.on('request', proxy.app);

  const admin = createApiKey(proxy.store, config.appSecret, { name: 'demo-admin', tenant: '*', scopes: ['admin'] }).key;
  const acmeKey = createApiKey(proxy.store, config.appSecret, { name: 'acme-crm', tenant: 'acme', scopes: ['upload', 'read'] }).key;
  const H = (key) => ({ authorization: `Bearer ${key}` });

  /** @type {{ name: string, pass: boolean, detail: string }[]} */
  const results = [];
  const check = async (name, fn) => {
    try {
      const detail = await fn();
      results.push({ name, pass: true, detail: detail || '' });
      log(`  PASS  ${name}${detail ? `  - ${detail}` : ''}`);
    } catch (err) {
      results.push({ name, pass: false, detail: err.message });
      log(`  FAIL  ${name}  - ${err.message}`);
    }
  };
  const expect = (cond, msg) => { if (!cond) throw new Error(msg); };
  const proxyUpload = async (key, files, tenant) => {
    const form = new FormData();
    for (const [name, buf, type] of files) form.append('file', new Blob([buf], { type: type || 'application/octet-stream' }), name);
    const res = await fetch(`${base}/api/files${tenant ? `?tenant=${tenant}` : ''}`, { method: 'POST', headers: H(key), body: form });
    return { status: res.status, body: await res.json() };
  };
  const postToStorage = async (upload, buf, filename) => {
    const form = new FormData();
    for (const [k, v] of Object.entries(upload.fields)) form.append(k, /** @type {string} */ (v));
    form.append('file', new Blob([buf]), filename);
    return fetch(upload.url, { method: 'POST', body: form });
  };

  log(`\nS3 Upload Proxy demo  (${base}, local storage in ${dir})\n`);
  let pdfId = '';
  let jpgId = '';

  await check('Request without API key is refused (401)', async () => {
    const r = await fetch(`${base}/api/files`);
    expect(r.status === 401, `got ${r.status}`);
  });

  await check('Proxy upload: PDF + DOCX + PNG stored, SHA-256 fingerprinted', async () => {
    const { status, body } = await proxyUpload(admin, [['Contract.pdf', makePdf(), 'application/pdf'], ['Brief.docx', makeDocx()], ['logo.png', makePng(), 'image/png']], 'globex');
    expect(status === 201, `status ${status}: ${JSON.stringify(body)}`);
    const pdf = body.results[0].file;
    expect(pdf.status === 'clean' && pdf.sha256 === sha(makePdf()), 'pdf not clean or hash mismatch');
    pdfId = pdf.id;
    return `${body.results.length} files, ${pdf.encryption}`;
  });

  await check('Photo GPS location removed, orientation kept', async () => {
    const { status, body } = await proxyUpload(admin, [['ID-card.jpg', makeJpegWithGps(), 'image/jpeg']], 'globex');
    expect(status === 201 && body.results[0].file.gpsRemoved, `status ${status} ${JSON.stringify(body)}`);
    jpgId = body.results[0].file.id;
    const dl = await (await fetch(`${base}/api/files/${jpgId}/download`, { headers: H(admin) })).json();
    const bytes = Buffer.from(await (await fetch(dl.url)).arrayBuffer());
    expect(!hasGps(bytes), 'GPS still present');
    expect(hasOrientation(bytes), 'orientation lost');
    return 'GPS tags + XMP location gone';
  });

  await check('Disguised malware "invoice.pdf" (Windows .exe) rejected', async () => {
    const { status, body } = await proxyUpload(admin, [['invoice.pdf', makeExe(), 'application/pdf']]);
    expect(status === 415, `status ${status}`);
    return body.results[0].message;
  });

  await check('SVG with script and HTML renamed to .jpg rejected', async () => {
    const a = await proxyUpload(admin, [['logo.svg', makeSvg(), 'image/svg+xml']]);
    const b = await proxyUpload(admin, [['photo.jpg', makeHtml(), 'image/jpeg']]);
    expect(a.status === 415 && b.status === 415, `status ${a.status}/${b.status}`);
    return b.body.results[0].message;
  });

  await check('Mixed batch: good file kept, bad file refused (207)', async () => {
    const { status, body } = await proxyUpload(admin, [['ok.pdf', makePdf('ok')], ['bad.pdf', makeExe()]]);
    expect(status === 207 && body.results[0].ok && !body.results[1].ok, `status ${status}`);
  });

  await check('File over the size limit rejected while streaming (413)', async () => {
    const big = Buffer.concat([makePdf(), Buffer.alloc(2.5 * 1024 * 1024, 0x20)]);
    const { status } = await proxyUpload(admin, [['huge.pdf', big]]);
    expect(status === 413, `status ${status}`);
  });

  await check('Download URL is short-lived, forces attachment, bytes match', async () => {
    const dl = await (await fetch(`${base}/api/files/${pdfId}/download?ttl=2m`, { headers: H(admin) })).json();
    const res = await fetch(dl.url);
    const buf = Buffer.from(await res.arrayBuffer());
    expect(res.ok && sha(buf) === sha(makePdf()), 'content mismatch');
    expect(/attachment; filename="Contract.pdf"/.test(res.headers.get('content-disposition') || ''), 'missing attachment header');
    expect(dl.expiresIn === 120, `ttl ${dl.expiresIn}`);
    return `expires in ${dl.expiresIn}s`;
  });

  await check('Tampered download URL refused', async () => {
    const dl = await (await fetch(`${base}/api/files/${pdfId}/download`, { headers: H(admin) })).json();
    const bad = dl.url.slice(0, -3) + (dl.url.endsWith('AAA') ? 'BBB' : 'AAA');
    const r = await fetch(bad);
    expect(r.status === 403, `got ${r.status}`);
  });

  await check('Tenant isolation: acme key cannot see globex files (404)', async () => {
    const r = await fetch(`${base}/api/files/${pdfId}`, { headers: H(acmeKey) });
    const r2 = await fetch(`${base}/api/files?tenant=globex`, { headers: H(acmeKey) });
    expect(r.status === 404 && r2.status === 403, `got ${r.status}/${r2.status}`);
  });

  await check('Scoped key: read/upload key cannot create links (403)', async () => {
    const r = await fetch(`${base}/api/links`, { method: 'POST', headers: { ...H(acmeKey), 'content-type': 'application/json' }, body: '{}' });
    expect(r.status === 403, `got ${r.status}`);
  });

  await check('Pre-signed PUT: signed size/type, verified after upload', async () => {
    const pdf = makePdf('put');
    const r = await fetch(`${base}/api/presign/upload`, {
      method: 'POST', headers: { ...H(acmeKey), 'content-type': 'application/json' },
      body: JSON.stringify({ filename: 'Payslip.pdf', contentType: 'application/pdf', size: pdf.length, method: 'put' }),
    });
    const intent = await r.json();
    expect(r.status === 201, `presign ${r.status} ${JSON.stringify(intent)}`);
    const wrongType = await fetch(intent.upload.url, { method: 'PUT', headers: { 'content-type': 'text/html' }, body: pdf });
    expect(wrongType.status === 403, `wrong content-type accepted (${wrongType.status})`);
    const put = await fetch(intent.upload.url, { method: 'PUT', headers: intent.upload.headers, body: pdf });
    expect(put.ok, `put ${put.status}`);
    const done = await (await fetch(intent.completeUrl, { method: 'POST', headers: H(acmeKey) })).json();
    expect(done.file?.status === 'clean', JSON.stringify(done));
    return 'wrong Content-Type refused by the signature';
  });

  // ---- client upload link (what the agency sends to its client) ----
  const lr = await fetch(`${base}/api/links`, {
    method: 'POST', headers: { ...H(admin), 'content-type': 'application/json' },
    body: JSON.stringify({ tenant: 'globex', label: 'Mortgage file - John Doe', expiresIn: '3d', maxFiles: 3, maxBytes: '5mb', allowedTypes: ['pdf', 'jpg'] }),
  });
  const { link } = await lr.json();
  const tokenPath = new URL(link.url).pathname;

  await check('Client link: portal page loads with strict CSP', async () => {
    const r = await fetch(link.url);
    const html = await r.text();
    expect(r.ok && html.includes('Mortgage file - John Doe'), `status ${r.status}`);
    expect((r.headers.get('content-security-policy') || '').includes("script-src 'self'"), 'missing CSP');
    expect(r.headers.get('referrer-policy') === 'no-referrer', 'token could leak through Referer');
  });

  let portalFileId = '';
  await check('Client link: browser-style pre-signed POST upload, then verified', async () => {
    const pdf = makePdf('client');
    const intent = await (await fetch(`${base}${tokenPath}/presign`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ filename: 'Bank statement.pdf', contentType: 'application/pdf', size: pdf.length }),
    })).json();
    expect(intent.upload?.method === 'POST', JSON.stringify(intent));
    const up = await postToStorage(intent.upload, pdf, 'Bank statement.pdf');
    expect(up.status === 201, `storage POST ${up.status}`);
    const done = await (await fetch(`${base}${tokenPath}/complete/${intent.fileId}`, { method: 'POST' })).json();
    expect(done.file?.status === 'clean', JSON.stringify(done));
    portalFileId = done.file.id;
    return `file ${portalFileId}`;
  });

  await check('Client link: file larger than the signed policy refused by storage', async () => {
    const small = makePdf('x');
    const intent = await (await fetch(`${base}${tokenPath}/presign`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ filename: 'a.pdf', size: small.length }),
    })).json();
    const up = await postToStorage(intent.upload, Buffer.concat([small, Buffer.alloc(50000)]), 'a.pdf');
    expect(up.status === 400, `got ${up.status}`);
  });

  await check('Client link: .docx refused (link only allows PDF/JPG)', async () => {
    const r = await fetch(`${base}${tokenPath}/presign`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ filename: 'x.docx', size: 1000 }) });
    expect(r.status === 415, `got ${r.status}`);
  });

  await check('Client link: exe uploaded as .pdf directly to storage caught at verify', async () => {
    const exe = makeExe();
    const intent = await (await fetch(`${base}${tokenPath}/presign`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ filename: 'scan.pdf', size: exe.length }),
    })).json();
    await postToStorage(intent.upload, exe, 'scan.pdf');
    const r = await fetch(`${base}${tokenPath}/complete/${intent.fileId}`, { method: 'POST' });
    const body = await r.json();
    expect(r.status === 415, `got ${r.status}`);
    const head = await proxy.storage.head(proxy.store.getFile(intent.fileId).object_key);
    expect(!head.exists, 'rejected object still stored');
    return body.message;
  });

  await check('Client link: proxy fallback upload counts against link limit', async () => {
    const form = new FormData();
    form.append('file', new Blob([makeJpegWithGps()]), 'house.jpg');
    const r = await fetch(`${base}${tokenPath}/files`, { method: 'POST', body: form });
    expect(r.status === 201, `got ${r.status}`);
    const info = await (await fetch(`${base}${tokenPath}/info`)).json();
    return `${info.files.length} received, ${info.remainingFiles} left`;
  });

  await check('Client link: tampered token refused', async () => {
    const bad = tokenPath.slice(0, -4) + (tokenPath.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    const r = await fetch(`${base}${bad}/info`);
    expect(r.status === 404, `got ${r.status}`);
  });

  await check('Client link: token cannot be reused as a download token', async () => {
    const token = tokenPath.split('/').pop();
    const r = await fetch(`${base}/_local/get/${token}`);
    expect(r.status === 403, `got ${r.status}`);
  });

  await check('Client link: revoked link stops working immediately (410)', async () => {
    await fetch(`${base}/api/links/${link.id}`, { method: 'DELETE', headers: H(admin) });
    const r = await fetch(`${base}${tokenPath}/info`);
    expect(r.status === 410, `got ${r.status}`);
  });

  await check('Audit trail records uploads, rejections and downloads', async () => {
    const ev = await (await fetch(`${base}/api/audit?limit=200`, { headers: H(admin) })).json();
    const actions = new Set(ev.events.map((e) => e.action));
    for (const a of ['upload.clean', 'upload.rejected', 'download.presigned', 'link.created', 'link.revoked', 'auth.failed']) {
      expect(actions.has(a), `missing ${a}`);
    }
    return `${ev.events.length} events`;
  });

  const passed = results.filter((r) => r.pass).length;
  log(`\n${passed}/${results.length} scenarios passed.`);

  const shutdown = async () => {
    await new Promise((r) => server.close(() => r(null)));
    server.closeAllConnections?.();
    await proxy.close();
    fs.rmSync(dir, { recursive: true, force: true });
  };

  if (keep) {
    const fresh = proxy.service.createLink({ tenant: 'demo', label: 'Demo upload link', ttl: 86400, actor: 'demo' });
    log(`\nServer kept running. Open this client upload link in a browser:\n  ${fresh.url}\nAdmin API key: ${admin}\nPress Ctrl+C to stop.`);
    return { results, passed, base, shutdown, adminKey: admin };
  }
  await shutdown();
  return { results, passed, base, shutdown: async () => {}, adminKey: admin };
}
