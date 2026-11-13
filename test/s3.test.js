// Real AWS SDK v3 client against a fake S3 over HTTP: proves the wire-level
// behaviour (encryption headers, multipart, signed headers, POST policy).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { S3Client } from '@aws-sdk/client-s3';
import { startFakeS3, s3Env } from './helpers/fake-s3.js';
import { S3Storage } from '../src/storage/s3.js';
import { loadConfig } from '../src/config.js';
import { createProxy } from '../src/index.js';
import { createApiKey } from '../src/security/apikeys.js';
import { makePdf, makeExe, makeJpegWithGps, hasGps } from '../src/demo/fixtures.js';

let fake;
const creds = { accessKeyId: 'AKIAFAKEFAKEFAKE', secretAccessKey: 'fake/secret/key/for/tests/only' };
const client = () => new S3Client({ region: 'us-east-1', endpoint: fake.endpoint, forcePathStyle: true, credentials: creds, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });

before(async () => { fake = await startFakeS3(); });
after(async () => { await fake.close(); });

test('put() sends SSE-S3 and tags; head/getRange/setTags/delete work', async () => {
  const s = new S3Storage({ bucket: fake.bucket, sse: 'AES256' }, client());
  await s.put({ key: 't/a.pdf', body: Readable.from([makePdf()]), contentType: 'application/pdf', tags: { scan: 'pending' } });
  const put = fake.requests.findLast((r) => r.method === 'PUT' && r.key === 't/a.pdf');
  assert.equal(put.headers['x-amz-server-side-encryption'], 'AES256');
  assert.equal(put.headers['x-amz-tagging'], 'scan=pending');
  const h = await s.head('t/a.pdf');
  assert.deepEqual([h.exists, h.size, h.sse], [true, makePdf().length, 'AES256']);
  assert.equal((await s.getRange('t/a.pdf', 0, 4)).toString(), '%PDF-');
  await s.setTags('t/a.pdf', { scan: 'clean' });
  assert.deepEqual(fake.objects.get('t/a.pdf').tags, { scan: 'clean' });
  await s.delete('t/a.pdf');
  assert.equal((await s.head('t/a.pdf')).exists, false);
});

test('large files use multipart with SSE-KMS on CreateMultipartUpload', async () => {
  const s = new S3Storage({ bucket: fake.bucket, sse: 'aws:kms', kmsKeyId: 'alias/client-docs' }, client());
  const big = Buffer.alloc(9 * 1024 * 1024 + 123, 7);
  await s.put({ key: 't/big.bin', body: Readable.from([big.subarray(0, 5e6), big.subarray(5e6)]), contentType: 'application/pdf' });
  const create = fake.requests.find((r) => r.method === 'POST' && 'uploads' in r.query && r.key === 't/big.bin');
  assert.equal(create.headers['x-amz-server-side-encryption'], 'aws:kms');
  assert.equal(create.headers['x-amz-server-side-encryption-aws-kms-key-id'], 'alias/client-docs');
  assert.equal(create.headers['x-amz-server-side-encryption-bucket-key-enabled'], 'true');
  assert.ok(fake.objects.get('t/big.bin').body.equals(big));
});

test('a failing stream aborts the multipart upload (no orphan parts)', async () => {
  const s = new S3Storage({ bucket: fake.bucket, sse: 'AES256' }, client());
  async function* broken() { yield Buffer.alloc(9 * 1024 * 1024); throw new Error('client disconnected'); }
  await assert.rejects(s.put({ key: 't/broken.bin', body: Readable.from(broken()), contentType: 'application/pdf' }), /disconnected/);
  assert.equal(fake.objects.has('t/broken.bin'), false);
  assert.equal(fake.multipart.size, 0);
});

test('pre-signed PUT signs content-type, content-length and SSE headers', async () => {
  const s = new S3Storage({ bucket: fake.bucket, sse: 'AES256' }, client());
  const body = makePdf();
  const p = await s.presignPut({ key: 't/put.pdf', contentType: 'application/pdf', size: body.length, ttl: 600, tags: { scan: 'pending' } });
  const u = new URL(p.url);
  const signed = u.searchParams.get('X-Amz-SignedHeaders').split(';');
  for (const h of ['content-type', 'content-length', 'host', 'x-amz-server-side-encryption', 'x-amz-tagging']) assert.ok(signed.includes(h), `${h} not signed`);
  assert.equal(u.searchParams.get('X-Amz-Expires'), '600');
  assert.ok(!u.searchParams.has('x-amz-server-side-encryption'), 'SSE must be a header, not a query param');
  assert.deepEqual(p.headers, { 'Content-Type': 'application/pdf', 'x-amz-server-side-encryption': 'AES256', 'x-amz-tagging': 'scan=pending' });
  const res = await fetch(p.url, { method: 'PUT', headers: p.headers, body });
  assert.equal(res.status, 200);
  assert.equal(fake.objects.get('t/put.pdf').headers['x-amz-server-side-encryption'], 'AES256');
});

test('pre-signed POST policy pins key, type, size range, SSE and tags', async () => {
  const s = new S3Storage({ bucket: fake.bucket, sse: 'aws:kms', kmsKeyId: 'arn:aws:kms:us-east-1:111:key/abc' }, client());
  const p = await s.presignPost({ key: 'acme/2026/01/f_1.pdf', contentType: 'application/pdf', maxBytes: 5000, ttl: 900, tags: { scan: 'pending' } });
  const policy = JSON.parse(Buffer.from(p.fields.Policy, 'base64').toString());
  const conds = JSON.stringify(policy.conditions);
  assert.ok(conds.includes('["content-length-range",1,5000]'));
  for (const c of ['{"key":"acme/2026/01/f_1.pdf"}', '{"Content-Type":"application/pdf"}', '{"x-amz-server-side-encryption":"aws:kms"}',
    '{"x-amz-server-side-encryption-aws-kms-key-id":"arn:aws:kms:us-east-1:111:key/abc"}', '"tagging":"<Tagging><TagSet><Tag><Key>scan</Key><Value>pending</Value></Tag></TagSet></Tagging>"']) {
    assert.ok(conds.includes(c), `missing condition ${c}`);
  }
  const ttl = (new Date(policy.expiration).getTime() - Date.now()) / 1000;
  assert.ok(ttl > 890 && ttl <= 900, `expiration ${ttl}`);
  assert.equal(p.fields['X-Amz-Algorithm'], 'AWS4-HMAC-SHA256');
});

test('pre-signed GET forces attachment, no-store and expires', async () => {
  const s = new S3Storage({ bucket: fake.bucket, sse: 'AES256' }, client());
  const url = new URL(await s.presignGet({ key: 'k.pdf', ttl: 300, contentDisposition: 'attachment; filename="a.pdf"', contentType: 'application/pdf' }));
  assert.equal(url.searchParams.get('response-content-disposition'), 'attachment; filename="a.pdf"');
  assert.equal(url.searchParams.get('response-cache-control'), 'private, no-store');
  assert.equal(url.searchParams.get('X-Amz-Expires'), '300');
});

// ---------------------------------------------------------------- full proxy on S3
async function startProxy(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's3proxy-test-'));
  const server = http.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const config = loadConfig({ ...s3Env(fake), APP_SECRET: 'k'.repeat(48), DATA_DIR: dir, PUBLIC_URL: base, RATE_LIMIT_MAX: '1000', ...env });
  const proxy = createProxy({ config, s3Client: client(), log: () => {} });
  server.on('request', proxy.app);
  const key = createApiKey(proxy.store, config.appSecret, { name: 't', tenant: '*', scopes: ['admin'] }).key;
  return {
    proxy, base, H: { authorization: `Bearer ${key}` },
    async close() { await new Promise((r) => { server.closeAllConnections(); server.close(r); }); await proxy.close(); fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

test('proxy upload to S3: SSE on the object, tagged clean, GPS stripped', async () => {
  const p = await startProxy();
  try {
    const form = new FormData();
    form.append('file', new Blob([makeJpegWithGps()]), 'passport.jpg');
    const res = await fetch(`${p.base}/api/files?tenant=acme`, { method: 'POST', headers: p.H, body: form });
    const body = await res.json();
    assert.equal(res.status, 201, JSON.stringify(body));
    const f = body.results[0].file;
    assert.equal(f.encryption, 'SSE-S3 (AES-256)');
    const obj = fake.objects.get(p.proxy.store.getFile(f.id).object_key);
    assert.equal(obj.headers['x-amz-server-side-encryption'], 'AES256');
    assert.deepEqual(obj.tags, { scan: 'clean', tenant: 'acme' });
    assert.ok(!hasGps(obj.body));
  } finally { await p.close(); }
});

test('direct PUT upload verified via complete; unencrypted object rejected', async () => {
  const p = await startProxy();
  try {
    const pdf = makePdf();
    const intent = await (await fetch(`${p.base}/api/presign/upload`, {
      method: 'POST', headers: { ...p.H, 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'acme', filename: 'a.pdf', size: pdf.length, method: 'put' }),
    })).json();
    assert.equal((await fetch(intent.upload.url, { method: 'PUT', headers: intent.upload.headers, body: pdf })).status, 200);
    const done = await (await fetch(intent.completeUrl, { method: 'POST', headers: p.H })).json();
    assert.equal(done.file.status, 'clean');
    assert.equal(done.file.sha256.length, 64);

    // Simulate an object that landed without the required encryption.
    const intent2 = await (await fetch(`${p.base}/api/presign/upload`, {
      method: 'POST', headers: { ...p.H, 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'acme', filename: 'b.pdf', size: pdf.length, method: 'put' }),
    })).json();
    await fetch(intent2.upload.url, { method: 'PUT', headers: { 'Content-Type': 'application/pdf' }, body: pdf });
    const r = await fetch(intent2.completeUrl, { method: 'POST', headers: p.H });
    assert.equal(r.status, 422);
    assert.match((await r.json()).message, /not encrypted/);
  } finally { await p.close(); }
});

test('direct upload of an exe disguised as PDF is deleted from S3 at verify', async () => {
  const p = await startProxy();
  try {
    const exe = makeExe();
    const intent = await (await fetch(`${p.base}/api/presign/upload`, {
      method: 'POST', headers: { ...p.H, 'content-type': 'application/json' }, body: JSON.stringify({ filename: 'invoice.pdf', size: exe.length, method: 'put' }),
    })).json();
    await fetch(intent.upload.url, { method: 'PUT', headers: intent.upload.headers, body: exe });
    const key = p.proxy.store.getFile(intent.fileId).object_key;
    assert.ok(fake.objects.has(key));
    const r = await fetch(intent.completeUrl, { method: 'POST', headers: p.H });
    assert.equal(r.status, 415);
    assert.ok(!fake.objects.has(key), 'rejected object must be deleted');
    const dl = await fetch(`${p.base}/api/files/${intent.fileId}/download`, { headers: p.H });
    assert.equal(dl.status, 409);
  } finally { await p.close(); }
});

test('direct JPEG upload gets GPS stripped server-side at verify', async () => {
  const p = await startProxy();
  try {
    const jpg = makeJpegWithGps();
    const intent = await (await fetch(`${p.base}/api/presign/upload`, {
      method: 'POST', headers: { ...p.H, 'content-type': 'application/json' }, body: JSON.stringify({ filename: 'house.jpg', size: jpg.length, method: 'put' }),
    })).json();
    await fetch(intent.upload.url, { method: 'PUT', headers: intent.upload.headers, body: jpg });
    const done = await (await fetch(intent.completeUrl, { method: 'POST', headers: p.H })).json();
    assert.equal(done.file.gpsRemoved, true);
    const obj = fake.objects.get(p.proxy.store.getFile(intent.fileId).object_key);
    assert.ok(!hasGps(obj.body));
    assert.equal(obj.headers['x-amz-server-side-encryption'], 'AES256');
    assert.equal([...fake.objects.keys()].filter((k) => k.includes('.gps-')).length, 0, 'temp object cleaned up');
  } finally { await p.close(); }
});

test('S3 outage returns 502 and the file is marked rejected (not lost silently)', async () => {
  const dead = new S3Client({ region: 'us-east-1', endpoint: 'http://127.0.0.1:9', forcePathStyle: true, credentials: creds, maxAttempts: 1 });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's3proxy-test-'));
  const config = loadConfig({ ...s3Env(fake), APP_SECRET: 'k'.repeat(48), DATA_DIR: dir });
  const proxy = createProxy({ config, s3Client: dead, log: () => {} });
  try {
    await assert.rejects(
      proxy.service.proxyUpload({ stream: Readable.from([makePdf()]), filename: 'a.pdf', tenant: 'acme', actor: 'test' }),
      (e) => e.status === 502,
    );
    assert.equal(proxy.store.listFiles({ status: 'rejected' }).length, 1);
  } finally { await proxy.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
