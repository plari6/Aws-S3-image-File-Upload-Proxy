import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { mockClient } from 'aws-sdk-client-mock';
import {
  S3Client, HeadBucketCommand, GetPublicAccessBlockCommand, PutPublicAccessBlockCommand, GetBucketOwnershipControlsCommand,
  GetBucketEncryptionCommand, GetBucketPolicyCommand, PutBucketPolicyCommand, GetBucketCorsCommand, PutBucketCorsCommand,
  GetBucketLifecycleConfigurationCommand, PutBucketLifecycleConfigurationCommand, GetBucketVersioningCommand, PutBucketOwnershipControlsCommand,
  PutBucketEncryptionCommand, PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import { checkBucket, setupBucket, iamPolicy } from '../src/bucket.js';
import { clamScan } from '../src/security/clamav.js';
import { createNotifier, verifyWebhook } from '../src/webhook.js';
import { loadConfig } from '../src/config.js';
import { createProxy } from '../src/index.js';
import { makePdf } from '../src/demo/fixtures.js';

const notFound = (name) => Object.assign(new Error(name), { name });
const opts = { bucket: 'docs', sse: 'AES256', origins: ['https://upload.example.com'] };

function insecureBucket() {
  const m = mockClient(S3Client);
  m.on(HeadBucketCommand).resolves({});
  m.on(GetPublicAccessBlockCommand).rejects(notFound('NoSuchPublicAccessBlockConfiguration'));
  m.on(GetBucketOwnershipControlsCommand).resolves({ OwnershipControls: { Rules: [{ ObjectOwnership: 'ObjectWriter' }] } });
  m.on(GetBucketEncryptionCommand).rejects(notFound('ServerSideEncryptionConfigurationNotFoundError'));
  m.on(GetBucketPolicyCommand).resolves({ Policy: JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'Keep', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::1:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::docs/*' }] }) });
  m.on(GetBucketCorsCommand).resolves({ CORSRules: [{ ID: 'old', AllowedOrigins: ['*'], AllowedMethods: ['PUT'] }, { ID: 'cdn', AllowedOrigins: ['https://cdn.example.com'], AllowedMethods: ['GET'] }] });
  m.on(GetBucketLifecycleConfigurationCommand).resolves({ Rules: [{ ID: 'archive', Status: 'Enabled', Filter: { Prefix: 'old/' }, Expiration: { Days: 365 } }] });
  m.on(GetBucketVersioningCommand).resolves({});
  for (const c of [PutPublicAccessBlockCommand, PutBucketOwnershipControlsCommand, PutBucketEncryptionCommand, PutBucketPolicyCommand, PutBucketCorsCommand, PutBucketLifecycleConfigurationCommand, PutBucketVersioningCommand]) m.on(c).resolves({});
  return m;
}

test('bucket check scores an insecure bucket and explains each failure', async () => {
  const m = insecureBucket();
  const r = await checkBucket(new S3Client({ region: 'us-east-1' }), opts);
  const failed = r.results.filter((x) => !x.ok).map((x) => x.id);
  assert.deepEqual(failed.sort(), ['acls-disabled', 'cors', 'default-encryption', 'lifecycle', 'public-access-block', 'tls-only', 'versioning'].sort());
  assert.ok(r.score < 25, `score ${r.score}`);
  assert.match(r.results.find((x) => x.id === 'cors').detail, /any website/);
  m.restore();
});

test('bucket setup dry run changes nothing; --yes merges with existing config', async () => {
  let m = insecureBucket();
  const dry = await setupBucket(new S3Client({ region: 'us-east-1' }), { ...opts, dryRun: true });
  assert.equal(dry.plan.length, 6); // versioning only with --versioning
  assert.equal(m.commandCalls(PutBucketPolicyCommand).length, 0);
  m.restore();

  m = insecureBucket();
  await setupBucket(new S3Client({ region: 'us-east-1' }), { ...opts, versioning: true, pendingDays: 3 });
  const policy = JSON.parse(m.commandCalls(PutBucketPolicyCommand)[0].args[0].input.Policy);
  assert.deepEqual(policy.Statement.map((s) => s.Sid), ['Keep', 'S3ProxyDenyInsecureTransport'], 'existing statements kept');
  const cors = m.commandCalls(PutBucketCorsCommand)[0].args[0].input.CORSConfiguration.CORSRules;
  assert.deepEqual(cors.map((c) => c.ID), ['cdn', 's3proxy-uploads'], 'wildcard upload rule removed, CDN rule kept');
  assert.deepEqual(cors[1].AllowedOrigins, ['https://upload.example.com']);
  const rules = m.commandCalls(PutBucketLifecycleConfigurationCommand)[0].args[0].input.LifecycleConfiguration.Rules;
  assert.deepEqual(rules.map((x) => x.ID), ['archive', 's3proxy-expire-unverified', 's3proxy-abort-multipart']);
  assert.equal(rules[1].Expiration.Days, 3);
  assert.equal(m.commandCalls(PutBucketVersioningCommand).length, 1);
  m.restore();
});

test('IAM policy is least privilege (no bucket-wide or admin actions by default)', () => {
  const p = iamPolicy({ bucket: 'docs', prefix: 'clients', sse: 'aws:kms', kmsKeyArn: 'arn:aws:kms:eu-west-1:1:key/k' });
  assert.equal(p.Statement[0].Resource, 'arn:aws:s3:::docs/clients/*');
  assert.ok(!JSON.stringify(p).includes('s3:*') && !JSON.stringify(p).includes('ListBucket'));
  assert.deepEqual(p.Statement[1].Action, ['kms:GenerateDataKey', 'kms:Decrypt']);
  assert.ok(iamPolicy({ bucket: 'docs', sse: 'AES256', admin: true }).Statement.some((s) => s.Sid === 'BucketHardeningSetupOnly'));
});

/** Fake clamd: replies FOUND when the stream contains the EICAR marker. */
async function fakeClamd() {
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.subarray(-4).equals(Buffer.alloc(4))) {
        const found = buf.includes(Buffer.from('EICAR-STANDARD-ANTIVIRUS-TEST-FILE'));
        sock.end(found ? 'stream: Eicar-Test-Signature FOUND\0' : 'stream: OK\0');
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

test('ClamAV client: clean and infected verdicts', async () => {
  const clam = await fakeClamd();
  try {
    assert.equal((await clamScan(Readable.from([makePdf()]), { host: '127.0.0.1', port: clam.port })).clean, true);
    const v = await clamScan(Readable.from([Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')]), { host: '127.0.0.1', port: clam.port });
    assert.deepEqual([v.clean, v.signature], [false, 'Eicar-Test-Signature']);
    await assert.rejects(clamScan(Readable.from([Buffer.from('x')]), { host: '127.0.0.1', port: 9, timeoutMs: 2000 }), /unreachable/);
  } finally { await clam.close(); }
});

test('infected upload is deleted, never downloadable, and a signed webhook fires', async () => {
  const clam = await fakeClamd();
  const events = [];
  const hook = http.createServer((req, res) => {
    let b = '';
    req.on('data', (d) => { b += d; });
    req.on('end', () => { events.push({ sig: req.headers['x-s3proxy-signature'], body: b }); res.end('ok'); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's3proxy-test-'));
  const config = loadConfig({
    APP_SECRET: 'k'.repeat(48), DATA_DIR: dir, STORAGE_DRIVER: 'local', CLAMAV_HOST: '127.0.0.1', CLAMAV_PORT: String(clam.port),
    WEBHOOK_URL: `http://127.0.0.1:${hook.address().port}/hook`, WEBHOOK_SECRET: 'whsec-test',
  });
  const proxy = createProxy({ config, log: () => {} });
  try {
    const eicar = Buffer.concat([makePdf().subarray(0, 100), Buffer.from(' EICAR-STANDARD-ANTIVIRUS-TEST-FILE '), makePdf().subarray(100)]);
    await assert.rejects(proxy.service.proxyUpload({ stream: Readable.from([eicar]), filename: 'cv.pdf', tenant: 'acme', actor: 't' }), (e) => e.code === 'malware');
    const bad = proxy.store.listFiles({ status: 'rejected' })[0];
    assert.match(bad.reason, /Eicar-Test-Signature/);
    assert.equal((await proxy.storage.head(bad.object_key)).exists, false);

    const ok = await proxy.service.proxyUpload({ stream: Readable.from([makePdf()]), filename: 'cv.pdf', tenant: 'acme', actor: 't' });
    assert.equal(ok.scan, 'clean');
    await proxy.notifier.flush();
    assert.deepEqual(events.map((e) => JSON.parse(e.body).event), ['file.malware', 'file.uploaded']);
    assert.ok(events.every((e) => verifyWebhook('whsec-test', e.sig, e.body)));
    assert.equal(verifyWebhook('wrong', events[0].sig, events[0].body), false);
  } finally {
    await proxy.close();
    await clam.close();
    await new Promise((r) => hook.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SCAN_REQUIRED keeps the file pending when the scanner is down', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's3proxy-test-'));
  const config = loadConfig({ APP_SECRET: 'k'.repeat(48), DATA_DIR: dir, STORAGE_DRIVER: 'local', CLAMAV_HOST: '127.0.0.1', CLAMAV_PORT: '9', CLAMAV_TIMEOUT_MS: '2000', SCAN_REQUIRED: 'true' });
  const proxy = createProxy({ config, log: () => {} });
  try {
    await assert.rejects(proxy.service.proxyUpload({ stream: Readable.from([makePdf()]), filename: 'a.pdf', tenant: 't', actor: 't' }), (e) => e.status === 503);
    const [f] = proxy.store.listFiles({ status: 'pending' });
    assert.ok(f, 'file held as pending');
    assert.equal((await proxy.storage.head(f.object_key)).exists, true);
    await assert.rejects(proxy.service.presignDownload(f.id, { actor: 't' }), (e) => e.code === 'not_clean');
  } finally { await proxy.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('webhook notifier never throws when the receiver is down', async () => {
  const n = createNotifier({ url: 'http://127.0.0.1:9/x', secret: 's', timeoutMs: 500 });
  n.notify('file.uploaded', { id: 1 });
  await n.flush();
});
