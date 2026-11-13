#!/usr/bin/env node
// @ts-check
// s3proxy - command-line interface for the secure S3 upload proxy.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { Command, Option } from 'commander';
import dotenv from 'dotenv';
import { loadConfig, validateConfig, parseDuration, parseBytes } from '../src/config.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

const program = new Command();
program
  .name('s3proxy')
  .description('Secure AWS S3 image/file upload proxy: encrypted pre-signed URLs, client upload links, file checks, bucket hardening.')
  .version(pkg.version)
  .option('--env-file <path>', 'load settings from this .env file', '.env')
  .hook('preAction', (cmd) => {
    const file = cmd.opts().envFile;
    if (fs.existsSync(file)) dotenv.config({ path: file, quiet: true });
  });

// ------------------------------------------------------------------ helpers
const out = (v) => console.log(typeof v === 'string' ? v : JSON.stringify(v, null, 2));
const fail = (msg, code = 1) => { console.error(`error: ${msg}`); process.exit(code); };
const fmtBytes = (n) => (n == null ? '-' : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);

function table(rows, cols) {
  if (!rows.length) return console.log('(none)');
  const widths = cols.map(([h, f]) => Math.min(60, Math.max(h.length, ...rows.map((r) => String(f(r) ?? '').length))));
  const line = (vals) => vals.map((v, i) => String(v ?? '').slice(0, widths[i]).padEnd(widths[i])).join('  ');
  console.log(line(cols.map(([h]) => h)));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const r of rows) console.log(line(cols.map(([, f]) => f(r))));
}

/** Build the proxy from env; exits with a readable message if config is invalid. */
async function open({ strict = true } = {}) {
  const config = loadConfig();
  const { errors, warnings } = validateConfig(config);
  if (strict && errors.length) fail(`${errors.join('\n  ')}\nRun "s3proxy doctor" for details.`);
  for (const w of warnings) if (strict && process.env.S3PROXY_QUIET !== '1') console.error(`warning: ${w}`);
  const { createProxy } = await import('../src/index.js');
  return createProxy({ config });
}

async function withProxy(fn) {
  const p = await open();
  try { await fn(p); } catch (err) {
    if (err?.status) fail(`${err.message} (${err.code})`);
    throw err;
  } finally { await p.close(); }
}

// --------------------------------------------------------------------- init
program.command('init')
  .description('create .env with a fresh APP_SECRET (never overwrites existing values)')
  .option('--bucket <name>', 'S3 bucket (switches STORAGE_DRIVER to s3)')
  .option('--region <region>', 'AWS region', 'us-east-1')
  .option('--public-url <url>', 'public HTTPS URL of this proxy')
  .action((o) => {
    const file = program.opts().envFile;
    const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const has = (k) => new RegExp(`^${k}=.+`, 'm').test(existing);
    const add = [];
    if (!existing) add.push(fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8').replace(/^APP_SECRET=.*$/m, '').trimEnd());
    if (!has('APP_SECRET')) add.push(`APP_SECRET=${crypto.randomBytes(48).toString('base64url')}`);
    if (o.bucket && !has('S3_BUCKET')) add.push(`STORAGE_DRIVER=s3\nS3_BUCKET=${o.bucket}\nAWS_REGION=${o.region}`);
    if (o.publicUrl && !has('PUBLIC_URL')) add.push(`PUBLIC_URL=${o.publicUrl}`);
    if (!add.length) return console.log(`${file} already configured; nothing changed.`);
    fs.writeFileSync(file, `${existing ? `${existing.trimEnd()}\n` : ''}${add.join('\n')}\n`, { mode: 0o600 });
    console.log(`Wrote ${file}. Next: "s3proxy doctor", then "s3proxy keys create --name crm --scopes admin".`);
  });

// ------------------------------------------------------------------- doctor
program.command('doctor')
  .description('check configuration, storage access and virus scanner')
  .action(async () => {
    const config = loadConfig();
    const { errors, warnings } = validateConfig(config);
    console.log(`Storage   : ${config.storage.driver === 's3' ? `s3://${config.storage.bucket} (${config.storage.region}), SSE ${config.storage.sse}` : `local ${config.storage.localDir}`}`);
    console.log(`Public URL: ${config.publicUrl}`);
    console.log(`Limits    : ${fmtBytes(config.uploads.maxFileBytes)} per file, types ${config.uploads.allowedTypes.join(',')}`);
    console.log(`URL TTLs  : upload ${config.uploads.uploadUrlTtl}s, download ${config.uploads.downloadUrlTtl}s`);
    for (const e of errors) console.log(`  ERROR  ${e}`);
    for (const w of warnings) console.log(`  WARN   ${w}`);
    if (errors.length) process.exit(1);
    const { createStorage } = await import('../src/storage/index.js');
    const storage = createStorage(config);
    try {
      const key = `${config.storage.prefix ? `${config.storage.prefix}/` : ''}_doctor/${crypto.randomBytes(6).toString('hex')}.txt`;
      const { Readable } = await import('node:stream');
      await storage.put({ key, body: Readable.from([Buffer.from('ok')]), contentType: 'text/plain', tags: { scan: 'pending' } });
      const h = await storage.head(key);
      await storage.delete(key);
      console.log(`  OK     write/read/delete on storage (encryption reported: ${h.sse || 'n/a'})`);
    } catch (err) {
      console.log(`  ERROR  storage: ${err.name || ''} ${err.message}`);
      process.exitCode = 1;
    }
    if (config.scan.clamavHost) {
      const { clamPing } = await import('../src/security/clamav.js');
      const up = await clamPing({ host: config.scan.clamavHost, port: config.scan.clamavPort });
      console.log(`  ${up ? 'OK   ' : 'ERROR'}  ClamAV at ${config.scan.clamavHost}:${config.scan.clamavPort}`);
      if (!up && config.scan.required) process.exitCode = 1;
    } else console.log('  INFO   no ClamAV configured (CLAMAV_HOST) - files are type-checked but not virus-scanned');
  });

// -------------------------------------------------------------------- serve
program.command('serve')
  .description('start the HTTP API and client upload portal')
  .option('-p, --port <port>', 'port (default PORT or 8080)')
  .action(async (o) => {
    if (o.port) process.env.PORT = o.port;
    const p = await open();
    const { config, storage, app, service } = p;
    const server = app.listen(config.port, config.host, () => {
      console.log(`s3proxy listening on ${config.host}:${config.port}  storage: ${storage.describe()}`);
      console.log(`public URL: ${config.publicUrl}`);
    });
    server.requestTimeout = 30 * 60 * 1000; // large proxy uploads on slow links
    server.headersTimeout = 60 * 1000;
    const sweep = setInterval(() => service.cleanupPending(24 * 3600).catch(() => {}), 3600 * 1000);
    sweep.unref();
    const stop = () => {
      console.log('shutting down...');
      server.close(async () => { await p.close(); process.exit(0); });
      setTimeout(() => process.exit(0), 10000).unref();
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });

// --------------------------------------------------------------------- keys
const keys = program.command('keys').description('manage API keys for your systems (CRM, n8n, back office)');
keys.command('create')
  .requiredOption('--name <name>', 'who uses the key, e.g. "hubspot-sync"')
  .option('--tenant <tenant>', 'restrict to one client/tenant ("*" = all)', '*')
  .option('--scopes <list>', 'upload,read,delete,links,admin', 'upload,read')
  .action((o) => withProxy(async ({ store, config }) => {
    const { createApiKey } = await import('../src/security/apikeys.js');
    const k = createApiKey(store, config.appSecret, { name: o.name, tenant: o.tenant, scopes: o.scopes.split(',').map((s) => s.trim()) });
    store.audit({ action: 'key.created', actor: 'cli', tenant: k.tenant, target: k.id, detail: { name: k.name, scopes: k.scopes } });
    console.log(`API key for "${k.name}" (tenant ${k.tenant}, scopes ${k.scopes.join(',')}):\n\n  ${k.key}\n\nShown once. Store it in your secret manager; send it as "Authorization: Bearer <key>".`);
  }));
keys.command('list').option('--json').action((o) => withProxy(async ({ store }) => {
  const rows = store.listKeys();
  if (o.json) return out(rows);
  table(rows, [['ID', (r) => r.id], ['NAME', (r) => r.name], ['TENANT', (r) => r.tenant], ['SCOPES', (r) => r.scopes], ['LAST USED', (r) => r.last_used_at || '-'], ['STATUS', (r) => (r.revoked_at ? 'revoked' : 'active')]]);
}));
keys.command('revoke <id>').action((id) => withProxy(async ({ store }) => {
  if (!store.revokeKey(id)) fail(`no active key ${id}`);
  store.audit({ action: 'key.revoked', actor: 'cli', target: id });
  console.log(`Key ${id} revoked.`);
}));

// --------------------------------------------------------------------- link
const link = program.command('link').description('secure upload links to send to clients (no login needed)');
link.command('create')
  .requiredOption('--tenant <tenant>', 'client / tenant id, e.g. "acme"')
  .option('--label <text>', 'what you are asking for, shown on the page')
  .option('--expires <duration>', 'link lifetime, e.g. 3d, 12h', '7d')
  .option('--max-files <n>', 'maximum number of files')
  .option('--max-size <size>', 'total size budget, e.g. 200mb')
  .option('--types <list>', 'allowed types for this link, e.g. pdf,jpg')
  .option('--json')
  .action((o) => withProxy(async ({ service }) => {
    const l = service.createLink({
      tenant: o.tenant, label: o.label, ttl: parseDuration(o.expires, undefined), maxFiles: o.maxFiles ? Number(o.maxFiles) : undefined,
      maxBytes: o.maxSize ? parseBytes(o.maxSize, undefined) : undefined, allowedTypes: o.types ? o.types.split(',') : undefined, actor: 'cli',
    });
    if (o.json) return out(l);
    console.log(`Upload link for ${l.tenant}${l.label ? ` - ${l.label}` : ''}\n\n  ${l.url}\n`);
    console.log(`Expires ${l.expiresAt} | max ${l.maxFiles} files, ${fmtBytes(l.maxBytes)} | types ${l.allowedTypes.join(', ')} | id ${l.id}`);
  }));
link.command('list').option('--tenant <tenant>').option('--json').action((o) => withProxy(async ({ store, service }) => {
  const rows = store.listLinks(o.tenant).map((l) => service.describeLink(l));
  if (o.json) return out(rows);
  table(rows, [['ID', (r) => r.id], ['TENANT', (r) => r.tenant], ['LABEL', (r) => r.label || ''], ['FILES', (r) => `${r.usedFiles}/${r.maxFiles}`], ['EXPIRES', (r) => r.expiresAt.slice(0, 16)], ['STATUS', (r) => r.status]]);
}));
link.command('revoke <id>').action((id) => withProxy(async ({ service }) => {
  const l = service.revokeLink(id, 'cli');
  console.log(`Link ${l.id} (${l.label || l.tenant}) revoked.`);
}));

// ------------------------------------------------------------------- upload
program.command('upload <files...>')
  .description('upload local files through all checks (type, size, GPS strip, scan) into S3')
  .option('--tenant <tenant>', 'client / tenant id', 'default')
  .option('--json')
  .action((files, o) => withProxy(async ({ service }) => {
    const rows = [];
    for (const f of files) {
      try {
        const file = await service.proxyUpload({ stream: fs.createReadStream(f), filename: path.basename(f), tenant: o.tenant, actor: 'cli', method: 'cli' });
        rows.push({ path: f, ok: true, ...file });
      } catch (err) {
        if (!err.status) throw err;
        rows.push({ path: f, ok: false, error: err.message });
      }
    }
    if (o.json) return out(rows);
    table(rows, [['FILE', (r) => r.path], ['RESULT', (r) => (r.ok ? 'stored' : 'REJECTED')], ['ID / REASON', (r) => (r.ok ? r.id : r.error)], ['SIZE', (r) => fmtBytes(r.size)], ['SHA-256', (r) => (r.sha256 || '').slice(0, 16)]]);
    if (rows.some((r) => !r.ok)) process.exitCode = 2;
  }));

// ------------------------------------------------------------------ presign
const presign = program.command('presign').description('create pre-signed URLs');
presign.command('upload <filename>')
  .option('--size <bytes>', 'exact file size (required for --method put)')
  .option('--type <mime>', 'Content-Type')
  .addOption(new Option('--method <m>', 'post (browser form) or put').choices(['post', 'put']).default('post'))
  .option('--tenant <tenant>', 'client / tenant id', 'default')
  .action((filename, o) => withProxy(async ({ service, config }) => {
    const r = await service.createUploadIntent({ filename, contentType: o.type, size: o.size ? Number(o.size) : undefined, method: o.method, tenant: o.tenant, actor: 'cli' });
    out({ ...r, completeWith: `s3proxy verify ${r.fileId}`, completeUrl: `${config.publicUrl}/api/files/${r.fileId}/complete` });
  }));
presign.command('download <fileId>')
  .option('--expires <duration>', 'URL lifetime, e.g. 10m')
  .option('--inline', 'open in browser instead of downloading (images/PDF only)')
  .action((id, o) => withProxy(async ({ service }) => {
    const r = await service.presignDownload(id, { ttl: o.expires ? parseDuration(o.expires, undefined) : undefined, inline: o.inline, actor: 'cli' });
    console.log(`${r.url}\n\nValid for ${r.expiresIn}s (until ${r.expiresAt}) - ${r.file.name}`);
  }));

program.command('verify <fileId>')
  .description('verify a direct (pre-signed) upload: exists, encrypted, real type, scan')
  .action((id) => withProxy(async ({ service }) => out(await service.completeUpload(id, { actor: 'cli' }))));

// -------------------------------------------------------------------- files
const files = program.command('files').description('list, inspect, download and delete stored files');
files.command('list')
  .option('--tenant <tenant>').option('--status <status>', 'pending|clean|rejected|deleted').option('--link <id>').option('--limit <n>', '', '50').option('--json')
  .action((o) => withProxy(async ({ store, service }) => {
    const rows = store.listFiles({ tenant: o.tenant, status: o.status, linkId: o.link, limit: Number(o.limit) }).map((f) => service.publicFile(f));
    if (o.json) return out(rows);
    table(rows, [['ID', (r) => r.id], ['TENANT', (r) => r.tenant], ['NAME', (r) => r.name], ['SIZE', (r) => fmtBytes(r.size)], ['STATUS', (r) => r.status], ['VIA', (r) => r.method], ['CREATED', (r) => r.createdAt.slice(0, 16)], ['REASON', (r) => r.reason || '']]);
  }));
files.command('show <id>').action((id) => withProxy(async ({ service }) => {
  const f = service.getFile(id);
  if (!f) fail('file not found');
  out(service.publicFile(f));
}));
files.command('download <id>')
  .option('-o, --out <path>', 'output file (default: original name in current folder)')
  .action((id, o) => withProxy(async ({ service, storage, store }) => {
    const f = service.getFile(id);
    if (!f) fail('file not found');
    if (f.status !== 'clean') fail(`file is ${f.status}`);
    const dest = o.out || f.original_name;
    const hash = crypto.createHash('sha256');
    const src = await storage.getStream(f.object_key);
    src.on('data', (c) => hash.update(c));
    await pipeline(src, fs.createWriteStream(dest));
    const digest = hash.digest('hex');
    store.audit({ action: 'file.downloaded', actor: 'cli', tenant: f.tenant, target: f.id });
    if (f.sha256 && digest !== f.sha256) fail(`integrity check FAILED: ${digest} != ${f.sha256}`);
    console.log(`Saved ${dest} (${fmtBytes(f.size)}), SHA-256 ${f.sha256 ? 'verified' : digest}`);
  }));
files.command('delete <id>').action((id) => withProxy(async ({ service }) => {
  await service.deleteFile(id, { actor: 'cli' });
  console.log(`Deleted ${id}.`);
}));

program.command('cleanup')
  .description('expire pending uploads that were never completed')
  .option('--older-than <duration>', 'age', '24h')
  .action((o) => withProxy(async ({ service }) => console.log(`Expired ${await service.cleanupPending(parseDuration(o.olderThan, 86400), 'cli')} pending upload(s).`)));

program.command('stats').option('--tenant <tenant>').action((o) => withProxy(async ({ store }) => {
  table(store.stats(o.tenant), [['STATUS', (r) => r.status], ['FILES', (r) => r.files], ['BYTES', (r) => fmtBytes(Number(r.bytes))]]);
}));

program.command('audit')
  .description('show the audit trail')
  .option('--limit <n>', '', '50').option('--tenant <tenant>').option('--action <action>').option('--json')
  .action((o) => withProxy(async ({ store }) => {
    const rows = store.listAudit({ limit: Number(o.limit), tenant: o.tenant, action: o.action });
    if (o.json) return out(rows);
    table(rows, [['TIME', (r) => r.ts.slice(0, 19)], ['ACTION', (r) => r.action], ['OUTCOME', (r) => r.outcome], ['ACTOR', (r) => r.actor || ''], ['TENANT', (r) => r.tenant || ''], ['TARGET', (r) => r.target || ''], ['DETAIL', (r) => r.detail || '']]);
  }));

// ------------------------------------------------------------------- bucket
const bucket = program.command('bucket').description('audit and harden the S3 bucket');
const bucketOpts = (config) => ({
  bucket: config.storage.bucket, sse: config.storage.sse, kmsKeyId: config.storage.kmsKeyId, prefix: config.storage.prefix,
  origins: [new URL(config.publicUrl).origin],
});
async function s3ClientFor(config) {
  if (config.storage.driver !== 's3') fail('bucket commands need STORAGE_DRIVER=s3 and S3_BUCKET');
  const { S3Client } = await import('@aws-sdk/client-s3');
  return new S3Client({ region: config.storage.region, endpoint: config.storage.endpoint, forcePathStyle: config.storage.forcePathStyle });
}
bucket.command('check').option('--json').description('read-only security audit with a 0-100 score').action(async (o) => {
  const config = loadConfig();
  const { checkBucket } = await import('../src/bucket.js');
  const r = await checkBucket(await s3ClientFor(config), bucketOpts(config));
  if (o.json) return out({ ...r, current: undefined });
  console.log(`Bucket ${r.bucket}: security score ${r.score}/100\n`);
  for (const c of r.results) console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  [${c.level}] ${c.title}\n        ${c.detail}${c.fix ? `\n        fix: ${c.fix}` : ''}`);
  if (r.score < 100) console.log('\nRun "s3proxy bucket setup" to see the fix plan, "--yes" to apply it.');
  if (r.results.some((c) => !c.ok && c.level === 'critical')) process.exitCode = 1;
});
bucket.command('setup')
  .description('apply missing protections (dry run unless --yes)')
  .option('--yes', 'apply the changes')
  .option('--versioning', 'also enable versioning')
  .option('--pending-days <n>', 'delete unverified uploads after N days', '2')
  .action(async (o) => {
    const config = loadConfig();
    const { setupBucket } = await import('../src/bucket.js');
    const r = await setupBucket(await s3ClientFor(config), { ...bucketOpts(config), versioning: o.versioning, pendingDays: Number(o.pendingDays), dryRun: !o.yes });
    if (!r.plan.length) return console.log('Nothing to change: all protections are in place.');
    console.log(`${r.dryRun ? 'Plan (dry run, nothing changed)' : 'Applied'}:`);
    for (const p of r.plan) console.log(`  - ${p.action}`);
    if (r.dryRun) console.log('\nRe-run with --yes to apply.');
  });
bucket.command('iam-policy')
  .description('print the least-privilege IAM policy for the proxy role')
  .option('--admin', 'include the permissions "bucket setup" needs')
  .option('--kms-key-arn <arn>')
  .action(async (o) => {
    const config = loadConfig();
    const { iamPolicy } = await import('../src/bucket.js');
    out(iamPolicy({ bucket: config.storage.bucket || 'YOUR_BUCKET', prefix: config.storage.prefix, sse: config.storage.sse, kmsKeyArn: o.kmsKeyArn, admin: o.admin }));
  });

// --------------------------------------------------------------------- demo
program.command('demo')
  .description('offline end-to-end demo (local storage, real HTTP, attack scenarios)')
  .option('--keep', 'keep the server running and print a client upload link')
  .option('-p, --port <port>', 'port for --keep', '0')
  .action(async (o) => {
    const { runDemo } = await import('../src/demo/run.js');
    const r = await runDemo({ keep: o.keep, port: Number(o.port) });
    if (r.passed !== r.results.length) process.exitCode = 1;
    if (o.keep) process.on('SIGINT', async () => { await r.shutdown(); process.exit(0); });
  });

program.parseAsync().catch((err) => {
  console.error(`error: ${err?.name && err.name !== 'Error' ? `${err.name}: ` : ''}${err?.message || err}`);
  process.exit(1);
});
