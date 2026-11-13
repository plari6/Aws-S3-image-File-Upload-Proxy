import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { detectType, checkFileType, typeFromName } from '../src/security/filetype.js';
import { sanitizeFilename, buildObjectKey, contentDisposition, sanitizeTenant } from '../src/security/filename.js';
import { sealToken, openToken, TokenError } from '../src/security/tokens.js';
import { GpsStripper, stripJpegHeader } from '../src/security/exif.js';
import { Sniffer, Meter, UploadRejected } from '../src/security/inspect.js';
import { parseDuration, parseBytes, loadConfig, validateConfig } from '../src/config.js';
import { makePdf, makePng, makeExe, makeSvg, makeHtml, makeDocx, makeJpegWithGps, hasGps, hasOrientation } from '../src/demo/fixtures.js';

const SECRET = 'x'.repeat(40);
const ALLOWED = ['jpg', 'png', 'pdf', 'docx', 'txt', 'csv'];

test('detectType recognises documents and images by content', () => {
  assert.equal(detectType(makePdf()), 'pdf');
  assert.equal(detectType(makePng()), 'png');
  assert.equal(detectType(makeJpegWithGps()), 'jpg');
  assert.equal(detectType(makeDocx()), 'docx');
  assert.equal(detectType(Buffer.from('name,email\nann,a@x.io\n')), 'csv');
  assert.equal(detectType(Buffer.from('just some notes\n')), 'txt');
  assert.equal(detectType(Buffer.from('RIFF\0\0\0\0WEBPVP8 ')), 'webp');
  assert.equal(detectType(Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from('ftypheic')])), 'heic');
});

test('detectType flags executables, scripts and active content', () => {
  assert.equal(detectType(makeExe()), 'exe');
  assert.equal(detectType(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1])), 'elf');
  assert.equal(detectType(Buffer.from('#!/bin/sh\nrm -rf /')), 'script');
  assert.equal(detectType(makeSvg()), 'svg');
  assert.equal(detectType(makeHtml()), 'html');
  assert.equal(detectType(Buffer.from('<script>alert(1)</script>')), 'html');
  assert.equal(detectType(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])), 'msi');
  assert.equal(detectType(Buffer.from([1, 2, 3, 0, 0, 9, 200, 3])), null);
});

test('checkFileType enforces allow list, danger list and extension match', () => {
  assert.equal(checkFileType({ detected: 'pdf', filename: 'a.pdf', allowedTypes: ALLOWED }).ok, true);
  assert.equal(checkFileType({ detected: 'jpg', filename: 'a.JPEG', allowedTypes: ALLOWED }).ok, true);
  assert.match(checkFileType({ detected: 'exe', filename: 'invoice.pdf', allowedTypes: ALLOWED }).reason, /dangerous/);
  assert.match(checkFileType({ detected: 'svg', filename: 'a.svg', allowedTypes: [...ALLOWED, 'svg'] }).reason, /dangerous/);
  assert.match(checkFileType({ detected: 'png', filename: 'photo.jpg', allowedTypes: ALLOWED }).reason, /does not match/);
  assert.match(checkFileType({ detected: 'gif', filename: 'a.gif', allowedTypes: ALLOWED }).reason, /not allowed/);
  assert.equal(checkFileType({ detected: 'csv', filename: 'list.txt', allowedTypes: ALLOWED }).ok, true);
  assert.match(checkFileType({ detected: null, filename: 'a.pdf', allowedTypes: ALLOWED }).reason, /unknown/);
  assert.equal(typeFromName('archive.tar.gz'), 'gz');
});

test('sanitizeFilename removes paths, control and bidi characters', () => {
  assert.equal(sanitizeFilename('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeFilename('C:\\Users\\x\\doc.pdf'), 'doc.pdf');
  assert.equal(sanitizeFilename('invoice\u202Efdp.exe'), 'invoicefdp.exe');
  assert.equal(sanitizeFilename('a\u0000b<>.pdf'), 'ab__.pdf');
  assert.equal(sanitizeFilename('...hidden'), 'hidden');
  assert.equal(sanitizeFilename(''), 'file');
  const long = sanitizeFilename(`${'a'.repeat(300)}.pdf`);
  assert.ok(long.length <= 150 && long.endsWith('.pdf'));
  assert.equal(sanitizeTenant('../ACME Corp!'), 'acme-corp');
});

test('object keys are server-generated and tenant-scoped', () => {
  const key = buildObjectKey({ prefix: 'docs', tenant: '../evil', fileId: 'f_abc', ext: 'p/d\\f', date: new Date('2026-03-04') });
  assert.equal(key, 'docs/evil/2026/03/f_abc.pdf');
  assert.equal(contentDisposition('Résumé "final".pdf'), `attachment; filename="R_sum_ _final_.pdf"; filename*=UTF-8''R%C3%A9sum%C3%A9%20_final_.pdf`);
});

test('tokens are encrypted, tamper-proof, purpose-bound and expire', () => {
  const t = sealToken(SECRET, 'upload-link', { lid: 'l_1', t: 'acme' }, 60);
  assert.ok(!Buffer.from(t.slice(3), 'base64url').toString('latin1').includes('acme'), 'payload must not be readable');
  assert.equal(openToken(SECRET, 'upload-link', t).lid, 'l_1');
  const flipped = t.slice(0, 10) + (t[10] === 'A' ? 'B' : 'A') + t.slice(11);
  assert.throws(() => openToken(SECRET, 'upload-link', flipped), TokenError);
  assert.throws(() => openToken(SECRET, 'local-get', t), /Invalid token/);
  assert.throws(() => openToken('y'.repeat(40), 'upload-link', t), /Invalid token/);
  const expired = sealToken(SECRET, 'upload-link', { lid: 'l' }, -1);
  assert.throws(() => openToken(SECRET, 'upload-link', expired), (e) => e.code === 'expired');
  assert.throws(() => openToken(SECRET, 'upload-link', 'garbage'), (e) => e.code === 'malformed');
  assert.throws(() => sealToken('short', 'x', {}, 1), /32 characters/);
});

test('GPS is removed from JPEG, orientation and image data kept', async () => {
  const src = makeJpegWithGps();
  assert.ok(hasGps(src) && hasOrientation(src));
  const res = stripJpegHeader(src);
  assert.equal(res.done, true);
  assert.equal(res.removedTags, 2);
  assert.equal(res.droppedSegments, 1);
  assert.ok(!hasGps(res.out) && hasOrientation(res.out));
  assert.ok(res.out.subarray(-3002).equals(src.subarray(-3002)), 'scan data untouched');

  // Streaming in 7-byte chunks gives the same result.
  const chunks = [];
  for (let i = 0; i < src.length; i += 7) chunks.push(src.subarray(i, i + 7));
  const g = new GpsStripper();
  const outBufs = [];
  await new Promise((resolve, reject) => Readable.from(chunks).pipe(g).on('data', (d) => outBufs.push(d)).on('end', resolve).on('error', reject));
  assert.ok(Buffer.concat(outBufs).equals(res.out));
  assert.equal(g.stats.stripped, true);
});

test('GpsStripper passes non-JPEG files through untouched', async () => {
  const pdf = makePdf();
  const g = new GpsStripper();
  const bufs = [];
  await new Promise((r) => Readable.from([pdf]).pipe(g).on('data', (d) => bufs.push(d)).on('end', r));
  assert.ok(Buffer.concat(bufs).equals(pdf));
  assert.equal(g.stats.stripped, false);
});

async function runChain(buf, { filename, maxBytes = 1e6 }) {
  const s = new Sniffer({ filename, allowedTypes: ALLOWED });
  const m = new Meter({ maxBytes });
  const { pipeline } = await import('node:stream/promises');
  const { Writable } = await import('node:stream');
  await pipeline(Readable.from([buf]), s, m, new Writable({ write(_c, _e, cb) { cb(); } }));
  return { type: s.result.type, bytes: m.bytes, sha256: m.sha256 };
}

test('Sniffer + Meter: type, size limit and SHA-256 while streaming', async () => {
  const pdf = makePdf();
  const r = await runChain(pdf, { filename: 'a.pdf' });
  assert.deepEqual(r, { type: 'pdf', bytes: pdf.length, sha256: crypto.createHash('sha256').update(pdf).digest('hex') });
  await assert.rejects(runChain(makeExe(), { filename: 'a.pdf' }), (e) => e instanceof UploadRejected && e.status === 415);
  await assert.rejects(runChain(pdf, { filename: 'a.pdf', maxBytes: 100 }), (e) => e.status === 413);
  await assert.rejects(runChain(Buffer.alloc(0), { filename: 'a.pdf' }), /empty/);
});

test('config parsing and validation', () => {
  assert.equal(parseDuration('15m'), 900);
  assert.equal(parseDuration('7d'), 604800);
  assert.equal(parseDuration('', 5), 5);
  assert.throws(() => parseDuration('soon'));
  assert.equal(parseBytes('25mb'), 25 * 1024 * 1024);
  assert.equal(parseBytes('1.5kb'), 1536);
  const bad = validateConfig(loadConfig({ STORAGE_DRIVER: 's3', ALLOWED_TYPES: 'pdf,svg', APP_SECRET: 'short' }));
  assert.ok(bad.errors.some((e) => e.includes('APP_SECRET')));
  assert.ok(bad.errors.some((e) => e.includes('S3_BUCKET')));
  assert.ok(bad.errors.some((e) => e.includes('unsafe type')));
  const good = validateConfig(loadConfig({ APP_SECRET: SECRET, S3_BUCKET: 'b', PUBLIC_URL: 'https://upload.example.com' }));
  assert.deepEqual(good.errors, []);
  assert.ok(validateConfig(loadConfig({ APP_SECRET: SECRET, S3_BUCKET: 'b', PUBLIC_URL: 'http://upload.example.com' })).warnings.some((w) => w.includes('HTTPS')));
});
