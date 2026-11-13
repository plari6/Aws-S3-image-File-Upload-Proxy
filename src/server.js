// @ts-check
// Express 5 app: authenticated REST API for the agency's systems, plus the
// public client upload portal reached through encrypted upload links.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import multer from 'multer';
import { UploadRejected } from './service.js';
import { verifyApiKey, keyAllows } from './security/apikeys.js';
import { sanitizeTenant } from './security/filename.js';
import { parseDuration, parseBytes } from './config.js';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

/** Fixed-window per-key rate limiter (in memory, one process). */
export function rateLimiter({ windowSec, max }) {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, Math.max(windowSec, 10) * 1000);
  timer.unref();
  return (bucket) => (req, res, next) => {
    const key = `${bucket}:${req.ip}`;
    const now = Date.now();
    let e = hits.get(key);
    if (!e || e.reset <= now) { e = { n: 0, reset: now + windowSec * 1000 }; hits.set(key, e); }
    e.n++;
    res.set('RateLimit-Limit', String(max));
    res.set('RateLimit-Remaining', String(Math.max(0, max - e.n)));
    if (e.n > max) {
      res.set('Retry-After', String(Math.ceil((e.reset - now) / 1000)));
      return res.status(429).json({ error: 'rate_limited', message: 'Too many requests, slow down.' });
    }
    next();
  };
}

/** Multer storage engine that streams each file through the upload service. */
function proxyStorage(service) {
  return {
    _handleFile(req, file, cb) {
      service.proxyUpload({ stream: file.stream, filename: file.originalname, declaredMime: file.mimetype, ...req.uploadCtx })
        .then((result) => cb(null, { result }))
        .catch((err) => (err instanceof UploadRejected ? cb(null, { error: err }) : cb(err)));
    },
    _removeFile(req, file, cb) {
      const id = file.result?.id;
      if (!id) return cb(null);
      service.deleteFile(id, { actor: 'system:aborted-request' }).then(() => cb(null), () => cb(null));
    },
  };
}

const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * @param {{ config: import('./config.js').Config, store: import('./store.js').Store, storage: any, service: import('./service.js').UploadService, log?: (m: string) => void }} deps
 */
export function createApp({ config, store, storage, service, log = () => {} }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  const limit = rateLimiter(config.rateLimit);
  const strictLimit = rateLimiter({ windowSec: config.rateLimit.windowSec, max: Math.max(5, Math.floor(config.rateLimit.max / 2)) });

  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer', // upload-link tokens must never leak via Referer
      'Cache-Control': 'no-store',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    });
    if (config.publicUrl.startsWith('https://')) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true, storage: storage.name }));
  app.get('/favicon.ico', (_req, res) => res.status(204).end());

  // Local driver plays the role of S3 for pre-signed URLs.
  if (typeof storage.router === 'function') app.use('/_local', limit('local'), storage.router());

  const json = express.json({ limit: '16kb' });
  const upload = multer({
    storage: proxyStorage(service),
    limits: {
      files: config.uploads.maxFilesPerRequest,
      fileSize: config.uploads.maxFileBytes + 1, // backstop; the Meter rejects first at max+1 bytes
      fields: 10, fieldSize: 1024, parts: config.uploads.maxFilesPerRequest + 10,
    },
  });

  // ------------------------------------------------------------------ auth
  const auth = (scope) => (req, res, next) => {
    const header = req.get('authorization') || '';
    const presented = header.startsWith('Bearer ') ? header.slice(7).trim() : req.get('x-api-key');
    const key = verifyApiKey(store, config.appSecret, presented);
    if (!key) {
      store.audit({ action: 'auth.failed', ip: req.ip, outcome: 'denied', detail: { path: req.path } });
      return res.status(401).json({ error: 'unauthorized', message: 'Missing or invalid API key.' });
    }
    const requested = req.body?.tenant ?? req.query.tenant;
    const tenant = key.tenant === '*' ? (requested ? sanitizeTenant(requested) : undefined) : key.tenant;
    if (key.tenant !== '*' && requested && sanitizeTenant(requested) !== key.tenant) {
      return res.status(403).json({ error: 'forbidden', message: 'This key is limited to another tenant.' });
    }
    if (!keyAllows(key, scope, tenant)) return res.status(403).json({ error: 'forbidden', message: `This key lacks the "${scope}" scope.` });
    req.apiKey = key;
    req.tenant = tenant; // undefined = all tenants (only for "*" keys)
    req.scopeTenant = key.tenant; // used to restrict lookups by id
    req.actor = `key:${key.id}:${key.name}`;
    next();
  };

  const ok = (fn) => async (req, res, next) => {
    try { await fn(req, res); } catch (err) { next(err); }
  };

  // ------------------------------------------------------------------- API
  const api = express.Router();
  api.use(limit('api'));

  api.post('/files', auth('upload'), (req, res, next) => {
    req.uploadCtx = { tenant: req.tenant || sanitizeTenant(req.query.tenant || 'default'), actor: req.actor, ip: req.ip };
    upload.array('file')(req, res, (err) => {
      if (err) return next(err);
      const results = (req.files || []).map((f) => (f.error
        ? { name: f.originalname, ok: false, error: f.error.code, message: f.error.message }
        : { name: f.originalname, ok: true, file: f.result }));
      if (!results.length) return res.status(400).json({ error: 'no_file', message: 'Send files in multipart field "file".' });
      const allOk = results.every((r) => r.ok);
      res.status(allOk ? 201 : results.some((r) => r.ok) ? 207 : (req.files[0].error.status || 422)).json({ results });
    });
  });

  api.post('/presign/upload', json, auth('upload'), ok(async (req, res) => {
    const { filename, contentType, size, method } = req.body || {};
    if (!filename) throw new UploadRejected('filename is required', 400, 'bad_request');
    const intent = await service.createUploadIntent({
      filename, contentType, size, method, tenant: req.tenant || 'default', actor: req.actor, ip: req.ip,
    });
    res.status(201).json({ ...intent, completeUrl: `${config.publicUrl}/api/files/${intent.fileId}/complete` });
  }));

  api.post('/files/:id/complete', auth('upload'), ok(async (req, res) => {
    const file = await service.completeUpload(req.params.id, { actor: req.actor, ip: req.ip, tenant: req.scopeTenant });
    res.json({ file });
  }));

  api.get('/files', auth('read'), ok(async (req, res) => {
    const files = store.listFiles({ tenant: req.tenant, status: req.query.status, linkId: req.query.link, limit: req.query.limit, since: req.query.since });
    res.json({ files: files.map((f) => service.publicFile(f)) });
  }));

  api.get('/files/:id', auth('read'), ok(async (req, res) => {
    const f = service.getFile(req.params.id, req.scopeTenant);
    if (!f) throw new UploadRejected('file not found', 404, 'not_found');
    res.json({ file: service.publicFile(f) });
  }));

  api.get('/files/:id/download', auth('read'), ok(async (req, res) => {
    const ttl = req.query.ttl ? parseDuration(req.query.ttl, undefined) : undefined;
    const r = await service.presignDownload(req.params.id, { ttl, inline: req.query.inline === '1', actor: req.actor, ip: req.ip, tenant: req.scopeTenant });
    if (req.query.redirect === '1') return res.redirect(302, r.url);
    res.json(r);
  }));

  api.delete('/files/:id', auth('delete'), ok(async (req, res) => {
    await service.deleteFile(req.params.id, { actor: req.actor, ip: req.ip, tenant: req.scopeTenant });
    res.status(204).end();
  }));

  api.post('/links', json, auth('links'), ok(async (req, res) => {
    const b = req.body || {};
    const link = service.createLink({
      tenant: req.tenant || 'default', label: b.label, ttl: b.expiresIn ? parseDuration(b.expiresIn, undefined) : undefined,
      maxFiles: b.maxFiles, maxBytes: b.maxBytes ? parseBytes(b.maxBytes, undefined) : undefined,
      allowedTypes: Array.isArray(b.allowedTypes) ? b.allowedTypes : b.allowedTypes ? String(b.allowedTypes).split(',') : undefined,
      actor: req.actor,
    });
    res.status(201).json({ link });
  }));

  api.get('/links', auth('links'), ok(async (req, res) => {
    res.json({ links: store.listLinks(req.tenant).map((l) => service.describeLink(l)) });
  }));

  api.delete('/links/:id', auth('links'), ok(async (req, res) => {
    const l = store.getLink(req.params.id);
    if (!l || (req.scopeTenant !== '*' && l.tenant !== req.scopeTenant)) throw new UploadRejected('link not found', 404, 'not_found');
    res.json({ link: service.revokeLink(req.params.id, req.actor) });
  }));

  api.get('/stats', auth('read'), (req, res) => res.json({ tenant: req.tenant || 'all', byStatus: store.stats(req.tenant) }));
  api.get('/audit', auth('admin'), (req, res) => res.json({ events: store.listAudit({ limit: req.query.limit, tenant: req.tenant, action: req.query.action }) }));

  app.use('/api', api);

  // ------------------------------------------------- client upload portal
  const portal = express.Router({ mergeParams: true });
  const linkFrom = (req) => service.resolveLink(req.params.token);
  const pageTemplate = fs.readFileSync(path.join(PUBLIC_DIR, 'upload.html'), 'utf8');
  const s3Origin = storage.name === 's3'
    ? (config.storage.endpoint ? new URL(config.storage.endpoint).origin : `https://${config.storage.bucket}.s3.${config.storage.region}.amazonaws.com https://${config.storage.bucket}.s3.amazonaws.com`)
    : '';

  portal.get('/', strictLimit('page'), (req, res) => {
    let state = 'ok';
    let message = '';
    let link = null;
    try { link = linkFrom(req); } catch (err) { state = 'error'; message = err.message; }
    res.set('Content-Security-Policy', [
      "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data: blob:",
      `connect-src 'self' ${s3Origin}`.trim(), "form-action 'none'", "base-uri 'none'", "frame-ancestors 'none'",
    ].join('; '));
    res.status(state === 'ok' ? 200 : 410).type('html').send(pageTemplate
      .replaceAll('{{BRAND}}', escapeHtml(process.env.BRAND_NAME || 'Secure document upload'))
      .replaceAll('{{LABEL}}', escapeHtml(link?.label || ''))
      .replaceAll('{{STATE}}', state)
      .replaceAll('{{MESSAGE}}', escapeHtml(message)));
  });

  portal.get('/info', limit('portal'), ok(async (req, res) => {
    const link = linkFrom(req);
    const d = service.describeLink(link);
    const files = store.listFiles({ linkId: link.id, status: 'clean', limit: 200 }).map((f) => ({ id: f.id, name: f.original_name, size: f.size, at: f.completed_at }));
    res.json({
      label: d.label, expiresAt: d.expiresAt, allowedTypes: d.allowedTypes,
      maxFileBytes: Math.min(config.uploads.maxFileBytes, d.maxBytes), remainingFiles: Math.max(0, d.maxFiles - d.usedFiles),
      remainingBytes: Math.max(0, d.maxBytes - d.usedBytes), files,
    });
  }));

  portal.post('/presign', strictLimit('portal-presign'), json, ok(async (req, res) => {
    const link = linkFrom(req);
    const { filename, contentType, size } = req.body || {};
    if (!filename) throw new UploadRejected('filename is required', 400, 'bad_request');
    const intent = await service.createUploadIntent({ filename, contentType, size, method: 'post', tenant: link.tenant, actor: `link:${link.id}`, ip: req.ip, link });
    res.status(201).json(intent);
  }));

  portal.post('/complete/:fileId', strictLimit('portal-complete'), ok(async (req, res) => {
    const link = linkFrom(req);
    const file = await service.completeUpload(req.params.fileId, { actor: `link:${link.id}`, ip: req.ip, linkId: link.id });
    res.json({ file: { id: file.id, name: file.name, size: file.size, status: file.status } });
  }));

  // Fallback when the browser cannot reach S3 directly (strict corporate proxy, CORS not set up).
  portal.post('/files', strictLimit('portal-proxy'), (req, res, next) => {
    let link;
    try { link = linkFrom(req); } catch (err) { return next(err); }
    req.uploadCtx = { tenant: link.tenant, actor: `link:${link.id}`, ip: req.ip, link, method: 'proxy-link' };
    upload.array('file')(req, res, (err) => {
      if (err) return next(err);
      const results = (req.files || []).map((f) => (f.error
        ? { name: f.originalname, ok: false, message: f.error.message }
        : { name: f.originalname, ok: true, file: { id: f.result.id, name: f.result.name, size: f.result.size } }));
      res.status(results.length && results.every((r) => r.ok) ? 201 : 207).json({ results });
    });
  });

  app.use('/u/:token', portal);
  app.use('/static', express.static(PUBLIC_DIR, { index: false, maxAge: '1h', setHeaders: (res) => res.set('Cache-Control', 'public, max-age=3600') }));

  // ------------------------------------------------------------- errors
  app.use((_req, res) => res.status(404).json({ error: 'not_found', message: 'Not found.' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof UploadRejected) return res.status(err.status).json({ error: err.code, message: err.message });
    if (err instanceof multer.MulterError) {
      const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      const message = err.code === 'LIMIT_FILE_SIZE'
        ? `file is larger than the ${(config.uploads.maxFileBytes / 1024 / 1024).toFixed(1)} MB limit`
        : err.code === 'LIMIT_FILE_COUNT' ? `at most ${config.uploads.maxFilesPerRequest} files per request` : err.message;
      return res.status(status).json({ error: err.code.toLowerCase(), message });
    }
    if (err?.type === 'entity.parse.failed' || err?.type === 'entity.too.large') {
      return res.status(400).json({ error: 'bad_request', message: 'Invalid JSON body.' });
    }
    log(`error on ${req.method} ${req.path}: ${err?.stack || err}`);
    res.status(500).json({ error: 'internal', message: 'Internal error.' });
  });

  return app;
}
