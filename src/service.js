// @ts-check
// Upload service: the single place where upload rules live. Used by the HTTP
// API, the client upload page and the CLI, so every path gets the same checks:
//   1. server-generated object key (client name is metadata only)
//   2. real type from magic bytes, matching the extension, on the allow list
//   3. size limits (proxy: counted while streaming; direct: POST policy / signed length)
//   4. server-side encryption on every object, verified after direct uploads
//   5. GPS removed from photos, optional ClamAV scan, SHA-256 fingerprint
//   6. object tagged scan=pending until it passes; only clean files get download URLs
import { PassThrough, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import crypto from 'node:crypto';
import { Sniffer, Meter, UploadRejected } from './security/inspect.js';
import { GpsStripper, stripJpegHeader } from './security/exif.js';
import { SNIFF_BYTES, detectType, checkFileType, canonicalType, typeFromMime, typeFromName, mimeFor } from './security/filetype.js';
import { sanitizeFilename, sanitizeTenant, newId, buildObjectKey, contentDisposition } from './security/filename.js';
import { sealToken, openToken, TokenError } from './security/tokens.js';
import { clamScan } from './security/clamav.js';

export { UploadRejected };

const INLINE_SAFE = ['jpg', 'png', 'gif', 'webp', 'pdf'];

export class UploadService {
  /**
   * @param {{ config: import('./config.js').Config, store: import('./store.js').Store, storage: any, notifier?: { notify: Function, flush: Function }, log?: (m: string) => void }} deps
   */
  constructor({ config, store, storage, notifier, log }) {
    this.config = config;
    this.store = store;
    this.storage = storage;
    this.notifier = notifier || { notify() {}, async flush() {} };
    this.log = log || (() => {});
  }

  // ------------------------------------------------------------------ helpers
  #allowedTypes(link) {
    const base = this.config.uploads.allowedTypes.map(canonicalType);
    if (!link?.allowed_types) return base;
    const own = link.allowed_types.split(',').map(canonicalType);
    return own.filter((t) => base.includes(t));
  }

  #audit(action, e) {
    this.store.audit({ action, ...e });
  }

  #publicFile(f) {
    if (!f) return null;
    return {
      id: f.id, tenant: f.tenant, name: f.original_name, type: f.file_type, contentType: f.content_type, size: f.size,
      sha256: f.sha256, status: f.status, reason: f.reason, method: f.method, linkId: f.link_id, uploadedBy: f.uploaded_by,
      encryption: f.sse, scan: f.scan, gpsRemoved: Boolean(f.gps_removed), createdAt: f.created_at, completedAt: f.completed_at,
    };
  }

  publicFile(f) {
    return this.#publicFile(f);
  }

  /** Pre-flight check of name + declared MIME before any byte is accepted. */
  #precheck(filename, declaredMime, allowed) {
    const byName = typeFromName(filename);
    if (!byName) throw new UploadRejected('file name needs an extension (e.g. .pdf, .jpg)', 400, 'no_extension');
    if (!allowed.includes(byName)) throw new UploadRejected(`file type ".${byName}" is not allowed (allowed: ${allowed.join(', ')})`, 415, 'type_rejected');
    if (declaredMime && declaredMime !== 'application/octet-stream') {
      const byMime = typeFromMime(declaredMime);
      const textPair = ['csv', 'txt'].includes(byName) && ['csv', 'txt'].includes(byMime || '');
      if (byMime && byMime !== byName && !textPair) {
        throw new UploadRejected(`declared Content-Type ${declaredMime} does not match .${byName}`, 415, 'type_rejected');
      }
    }
    return byName;
  }

  #encryptionLabel() {
    const s = this.config.storage;
    if (this.storage.name !== 's3') return 'none (local demo)';
    return s.sse === 'aws:kms' ? `SSE-KMS${s.kmsKeyId ? ` (${s.kmsKeyId})` : ''}` : 'SSE-S3 (AES-256)';
  }

  // ------------------------------------------------------------ proxy upload
  /**
   * Stream a file through the proxy into S3.
   * @param {{ stream: import('node:stream').Readable, filename: string, declaredMime?: string, tenant: string, actor: string, ip?: string, link?: any, method?: string }} p
   */
  async proxyUpload({ stream, filename, declaredMime, tenant, actor, ip, link, method = 'proxy' }) {
    const name = sanitizeFilename(filename);
    const t = sanitizeTenant(link ? link.tenant : tenant);
    const allowed = this.#allowedTypes(link);
    const maxBytes = link ? Math.min(this.config.uploads.maxFileBytes, this.#linkRemaining(link).bytes) : this.config.uploads.maxFileBytes;
    try {
      this.#precheck(name, declaredMime, allowed);
      if (link) this.#assertLinkCapacity(link, 1);
    } catch (err) {
      stream.resume(); // drain so the connection can close cleanly
      this.#audit('upload.rejected', { actor, tenant: t, ip, outcome: 'rejected', detail: { name, reason: err.message } });
      throw err;
    }

    const id = newId('f');
    const key = buildObjectKey({ prefix: this.config.storage.prefix, tenant: t, fileId: id, ext: typeFromName(name) || 'bin' });
    this.store.insertFile({
      id, tenant: t, object_key: key, original_name: name, declared_type: declaredMime || null, status: 'pending',
      method, link_id: link?.id || null, uploaded_by: actor, ip: ip || null,
    });

    const sniffer = new Sniffer({ filename: name, allowedTypes: allowed });
    const gps = this.config.uploads.stripGps ? new GpsStripper() : null;
    const meter = new Meter({ maxBytes });
    const out = new PassThrough();
    // The source is piped (not part of the pipeline) so that on rejection we can
    // drain the rest of a multipart body instead of stalling the request parser.
    const piping = pipeline(/** @type {any} */ ([sniffer, ...(gps ? [gps] : []), meter, out]));
    piping.catch(() => {}); // handled below
    stream.on('error', (e) => sniffer.destroy(e));
    stream.pipe(sniffer);
    const drain = () => { stream.unpipe(sniffer); stream.resume(); };

    let file;
    try {
      await new Promise((resolve, reject) => {
        sniffer.once('type', resolve);
        piping.then(() => resolve(null), reject);
      });
      if (!sniffer.result) throw new UploadRejected('file could not be read', 400, 'bad_request');
      const putting = this.storage.put({
        key, body: out, contentType: sniffer.result.mime, contentDisposition: contentDisposition(name),
        tags: { scan: 'pending', tenant: t },
      });
      const [pipeRes, putRes] = await Promise.allSettled([piping, putting]);
      if (pipeRes.status === 'rejected') {
        if (putRes.status === 'fulfilled') await this.storage.delete(key).catch(() => {});
        throw pipeRes.reason;
      }
      if (putRes.status === 'rejected') throw putRes.reason;
      file = this.store.updateFile(id, {
        size: meter.bytes, sha256: meter.sha256, file_type: sniffer.result.type, content_type: sniffer.result.mime,
        sse: this.#encryptionLabel(), gps_removed: gps?.stats.stripped ? 1 : 0,
      });
    } catch (err) {
      drain();
      out.destroy();
      const rejected = err instanceof UploadRejected;
      this.store.updateFile(id, { status: 'rejected', reason: rejected ? err.message : `storage error: ${err.message}` });
      this.#audit('upload.rejected', { actor, tenant: t, target: id, ip, outcome: rejected ? 'rejected' : 'error', detail: { name, reason: err.message } });
      if (!rejected) this.log(`upload ${id} failed: ${err.stack || err.message}`);
      throw rejected ? err : new UploadRejected('storage is unavailable, please retry', 502, 'storage_error');
    }
    // Stored safely (tagged scan=pending). Scanning records its own outcome.
    return this.#finish(file, { actor, ip, sha256: meter.sha256 });
  }

  // ------------------------------------------------------- direct (presigned)
  /**
   * Issue a pre-signed URL so the browser uploads straight to S3.
   * @param {{ filename: string, contentType?: string, size?: number, method?: 'post'|'put', tenant: string, actor: string, ip?: string, link?: any }} p
   */
  async createUploadIntent({ filename, contentType, size, method = 'post', tenant, actor, ip, link }) {
    const name = sanitizeFilename(filename);
    const t = sanitizeTenant(link ? link.tenant : tenant);
    const allowed = this.#allowedTypes(link);
    const type = this.#precheck(name, contentType, allowed);
    const mime = mimeFor(type);
    if (!['post', 'put'].includes(method)) throw new UploadRejected('method must be "post" or "put"', 400, 'bad_request');
    let maxBytes = this.config.uploads.maxFileBytes;
    if (link) {
      this.#assertLinkCapacity(link, 1);
      maxBytes = Math.min(maxBytes, this.#linkRemaining(link).bytes);
    }
    if (size !== undefined && size !== null && size !== '') {
      size = Number(size);
      if (!Number.isInteger(size) || size < 1) throw new UploadRejected('size must be a positive whole number of bytes', 400, 'bad_request');
      if (size > maxBytes) throw new UploadRejected(`file is larger than the ${(maxBytes / 1024 / 1024).toFixed(1)} MB limit`, 413, 'too_large');
      if (method === 'post') maxBytes = size; // reserve only what is needed
    } else if (method === 'put') {
      throw new UploadRejected('size is required for PUT uploads (it becomes a signed header)', 400, 'bad_request');
    }

    const id = newId('f');
    const key = buildObjectKey({ prefix: this.config.storage.prefix, tenant: t, fileId: id, ext: type });
    const ttl = this.config.uploads.uploadUrlTtl;
    const tags = { scan: 'pending', tenant: t };
    const upload = method === 'put'
      ? await this.storage.presignPut({ key, contentType: mime, size: /** @type {number} */ (size), ttl, tags })
      : await this.storage.presignPost({ key, contentType: mime, maxBytes, ttl, tags });
    this.store.insertFile({
      id, tenant: t, object_key: key, original_name: name, declared_type: contentType || null, content_type: mime,
      status: 'pending', method: `presigned-${method}`, link_id: link?.id || null, uploaded_by: actor, ip: ip || null,
      max_bytes: method === 'put' ? size : maxBytes,
    });
    this.#audit('upload.presigned', { actor, tenant: t, target: id, ip, detail: { name, method, maxBytes } });
    return {
      fileId: id,
      name,
      expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
      maxBytes: method === 'put' ? size : maxBytes,
      upload,
    };
  }

  /**
   * After a direct upload: verify the object really is what was approved.
   * @param {string} fileId
   * @param {{ actor: string, ip?: string, tenant?: string, linkId?: string }} ctx
   */
  async completeUpload(fileId, { actor, ip, tenant, linkId }) {
    const file = this.store.getFile(fileId);
    if (!file || (tenant && tenant !== '*' && file.tenant !== tenant) || (linkId && file.link_id !== linkId)) {
      throw new UploadRejected('file not found', 404, 'not_found');
    }
    if (file.status === 'clean') return this.#publicFile(file); // idempotent
    if (file.status !== 'pending') throw new UploadRejected(`file is ${file.status}${file.reason ? `: ${file.reason}` : ''}`, 409, 'conflict');

    const head = await this.storage.head(file.object_key);
    if (!head.exists) throw new UploadRejected('the file has not been uploaded yet', 409, 'not_uploaded');

    const reject = async (reason, status = 422, code = 'rejected') => {
      if (this.config.uploads.deleteRejected) await this.storage.delete(file.object_key).catch(() => {});
      else await this.storage.setTags(file.object_key, { scan: 'rejected', tenant: file.tenant }).catch(() => {});
      this.store.updateFile(fileId, { status: 'rejected', reason, size: head.size, completed_at: new Date().toISOString() });
      this.#audit('upload.rejected', { actor, tenant: file.tenant, target: fileId, ip, outcome: 'rejected', detail: { name: file.original_name, reason } });
      throw new UploadRejected(reason, status, code);
    };

    if (head.size < 1) return reject('empty file');
    if (file.max_bytes && head.size > file.max_bytes) return reject('file is larger than approved', 413, 'too_large');
    if (file.method === 'presigned-put' && head.size !== file.max_bytes) return reject('file size differs from the signed size');
    if (this.storage.name === 's3') {
      const wantSse = this.config.storage.sse;
      if (head.sse !== wantSse) return reject(`object is not encrypted with ${wantSse} (got ${head.sse || 'none'})`);
      if (wantSse === 'aws:kms' && this.config.storage.kmsKeyId && head.kmsKeyId && !head.kmsKeyId.includes(this.config.storage.kmsKeyId.replace(/^.*key\//, ''))) {
        return reject('object is encrypted with a different KMS key');
      }
    }

    const headBytes = await this.storage.getRange(file.object_key, 0, SNIFF_BYTES - 1);
    const link = file.link_id ? this.store.getLink(file.link_id) : null;
    const verdict = checkFileType({ detected: detectType(headBytes), filename: file.original_name, allowedTypes: this.#allowedTypes(link) });
    if (!verdict.ok) return reject(verdict.reason, 415, 'type_rejected');

    let gpsRemoved = 0;
    if (verdict.type === 'jpg' && this.config.uploads.stripGps) gpsRemoved = await this.#stripStoredJpeg(file);
    const after = gpsRemoved ? await this.storage.head(file.object_key) : head;

    const updated = this.store.updateFile(fileId, {
      size: after.size, file_type: verdict.type, content_type: verdict.mime, sse: this.#encryptionLabel(), gps_removed: gpsRemoved ? 1 : 0,
    });
    return this.#finish(updated, { actor, ip, sha256: null });
  }

  /** Rewrite a stored JPEG without GPS (direct uploads bypass the proxy stream). */
  async #stripStoredJpeg(file) {
    const head = await this.storage.getRange(file.object_key, 0, 512 * 1024 - 1);
    const probe = stripJpegHeader(Buffer.from(head));
    if (probe.done && probe.removedTags + probe.droppedSegments === 0) return 0;
    const gps = new GpsStripper();
    const source = await this.storage.getStream(file.object_key);
    const body = new PassThrough();
    pipeline(source, gps, body).catch((e) => body.destroy(e));
    const tmpKey = `${file.object_key}.gps-${crypto.randomBytes(4).toString('hex')}`;
    // Write to a temporary key first, then copy back by streaming (works on S3 and
    // on Windows, where a file being read cannot be replaced).
    await this.storage.put({ key: tmpKey, body, contentType: 'image/jpeg', tags: { scan: 'pending', tenant: file.tenant } });
    if (!gps.stats.stripped) { await this.storage.delete(tmpKey); return 0; }
    await this.storage.put({
      key: file.object_key, body: await this.storage.getStream(tmpKey), contentType: 'image/jpeg',
      contentDisposition: contentDisposition(file.original_name), tags: { scan: 'pending', tenant: file.tenant },
    });
    await this.storage.delete(tmpKey);
    return 1;
  }

  /** Hash + malware scan, then mark clean. */
  async #finish(file, { actor, ip, sha256 }) {
    const scanCfg = this.config.scan;
    let scan = 'skipped';
    let hash = sha256;
    if (scanCfg.clamavHost || !hash) {
      const source = await this.storage.getStream(file.object_key);
      const hasher = crypto.createHash('sha256');
      const tap = new Transform({ transform(c, _e, cb) { hasher.update(c); cb(null, c); } });
      const piping = pipeline(source, tap);
      piping.catch(() => {}); // a scanner failure destroys tap; handled below
      if (scanCfg.clamavHost) {
        try {
          const verdict = await clamScan(tap, { host: scanCfg.clamavHost, port: scanCfg.clamavPort, timeoutMs: scanCfg.timeoutMs });
          scan = verdict.clean ? 'clean' : `infected:${verdict.signature}`;
        } catch (err) {
          tap.destroy();
          this.log(`scan error for ${file.id}: ${err.message}`);
          if (scanCfg.required) {
            this.#audit('scan.error', { actor, tenant: file.tenant, target: file.id, ip, outcome: 'error', detail: err.message });
            throw new UploadRejected('virus scanner unavailable; the file is held as pending, retry later', 503, 'scan_unavailable');
          }
          scan = 'error';
        }
      } else {
        tap.resume();
      }
      await piping.catch(() => {});
      if (!hash) hash = hasher.digest('hex');
    }

    if (scan.startsWith('infected:')) {
      await this.storage.delete(file.object_key).catch(() => {});
      this.store.updateFile(file.id, { status: 'rejected', reason: `malware detected (${scan.slice(9)})`, scan, sha256: hash, completed_at: new Date().toISOString() });
      this.#audit('upload.malware', { actor, tenant: file.tenant, target: file.id, ip, outcome: 'rejected', detail: { name: file.original_name, scan } });
      this.notifier.notify('file.malware', { id: file.id, tenant: file.tenant, name: file.original_name, scan });
      throw new UploadRejected('malware detected; the file was deleted', 422, 'malware');
    }

    await this.storage.setTags(file.object_key, { scan: 'clean', tenant: file.tenant });
    const done = this.store.updateFile(file.id, { status: 'clean', scan, sha256: hash, completed_at: new Date().toISOString() });
    const pub = this.#publicFile(done);
    const link = done.link_id ? this.store.getLink(done.link_id) : null;
    this.#audit('upload.clean', { actor, tenant: done.tenant, target: done.id, ip, detail: { name: done.original_name, size: done.size, type: done.file_type, method: done.method } });
    this.notifier.notify('file.uploaded', { ...pub, link: link ? { id: link.id, label: link.label } : null });
    return pub;
  }

  // ----------------------------------------------------------------- reading
  getFile(fileId, tenant) {
    const f = this.store.getFile(fileId);
    if (!f || f.status === 'deleted' || (tenant && tenant !== '*' && f.tenant !== tenant)) return null;
    return f;
  }

  /**
   * Short-lived download URL (only for files that passed every check).
   * @param {string} fileId
   * @param {{ ttl?: number, inline?: boolean, actor: string, ip?: string, tenant?: string }} p
   */
  async presignDownload(fileId, { ttl, inline = false, actor, ip, tenant }) {
    const f = this.getFile(fileId, tenant);
    if (!f) throw new UploadRejected('file not found', 404, 'not_found');
    if (f.status !== 'clean') throw new UploadRejected(`file is ${f.status}; only verified files can be downloaded`, 409, 'not_clean');
    const u = this.config.uploads;
    const seconds = Math.min(Math.max(Number(ttl) || u.downloadUrlTtl, 30), u.maxDownloadUrlTtl);
    const disposition = inline && INLINE_SAFE.includes(f.file_type) ? 'inline' : 'attachment';
    const url = await this.storage.presignGet({
      key: f.object_key, ttl: seconds, contentDisposition: contentDisposition(f.original_name, disposition), contentType: f.content_type,
    });
    this.#audit('download.presigned', { actor, tenant: f.tenant, target: f.id, ip, detail: { ttl: seconds, disposition } });
    return { url, expiresIn: seconds, expiresAt: new Date(Date.now() + seconds * 1000).toISOString(), file: this.#publicFile(f) };
  }

  async deleteFile(fileId, { actor, ip, tenant }) {
    const f = this.getFile(fileId, tenant);
    if (!f) throw new UploadRejected('file not found', 404, 'not_found');
    await this.storage.delete(f.object_key);
    this.store.updateFile(f.id, { status: 'deleted', deleted_at: new Date().toISOString() });
    this.#audit('file.deleted', { actor, tenant: f.tenant, target: f.id, ip, detail: { name: f.original_name } });
    this.notifier.notify('file.deleted', { id: f.id, tenant: f.tenant, name: f.original_name });
    return true;
  }

  /** Expire pending uploads whose URL was never used or never completed. */
  async cleanupPending(olderThanSec = 24 * 3600, actor = 'system') {
    const cutoff = new Date(Date.now() - olderThanSec * 1000).toISOString();
    const stale = this.store.stalePending(cutoff);
    for (const f of stale) {
      await this.storage.delete(f.object_key).catch(() => {});
      this.store.updateFile(f.id, { status: 'rejected', reason: 'expired: upload never completed' });
    }
    if (stale.length) this.#audit('cleanup.pending', { actor, detail: { removed: stale.length } });
    return stale.length;
  }

  // ------------------------------------------------------------ client links
  /**
   * Create a secure upload link to send to a client (no account needed).
   * @param {{ tenant: string, label?: string, ttl?: number, maxFiles?: number, maxBytes?: number, allowedTypes?: string[], actor: string }} p
   */
  createLink({ tenant, label, ttl, maxFiles, maxBytes, allowedTypes, actor }) {
    const L = this.config.links;
    const seconds = Math.min(Number(ttl) || L.defaultTtl, 90 * 86400);
    const id = newId('l');
    const t = sanitizeTenant(tenant);
    const types = allowedTypes?.length ? allowedTypes.map(canonicalType) : null;
    if (types) {
      const base = this.config.uploads.allowedTypes.map(canonicalType);
      const bad = types.filter((x) => !base.includes(x));
      if (bad.length) throw new UploadRejected(`types not allowed by the server: ${bad.join(', ')}`, 400, 'bad_request');
    }
    const link = this.store.insertLink({
      id, tenant: t, label: label ? String(label).slice(0, 120) : null, created_by: actor,
      expires_at: new Date(Date.now() + seconds * 1000).toISOString(),
      max_files: Math.max(1, Math.min(Number(maxFiles) || L.defaultMaxFiles, 1000)),
      max_bytes: Math.max(1024, Number(maxBytes) || L.defaultMaxBytes),
      allowed_types: types ? types.join(',') : null,
    });
    const token = sealToken(this.config.appSecret, 'upload-link', { lid: id, t }, seconds);
    this.#audit('link.created', { actor, tenant: t, target: id, detail: { label, expires: link.expires_at } });
    return { ...this.describeLink(link), url: `${this.config.publicUrl}/u/${token}` };
  }

  describeLink(link) {
    const usage = this.store.linkUsage(link.id);
    const expired = new Date(link.expires_at).getTime() < Date.now();
    return {
      id: link.id, tenant: link.tenant, label: link.label, createdAt: link.created_at, expiresAt: link.expires_at,
      maxFiles: link.max_files, maxBytes: link.max_bytes, allowedTypes: this.#allowedTypes(link),
      usedFiles: usage.files, usedBytes: usage.bytes,
      status: link.revoked_at ? 'revoked' : expired ? 'expired' : usage.files >= link.max_files ? 'full' : 'active',
    };
  }

  /** Decrypt and validate a link token from the client's URL. */
  resolveLink(token) {
    let payload;
    try {
      payload = openToken(this.config.appSecret, 'upload-link', token);
    } catch (err) {
      const expired = err instanceof TokenError && err.code === 'expired';
      throw new UploadRejected(expired ? 'this upload link has expired' : 'this upload link is not valid', expired ? 410 : 404, expired ? 'link_expired' : 'link_invalid');
    }
    const link = this.store.getLink(payload.lid);
    if (!link || link.tenant !== payload.t) throw new UploadRejected('this upload link is not valid', 404, 'link_invalid');
    if (link.revoked_at) throw new UploadRejected('this upload link was cancelled', 410, 'link_revoked');
    if (new Date(link.expires_at).getTime() < Date.now()) throw new UploadRejected('this upload link has expired', 410, 'link_expired');
    return link;
  }

  revokeLink(id, actor) {
    const link = this.store.revokeLink(id);
    if (!link) throw new UploadRejected('link not found', 404, 'not_found');
    this.#audit('link.revoked', { actor, tenant: link.tenant, target: id });
    return this.describeLink(link);
  }

  #linkRemaining(link) {
    const u = this.store.linkUsage(link.id);
    return { files: link.max_files - u.files, bytes: link.max_bytes - u.bytes };
  }

  #assertLinkCapacity(link, files) {
    const r = this.#linkRemaining(link);
    if (r.files < files) throw new UploadRejected(`this link accepts at most ${link.max_files} files`, 409, 'link_full');
    if (r.bytes < 1) throw new UploadRejected('this link has no storage space left', 409, 'link_full');
  }
}
