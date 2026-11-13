// @ts-check
// Local filesystem driver for demos, development and tests. It mimics S3
// closely, including pre-signed POST/PUT/GET URLs (encrypted tokens served by
// this app under /_local), so the browser upload flow is identical to production.
// Not for production: files sit unencrypted on the server's disk.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import express from 'express';
import multer from 'multer';
import { sealToken, openToken, safeEqual } from '../security/tokens.js';

const KEY_RE = /^[A-Za-z0-9_\-./]{1,512}$/;

export class LocalStorage {
  /** @param {{ dir: string, publicUrl: string, appSecret: string }} opts */
  constructor({ dir, publicUrl, appSecret }) {
    this.name = 'local';
    this.dir = path.resolve(dir);
    this.publicUrl = publicUrl;
    this.appSecret = appSecret;
    this.sse = 'none (local demo)';
    fs.mkdirSync(this.dir, { recursive: true });
  }

  describe() {
    return `local folder ${this.dir} (demo driver, not encrypted)`;
  }

  #path(key) {
    if (!KEY_RE.test(key) || key.split('/').some((p) => p === '..' || p === '.' || p === '')) throw new Error(`Invalid object key: ${key}`);
    const p = path.join(this.dir, ...key.split('/'));
    if (!p.startsWith(this.dir + path.sep)) throw new Error(`Invalid object key: ${key}`);
    return p;
  }

  async #writeMeta(key, meta) {
    await fsp.writeFile(`${this.#path(key)}.meta.json`, JSON.stringify(meta));
  }

  async #readMeta(key) {
    try { return JSON.parse(await fsp.readFile(`${this.#path(key)}.meta.json`, 'utf8')); } catch { return {}; }
  }

  async put({ key, body, contentType, contentDisposition, tags = {} }) {
    const file = this.#path(key);
    await fsp.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.part`;
    try {
      await pipeline(body, fs.createWriteStream(tmp));
      await fsp.rename(tmp, file);
    } catch (err) {
      await fsp.rm(tmp, { force: true });
      throw err;
    }
    await this.#writeMeta(key, { contentType, contentDisposition, tags, sse: null });
    return { etag: null, versionId: null };
  }

  async head(key) {
    try {
      const st = await fsp.stat(this.#path(key));
      const meta = await this.#readMeta(key);
      return { exists: true, size: st.size, contentType: meta.contentType, sse: meta.sse || null, kmsKeyId: null, tags: meta.tags || {} };
    } catch {
      return { exists: false };
    }
  }

  async getRange(key, start, end) {
    const fh = await fsp.open(this.#path(key), 'r');
    try {
      const buf = Buffer.alloc(end - start + 1);
      const { bytesRead } = await fh.read(buf, 0, buf.length, start);
      return buf.subarray(0, bytesRead);
    } finally {
      await fh.close();
    }
  }

  async getStream(key) {
    return fs.createReadStream(this.#path(key));
  }

  async delete(key) {
    await fsp.rm(this.#path(key), { force: true });
    await fsp.rm(`${this.#path(key)}.meta.json`, { force: true });
  }

  async setTags(key, tags) {
    const meta = await this.#readMeta(key);
    await this.#writeMeta(key, { ...meta, tags });
  }

  async presignPost({ key, contentType, maxBytes, ttl, tags = {} }) {
    const policy = sealToken(this.appSecret, 'local-post', { key, contentType, maxBytes, tags }, ttl);
    return {
      method: 'POST',
      url: `${this.publicUrl}/_local/upload`,
      fields: { key, 'Content-Type': contentType, success_action_status: '201', policy },
    };
  }

  async presignPut({ key, contentType, size, ttl, tags = {} }) {
    const token = sealToken(this.appSecret, 'local-put', { key, contentType, size, tags }, ttl);
    return { method: 'PUT', url: `${this.publicUrl}/_local/put/${token}`, headers: { 'Content-Type': contentType } };
  }

  async presignGet({ key, ttl, contentDisposition, contentType }) {
    const token = sealToken(this.appSecret, 'local-get', { key, contentDisposition, contentType }, ttl);
    return `${this.publicUrl}/_local/get/${token}`;
  }

  /** Routes that play the part of the S3 endpoint for pre-signed URLs. */
  router() {
    const r = express.Router();
    const s3Error = (res, status, code, message) =>
      res.status(status).type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`);

    const upload = multer({ storage: multer.memoryStorage(), limits: { files: 1, fields: 20, fileSize: 5 * 1024 ** 3 } });
    r.post('/upload', (req, res) => {
      upload.single('file')(req, res, async (err) => {
        if (err) return s3Error(res, 400, 'MalformedPOSTRequest', err.message);
        let p;
        try { p = openToken(this.appSecret, 'local-post', req.body?.policy); } catch (e) {
          return s3Error(res, 403, 'AccessDenied', e.code === 'expired' ? 'Request has expired' : 'Invalid policy');
        }
        if (req.body.key !== p.key) return s3Error(res, 403, 'AccessDenied', 'Policy condition failed: key');
        if (req.body['Content-Type'] !== p.contentType) return s3Error(res, 403, 'AccessDenied', 'Policy condition failed: Content-Type');
        if (!req.file) return s3Error(res, 400, 'InvalidArgument', 'POST requires exactly one file upload per request');
        if (req.file.size < 1 || req.file.size > p.maxBytes) return s3Error(res, 400, 'EntityTooLarge', 'Your proposed upload exceeds the maximum allowed size');
        const file = this.#path(p.key);
        await fsp.mkdir(path.dirname(file), { recursive: true });
        await fsp.writeFile(file, req.file.buffer);
        await this.#writeMeta(p.key, { contentType: p.contentType, tags: p.tags, sse: null });
        res.status(201).type('application/xml').send(`<PostResponse><Key>${p.key}</Key></PostResponse>`);
      });
    });

    r.put('/put/:token', async (req, res) => {
      let p;
      try { p = openToken(this.appSecret, 'local-put', req.params.token); } catch (e) {
        return s3Error(res, 403, 'AccessDenied', e.code === 'expired' ? 'Request has expired' : 'Invalid signature');
      }
      if (!safeEqual(req.get('content-type') || '', p.contentType)) return s3Error(res, 403, 'SignatureDoesNotMatch', 'Content-Type differs from the signed value');
      if (Number(req.get('content-length')) !== p.size) return s3Error(res, 403, 'SignatureDoesNotMatch', 'Content-Length differs from the signed value');
      let seen = 0;
      const limiter = new Transform({
        transform(chunk, _e, cb) {
          seen += chunk.length;
          cb(seen > p.size ? new Error('body longer than signed length') : null, chunk);
        },
      });
      try {
        const file = this.#path(p.key);
        await fsp.mkdir(path.dirname(file), { recursive: true });
        await pipeline(req, limiter, fs.createWriteStream(file));
        await this.#writeMeta(p.key, { contentType: p.contentType, tags: p.tags, sse: null });
        res.status(200).end();
      } catch (e) {
        s3Error(res, 400, 'IncompleteBody', e.message);
      }
    });

    r.get('/get/:token', async (req, res) => {
      let p;
      try { p = openToken(this.appSecret, 'local-get', req.params.token); } catch (e) {
        return s3Error(res, 403, 'AccessDenied', e.code === 'expired' ? 'Request has expired' : 'Invalid signature');
      }
      const h = await this.head(p.key);
      if (!h.exists) return s3Error(res, 404, 'NoSuchKey', 'The specified key does not exist.');
      res.set({
        'Content-Type': p.contentType || h.contentType || 'application/octet-stream',
        'Content-Disposition': p.contentDisposition,
        'Content-Length': String(h.size),
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      await pipeline(await this.getStream(p.key), res).catch(() => {});
    });
    return r;
  }
}
