// @ts-check
// Streaming checks applied to every byte that passes through the proxy:
//   Sniffer -> decides the real type from the first bytes and refuses bad files
//   Meter   -> counts bytes (hard size limit) and computes SHA-256
import crypto from 'node:crypto';
import { Transform } from 'node:stream';
import { SNIFF_BYTES, detectType, checkFileType } from './filetype.js';

export class UploadRejected extends Error {
  /** @param {string} reason @param {number} [status] @param {string} [code] */
  constructor(reason, status = 422, code = 'rejected') {
    super(reason);
    this.status = status;
    this.code = code;
  }
}

export class Sniffer extends Transform {
  /** @param {{ filename?: string, allowedTypes: string[] }} opts */
  constructor({ filename, allowedTypes }) {
    super();
    this.filename = filename;
    this.allowedTypes = allowedTypes;
    /** @type {Buffer[]} */
    this.head = [];
    this.headBytes = 0;
    this.decided = false;
    /** @type {{ type: string, mime: string } | null} */
    this.result = null;
  }

  _transform(chunk, _enc, cb) {
    if (this.decided) return cb(null, chunk);
    this.head.push(chunk);
    this.headBytes += chunk.length;
    if (this.headBytes < SNIFF_BYTES) return cb();
    this.#decide(cb);
  }

  _flush(cb) {
    if (!this.decided) return this.#decide(cb);
    cb();
  }

  #decide(cb) {
    this.decided = true;
    const buf = Buffer.concat(this.head);
    this.head = [];
    if (buf.length === 0) return cb(new UploadRejected('empty file'));
    const verdict = checkFileType({ detected: detectType(buf), filename: this.filename, allowedTypes: this.allowedTypes });
    if (!verdict.ok) return cb(new UploadRejected(verdict.reason, 415, 'type_rejected'));
    this.result = { type: verdict.type, mime: verdict.mime };
    this.emit('type', this.result);
    cb(null, buf);
  }
}

export class Meter extends Transform {
  /** @param {{ maxBytes: number }} opts */
  constructor({ maxBytes }) {
    super();
    this.maxBytes = maxBytes;
    this.bytes = 0;
    this.hash = crypto.createHash('sha256');
    this.sha256 = '';
  }

  _transform(chunk, _enc, cb) {
    this.bytes += chunk.length;
    if (this.bytes > this.maxBytes) {
      return cb(new UploadRejected(`file is larger than the ${Math.round(this.maxBytes / 1024 / 1024 * 10) / 10} MB limit`, 413, 'too_large'));
    }
    this.hash.update(chunk);
    cb(null, chunk);
  }

  _flush(cb) {
    this.sha256 = this.hash.digest('hex');
    cb();
  }
}
