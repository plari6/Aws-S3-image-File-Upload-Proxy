// @ts-check
// Encrypted, authenticated tokens (AES-256-GCM). Used for client upload links
// and for the local storage driver's pre-signed URLs. The payload (tenant,
// limits, object key) is unreadable and tamper-proof, and the "purpose" is bound
// as additional authenticated data, so a token minted for one purpose is useless
// for another (no token confusion).
import crypto from 'node:crypto';

const VERSION = 'v1';

/** Derive a 32-byte sub-key from the app secret (HKDF-SHA256). */
export function deriveKey(secret, label) {
  if (!secret || secret.length < 32) throw new Error('APP_SECRET must be at least 32 characters');
  return Buffer.from(crypto.hkdfSync('sha256', secret, 's3proxy', label, 32));
}

/**
 * @param {string} secret
 * @param {string} purpose e.g. "upload-link", "local-get"
 * @param {Record<string, unknown>} payload
 * @param {number} ttlSec
 */
export function sealToken(secret, purpose, payload, ttlSec) {
  const key = deriveKey(secret, 'token-enc');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`${VERSION}:${purpose}`));
  const body = JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSec });
  const ct = Buffer.concat([cipher.update(body, 'utf8'), cipher.final()]);
  return `${VERSION}.${Buffer.concat([iv, ct, cipher.getAuthTag()]).toString('base64url')}`;
}

export class TokenError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

/**
 * @param {string} secret
 * @param {string} purpose
 * @param {string} token
 * @returns {Record<string, any>}
 */
export function openToken(secret, purpose, token) {
  if (typeof token !== 'string' || token.length > 4096 || !token.startsWith(`${VERSION}.`)) {
    throw new TokenError('Malformed token', 'malformed');
  }
  const raw = Buffer.from(token.slice(VERSION.length + 1), 'base64url');
  if (raw.length < 12 + 16 + 2) throw new TokenError('Malformed token', 'malformed');
  const key = deriveKey(secret, 'token-enc');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(12, raw.length - 16);
  let payload;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(`${VERSION}:${purpose}`));
    decipher.setAuthTag(tag);
    payload = JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8'));
  } catch {
    throw new TokenError('Invalid token', 'invalid');
  }
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new TokenError('Token expired', 'expired');
  }
  return payload;
}

/** HMAC-SHA256 hex, used for webhook signatures and local POST policies. */
export function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/** Constant-time string compare. */
export function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
