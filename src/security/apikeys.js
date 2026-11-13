// @ts-check
// API keys for the agency's own systems (CRM, n8n, back office).
// Format: s3p_<id>_<secret>. Only an HMAC of the secret (peppered with a key
// derived from APP_SECRET) is stored, so a leaked database cannot be replayed.
import crypto from 'node:crypto';
import { deriveKey, hmac, safeEqual } from './tokens.js';
import { sanitizeTenant } from './filename.js';

export const SCOPES = ['upload', 'read', 'delete', 'links', 'admin'];

/**
 * @param {import('../store.js').Store} store
 * @param {string} appSecret
 * @param {{ name: string, tenant?: string, scopes?: string[] }} opts
 */
export function createApiKey(store, appSecret, { name, tenant = '*', scopes = ['upload', 'read'] }) {
  const bad = scopes.filter((s) => !SCOPES.includes(s));
  if (bad.length) throw new Error(`Unknown scope(s): ${bad.join(', ')} (valid: ${SCOPES.join(', ')})`);
  const id = crypto.randomBytes(6).toString('hex');
  const secret = crypto.randomBytes(24).toString('base64url');
  const t = tenant === '*' ? '*' : sanitizeTenant(tenant);
  store.insertKey({ id, name, tenant: t, scopes: scopes.join(','), secret_hash: hashSecret(appSecret, secret) });
  return { id, name, tenant: t, scopes, key: `s3p_${id}_${secret}` };
}

function hashSecret(appSecret, secret) {
  return hmac(deriveKey(appSecret, 'api-key-pepper'), secret);
}

/**
 * @returns {{ id: string, name: string, tenant: string, scopes: string[] } | null}
 */
export function verifyApiKey(store, appSecret, presented) {
  const m = String(presented || '').match(/^s3p_([0-9a-f]{12})_([A-Za-z0-9_-]{32})$/);
  if (!m) return null;
  const row = store.getKey(m[1]);
  const expected = row ? row.secret_hash : '0'.repeat(64);
  const ok = safeEqual(hashSecret(appSecret, m[2]), expected); // compute even when unknown (timing)
  if (!row || !ok || row.revoked_at) return null;
  store.touchKey(row.id);
  return { id: row.id, name: row.name, tenant: row.tenant, scopes: row.scopes.split(',') };
}

/** Does this key cover the tenant and scope? admin implies every scope. */
export function keyAllows(key, scope, tenant) {
  if (!key) return false;
  const scopeOk = key.scopes.includes('admin') || key.scopes.includes(scope);
  const tenantOk = key.tenant === '*' || tenant === undefined || key.tenant === tenant;
  return scopeOk && tenantOk;
}
