// @ts-check
// Signed event notifications (n8n, Make, Zapier, CRM, Slack relay).
// Header: X-S3Proxy-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">
import { hmac, safeEqual } from './security/tokens.js';

/**
 * @param {{ url: string, secret: string, timeoutMs: number }} cfg
 * @param {(msg: string) => void} [log]
 */
export function createNotifier(cfg, log = () => {}) {
  /** @type {Promise<unknown>[]} */
  const inflight = [];
  async function send(event, data) {
    const body = JSON.stringify({ event, at: new Date().toISOString(), data });
    const t = Math.floor(Date.now() / 1000);
    const headers = { 'content-type': 'application/json', 'user-agent': 's3-upload-proxy/1.0' };
    if (cfg.secret) headers['x-s3proxy-signature'] = `t=${t},v1=${hmac(cfg.secret, `${t}.${body}`)}`;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(cfg.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(cfg.timeoutMs) });
        if (res.ok) return true;
        if (res.status < 500 && res.status !== 429) { log(`webhook ${event}: HTTP ${res.status}, not retried`); return false; }
      } catch (err) {
        if (attempt === 3) log(`webhook ${event} failed: ${err.message}`);
      }
      await new Promise((r) => setTimeout(r, 500 * attempt ** 2));
    }
    return false;
  }
  return {
    enabled: Boolean(cfg.url),
    /** Fire and forget; never blocks or fails an upload. */
    notify(event, data) {
      if (!cfg.url) return;
      const p = send(event, data).catch(() => {});
      inflight.push(p);
      p.finally(() => inflight.splice(inflight.indexOf(p), 1));
    },
    /** Wait for pending deliveries (CLI exit, tests). */
    async flush() {
      await Promise.allSettled([...inflight]);
    },
  };
}

/** Verify a received event (for the receiving side; exported for clients). */
export function verifyWebhook(secret, header, rawBody, toleranceSec = 300) {
  const m = String(header || '').match(/^t=(\d+),v1=([0-9a-f]{64})$/);
  if (!m) return false;
  if (Math.abs(Date.now() / 1000 - Number(m[1])) > toleranceSec) return false;
  return safeEqual(hmac(secret, `${m[1]}.${rawBody}`), m[2]);
}
