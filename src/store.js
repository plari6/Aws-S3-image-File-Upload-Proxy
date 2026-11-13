// @ts-check
// SQLite store (built-in node:sqlite): file records, client upload links,
// API keys (hashed) and the audit trail. File bytes live only in S3.
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  declared_type TEXT,
  content_type TEXT,
  file_type TEXT,
  size INTEGER,
  max_bytes INTEGER,
  sha256 TEXT,
  status TEXT NOT NULL,            -- pending | clean | rejected | deleted
  reason TEXT,
  method TEXT NOT NULL,            -- proxy | presigned-post | presigned-put | cli
  link_id TEXT,
  uploaded_by TEXT,
  ip TEXT,
  sse TEXT,
  scan TEXT,                       -- skipped | clean | infected:<sig> | error
  gps_removed INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  deleted_at TEXT
);
CREATE INDEX IF NOT EXISTS files_tenant ON files(tenant, created_at);
CREATE INDEX IF NOT EXISTS files_link ON files(link_id);
CREATE INDEX IF NOT EXISTS files_status ON files(status, created_at);

CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  label TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_files INTEGER NOT NULL,
  max_bytes INTEGER NOT NULL,
  allowed_types TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tenant TEXT NOT NULL,            -- "*" = all tenants
  scopes TEXT NOT NULL,            -- comma list: upload,read,delete,links,admin
  secret_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  tenant TEXT,
  target TEXT,
  ip TEXT,
  outcome TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
`;

const now = () => new Date().toISOString();
/** node:sqlite cannot bind undefined: turn it into NULL. */
const clean = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v === undefined ? null : v]));

export class Store {
  /** @param {string} dbPath file path or ":memory:" */
  constructor(dbPath) {
    if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
    this.db.exec(SCHEMA);
  }

  close() {
    this.db.close();
  }

  // ---------- files ----------
  insertFile(f) {
    const row = {
      declared_type: null, content_type: null, file_type: null, size: null, max_bytes: null, sha256: null,
      reason: null, link_id: null, uploaded_by: null, ip: null, sse: null, scan: null, gps_removed: 0,
      completed_at: null, created_at: now(), ...f,
    };
    this.db.prepare(`INSERT INTO files (id, tenant, object_key, original_name, declared_type, content_type, file_type, size, max_bytes,
      sha256, status, reason, method, link_id, uploaded_by, ip, sse, scan, gps_removed, created_at, completed_at)
      VALUES (:id, :tenant, :object_key, :original_name, :declared_type, :content_type, :file_type, :size, :max_bytes,
      :sha256, :status, :reason, :method, :link_id, :uploaded_by, :ip, :sse, :scan, :gps_removed, :created_at, :completed_at)`).run(clean(row));
    return this.getFile(row.id);
  }

  updateFile(id, fields) {
    const keys = Object.keys(fields);
    if (!keys.length) return this.getFile(id);
    this.db.prepare(`UPDATE files SET ${keys.map((k) => `${k} = :${k}`).join(', ')} WHERE id = :id`).run(clean({ ...fields, id }));
    return this.getFile(id);
  }

  getFile(id) {
    return /** @type {any} */ (this.db.prepare('SELECT * FROM files WHERE id = ?').get(id)) || null;
  }

  /** @param {{ tenant?: string, status?: string, linkId?: string, limit?: number, since?: string }} q */
  listFiles(q = {}) {
    const where = [];
    const params = {};
    if (q.tenant) { where.push('tenant = :tenant'); params.tenant = q.tenant; }
    if (q.status) { where.push('status = :status'); params.status = q.status; }
    else where.push("status != 'deleted'");
    if (q.linkId) { where.push('link_id = :linkId'); params.linkId = q.linkId; }
    if (q.since) { where.push('created_at >= :since'); params.since = q.since; }
    params.limit = Math.min(Math.max(Number(q.limit) || 100, 1), 1000);
    return this.db.prepare(`SELECT * FROM files ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC LIMIT :limit`).all(params);
  }

  /** Pending uploads older than the cutoff (presigned URL never used or never completed). */
  stalePending(beforeIso) {
    return this.db.prepare("SELECT * FROM files WHERE status = 'pending' AND created_at < ?").all(beforeIso);
  }

  /** Files and bytes counted against a link (pending reservations included). */
  linkUsage(linkId) {
    const r = /** @type {any} */ (this.db.prepare(`SELECT COUNT(*) AS files, COALESCE(SUM(COALESCE(size, max_bytes, 0)), 0) AS bytes
      FROM files WHERE link_id = ? AND status IN ('pending', 'clean')`).get(linkId));
    return { files: Number(r.files), bytes: Number(r.bytes) };
  }

  stats(tenant) {
    const params = tenant ? [tenant] : [];
    return this.db.prepare(`SELECT status, COUNT(*) AS files, COALESCE(SUM(size), 0) AS bytes FROM files
      ${tenant ? 'WHERE tenant = ?' : ''} GROUP BY status`).all(...params);
  }

  // ---------- links ----------
  insertLink(l) {
    this.db.prepare(`INSERT INTO links (id, tenant, label, created_by, created_at, expires_at, max_files, max_bytes, allowed_types)
      VALUES (:id, :tenant, :label, :created_by, :created_at, :expires_at, :max_files, :max_bytes, :allowed_types)`)
      .run(clean({ label: null, created_by: null, allowed_types: null, created_at: now(), ...l }));
    return this.getLink(l.id);
  }

  getLink(id) {
    return /** @type {any} */ (this.db.prepare('SELECT * FROM links WHERE id = ?').get(id)) || null;
  }

  listLinks(tenant) {
    return tenant
      ? this.db.prepare('SELECT * FROM links WHERE tenant = ? ORDER BY created_at DESC').all(tenant)
      : this.db.prepare('SELECT * FROM links ORDER BY created_at DESC').all();
  }

  revokeLink(id) {
    this.db.prepare('UPDATE links SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now(), id);
    return this.getLink(id);
  }

  // ---------- API keys ----------
  insertKey(k) {
    this.db.prepare(`INSERT INTO api_keys (id, name, tenant, scopes, secret_hash, created_at)
      VALUES (:id, :name, :tenant, :scopes, :secret_hash, :created_at)`).run({ created_at: now(), ...k });
  }

  getKey(id) {
    return /** @type {any} */ (this.db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id)) || null;
  }

  listKeys() {
    return this.db.prepare('SELECT id, name, tenant, scopes, created_at, last_used_at, revoked_at FROM api_keys ORDER BY created_at DESC').all();
  }

  touchKey(id) {
    this.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now(), id);
  }

  revokeKey(id) {
    return this.db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now(), id).changes > 0;
  }

  // ---------- audit ----------
  audit(e) {
    const row = { ts: now(), actor: null, tenant: null, target: null, ip: null, outcome: 'ok', detail: null, ...e };
    if (row.detail && typeof row.detail !== 'string') row.detail = JSON.stringify(row.detail);
    this.db.prepare(`INSERT INTO audit (ts, actor, action, tenant, target, ip, outcome, detail)
      VALUES (:ts, :actor, :action, :tenant, :target, :ip, :outcome, :detail)`).run(clean(row));
    return row;
  }

  listAudit({ limit = 50, tenant, action } = {}) {
    const where = [];
    const params = { limit: Math.min(Number(limit) || 50, 5000) };
    if (tenant) { where.push('tenant = :tenant'); params.tenant = tenant; }
    if (action) { where.push('action = :action'); params.action = action; }
    return this.db.prepare(`SELECT * FROM audit ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT :limit`).all(params);
  }
}
