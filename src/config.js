// @ts-check
// Configuration from environment variables. Every setting has a safe default,
// and validateConfig() lists problems before the server starts.
import path from 'node:path';

/** Parse "15m", "7d", "3600" (seconds) into seconds. */
export function parseDuration(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'number') return value;
  const m = String(value).trim().match(/^(\d+(?:\.\d+)?)\s*(s|m|h|d|w)?$/i);
  if (!m) throw new Error(`Invalid duration "${value}" (use 30s, 15m, 12h, 7d)`);
  const mult = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[(m[2] || 's').toLowerCase()];
  return Math.round(Number(m[1]) * mult);
}

/** Parse "25mb", "500kb", "1gb", "1048576" into bytes. */
export function parseBytes(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'number') return value;
  const m = String(value).trim().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i);
  if (!m) throw new Error(`Invalid size "${value}" (use 500kb, 25mb, 1gb)`);
  const mult = { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3 }[(m[2] || 'b').toLowerCase()];
  return Math.round(Number(m[1]) * mult);
}

const bool = (v, d) => (v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)));
const list = (v, d) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : d);

export const DEFAULT_TYPES = ['jpg', 'png', 'webp', 'gif', 'heic', 'pdf', 'docx', 'xlsx', 'pptx', 'txt', 'csv'];

/**
 * @param {Record<string, string | undefined>} [env]
 */
export function loadConfig(env = process.env) {
  const dataDir = path.resolve(env.DATA_DIR || './data');
  const port = Number(env.PORT || 8080);
  return {
    port,
    host: env.HOST || '0.0.0.0',
    publicUrl: (env.PUBLIC_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
    trustProxy: env.TRUST_PROXY ? (/^\d+$/.test(env.TRUST_PROXY) ? Number(env.TRUST_PROXY) : env.TRUST_PROXY) : false,
    appSecret: env.APP_SECRET || '',
    dataDir,
    dbPath: env.DB_PATH || path.join(dataDir, 's3proxy.db'),

    storage: {
      driver: /** @type {'s3'|'local'} */ ((env.STORAGE_DRIVER || (env.S3_BUCKET ? 's3' : 'local')).toLowerCase()),
      bucket: env.S3_BUCKET || '',
      region: env.AWS_REGION || env.AWS_DEFAULT_REGION || 'us-east-1',
      endpoint: env.S3_ENDPOINT || undefined, // MinIO / R2 / LocalStack / tests
      forcePathStyle: bool(env.S3_FORCE_PATH_STYLE, Boolean(env.S3_ENDPOINT)),
      prefix: (env.S3_PREFIX || '').replace(/^\/+|\/+$/g, ''),
      sse: /** @type {'AES256'|'aws:kms'} */ (env.S3_SSE || 'AES256'),
      kmsKeyId: env.S3_KMS_KEY_ID || undefined,
      localDir: path.resolve(env.LOCAL_STORAGE_DIR || path.join(dataDir, 'bucket')),
    },

    uploads: {
      maxFileBytes: parseBytes(env.MAX_FILE_SIZE, 25 * 1024 * 1024),
      maxFilesPerRequest: Number(env.MAX_FILES_PER_REQUEST || 10),
      allowedTypes: list(env.ALLOWED_TYPES, DEFAULT_TYPES).map((t) => t.toLowerCase()),
      uploadUrlTtl: parseDuration(env.UPLOAD_URL_TTL, 900), // 15 min
      downloadUrlTtl: parseDuration(env.DOWNLOAD_URL_TTL, 300), // 5 min
      maxDownloadUrlTtl: parseDuration(env.MAX_DOWNLOAD_URL_TTL, 3600),
      stripGps: bool(env.STRIP_GPS, true),
      deleteRejected: bool(env.DELETE_REJECTED, true),
    },

    links: {
      defaultTtl: parseDuration(env.LINK_TTL, 7 * 86400),
      defaultMaxFiles: Number(env.LINK_MAX_FILES || 20),
      defaultMaxBytes: parseBytes(env.LINK_MAX_BYTES, 200 * 1024 * 1024),
    },

    scan: {
      clamavHost: env.CLAMAV_HOST || '',
      clamavPort: Number(env.CLAMAV_PORT || 3310),
      timeoutMs: Number(env.CLAMAV_TIMEOUT_MS || 60000),
      required: bool(env.SCAN_REQUIRED, false),
    },

    rateLimit: {
      windowSec: parseDuration(env.RATE_LIMIT_WINDOW, 60),
      max: Number(env.RATE_LIMIT_MAX || 60),
    },

    webhook: {
      url: env.WEBHOOK_URL || '',
      secret: env.WEBHOOK_SECRET || '',
      timeoutMs: Number(env.WEBHOOK_TIMEOUT_MS || 5000),
    },
  };
}

/** @typedef {ReturnType<typeof loadConfig>} Config */

/**
 * @param {Config} config
 * @returns {{ errors: string[], warnings: string[] }}
 */
export function validateConfig(config) {
  const errors = [];
  const warnings = [];
  if (!config.appSecret) errors.push('APP_SECRET is missing (run "s3proxy init" to generate one).');
  else if (config.appSecret.length < 32) errors.push('APP_SECRET must be at least 32 characters.');
  const s = config.storage;
  if (!['s3', 'local'].includes(s.driver)) errors.push(`STORAGE_DRIVER must be "s3" or "local", got "${s.driver}".`);
  if (s.driver === 's3' && !s.bucket) errors.push('S3_BUCKET is required when STORAGE_DRIVER=s3.');
  if (!['AES256', 'aws:kms'].includes(s.sse)) errors.push('S3_SSE must be "AES256" or "aws:kms".');
  if (s.sse === 'aws:kms' && !s.kmsKeyId) warnings.push('S3_SSE=aws:kms without S3_KMS_KEY_ID uses the AWS-managed aws/s3 key.');
  if (s.driver === 'local') warnings.push('STORAGE_DRIVER=local stores files on this disk (demo/dev only), not in S3.');
  if (!config.publicUrl.startsWith('https://') && !/localhost|127\.0\.0\.1/.test(config.publicUrl)) {
    warnings.push(`PUBLIC_URL (${config.publicUrl}) is not HTTPS: client links would travel in clear text.`);
  }
  if (config.uploads.uploadUrlTtl > 3600) warnings.push('UPLOAD_URL_TTL over 1h gives leaked upload URLs a long life.');
  if (config.uploads.downloadUrlTtl > 3600) warnings.push('DOWNLOAD_URL_TTL over 1h gives leaked download URLs a long life.');
  if (config.uploads.allowedTypes.some((t) => ['svg', 'html', 'htm', 'js', 'exe'].includes(t))) {
    errors.push('ALLOWED_TYPES contains an unsafe type (svg/html/js/exe can carry scripts or malware).');
  }
  if (config.scan.required && !config.scan.clamavHost) errors.push('SCAN_REQUIRED=true needs CLAMAV_HOST.');
  if (config.webhook.url && !config.webhook.secret) warnings.push('WEBHOOK_URL set without WEBHOOK_SECRET: receivers cannot verify events.');
  return { errors, warnings };
}
