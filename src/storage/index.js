// @ts-check
import { S3Storage } from './s3.js';
import { LocalStorage } from './local.js';

/**
 * @param {import('../config.js').Config} config
 * @param {{ s3Client?: import('@aws-sdk/client-s3').S3Client }} [deps]
 */
export function createStorage(config, deps = {}) {
  const s = config.storage;
  if (s.driver === 's3') return new S3Storage(s, deps.s3Client);
  return new LocalStorage({ dir: s.localDir, publicUrl: config.publicUrl, appSecret: config.appSecret });
}

export { S3Storage, LocalStorage };
