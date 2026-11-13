// @ts-check
// Library entry: build the whole proxy from a config, or use the parts.
import { loadConfig, validateConfig } from './config.js';
import { Store } from './store.js';
import { createStorage } from './storage/index.js';
import { UploadService, UploadRejected } from './service.js';
import { createApp } from './server.js';
import { createNotifier, verifyWebhook } from './webhook.js';

/**
 * @param {{ config?: ReturnType<typeof loadConfig>, s3Client?: import('@aws-sdk/client-s3').S3Client, log?: (m: string) => void }} [opts]
 */
export function createProxy(opts = {}) {
  const config = opts.config || loadConfig();
  const log = opts.log || ((m) => console.error(`[s3proxy] ${m}`));
  const store = new Store(config.dbPath);
  const storage = createStorage(config, { s3Client: opts.s3Client });
  const notifier = createNotifier(config.webhook, log);
  const service = new UploadService({ config, store, storage, notifier, log });
  const app = createApp({ config, store, storage, service, log });
  return {
    config, store, storage, service, app, notifier,
    async close() {
      await notifier.flush();
      store.close();
    },
  };
}

export { loadConfig, validateConfig, Store, createStorage, UploadService, UploadRejected, createApp, createNotifier, verifyWebhook };
export { iamPolicy, checkBucket, setupBucket } from './bucket.js';
export { sealToken, openToken } from './security/tokens.js';
export { createApiKey, verifyApiKey } from './security/apikeys.js';
export { detectType, checkFileType } from './security/filetype.js';
