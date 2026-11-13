// The offline demo is also the HTTP integration suite: every scenario must pass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { runDemo } from '../src/demo/run.js';
import { loadConfig } from '../src/config.js';
import { createProxy } from '../src/index.js';

test('end-to-end demo: all client and attack scenarios pass', async () => {
  const lines = [];
  const r = await runDemo({ log: (l) => lines.push(l) });
  const failed = r.results.filter((x) => !x.pass);
  assert.deepEqual(failed, [], lines.join('\n'));
  assert.ok(r.results.length >= 20);
});

test('portal endpoints are rate limited (429 + Retry-After)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 's3proxy-test-'));
  const proxy = createProxy({ config: loadConfig({ APP_SECRET: 'k'.repeat(48), DATA_DIR: dir, STORAGE_DRIVER: 'local', RATE_LIMIT_MAX: '6' }), log: () => {} });
  const server = proxy.app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  try {
    const statuses = [];
    let retryAfter = null;
    for (let i = 0; i < 8; i++) {
      const res = await fetch(`http://127.0.0.1:${server.address().port}/u/v1.guess${i}/presign`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      statuses.push(res.status);
      if (res.status === 429) retryAfter = res.headers.get('retry-after');
    }
    assert.deepEqual(statuses, [404, 404, 404, 404, 404, 429, 429, 429]); // token guessing is throttled
    assert.ok(Number(retryAfter) > 0);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    await proxy.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
