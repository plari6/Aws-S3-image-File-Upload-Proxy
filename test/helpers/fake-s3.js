// Minimal path-style S3 HTTP server for tests: lets the real AWS SDK v3 client
// (and pre-signed URLs) talk over the wire, and records every request so tests
// can assert encryption headers, multipart behaviour and signed headers.
import http from 'node:http';
import crypto from 'node:crypto';

export async function startFakeS3({ bucket = 'test-bucket', sseOverride } = {}) {
  /** @type {Map<string, { body: Buffer, headers: Record<string,string>, tags: Record<string,string> }>} */
  const objects = new Map();
  const multipart = new Map();
  const requests = [];
  const xml = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/xml' }); res.end(`<?xml version="1.0" encoding="UTF-8"?>${body}`); };
  const readBody = (req) => new Promise((resolve) => { const c = []; req.on('data', (d) => c.push(d)); req.on('end', () => resolve(Buffer.concat(c))); });
  const sseHeaders = (h) => {
    const out = {};
    const sse = sseOverride === undefined ? h['x-amz-server-side-encryption'] : sseOverride;
    if (sse) out['x-amz-server-side-encryption'] = sse;
    if (h['x-amz-server-side-encryption-aws-kms-key-id']) out['x-amz-server-side-encryption-aws-kms-key-id'] = h['x-amz-server-side-encryption-aws-kms-key-id'];
    return out;
  };
  const parseTags = (q) => Object.fromEntries(new URLSearchParams(q || ''));

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const [, b, ...rest] = url.pathname.split('/');
    const key = decodeURIComponent(rest.join('/'));
    const q = url.searchParams;
    const body = await readBody(req);
    requests.push({ method: req.method, key, query: Object.fromEntries(q), headers: req.headers, size: body.length });
    if (b !== bucket) return xml(res, 404, '<Error><Code>NoSuchBucket</Code></Error>');

    if (req.method === 'POST' && q.has('uploads')) {
      const id = crypto.randomBytes(8).toString('hex');
      multipart.set(id, { key, parts: new Map(), headers: req.headers });
      return xml(res, 200, `<InitiateMultipartUploadResult><Bucket>${bucket}</Bucket><Key>${key}</Key><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
    }
    if (req.method === 'PUT' && q.has('uploadId')) {
      const mp = multipart.get(q.get('uploadId'));
      mp.parts.set(Number(q.get('partNumber')), body);
      res.writeHead(200, { etag: `"${crypto.createHash('md5').update(body).digest('hex')}"` });
      return res.end();
    }
    if (req.method === 'POST' && q.has('uploadId')) {
      const mp = multipart.get(q.get('uploadId'));
      const data = Buffer.concat([...mp.parts.keys()].sort((x, y) => x - y).map((n) => mp.parts.get(n)));
      objects.set(key, { body: data, headers: mp.headers, tags: parseTags(mp.headers['x-amz-tagging']) });
      multipart.delete(q.get('uploadId'));
      return xml(res, 200, `<CompleteMultipartUploadResult><Bucket>${bucket}</Bucket><Key>${key}</Key><ETag>"x-2"</ETag></CompleteMultipartUploadResult>`);
    }
    if (req.method === 'DELETE' && q.has('uploadId')) { multipart.delete(q.get('uploadId')); res.writeHead(204); return res.end(); }
    if (req.method === 'PUT' && q.has('tagging')) {
      const obj = objects.get(key);
      if (!obj) return xml(res, 404, '<Error><Code>NoSuchKey</Code></Error>');
      obj.tags = Object.fromEntries([...body.toString().matchAll(/<Key>([^<]*)<\/Key>\s*<Value>([^<]*)<\/Value>/g)].map((m) => [m[1], m[2]]));
      return xml(res, 200, '<Tagging/>');
    }
    if (req.method === 'PUT') {
      if (req.headers['content-length'] !== undefined && Number(req.headers['content-length']) !== body.length) return xml(res, 400, '<Error><Code>IncompleteBody</Code></Error>');
      objects.set(key, { body, headers: req.headers, tags: parseTags(req.headers['x-amz-tagging']) });
      res.writeHead(200, { etag: '"abc"', ...sseHeaders(req.headers) });
      return res.end();
    }
    const obj = objects.get(key);
    if (req.method === 'HEAD') {
      if (!obj) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-length': obj.body.length, 'content-type': obj.headers['content-type'] || 'application/octet-stream', ...sseHeaders(obj.headers) });
      return res.end();
    }
    if (req.method === 'GET') {
      if (!obj) return xml(res, 404, '<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>');
      const range = req.headers.range?.match(/bytes=(\d+)-(\d+)/);
      if (range) {
        const s = Number(range[1]);
        const e = Math.min(Number(range[2]), obj.body.length - 1);
        res.writeHead(206, { 'content-length': e - s + 1, 'content-range': `bytes ${s}-${e}/${obj.body.length}` });
        return res.end(obj.body.subarray(s, e + 1));
      }
      res.writeHead(200, { 'content-length': obj.body.length, 'content-type': obj.headers['content-type'] });
      return res.end(obj.body);
    }
    if (req.method === 'DELETE') { objects.delete(key); res.writeHead(204); return res.end(); }
    xml(res, 400, '<Error><Code>NotImplemented</Code></Error>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  return {
    endpoint, bucket, objects, requests, multipart,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  };
}

export function s3Env(fake, extra = {}) {
  return {
    STORAGE_DRIVER: 's3', S3_BUCKET: fake.bucket, S3_ENDPOINT: fake.endpoint, S3_FORCE_PATH_STYLE: 'true', AWS_REGION: 'us-east-1',
    AWS_ACCESS_KEY_ID: 'AKIAFAKEFAKEFAKE', AWS_SECRET_ACCESS_KEY: 'fake/secret/key/for/tests/only',
    ...extra,
  };
}
