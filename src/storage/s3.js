// @ts-check
// AWS S3 driver (AWS SDK v3). Every write is server-side encrypted (SSE-S3 or
// SSE-KMS) and every pre-signed URL *requires* that encryption: the SSE header
// is a signed header / POST-policy condition, so an upload without it fails.
import {
  S3Client, PutObjectCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand, PutObjectTaggingCommand,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createPresignedPost } from '@aws-sdk/s3-presigned-post';

/** S3 tag set -> URL-encoded "a=b&c=d" (PUT header) */
const tagQuery = (tags) => new URLSearchParams(tags).toString();
/** S3 tag set -> XML (POST policy "tagging" field) */
const tagXml = (tags) =>
  `<Tagging><TagSet>${Object.entries(tags).map(([k, v]) => `<Tag><Key>${k}</Key><Value>${v}</Value></Tag>`).join('')}</TagSet></Tagging>`;

export class S3Storage {
  /**
   * @param {{ bucket: string, region: string, endpoint?: string, forcePathStyle?: boolean, sse: 'AES256'|'aws:kms', kmsKeyId?: string }} opts
   * @param {S3Client} [client] inject for tests
   */
  constructor(opts, client) {
    this.name = 's3';
    this.bucket = opts.bucket;
    this.sse = opts.sse;
    this.kmsKeyId = opts.kmsKeyId;
    this.client = client || new S3Client({
      region: opts.region,
      endpoint: opts.endpoint,
      forcePathStyle: opts.forcePathStyle,
      // Do not let the SDK add CRC32 checksum requirements to pre-signed URLs:
      // browsers cannot compute them, and S3 still verifies Content-MD5/SigV4.
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
    });
  }

  describe() {
    return `s3://${this.bucket} (SSE ${this.sse}${this.kmsKeyId ? ` key ${this.kmsKeyId}` : ''})`;
  }

  #sseParams() {
    return this.sse === 'aws:kms'
      ? { ServerSideEncryption: /** @type {const} */ ('aws:kms'), SSEKMSKeyId: this.kmsKeyId, BucketKeyEnabled: true }
      : { ServerSideEncryption: /** @type {const} */ ('AES256') };
  }

  /** Headers a browser must send with a pre-signed PUT (they are signed). */
  #sseHeaders() {
    const h = { 'x-amz-server-side-encryption': this.sse };
    if (this.sse === 'aws:kms') {
      if (this.kmsKeyId) h['x-amz-server-side-encryption-aws-kms-key-id'] = this.kmsKeyId;
      h['x-amz-server-side-encryption-bucket-key-enabled'] = 'true';
    }
    return h;
  }

  /**
   * Stream an object to S3 (multipart for large files, aborted on error).
   * @param {{ key: string, body: import('node:stream').Readable, contentType: string, contentDisposition?: string, tags?: Record<string,string>, metadata?: Record<string,string> }} p
   */
  async put({ key, body, contentType, contentDisposition, tags = {}, metadata }) {
    const upload = new Upload({
      client: this.client,
      queueSize: 4,
      partSize: 8 * 1024 * 1024,
      leavePartsOnError: false,
      params: {
        Bucket: this.bucket, Key: key, Body: body, ContentType: contentType, ContentDisposition: contentDisposition,
        Metadata: metadata, Tagging: Object.keys(tags).length ? tagQuery(tags) : undefined, ...this.#sseParams(),
      },
    });
    try {
      const res = await upload.done();
      return { etag: res.ETag, versionId: res.VersionId };
    } catch (err) {
      await upload.abort().catch(() => {});
      throw err;
    }
  }

  async head(key) {
    try {
      const r = await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return { exists: true, size: Number(r.ContentLength), contentType: r.ContentType, sse: r.ServerSideEncryption || null, kmsKeyId: r.SSEKMSKeyId || null };
    } catch (err) {
      if (err?.name === 'NotFound' || err?.$metadata?.httpStatusCode === 404) return { exists: false };
      throw err;
    }
  }

  /** First bytes of an object (for type sniffing after a direct upload). */
  async getRange(key, start, end) {
    const r = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key, Range: `bytes=${start}-${end}` }));
    return Buffer.from(await /** @type {any} */ (r.Body).transformToByteArray());
  }

  /** @returns {Promise<import('node:stream').Readable>} */
  async getStream(key) {
    const r = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    return /** @type {any} */ (r.Body);
  }

  async delete(key) {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }

  async setTags(key, tags) {
    await this.client.send(new PutObjectTaggingCommand({
      Bucket: this.bucket, Key: key, Tagging: { TagSet: Object.entries(tags).map(([Key, Value]) => ({ Key, Value })) },
    }));
  }

  /**
   * Browser-friendly pre-signed POST: the policy enforces size range, exact
   * Content-Type, key, encryption and tags. Nothing else can be uploaded with it.
   * @param {{ key: string, contentType: string, maxBytes: number, ttl: number, tags?: Record<string,string> }} p
   */
  async presignPost({ key, contentType, maxBytes, ttl, tags = {} }) {
    const fields = { 'Content-Type': contentType, success_action_status: '201', ...this.#sseHeaders() };
    if (Object.keys(tags).length) fields.tagging = tagXml(tags);
    const { url, fields: signed } = await createPresignedPost(this.client, {
      Bucket: this.bucket,
      Key: key,
      Expires: ttl,
      Fields: fields,
      // Fields are added as exact-match conditions by the SDK; add the size range.
      Conditions: [['content-length-range', 1, maxBytes]],
    });
    return { method: 'POST', url, fields: signed };
  }

  /**
   * Pre-signed PUT: Content-Type, exact Content-Length, encryption and tags are
   * signed headers, so the uploader must send exactly what was approved.
   * @param {{ key: string, contentType: string, size: number, ttl: number, tags?: Record<string,string> }} p
   */
  async presignPut({ key, contentType, size, ttl, tags = {} }) {
    const tagging = Object.keys(tags).length ? tagQuery(tags) : undefined;
    const cmd = new PutObjectCommand({
      Bucket: this.bucket, Key: key, ContentType: contentType, ContentLength: size, Tagging: tagging, ...this.#sseParams(),
    });
    const unhoist = new Set(['x-amz-server-side-encryption', 'x-amz-server-side-encryption-aws-kms-key-id',
      'x-amz-server-side-encryption-bucket-key-enabled', 'x-amz-tagging']);
    const url = await getSignedUrl(this.client, cmd, {
      expiresIn: ttl, signableHeaders: new Set(['content-type', 'content-length']), unhoistableHeaders: unhoist,
    });
    const headers = { 'Content-Type': contentType, ...this.#sseHeaders() };
    if (tagging) headers['x-amz-tagging'] = tagging;
    return { method: 'PUT', url, headers };
  }

  /**
   * Short-lived download URL that forces a download with the original name.
   * @param {{ key: string, ttl: number, contentDisposition: string, contentType?: string }} p
   */
  async presignGet({ key, ttl, contentDisposition, contentType }) {
    const cmd = new GetObjectCommand({
      Bucket: this.bucket, Key: key, ResponseContentDisposition: contentDisposition,
      ResponseContentType: contentType, ResponseCacheControl: 'private, no-store',
    });
    return getSignedUrl(this.client, cmd, { expiresIn: ttl });
  }
}
