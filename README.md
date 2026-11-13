# AWS S3 Secure Image/File Upload Proxy

Collect client documents (IDs, contracts, payslips, invoices, photos) into **your own AWS S3 bucket** safely. Files travel over short-lived pre-signed URLs, are encrypted at rest, checked for their *real* type, cleaned of GPS location and virus-scanned (optional) before anyone can download them. Every step is recorded in an audit trail.

It comes as a CLI, a REST API for your CRM or n8n, and a branded upload page that clients reach through an expiring link. They need no account.

**Stack:** JavaScript (Node 24 ESM): Express 5, Multer 2, AWS SDK v3 (`client-s3`, `lib-storage`, `s3-request-presigner`, `s3-presigned-post`), commander, built-in `node:sqlite`. No build step and no LLM calls (it sits in the security path).

```
Client browser ──(1) POST /u/<link>/presign──────────────▶ Proxy ── checks name/type/size/link quota
       │                                                     │      signs a POST policy (SSE, size, type, key, tags)
       │◀────────────── pre-signed POST (15 min) ────────────┘
       ├──(2) file goes straight to S3 (HTTPS, SSE-S3/KMS) ──▶ S3  object tagged scan=pending
       └──(3) POST /u/<link>/complete/<id> ──────────────────▶ Proxy ── HEAD: exists, size, encryption
                                                                     Range GET: magic bytes = real type
                                                                     JPEG: GPS removed · ClamAV scan · SHA-256
                                                                     tag scan=clean → webhook to CRM / n8n
Your team / CRM ── GET /api/files/<id>/download ──▶ 5-minute download URL (attachment, no-store)
```

## Features

| Area | What it does |
|---|---|
| Encrypted pre-signed URLs | POST policy or signed PUT that **requires** SSE-S3 or SSE-KMS (the SSE header is signed), pins key, exact Content-Type and size range, tags the upload `scan=pending`, expires in 15 min (configurable). Download URLs last 5 min, force `attachment`, `no-store`. |
| Proxy upload | `POST /api/files` (Multer) streams through checks into S3 using multipart upload, without buffering the whole file. A failed upload is aborted, so no orphan parts remain. |
| Client upload links | `s3proxy link create` gives a link such as `https://upload.you.com/u/v1.…`. The token is **AES-256-GCM encrypted**, bound to its purpose and revocable, and carries limits on files, total size, allowed types and expiry. The upload page shows progress and falls back to the proxy if the browser can't reach S3. |
| Real file type | Checks magic bytes, never the file name. Refuses EXE/ELF/Mach-O/MSI/scripts, SVG/HTML with script, a file whose extension doesn't match its content (an `invoice.pdf` that is really an `.exe`), and ZIPs carrying executables. |
| Privacy | Removes GPS from JPEG EXIF and drops the XMP and Photoshop blocks while keeping orientation. Pixels are not re-encoded. This runs for direct uploads too, rewritten server-side. |
| Malware scan | Optional ClamAV (`clamd` INSTREAM) runs before a file becomes downloadable. Infected files are deleted and a `file.malware` webhook fires. With `SCAN_REQUIRED`, files stay pending while the scanner is down. |
| Access control | Hashed API keys (HMAC-peppered) with scopes `upload, read, delete, links, admin`, each bound to a tenant. Another tenant's file returns 404. Rate limits apply per IP, with a stricter limit on the public portal. |
| Bucket hardening | `bucket check` scores 0-100: Block Public Access, ACLs off, default encryption, TLS-only policy, no public Allow, CORS only from your portal, lifecycle rules that expire unverified uploads and abort stale multipart uploads, versioning. `bucket setup --yes` fixes them by merging with your existing policy, CORS and lifecycle rules. `bucket iam-policy` prints a least-privilege role policy. |
| Evidence | Each file gets a SHA-256 hash. An SQLite audit trail records uploads, rejections, downloads, links and failed authentication. Signed webhooks (`X-S3Proxy-Signature`) go to n8n, Make, Zapier or a CRM. |

## Quick start (no AWS needed)

```bash
npm install
npm run demo          # 22 real HTTP scenarios: uploads, attacks, links, tenant isolation
node bin/s3proxy.js demo --keep   # leaves the server running + prints a client upload link to open
npm test              # 30 tests, offline (fake S3 over HTTP, fake ClamAV, mocked AWS for bucket checks)
```

## Production setup (AWS)

```bash
node bin/s3proxy.js init --bucket my-client-docs --region eu-west-1 --public-url https://upload.example.com
node bin/s3proxy.js bucket iam-policy --admin > policy.json   # attach to the proxy's IAM role / user
node bin/s3proxy.js doctor                  # config + write/read/delete test on the bucket
node bin/s3proxy.js bucket check            # security score
node bin/s3proxy.js bucket setup            # dry-run plan; add --yes (and --versioning) to apply
node bin/s3proxy.js keys create --name crm --scopes admin
node bin/s3proxy.js serve                   # or: docker compose up -d (adds ClamAV)
```

Credentials come from the normal AWS chain: an IAM role on EC2, ECS or Lambda, `AWS_PROFILE`, or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` for a dedicated user. Pre-signed URLs carry the signer's permissions, so keep the role to the printed policy. Put the proxy behind HTTPS (ALB, nginx or Caddy) and set `TRUST_PROXY=1`. For per-client key control and CloudTrail records of every decrypt, use `S3_SSE=aws:kms` with `S3_KMS_KEY_ID`. MinIO, R2 and LocalStack also work through `S3_ENDPOINT`.

## CLI

```
s3proxy init | doctor | serve [-p] | demo [--keep]
s3proxy keys create --name <n> [--tenant t] [--scopes upload,read,delete,links,admin] | list | revoke <id>
s3proxy link create --tenant <t> [--label] [--expires 7d] [--max-files] [--max-size 200mb] [--types pdf,jpg] | list | revoke <id>
s3proxy upload <files...> --tenant <t>          # exit 2 if any file was rejected
s3proxy presign upload <name> [--size --type --method post|put --tenant]
s3proxy presign download <fileId> [--expires 10m] [--inline]
s3proxy verify <fileId>                          # check a direct upload
s3proxy files list|show|download|delete          # download verifies SHA-256
s3proxy cleanup [--older-than 24h] | stats | audit [--action upload.rejected]
s3proxy bucket check [--json] | setup [--yes] [--versioning] [--pending-days 2] | iam-policy [--admin] [--kms-key-arn]
```

## REST API

Authenticate with `Authorization: Bearer s3p_…` (or `X-API-Key`). A key bound to all tenants (`*`) can pass `tenant` in the query or body.

| Method & path | Scope | Purpose |
|---|---|---|
| `POST /api/files` (multipart `file`, up to 10) | upload | Proxy upload. Returns 201, or 207 when a batch is mixed, with per-file results. |
| `POST /api/presign/upload` `{filename, contentType?, size?, method: post\|put}` | upload | Returns a pre-signed upload plus `completeUrl`. |
| `POST /api/files/:id/complete` | upload | Verifies a direct upload: existence, encryption, real type, GPS, scan. |
| `GET /api/files?status=&link=&since=` · `GET /api/files/:id` | read | Lists files and their metadata. |
| `GET /api/files/:id/download?ttl=10m&inline=1&redirect=1` | read | Returns a short-lived URL (only for `clean` files). |
| `DELETE /api/files/:id` | delete | Deletes from S3 and marks the record. |
| `POST /api/links` `{label, expiresIn, maxFiles, maxBytes, allowedTypes}` · `GET` · `DELETE /api/links/:id` | links | Manages client upload links. |
| `GET /api/stats` · `GET /api/audit` | read / admin | Reporting. |
| `GET /u/:token` (page), `/info`, `POST /presign`, `POST /complete/:id`, `POST /files` | link token | Client portal. |

Webhook events are `file.uploaded`, `file.malware` and `file.deleted`. Each carries the header `X-S3Proxy-Signature: t=<unix>,v1=HMAC_SHA256(secret, "t.body")`. See [examples/webhook-receiver.mjs](examples/webhook-receiver.mjs) and [examples/api-client.mjs](examples/api-client.mjs).

## Configuration

All settings are environment variables; see [.env.example](.env.example). The most important ones:

`APP_SECRET`, `PUBLIC_URL`, `STORAGE_DRIVER=s3|local`, `S3_BUCKET`, `AWS_REGION`, `S3_PREFIX`, `S3_SSE=AES256|aws:kms`, `S3_KMS_KEY_ID`, `MAX_FILE_SIZE=25mb`, `ALLOWED_TYPES`, `UPLOAD_URL_TTL=15m`, `DOWNLOAD_URL_TTL=5m`, `STRIP_GPS`, `CLAMAV_HOST`, `SCAN_REQUIRED`, `LINK_TTL=7d`, `BRAND_NAME`, `WEBHOOK_URL`, `WEBHOOK_SECRET`, `RATE_LIMIT_MAX`, `TRUST_PROXY`.

## Security notes and limits

- A file can only be downloaded once it is `clean`. Unverified objects keep `scan=pending`, and the lifecycle rule deletes them after 2 days.
- GPS stripping covers JPEG (EXIF + XMP). PNG, HEIC and video metadata are passed through unchanged.
- The type check reads file headers. It does not prove that a PDF or Office document is free of malicious macros or JavaScript; ClamAV covers known signatures. Legacy `.doc`/`.xls` (OLE) files are refused.
- Rate limits are in memory, per process. When you run several replicas, also rate-limit at the load balancer or WAF.
- Rotating `APP_SECRET` invalidates every upload link and API key at once (useful as a kill switch).
- The `local` driver is for demos and tests only: files sit unencrypted on the server's disk.

## Project layout

```
bin/s3proxy.js          CLI
src/service.js          upload rules (shared by API, portal, CLI)
src/server.js           Express app: API, portal, errors, rate limits, headers
src/storage/s3.js       AWS SDK v3 driver (SSE, multipart, presign POST/PUT/GET)
src/storage/local.js    filesystem driver that emulates S3 pre-signed URLs
src/security/*          tokens (AES-GCM), API keys, file type, file names, GPS, ClamAV, stream checks
src/bucket.js           bucket audit / hardening / IAM policy
src/store.js            SQLite: files, links, keys, audit
src/demo/               offline demo + synthetic fixtures
public/                 client upload page (strict CSP, no inline script)
test/                   node:test suites, fake S3 server
```

## License

MIT
