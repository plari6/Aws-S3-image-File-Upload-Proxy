// @ts-check
// Bucket hardening: audit and (on request) fix the S3 settings that decide
// whether client documents are actually safe: no public access, ACLs off,
// default encryption, TLS-only policy, browser CORS for uploads only from our
// portal, lifecycle cleanup of unverified uploads, versioning.
import {
  GetPublicAccessBlockCommand, PutPublicAccessBlockCommand, GetBucketOwnershipControlsCommand, PutBucketOwnershipControlsCommand,
  GetBucketEncryptionCommand, PutBucketEncryptionCommand, GetBucketPolicyCommand, PutBucketPolicyCommand,
  GetBucketCorsCommand, PutBucketCorsCommand, GetBucketLifecycleConfigurationCommand, PutBucketLifecycleConfigurationCommand,
  GetBucketVersioningCommand, PutBucketVersioningCommand, HeadBucketCommand,
} from '@aws-sdk/client-s3';

const CORS_ID = 's3proxy-uploads';
const LIFECYCLE_PENDING = 's3proxy-expire-unverified';
const LIFECYCLE_MULTIPART = 's3proxy-abort-multipart';
const TLS_SID = 'S3ProxyDenyInsecureTransport';

const code = (err) => err?.name || err?.Code || '';
async function tryGet(client, cmd, missing) {
  try { return await client.send(cmd); } catch (err) {
    if (missing.includes(code(err)) || err?.$metadata?.httpStatusCode === 404) return null;
    throw err;
  }
}

export function corsRule(origins) {
  return {
    ID: CORS_ID,
    AllowedOrigins: origins,
    AllowedMethods: ['POST', 'PUT'],
    AllowedHeaders: ['content-type', 'x-amz-server-side-encryption', 'x-amz-server-side-encryption-aws-kms-key-id',
      'x-amz-server-side-encryption-bucket-key-enabled', 'x-amz-tagging'],
    ExposeHeaders: ['ETag'],
    MaxAgeSeconds: 3000,
  };
}

export function lifecycleRules(prefix, pendingDays) {
  return [
    {
      ID: LIFECYCLE_PENDING,
      Status: 'Enabled',
      Filter: { And: { Prefix: prefix ? `${prefix}/` : '', Tags: [{ Key: 'scan', Value: 'pending' }] } },
      Expiration: { Days: pendingDays },
      NoncurrentVersionExpiration: { NoncurrentDays: 1 },
    },
    {
      ID: LIFECYCLE_MULTIPART,
      Status: 'Enabled',
      Filter: { Prefix: prefix ? `${prefix}/` : '' },
      AbortIncompleteMultipartUpload: { DaysAfterInitiation: 1 },
    },
  ];
}

export function tlsStatement(bucket) {
  return {
    Sid: TLS_SID,
    Effect: 'Deny',
    Principal: '*',
    Action: 's3:*',
    Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
    Condition: { Bool: { 'aws:SecureTransport': 'false' } },
  };
}

/**
 * Inspect the bucket. Read-only.
 * @param {import('@aws-sdk/client-s3').S3Client} client
 * @param {{ bucket: string, sse: string, kmsKeyId?: string, prefix?: string, origins: string[] }} o
 */
export async function checkBucket(client, o) {
  /** @type {{ id: string, ok: boolean, level: 'critical'|'high'|'medium'|'low', title: string, detail: string, fix?: string }[]} */
  const results = [];
  const add = (id, ok, level, title, detail, fix) => results.push({ id, ok, level, title, detail, fix: ok ? undefined : fix });

  await client.send(new HeadBucketCommand({ Bucket: o.bucket }));

  const pab = await tryGet(client, new GetPublicAccessBlockCommand({ Bucket: o.bucket }), ['NoSuchPublicAccessBlockConfiguration']);
  const c = pab?.PublicAccessBlockConfiguration;
  const allBlocked = Boolean(c && c.BlockPublicAcls && c.IgnorePublicAcls && c.BlockPublicPolicy && c.RestrictPublicBuckets);
  add('public-access-block', allBlocked, 'critical', 'Block all public access',
    allBlocked ? 'All four settings are on.' : `Not fully blocked: ${JSON.stringify(c || 'not configured')}`,
    'Turn on all four Block Public Access settings.');

  const own = await tryGet(client, new GetBucketOwnershipControlsCommand({ Bucket: o.bucket }), ['OwnershipControlsNotFoundError']);
  const enforced = own?.OwnershipControls?.Rules?.[0]?.ObjectOwnership === 'BucketOwnerEnforced';
  add('acls-disabled', enforced, 'high', 'ACLs disabled (bucket owner enforced)',
    enforced ? 'Object ACLs cannot make single files public.' : 'Object ACLs are still active.', 'Set Object Ownership to BucketOwnerEnforced.');

  const enc = await tryGet(client, new GetBucketEncryptionCommand({ Bucket: o.bucket }), ['ServerSideEncryptionConfigurationNotFoundError']);
  const rule = enc?.ServerSideEncryptionConfiguration?.Rules?.[0];
  const algo = rule?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
  const encOk = o.sse === 'aws:kms' ? algo === 'aws:kms' || algo === 'aws:kms:dsse' : Boolean(algo);
  add('default-encryption', encOk, 'high', `Default encryption (${o.sse})`,
    algo ? `Default is ${algo}${rule?.BucketKeyEnabled ? ' with bucket key' : ''}.` : 'No default encryption rule.',
    `Set default encryption to ${o.sse}${o.kmsKeyId ? ` with key ${o.kmsKeyId}` : ''}.`);

  const pol = await tryGet(client, new GetBucketPolicyCommand({ Bucket: o.bucket }), ['NoSuchBucketPolicy']);
  let policy = null;
  try { policy = pol?.Policy ? JSON.parse(pol.Policy) : null; } catch { policy = null; }
  const statements = policy ? [].concat(policy.Statement || []) : [];
  const tls = statements.some((s) => s.Effect === 'Deny' && JSON.stringify(s.Condition || {}).includes('"aws:SecureTransport":"false"'));
  add('tls-only', tls, 'high', 'HTTPS only (deny aws:SecureTransport=false)',
    tls ? 'Plain HTTP requests are denied.' : 'Plain HTTP requests are not denied by policy.', 'Add a Deny statement for aws:SecureTransport=false.');
  const publicAllow = statements.some((s) => s.Effect === 'Allow' && (s.Principal === '*' || s.Principal?.AWS === '*') && !s.Condition);
  add('no-public-policy', !publicAllow, 'critical', 'No public Allow in bucket policy',
    publicAllow ? 'The bucket policy allows "*" without conditions.' : 'No unconditional public Allow statements.', 'Remove the public Allow statement.');

  const cors = await tryGet(client, new GetBucketCorsCommand({ Bucket: o.bucket }), ['NoSuchCORSConfiguration']);
  const rules = cors?.CORSRules || [];
  const ours = rules.find((r) => r.ID === CORS_ID) || rules.find((r) => (r.AllowedMethods || []).includes('POST'));
  const corsOk = Boolean(ours && o.origins.every((orig) => (ours.AllowedOrigins || []).includes(orig)));
  const wildcard = rules.some((r) => (r.AllowedOrigins || []).includes('*') && (r.AllowedMethods || []).some((m) => m !== 'GET' && m !== 'HEAD'));
  add('cors', corsOk && !wildcard, 'medium', 'Browser uploads allowed only from the portal',
    wildcard ? 'A CORS rule lets any website upload ("*").' : corsOk ? `POST/PUT allowed from ${o.origins.join(', ')}.` : 'Browser direct uploads will fail (no matching CORS rule); the portal falls back to the slower proxy.',
    `Add CORS rule for ${o.origins.join(', ')} (POST, PUT).`);

  const lc = await tryGet(client, new GetBucketLifecycleConfigurationCommand({ Bucket: o.bucket }), ['NoSuchLifecycleConfiguration']);
  const ids = (lc?.Rules || []).map((r) => r.ID);
  const lcOk = ids.includes(LIFECYCLE_PENDING) && ids.includes(LIFECYCLE_MULTIPART);
  add('lifecycle', lcOk, 'medium', 'Unverified uploads and broken multipart uploads expire',
    lcOk ? 'Cleanup rules present.' : 'Abandoned or rejected uploads would stay (and cost money) forever.', 'Add the s3proxy lifecycle rules.');

  const ver = await tryGet(client, new GetBucketVersioningCommand({ Bucket: o.bucket }), []);
  const versioned = ver?.Status === 'Enabled';
  add('versioning', versioned, 'low', 'Versioning (recovery from accidental delete/overwrite)',
    versioned ? 'Enabled.' : `Status: ${ver?.Status || 'never enabled'}.`, 'Enable versioning (run setup with --versioning).');

  const weights = { critical: 30, high: 20, medium: 10, low: 5 };
  const max = results.reduce((s, r) => s + weights[r.level], 0);
  const got = results.reduce((s, r) => s + (r.ok ? weights[r.level] : 0), 0);
  return { bucket: o.bucket, score: Math.round((got / max) * 100), results, current: { policy, corsRules: rules, lifecycleRules: lc?.Rules || [] } };
}

/**
 * Apply the fixes for failed checks. Merges with existing CORS rules,
 * lifecycle rules and bucket policy instead of replacing them.
 * @param {import('@aws-sdk/client-s3').S3Client} client
 * @param {{ bucket: string, sse: string, kmsKeyId?: string, prefix?: string, origins: string[], pendingDays?: number, versioning?: boolean, dryRun?: boolean }} o
 */
export async function setupBucket(client, o) {
  const report = await checkBucket(client, o);
  const failed = new Set(report.results.filter((r) => !r.ok).map((r) => r.id));
  /** @type {{ id: string, action: string }[]} */
  const plan = [];
  const run = async (id, action, fn) => {
    plan.push({ id, action });
    if (!o.dryRun) await fn();
  };
  const B = o.bucket;

  if (failed.has('public-access-block')) await run('public-access-block', 'Block all public access', () => client.send(new PutPublicAccessBlockCommand({
    Bucket: B, PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true },
  })));
  if (failed.has('acls-disabled')) await run('acls-disabled', 'Disable ACLs (BucketOwnerEnforced)', () => client.send(new PutBucketOwnershipControlsCommand({
    Bucket: B, OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] },
  })));
  if (failed.has('default-encryption')) await run('default-encryption', `Default encryption ${o.sse}`, () => client.send(new PutBucketEncryptionCommand({
    Bucket: B,
    ServerSideEncryptionConfiguration: {
      Rules: [{
        ApplyServerSideEncryptionByDefault: o.sse === 'aws:kms' ? { SSEAlgorithm: 'aws:kms', KMSMasterKeyID: o.kmsKeyId } : { SSEAlgorithm: 'AES256' },
        BucketKeyEnabled: o.sse === 'aws:kms',
      }],
    },
  })));
  if (failed.has('tls-only')) await run('tls-only', 'Add HTTPS-only bucket policy statement', () => {
    const policy = report.current.policy || { Version: '2012-10-17', Statement: [] };
    policy.Statement = [].concat(policy.Statement || []).filter((s) => s.Sid !== TLS_SID).concat(tlsStatement(B));
    return client.send(new PutBucketPolicyCommand({ Bucket: B, Policy: JSON.stringify(policy) }));
  });
  if (failed.has('cors')) await run('cors', `CORS: POST/PUT from ${o.origins.join(', ')}`, () => {
    const keep = report.current.corsRules.filter((r) => r.ID !== CORS_ID && !((r.AllowedOrigins || []).includes('*') && (r.AllowedMethods || []).some((m) => m !== 'GET' && m !== 'HEAD')));
    return client.send(new PutBucketCorsCommand({ Bucket: B, CORSConfiguration: { CORSRules: [...keep, corsRule(o.origins)] } }));
  });
  if (failed.has('lifecycle')) await run('lifecycle', `Lifecycle: expire unverified uploads after ${o.pendingDays || 2} day(s), abort multipart after 1 day`, () => {
    const keep = report.current.lifecycleRules.filter((r) => r.ID !== LIFECYCLE_PENDING && r.ID !== LIFECYCLE_MULTIPART);
    return client.send(new PutBucketLifecycleConfigurationCommand({
      Bucket: B, LifecycleConfiguration: { Rules: [...keep, ...lifecycleRules(o.prefix, o.pendingDays || 2)] },
    }));
  });
  if (failed.has('versioning') && o.versioning) await run('versioning', 'Enable versioning', () => client.send(new PutBucketVersioningCommand({
    Bucket: B, VersioningConfiguration: { Status: 'Enabled' },
  })));
  return { plan, before: report.score, dryRun: Boolean(o.dryRun) };
}

/**
 * Least-privilege IAM policy for the proxy's runtime role. Pre-signed URLs
 * carry the signer's permissions, so this is also the ceiling for every URL.
 * @param {{ bucket: string, prefix?: string, sse: string, kmsKeyArn?: string, admin?: boolean }} o
 */
export function iamPolicy(o) {
  const objects = `arn:aws:s3:::${o.bucket}/${o.prefix ? `${o.prefix}/` : ''}*`;
  const statements = [
    {
      Sid: 'UploadProxyObjects',
      Effect: 'Allow',
      Action: ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:PutObjectTagging', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts'],
      Resource: objects,
    },
    // No "deny unless x-amz-server-side-encryption" statement on purpose: multipart
    // UploadPart requests never carry that header, so it would break large uploads.
    // Encryption is enforced by signed headers/POST policy + bucket default encryption.
  ];
  if (o.sse === 'aws:kms') {
    statements.push({
      Sid: 'UseUploadKmsKey',
      Effect: 'Allow',
      Action: ['kms:GenerateDataKey', 'kms:Decrypt'],
      Resource: o.kmsKeyArn || 'arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID',
    });
  }
  if (o.admin) {
    statements.push({
      Sid: 'BucketHardeningSetupOnly',
      Effect: 'Allow',
      Action: ['s3:GetBucketPublicAccessBlock', 's3:PutBucketPublicAccessBlock', 's3:GetBucketOwnershipControls', 's3:PutBucketOwnershipControls',
        's3:GetEncryptionConfiguration', 's3:PutEncryptionConfiguration', 's3:GetBucketPolicy', 's3:PutBucketPolicy', 's3:GetBucketCORS',
        's3:PutBucketCORS', 's3:GetLifecycleConfiguration', 's3:PutLifecycleConfiguration', 's3:GetBucketVersioning', 's3:PutBucketVersioning', 's3:ListBucket'],
      Resource: `arn:aws:s3:::${o.bucket}`,
    });
  }
  return { Version: '2012-10-17', Statement: statements };
}
