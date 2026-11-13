// @ts-check
// Minimal ClamAV (clamd) client using the INSTREAM command over TCP.
// Point CLAMAV_HOST at a clamd container (e.g. clamav/clamav image, port 3310).
import net from 'node:net';

/**
 * Stream data to clamd and return the verdict.
 * @param {AsyncIterable<Buffer> | NodeJS.ReadableStream} source
 * @param {{ host: string, port?: number, timeoutMs?: number }} opts
 * @returns {Promise<{ clean: boolean, signature?: string, raw: string }>}
 */
export function clamScan(source, { host, port = 3310, timeoutMs = 60000 }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    let reply = '';
    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      err ? reject(err) : resolve(value);
    };
    socket.setTimeout(timeoutMs, () => finish(new Error(`ClamAV timed out after ${timeoutMs} ms`)));
    socket.on('error', (err) => finish(new Error(`ClamAV unreachable at ${host}:${port}: ${err.message}`)));
    socket.on('data', (d) => { reply += d.toString('utf8'); });
    socket.on('end', () => {
      const raw = reply.replace(/\0/g, '').trim();
      if (/:\s*OK$/.test(raw)) return finish(null, { clean: true, raw });
      const found = raw.match(/:\s*(.+)\s+FOUND$/);
      if (found) return finish(null, { clean: false, signature: found[1], raw });
      finish(new Error(`ClamAV error: ${raw || 'empty reply'}`));
    });
    socket.on('connect', async () => {
      try {
        socket.write('zINSTREAM\0');
        for await (const chunk of /** @type {AsyncIterable<Buffer>} */ (source)) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          for (let i = 0; i < buf.length; i += 64 * 1024) {
            const part = buf.subarray(i, i + 64 * 1024);
            const len = Buffer.alloc(4);
            len.writeUInt32BE(part.length);
            if (!socket.write(Buffer.concat([len, part]))) await new Promise((r) => socket.once('drain', r));
          }
        }
        socket.end(Buffer.alloc(4)); // zero-length chunk = end of stream
      } catch (err) {
        finish(err);
      }
    });
  });
}

/** PING/PONG health check. */
export function clamPing({ host, port = 3310, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let reply = '';
    socket.setTimeout(timeoutMs, () => { socket.destroy(); resolve(false); });
    socket.on('error', () => resolve(false));
    socket.on('connect', () => socket.write('zPING\0'));
    socket.on('data', (d) => { reply += d.toString(); });
    socket.on('close', () => resolve(reply.includes('PONG')));
  });
}
