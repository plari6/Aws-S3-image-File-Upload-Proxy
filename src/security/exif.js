// @ts-check
// Remove GPS location from JPEG photos while they stream through the proxy.
// Phone photos of IDs, contracts or a house embed the exact place they were
// taken. We blank the EXIF GPS block and drop XMP/Photoshop blocks (which can
// repeat the location), but keep the rest of EXIF so orientation still works.
// No image re-encoding: the picture's pixels are untouched.
import { Transform } from 'node:stream';

const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };
const GPS_TAG = 0x8825;
const MAX_HEADER = 2 * 1024 * 1024; // metadata larger than this is passed through untouched

/**
 * Blank the GPS IFD inside a TIFF/EXIF block, in place.
 * @param {Buffer} tiff
 * @returns {number} number of GPS entries removed
 */
export function scrubExifGps(tiff) {
  if (tiff.length < 8) return 0;
  const order = tiff.toString('latin1', 0, 2);
  if (order !== 'II' && order !== 'MM') return 0;
  const le = order === 'II';
  const u16 = (o) => (le ? tiff.readUInt16LE(o) : tiff.readUInt16BE(o));
  const u32 = (o) => (le ? tiff.readUInt32LE(o) : tiff.readUInt32BE(o));
  const in_ = (o, n) => o >= 0 && o + n <= tiff.length;
  if (u16(2) !== 0x2a) return 0;
  const ifd0 = u32(4);
  if (!in_(ifd0, 2)) return 0;
  const n0 = u16(ifd0);
  let gpsOffset = -1;
  for (let i = 0; i < n0; i++) {
    const e = ifd0 + 2 + i * 12;
    if (!in_(e, 12)) break;
    if (u16(e) === GPS_TAG) gpsOffset = u32(e + 8);
  }
  if (gpsOffset < 0 || !in_(gpsOffset, 2)) return 0;
  const n = u16(gpsOffset);
  let removed = 0;
  for (let i = 0; i < n; i++) {
    const e = gpsOffset + 2 + i * 12;
    if (!in_(e, 12)) break;
    const size = (TYPE_SIZE[u16(e + 2)] || 1) * u32(e + 4);
    if (size > 4) {
      const off = u32(e + 8);
      if (in_(off, size)) tiff.fill(0, off, off + size); // out-of-line value (coordinates)
    }
    tiff.fill(0, e, e + 12);
    removed++;
  }
  tiff.fill(0, gpsOffset, gpsOffset + 2); // entry count = 0
  return removed;
}

/**
 * Rewrite a JPEG header (everything before the first SOS marker).
 * @param {Buffer} buf JPEG bytes containing at least the full header
 * @returns {{ done: boolean, out?: Buffer, removedTags: number, droppedSegments: number }}
 *   done=false means more bytes are needed to reach the image data.
 */
export function stripJpegHeader(buf) {
  const parts = [buf.subarray(0, 2)];
  let i = 2;
  let removedTags = 0;
  let droppedSegments = 0;
  while (true) {
    if (i + 4 > buf.length) return { done: false, removedTags, droppedSegments };
    if (buf[i] !== 0xff) return { done: true, out: buf, removedTags: 0, droppedSegments: 0 }; // malformed: leave as is
    const marker = buf[i + 1];
    if (marker === 0xff) { i++; continue; } // fill byte
    if (marker === 0xda || marker === 0xd9) break; // start of scan / end of image
    if (marker >= 0xd0 && marker <= 0xd7) { parts.push(buf.subarray(i, i + 2)); i += 2; continue; }
    const len = buf.readUInt16BE(i + 2);
    if (i + 2 + len > buf.length) return { done: false, removedTags, droppedSegments };
    const seg = Buffer.from(buf.subarray(i, i + 2 + len)); // copy: we may modify it
    if (marker === 0xe1 && seg.toString('latin1', 4, 10) === 'Exif\0\0') {
      removedTags += scrubExifGps(seg.subarray(10));
      parts.push(seg);
    } else if (marker === 0xe1 || marker === 0xed) {
      droppedSegments++; // XMP (APP1) or Photoshop/IPTC (APP13): may hold location
    } else {
      parts.push(seg);
    }
    i += 2 + len;
  }
  parts.push(buf.subarray(i));
  return { done: true, out: Buffer.concat(parts), removedTags, droppedSegments };
}

/** Transform stream: strips GPS from JPEGs, passes every other file through unchanged. */
export class GpsStripper extends Transform {
  constructor() {
    super();
    /** @type {Buffer[]} */
    this.pending = [];
    this.pendingBytes = 0;
    this.passthrough = false;
    this.stats = { removedTags: 0, droppedSegments: 0, stripped: false };
  }

  _transform(chunk, _enc, cb) {
    if (this.passthrough) return cb(null, chunk);
    this.pending.push(chunk);
    this.pendingBytes += chunk.length;
    const buf = Buffer.concat(this.pending);
    if (buf.length >= 2 && !(buf[0] === 0xff && buf[1] === 0xd8)) return this.#release(buf, cb);
    if (buf.length < 4) return cb();
    const res = stripJpegHeader(buf);
    if (res.done) {
      this.stats = { removedTags: res.removedTags, droppedSegments: res.droppedSegments, stripped: res.removedTags + res.droppedSegments > 0 };
      return this.#release(res.out || buf, cb);
    }
    if (this.pendingBytes > MAX_HEADER) return this.#release(buf, cb);
    cb();
  }

  _flush(cb) {
    if (!this.passthrough && this.pending.length) {
      const buf = Buffer.concat(this.pending);
      const res = buf[0] === 0xff && buf[1] === 0xd8 ? stripJpegHeader(buf) : { done: false };
      this.push(res.done && res.out ? res.out : buf);
    }
    cb();
  }

  #release(buf, cb) {
    this.passthrough = true;
    this.pending = [];
    cb(null, buf);
  }
}
