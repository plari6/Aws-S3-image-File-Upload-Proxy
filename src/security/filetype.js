// @ts-check
// Detect the real file type from its first bytes ("magic numbers"), never from
// the file name or the browser's Content-Type, which a caller controls.
// A file named invoice.pdf that is really a Windows .exe is rejected.

/** Canonical type -> MIME type and accepted file extensions. */
export const TYPES = {
  jpg: { mime: 'image/jpeg', ext: ['jpg', 'jpeg'] },
  png: { mime: 'image/png', ext: ['png'] },
  gif: { mime: 'image/gif', ext: ['gif'] },
  webp: { mime: 'image/webp', ext: ['webp'] },
  heic: { mime: 'image/heic', ext: ['heic', 'heif'] },
  tiff: { mime: 'image/tiff', ext: ['tif', 'tiff'] },
  pdf: { mime: 'application/pdf', ext: ['pdf'] },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: ['docx'] },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ext: ['xlsx'] },
  pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ext: ['pptx'] },
  zip: { mime: 'application/zip', ext: ['zip'] },
  txt: { mime: 'text/plain', ext: ['txt'] },
  csv: { mime: 'text/csv', ext: ['csv'] },
  mp4: { mime: 'video/mp4', ext: ['mp4', 'm4v'] },
  mov: { mime: 'video/quicktime', ext: ['mov'] },
};

/** Types that are always refused, even if the allow list is misconfigured. */
const DANGEROUS = ['exe', 'elf', 'macho', 'html', 'svg', 'script', 'msi', 'jar'];

/** How many leading bytes detectType needs. */
export const SNIFF_BYTES = 4100;

const startsWith = (buf, bytes, offset = 0) =>
  buf.length >= offset + bytes.length && bytes.every((b, i) => buf[offset + i] === b);
const ascii = (buf, start, end) => buf.subarray(start, end).toString('latin1');

/**
 * Identify a file from its first bytes.
 * @param {Buffer} buf
 * @returns {string | null} canonical type, a dangerous marker, or null when unknown
 */
export function detectType(buf) {
  if (!buf || buf.length === 0) return null;
  // Executables and scripts first.
  if (startsWith(buf, [0x4d, 0x5a])) return 'exe'; // MZ (Windows PE / DLL)
  if (startsWith(buf, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if ([[0xcf, 0xfa, 0xed, 0xfe], [0xce, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe]].some((m) => startsWith(buf, m))) return 'macho';
  if (startsWith(buf, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'msi'; // OLE2: .msi, legacy .doc/.xls with macros
  if (startsWith(buf, [0x23, 0x21])) return 'script'; // #!

  if (startsWith(buf, [0xff, 0xd8, 0xff])) return 'jpg';
  if (startsWith(buf, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (ascii(buf, 0, 6) === 'GIF87a' || ascii(buf, 0, 6) === 'GIF89a') return 'gif';
  if (ascii(buf, 0, 4) === 'RIFF' && ascii(buf, 8, 12) === 'WEBP') return 'webp';
  if (startsWith(buf, [0x49, 0x49, 0x2a, 0x00]) || startsWith(buf, [0x4d, 0x4d, 0x00, 0x2a])) return 'tiff';
  if (ascii(buf, 4, 8) === 'ftyp') {
    const brand = ascii(buf, 8, 12);
    if (['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1', 'heim', 'heis'].includes(brand)) return 'heic';
    if (brand === 'qt  ') return 'mov';
    return 'mp4';
  }
  // PDF header may follow a few junk bytes (spec allows up to 1024).
  const head = ascii(buf, 0, Math.min(buf.length, 1024));
  if (head.indexOf('%PDF-') !== -1) return 'pdf';
  if (startsWith(buf, [0x50, 0x4b, 0x03, 0x04])) return detectZip(buf);

  // Text: refuse anything that looks like markup a browser would execute.
  if (looksLikeText(buf)) {
    const text = buf.toString('utf8').replace(/^﻿/, '').trimStart().slice(0, 1024).toLowerCase();
    if (/^<(\?xml[^>]*>\s*)?(<!doctype\s+)?svg|<svg[\s>]/.test(text)) return 'svg';
    if (/^<(!doctype\s+html|html|head|body|script|iframe)|<script[\s>]/.test(text)) return 'html';
    const firstLine = text.split(/\r?\n/, 1)[0];
    return firstLine.includes(',') || firstLine.includes(';') ? 'csv' : 'txt';
  }
  return null;
}

/** OOXML files are zips whose first entry names reveal the document kind. */
function detectZip(buf) {
  const names = ascii(buf, 0, buf.length);
  if (names.includes('word/')) return 'docx';
  if (names.includes('xl/')) return 'xlsx';
  if (names.includes('ppt/')) return 'pptx';
  if (names.includes('[Content_Types].xml')) {
    // Content types listed first; the part folders may be outside the sniffed window.
    if (names.includes('wordprocessingml')) return 'docx';
    if (names.includes('spreadsheetml')) return 'xlsx';
    if (names.includes('presentationml')) return 'pptx';
  }
  if (/\.(exe|dll|scr|bat|cmd|js|vbs|ps1|msi|jar|lnk)\b/i.test(names)) return 'exe'; // zip carrying executables
  return 'zip';
}

function looksLikeText(buf) {
  const sample = buf.subarray(0, Math.min(buf.length, 1024));
  let control = 0;
  for (const b of sample) {
    if (b === 0) return false;
    if (b < 0x09 || (b > 0x0d && b < 0x20)) control++;
  }
  return control / sample.length < 0.02;
}

/** Normalise a type or extension name ("jpeg" -> "jpg"). */
export function canonicalType(name) {
  const n = String(name || '').toLowerCase().replace(/^\./, '');
  for (const [type, info] of Object.entries(TYPES)) if (type === n || info.ext.includes(n)) return type;
  return n;
}

export function mimeFor(type) {
  return TYPES[type]?.mime || 'application/octet-stream';
}

/** Canonical type implied by a MIME type, or null. */
export function typeFromMime(mime) {
  const m = String(mime || '').toLowerCase().split(';')[0].trim();
  if (m === 'image/jpg' || m === 'image/pjpeg') return 'jpg';
  if (m === 'image/heif') return 'heic';
  for (const [type, info] of Object.entries(TYPES)) if (info.mime === m) return type;
  return null;
}

/** Type implied by a file name's extension, or null. */
export function typeFromName(filename) {
  const m = String(filename || '').toLowerCase().match(/\.([a-z0-9]{1,8})$/);
  if (!m) return null;
  for (const [type, info] of Object.entries(TYPES)) if (info.ext.includes(m[1])) return type;
  return m[1];
}

/**
 * Decide whether a sniffed file may be stored.
 * @param {{ detected: string | null, filename?: string, allowedTypes: string[] }} input
 * @returns {{ ok: true, type: string, mime: string } | { ok: false, reason: string }}
 */
export function checkFileType({ detected, filename, allowedTypes }) {
  if (!detected) return { ok: false, reason: 'unknown file type (content not recognised)' };
  if (DANGEROUS.includes(detected)) return { ok: false, reason: `dangerous content detected (${detected})` };
  const allowed = allowedTypes.map(canonicalType);
  if (!allowed.includes(detected)) return { ok: false, reason: `file type "${detected}" is not allowed` };
  const byName = filename ? typeFromName(filename) : null;
  // csv/txt are interchangeable text; everything else must match its extension.
  const textPair = ['csv', 'txt'].includes(detected) && ['csv', 'txt'].includes(byName || '');
  if (byName && byName !== detected && !textPair) {
    return { ok: false, reason: `file extension ".${byName}" does not match its content (${detected})` };
  }
  return { ok: true, type: detected, mime: mimeFor(detected) };
}
