/**
 * A minimal DER TLV reader, used for the one thing the schema library cannot
 * do reliably: slice the exact `tbsCertificate` bytes out of a certificate.
 * Re-serialising a parsed structure is deterministic for DER, but a verifier
 * that hashes what it re-encoded rather than what it was given has a
 * canonicalisation gap an attacker can stand in. Slicing the original bytes
 * has no such gap.
 */

export interface Tlv {
  tag: number;
  /** Offset of the first content byte. */
  start: number;
  /** Offset one past the last content byte. */
  end: number;
  /** Offset of the tag byte. */
  headerStart: number;
}

export function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset >= bytes.length) throw new Error('DER: unexpected end');
  const tag = bytes[offset]!;
  let i = offset + 1;
  let len = bytes[i++]!;
  if (len === undefined) throw new Error('DER: unexpected end');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: bad length');
    len = 0;
    for (let k = 0; k < n; k++) {
      const b = bytes[i++];
      if (b === undefined) throw new Error('DER: unexpected end');
      len = (len << 8) | b;
    }
  }
  if (i + len > bytes.length) throw new Error('DER: length exceeds input');
  return { tag, start: i, end: i + len, headerStart: offset };
}

/** The children of a constructed TLV, in order. */
export function children(bytes: Uint8Array, tlv: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let o = tlv.start;
  while (o < tlv.end) {
    const c = readTlv(bytes, o);
    out.push(c);
    o = c.end;
  }
  return out;
}

/** The bytes of a TLV including its header. */
export function slice(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  return bytes.subarray(tlv.headerStart, tlv.end);
}

/** The `tbsCertificate` bytes of a DER certificate, header included. */
export function tbsCertificateBytes(der: Uint8Array): Uint8Array {
  const outer = readTlv(der, 0);
  if (outer.tag !== 0x30) throw new Error('DER: certificate is not a SEQUENCE');
  const tbs = readTlv(der, outer.start);
  if (tbs.tag !== 0x30) throw new Error('DER: tbsCertificate is not a SEQUENCE');
  return slice(der, tbs);
}

/**
 * ECDSA signature conversion. Certificates and CMS carry DER `SEQUENCE { r, s }`;
 * Web Crypto and JOSE want fixed-width `r || s`. `width` is the field size in
 * bytes: 32 for P-256, 48 for P-384.
 */
export function ecdsaDerToRaw(der: Uint8Array, width: number): Uint8Array {
  const seq = readTlv(der, 0);
  if (seq.tag !== 0x30) throw new Error('ECDSA: signature is not a SEQUENCE');
  const [r, s] = children(der, seq);
  if (!r || !s || r.tag !== 0x02 || s.tag !== 0x02) throw new Error('ECDSA: bad signature');
  const out = new Uint8Array(width * 2);
  for (const [int, at] of [[r, 0], [s, width]] as const) {
    let v = der.subarray(int.start, int.end);
    while (v.length > width && v[0] === 0) v = v.subarray(1);
    if (v.length > width) throw new Error('ECDSA: integer wider than the field');
    out.set(v, at + width - v.length);
  }
  return out;
}

export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length % 2 !== 0) throw new Error('ECDSA: raw signature has odd length');
  const w = raw.length / 2;
  const int = (v: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    let body = v.subarray(i);
    if (body[0]! & 0x80) body = new Uint8Array([0, ...body]);
    return new Uint8Array([0x02, body.length, ...body]);
  };
  const r = int(raw.subarray(0, w));
  const s = int(raw.subarray(w));
  const len = r.length + s.length;
  const header = len < 128 ? [0x30, len] : [0x30, 0x81, len];
  return new Uint8Array([...header, ...r, ...s]);
}

/** Decodes a bare DER OBJECT IDENTIFIER (tag 0x06) to dotted form. */
export function decodeOid(der: Uint8Array): string {
  const tlv = readTlv(der, 0);
  if (tlv.tag !== 0x06) throw new Error('DER: not an OBJECT IDENTIFIER');
  const body = der.subarray(tlv.start, tlv.end);
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < body.length; i++) {
    v = v * 128 + (body[i]! & 0x7f);
    if ((body[i]! & 0x80) === 0) {
      if (parts.length === 0) {
        parts.push(Math.min(2, Math.floor(v / 40)), v - 40 * Math.min(2, Math.floor(v / 40)));
      } else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}
