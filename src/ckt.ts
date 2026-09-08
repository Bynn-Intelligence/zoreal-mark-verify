import { concat, sha256, toBase64Url } from './bytes.js';
import { readTlv, children } from './x509/der.js';

/**
 * RFC 9679 COSE Key Thumbprint of a P-256 key: SHA-256 over the deterministic
 * CBOR encoding of the EC2 key with exactly `kty`, `crv`, `x` and `y`, keys
 * in bytewise order of their encodings (1, -1, -2, -3). Written out by hand
 * because the structure is fixed and forty bytes of CBOR do not justify a
 * decoder dependency.
 */
export async function coseKeyThumbprintP256(spkiDer: Uint8Array): Promise<string> {
  const { x, y } = uncompressedPointFromSpki(spkiDer, 32);
  const cbor = concat(
    new Uint8Array([0xa4]), // map(4)
    new Uint8Array([0x01, 0x02]), // 1: 2 (kty: EC2)
    new Uint8Array([0x20, 0x01]), // -1: 1 (crv: P-256)
    new Uint8Array([0x21, 0x58, 0x20]), x, // -2: bytes(32)
    new Uint8Array([0x22, 0x58, 0x20]), y, // -3: bytes(32)
  );
  return toBase64Url(await sha256(cbor));
}

/** The x and y coordinates of the uncompressed point inside a SubjectPublicKeyInfo. */
export function uncompressedPointFromSpki(spkiDer: Uint8Array, width: number): { x: Uint8Array; y: Uint8Array } {
  const seq = readTlv(spkiDer, 0);
  const [, bitString] = children(spkiDer, seq);
  if (!bitString || bitString.tag !== 0x03) throw new Error('SPKI: no BIT STRING');
  // First content byte of a BIT STRING is the unused-bits count, then 0x04 || x || y.
  const point = spkiDer.subarray(bitString.start + 1, bitString.end);
  if (point.length !== 1 + width * 2 || point[0] !== 0x04) throw new Error('SPKI: not an uncompressed EC point');
  return { x: point.subarray(1, 1 + width), y: point.subarray(1 + width) };
}
