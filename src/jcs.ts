import canonicalize from 'canonicalize';
import { sha256, utf8 } from './bytes.js';

/** RFC 8785 JSON Canonicalization Scheme bytes of a value. */
export function jcs(value: unknown): Uint8Array {
  const s = canonicalize(value);
  if (typeof s !== 'string') throw new Error('value is not canonicalisable JSON');
  return utf8(s);
}

/** SHA-256 over the JCS bytes: `H(payload)`, and the record core hash. */
export async function jcsHash(value: unknown): Promise<Uint8Array> {
  return sha256(jcs(value));
}
