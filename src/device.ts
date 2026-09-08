import { concat, equal, fromBase64Url, sha256, toBase64Url, utf8 } from './bytes.js';
import { jcsHash } from './jcs.js';
import type { Payload } from './types.js';
import type { ParsedCert } from './x509/cert.js';
import { verifyEcdsa } from './x509/verify.js';

/**
 * The device signature: ECDSA P-256 with SHA-256 over
 * `SHA-256(JCS(payload)) || UTF-8(order) || UTF-8(aud)`, raw r||s.
 * Also confirms `payload.cert` names the leaf the signature is checked under,
 * which is what binds the signature to one exact certificate.
 */
export async function verifyDeviceSignature(payload: Payload, signatureB64: string, leaf: ParsedCert): Promise<Uint8Array> {
  if (leaf.key.kind !== 'ec' || leaf.key.curve !== 'P-256') throw new Error('the holder certificate is not a P-256 key');
  const expectedCert = toBase64Url(await sha256(leaf.der));
  if (payload.cert !== expectedCert) throw new Error('payload.cert does not name the certificate presented');
  const sig = fromBase64Url(signatureB64);
  if (sig.length !== 64) throw new Error(`device signature is ${sig.length} bytes, not 64`);
  const message = concat(await jcsHash(payload), utf8(payload.order), utf8(payload.aud));
  if (!(await verifyEcdsa(leaf.spkiDer, leaf.key, 'SHA-256', message, sig))) throw new Error('the device signature does not verify');
  if (!equal(await sha256(leaf.der), fromBase64Url(payload.cert))) throw new Error('payload.cert mismatch');
  return sig;
}
