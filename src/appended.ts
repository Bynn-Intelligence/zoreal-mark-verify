import { jwsClaims, parseGeneralJws, verifyJwsSignature, x5cOf } from './jws.js';
import { OID, type TrustAnchors } from './roots.js';
import { confirmPairing, validateChain, ChainError } from './x509/chain.js';

/**
 * An appended event (withdrawal, co-signer count, report count, a tree head)
 * is a JWS in General JSON Serialization with an ES256 and an ML-DSA-65
 * signature under the record service key: a leaf pair under the Document
 * Signing CAs whose extended key usage carries the record service purpose.
 * Chain validity alone is not enough, because every holder has one.
 */
export async function verifyAppended<T extends { id?: string }>(
  jws: unknown,
  expectedId: string,
  anchors: TrustAnchors,
  asOf: Date,
): Promise<T> {
  const parsed = parseGeneralJws(jws);
  const es = parsed.signatures.find((s) => s.header.alg === 'ES256');
  const ml = parsed.signatures.find((s) => s.header.alg === 'ML-DSA-65');
  if (!es || !ml || parsed.signatures.length !== 2) throw new Error('appended event needs one ES256 and one ML-DSA-65 signature');
  const x5c = (s: typeof es): string[] => {
    const c = x5cOf(s);
    if (!c) throw new Error('appended event carries no x5c chain');
    return c;
  };
  const classical = await validateChain(x5c(es), { anchors: anchors.classical, rootCertificates: anchors.rootCertificates, asOf, family: 'classical' });
  const postQuantum = await validateChain(x5c(ml), { anchors: anchors.postQuantum, rootCertificates: anchors.rootCertificates, asOf, family: 'post_quantum' });
  confirmPairing(classical, postQuantum, { sameLeafKey: false });
  for (const leaf of [classical.leaf, postQuantum.leaf]) {
    if (!leaf.extendedKeyUsage?.includes(OID.ekuRecordService)) throw new ChainError(`${leaf.subject} is not the record service`);
  }
  if (!(await verifyJwsSignature(parsed, es, classical.leaf))) throw new Error('the ES256 signature on the appended event does not verify');
  if (!(await verifyJwsSignature(parsed, ml, postQuantum.leaf))) throw new Error('the ML-DSA-65 signature on the appended event does not verify');
  const claims = jwsClaims<T>(parsed);
  if (claims.id !== expectedId) throw new Error('appended event names a different record');
  return claims;
}
