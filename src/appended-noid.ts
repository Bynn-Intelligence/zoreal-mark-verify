import { jwsClaims, parseGeneralJws, verifyJwsSignature, x5cOf } from './jws.js';
import { OID, type TrustAnchors } from './roots.js';
import { ChainError, confirmPairing, validateChain } from './x509/chain.js';

/** A signed tree head: the same signer as an appended event, but it names no record. */
export async function verifyAppendedNoId<T>(jws: unknown, anchors: TrustAnchors, asOf: Date): Promise<T> {
  const parsed = parseGeneralJws(jws);
  const es = parsed.signatures.find((s) => s.header.alg === 'ES256');
  const ml = parsed.signatures.find((s) => s.header.alg === 'ML-DSA-65');
  if (!es || !ml || parsed.signatures.length !== 2) throw new Error('tree head needs one ES256 and one ML-DSA-65 signature');
  const x5c = (s: typeof es): string[] => {
    const c = x5cOf(s);
    if (!c) throw new Error('tree head carries no x5c chain');
    return c;
  };
  const classical = await validateChain(x5c(es), { anchors: anchors.classical, rootCertificates: anchors.rootCertificates, asOf, family: 'classical' });
  const postQuantum = await validateChain(x5c(ml), { anchors: anchors.postQuantum, rootCertificates: anchors.rootCertificates, asOf, family: 'post_quantum' });
  confirmPairing(classical, postQuantum, { sameLeafKey: false });
  for (const leaf of [classical.leaf, postQuantum.leaf]) {
    if (!leaf.extendedKeyUsage?.includes(OID.ekuRecordService)) throw new ChainError(`${leaf.subject} is not the record service`);
  }
  if (!(await verifyJwsSignature(parsed, es, classical.leaf))) throw new Error('the ES256 signature on the tree head does not verify');
  if (!(await verifyJwsSignature(parsed, ml, postQuantum.leaf))) throw new Error('the ML-DSA-65 signature on the tree head does not verify');
  return jwsClaims<T>(parsed);
}
