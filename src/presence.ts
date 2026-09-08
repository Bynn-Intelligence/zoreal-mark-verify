import { equal, fromBase64Url, sha256, toBase64Url } from './bytes.js';
import { coseKeyThumbprintP256 } from './ckt.js';
import { jwsClaims, parseGeneralJws, verifyJwsSignature, x5cOf } from './jws.js';
import { OID, type TrustAnchors } from './roots.js';
import type { Grade, PresenceClaims } from './types.js';
import type { ParsedCert } from './x509/cert.js';
import { ChainError, confirmPairing, validateChain, type ValidatedChain } from './x509/chain.js';

export const MARK_AUDIENCE = 'https://zoreal.com/mark';

export interface PresenceOptions {
  anchors: TrustAnchors;
  /** The instant the attestation is judged at: gen_time when confirmed, now when pending. */
  asOf: Date;
  /** The holder's classical leaf, which `sub` and `cnf.ckt` must match. */
  holderLeaf: ParsedCert;
  /** The 64 device signature bytes, which `countersig_over` must hash to. */
  deviceSignature: Uint8Array;
  /** The sign order, which `nonce` must equal. */
  order: string;
  audience: string;
  /** Which grades this record may carry. */
  allowedGrades: Grade[];
}

export interface PresenceResult {
  claims: PresenceClaims;
  signer: { classical: ValidatedChain; postQuantum: ValidatedChain };
}

/**
 * Validates a presence attestation: two signatures, ES256 and ML-DSA-65, each
 * under its own chain to its pinned root, the two chains a pair, both leaves
 * carrying the presence-signing extended key usage; then every binding claim.
 *
 * The claim checks are the ones an implementer in a hurry skips, and each one
 * individually collapses the design into a bearer token: aud and nonce (replay
 * to another transaction), exp (holding a captured attestation), cnf.ckt
 * (presenting it beside a different device key), countersig_over (detaching it
 * from the signature it authorised), grade and channel (a weaker session
 * consumed as a stronger one).
 */
export async function verifyPresence(presence: unknown, opts: PresenceOptions): Promise<PresenceResult> {
  const jws = parseGeneralJws(presence);
  if (jws.signatures.length !== 2) throw new Error(`presence attestation carries ${jws.signatures.length} signatures, not two`);
  const es = jws.signatures.find((s) => s.header.alg === 'ES256');
  const ml = jws.signatures.find((s) => s.header.alg === 'ML-DSA-65');
  if (!es || !ml) throw new Error('presence attestation needs one ES256 and one ML-DSA-65 signature');

  const classical = await chainFromHeader(x5cOf(es), {
    anchors: opts.anchors.classical, rootCertificates: opts.anchors.rootCertificates, asOf: opts.asOf, family: 'classical',
  });
  const postQuantum = await chainFromHeader(x5cOf(ml), {
    anchors: opts.anchors.postQuantum, rootCertificates: opts.anchors.rootCertificates, asOf: opts.asOf, family: 'post_quantum',
  });
  confirmPairing(classical, postQuantum, { sameLeafKey: false });
  for (const leaf of [classical.leaf, postQuantum.leaf]) {
    if (!leaf.extendedKeyUsage?.includes(OID.ekuPresenceSigning)) {
      throw new ChainError(`${leaf.subject} is not a presence signer`);
    }
    if (leaf.keyUsage && !leaf.keyUsage.digitalSignature) throw new ChainError(`${leaf.subject} cannot sign`);
  }
  for (const s of [es, ml]) {
    if (s.header.typ !== undefined && s.header.typ !== 'presence+jwt') throw new Error(`presence attestation has typ ${s.header.typ}`);
  }
  if (!(await verifyJwsSignature(jws, es, classical.leaf))) throw new Error('the ES256 presence signature does not verify');
  if (!(await verifyJwsSignature(jws, ml, postQuantum.leaf))) throw new Error('the ML-DSA-65 presence signature does not verify');

  const claims = jwsClaims<PresenceClaims>(jws);
  const t = opts.asOf.getTime() / 1000;
  if (claims.aud !== opts.audience) throw new Error(`presence aud is ${claims.aud}, expected ${opts.audience}`);
  if (claims.zoreal?.nonce !== opts.order) throw new Error('presence nonce does not match the sign order');
  if (typeof claims.exp !== 'number' || !(claims.exp > t)) throw new Error('presence attestation had expired at the time judged');
  if (typeof claims.iat !== 'number' || claims.iat > t + 60) throw new Error('presence attestation is dated after the time judged');
  if (typeof claims.cti !== 'string' || claims.cti.length === 0) throw new Error('presence attestation has no cti');
  const expectedSub = toBase64Url(await sha256(opts.holderLeaf.der));
  if (claims.sub !== expectedSub) throw new Error('presence sub is not the holder certificate');
  const ckt = await coseKeyThumbprintP256(opts.holderLeaf.spkiDer);
  if (claims.cnf?.ckt !== ckt) throw new Error('presence cnf.ckt does not match the device key');
  const over = toBase64Url(await sha256(opts.deviceSignature));
  if (claims.zoreal?.countersig_over !== over) throw new Error('presence countersig_over is not the SHA-256 of the device signature');
  if (claims.zoreal?.verdict !== 'pass') throw new Error(`presence verdict is ${claims.zoreal?.verdict}`);
  if (claims.zoreal?.channel !== 'native_attested') throw new Error(`presence channel is ${claims.zoreal?.channel}`);
  if (!opts.allowedGrades.includes(claims.zoreal?.grade)) throw new Error(`presence grade is ${claims.zoreal?.grade}`);
  if (!equal(fromBase64Url(claims.sub), await sha256(opts.holderLeaf.der))) throw new Error('presence sub mismatch');
  return { claims, signer: { classical, postQuantum } };
}

async function chainFromHeader(x5c: unknown, opts: Parameters<typeof validateChain>[1]): Promise<ValidatedChain> {
  if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((c) => typeof c === 'string')) {
    throw new Error('presence signature carries no x5c chain');
  }
  return validateChain(x5c as string[], opts);
}
