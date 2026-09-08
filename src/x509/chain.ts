import { equal } from '../bytes.js';
import { OID } from '../roots.js';
import { parseCertificate, parseCertificateText, type ParsedCert } from './cert.js';
import { verifySignature } from './verify.js';

export type Family = 'classical' | 'post_quantum';

export interface ChainOptions {
  /** SPKI SHA-256 digests (base64) of the roots this family may end at. */
  anchors: string[];
  /** Root certificates (PEM or base64 DER) used to complete a chain whose last certificate is not a root. */
  rootCertificates?: string[];
  /** The instant validity is judged at. */
  asOf: Date;
  family: Family;
}

export interface ValidatedChain {
  certs: ParsedCert[];
  leaf: ParsedCert;
  issuer: ParsedCert;
  root: ParsedCert;
}

export class ChainError extends Error {}

/**
 * Validates a chain, leaf first, to a pinned root, failing closed.
 *
 * Every certificate's validity is judged as of `asOf`; every issuer must be a
 * CA with keyCertSign whose subject is the child's issuer and whose key verifies
 * the child's signature; every critical extension must be one this verifier
 * understands; the last certificate must be self-signed and its
 * SubjectPublicKeyInfo digest must be one of the anchors. A chain that ends
 * before a root is completed from `rootCertificates` when one of them matches
 * the last issuer; a chain that ends at a root the verifier does not pin is
 * rejected whatever that root says about itself.
 */
export async function validateChain(input: (Uint8Array | string)[], opts: ChainOptions): Promise<ValidatedChain> {
  if (input.length < 2) throw new ChainError('chain has fewer than two certificates');
  const certs: ParsedCert[] = [];
  for (const c of input) certs.push(typeof c === 'string' ? await parseCertificateText(c) : await parseCertificate(c));

  const last = certs[certs.length - 1]!;
  if (!equal(last.subjectDer, last.issuerDer)) {
    let completed = false;
    for (const pem of opts.rootCertificates ?? []) {
      const root = await parseCertificateText(pem);
      if (equal(root.subjectDer, last.issuerDer)) {
        certs.push(root);
        completed = true;
        break;
      }
    }
    if (!completed) throw new ChainError(`chain does not end at a root: last issuer is ${last.issuer}`);
  }

  const root = certs[certs.length - 1]!;
  if (!opts.anchors.includes(root.spkiSha256)) {
    throw new ChainError(`root ${root.subject} is not a pinned ${opts.family} anchor`);
  }
  expectFamily(root, opts.family);

  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i]!;
    if (cert.unknownCritical.length > 0) {
      throw new ChainError(`${cert.subject} carries unrecognised critical extension ${cert.unknownCritical.join(', ')}`);
    }
    if (opts.asOf < cert.notBefore || opts.asOf > cert.notAfter) {
      throw new ChainError(`${cert.subject} is not valid at ${opts.asOf.toISOString()}`);
    }
    const signer = i === certs.length - 1 ? cert : certs[i + 1]!;
    if (!equal(cert.issuerDer, signer.subjectDer)) {
      throw new ChainError(`${cert.subject} is not issued by ${signer.subject}`);
    }
    if (i < certs.length - 1 || true) {
      if (!signer.isCa) throw new ChainError(`${signer.subject} is not a CA`);
      if (signer.keyUsage && !signer.keyUsage.keyCertSign) throw new ChainError(`${signer.subject} cannot sign certificates`);
    }
    if (signer.pathLen !== undefined && i > 0) {
      // The signer may have at most pathLen CAs below it. Below `signer` sit certs[0..i];
      // certs[0] is the leaf, so the CAs below are i - 1.
      const casBelow = i - 1;
      if (casBelow > signer.pathLen) throw new ChainError(`${signer.subject} path length exceeded`);
    }
    if (i > 0 && !cert.isCa) throw new ChainError(`${cert.subject} sits above a leaf but is not a CA`);
    const ok = await verifySignature(signer, cert.signatureAlgorithm, cert.tbs, cert.signatureValue, true);
    if (!ok) throw new ChainError(`signature on ${cert.subject} does not verify under ${signer.subject}`);
  }

  const leaf = certs[0]!;
  if (leaf.isCa) throw new ChainError('the leaf is a CA certificate');
  return { certs, leaf, issuer: certs[1]!, root };
}

function expectFamily(root: ParsedCert, family: Family): void {
  if (family === 'classical' && root.key.kind !== 'ec') throw new ChainError('classical root is not an EC key');
  if (family === 'post_quantum' && root.key.kind !== 'ml-dsa') throw new ChainError('post-quantum root is not an ML-DSA key');
}

export interface PairingOptions {
  /** Holder pairs share the device key; signer pairs (presence, record service) do not. */
  sameLeafKey: boolean;
}

/**
 * Confirms two chains are the pair the issuer bound together: at every
 * position the classical certificate's paired-chain extension names the
 * SHA-256 of the post-quantum certificate at the same position, and, for
 * holder pairs, the two leaves carry the same SubjectPublicKeyInfo.
 *
 * The binding is one-directional by construction: the post-quantum half is
 * issued first and the classical half names it. Both halves are required;
 * accepting one alone is the wrong check, not a degraded one.
 */
export function confirmPairing(classical: ValidatedChain, postQuantum: ValidatedChain, opts: PairingOptions): void {
  if (classical.certs.length !== postQuantum.certs.length) {
    throw new ChainError('the classical and post-quantum chains differ in length');
  }
  for (let i = 0; i < classical.certs.length; i++) {
    const c = classical.certs[i]!;
    const q = postQuantum.certs[i]!;
    const ext = c.zoreal.get(OID.pairedChain) as { sibling_cert_sha256?: unknown } | undefined;
    const named = typeof ext?.sibling_cert_sha256 === 'string' ? ext.sibling_cert_sha256.toLowerCase() : undefined;
    if (!named) throw new ChainError(`${c.subject} carries no paired-chain binding`);
    if (named !== q.sha256Hex) throw new ChainError(`${c.subject} names a different post-quantum sibling than the one presented`);
  }
  if (opts.sameLeafKey && !equal(classical.leaf.spkiDer, postQuantum.leaf.spkiDer)) {
    throw new ChainError('the two leaves do not carry the same public key');
  }
}
