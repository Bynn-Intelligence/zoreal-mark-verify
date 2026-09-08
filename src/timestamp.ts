import { AsnConvert } from '@peculiar/asn1-schema';
import { ContentInfo, SignedData, id_signedData } from '@peculiar/asn1-cms';
import { TSTInfo, id_ct_tstInfo } from '@peculiar/asn1-tsp';
import { id_kp_timeStamping } from '@peculiar/asn1-x509';
import { bytesOf, equal, fromBase64, fromHex, sha256, toHex } from './bytes.js';
import { jcsHash } from './jcs.js';
import { leafHash, verifyInclusion } from './merkle.js';
import type { MarkRecord, Timestamp } from './types.js';
import { parseCertificate, type ParsedCert } from './x509/cert.js';
import { children, readTlv } from './x509/der.js';
import { verifySignature } from './x509/verify.js';

const ID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const ID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const ID_SHA256 = '2.16.840.1.101.3.4.2.1';

export interface TimestampOptions {
  /** SPKI SHA-256 digests (base64) of the timestamping anchors. */
  anchors: string[];
}

export type TimestampResult =
  | { status: 'confirmed'; genTime: Date; tsa: string }
  | { status: 'pending' }
  | { status: 'unconfirmed'; reason: string };

/** The record with the five appended fields removed: what the leaf hash covers. */
export function recordCore(record: MarkRecord): Record<string, unknown> {
  const { timestamp: _t, withdrawn: _w, co_signers: _c, reports: _r, log: _l, ...core } = record as unknown as Record<string, unknown>;
  return core;
}

/**
 * Verifies the RFC 3161 token and the Merkle inclusion proof. On success the
 * time is confirmed and every certificate validity in the record is judged as
 * of it. Any failure leaves the time unconfirmed, which is the same state as
 * pending, never a confirmed time from an unverified token.
 */
export async function verifyTimestamp(record: MarkRecord, opts: TimestampOptions): Promise<TimestampResult> {
  const ts: Timestamp | undefined = record.timestamp;
  if (!ts || ts.status === 'pending') return { status: 'pending' };
  try {
    if (!ts.token || !ts.merkle) throw new Error('timestamp is confirmed but carries no token or proof');
    const coreHash = await jcsHash(recordCore(record));
    const leaf = await leafHash(record.id, coreHash);
    const root = fromHex(ts.merkle.root);
    const proof = ts.merkle.proof.map(fromHex);
    if (!(await verifyInclusion(leaf, ts.merkle.index, ts.merkle.size, proof, root))) {
      throw new Error('the Merkle inclusion proof does not reach the stated root');
    }
    const r = await verifyTimestampToken(ts.token, await sha256(root), opts);
    if (r.status === 'confirmed' && ts.gen_time && Math.abs(new Date(ts.gen_time).getTime() - r.genTime.getTime()) > 1000) {
      throw new Error('gen_time in the record differs from the token');
    }
    return r;
  } catch (e) {
    return { status: 'unconfirmed', reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Verifies one RFC 3161 token (base64 DER `TimeStampToken`) over `imprint`,
 * the SHA-256 the token was requested for: the TSTInfo imprint must equal it,
 * the signed attributes must bind the content, the signature must verify under
 * the signer certificate the token carries, that certificate must carry the
 * timeStamping key purpose, and it must chain to a pinned anchor through the
 * certificates in the token, every one valid as of the token's own time.
 */
export async function verifyTimestampToken(tokenB64: string, imprint: Uint8Array, opts: TimestampOptions): Promise<TimestampResult> {
  try {
    const tokenDer = fromBase64(tokenB64);
    const ci = AsnConvert.parse(tokenDer, ContentInfo);
    if (ci.contentType !== id_signedData) throw new Error('token is not CMS SignedData');
    const sd = AsnConvert.parse(ci.content, SignedData);
    if (sd.encapContentInfo.eContentType !== id_ct_tstInfo) throw new Error('token content is not TSTInfo');
    const eContent = sd.encapContentInfo.eContent?.single;
    if (!eContent) throw new Error('token has no TSTInfo content');
    const eContentBytes = bytesOf(eContent.buffer);
    const tst = AsnConvert.parse(eContentBytes, TSTInfo);
    if (tst.messageImprint.hashAlgorithm.algorithm !== ID_SHA256) throw new Error('token imprint is not SHA-256');
    if (!equal(bytesOf(tst.messageImprint.hashedMessage.buffer), imprint)) throw new Error('token imprint does not match');
    const genTime = tst.genTime;

    if (sd.signerInfos.length !== 1) throw new Error(`token has ${sd.signerInfos.length} signers`);
    const si = sd.signerInfos[0]!;
    const certs: ParsedCert[] = [];
    for (const choice of sd.certificates ?? []) {
      if (choice.certificate) certs.push(await parseCertificate(new Uint8Array(AsnConvert.serialize(choice.certificate))));
    }
    const signer = findSigner(si, certs);
    if (!signer) throw new Error('token signer certificate is not in the token');
    if (!signer.extendedKeyUsage?.includes(id_kp_timeStamping)) throw new Error('token signer lacks the timeStamping key purpose');

    if (!si.signedAttrs || si.signedAttrs.length === 0) throw new Error('token has no signed attributes');
    let contentTypeOk = false;
    let digestOk = false;
    for (const attr of si.signedAttrs) {
      const v = attr.attrValues[0];
      if (!v) continue;
      if (attr.attrType === ID_CONTENT_TYPE) {
        contentTypeOk = decodeOidValue(bytesOf(v)) === id_ct_tstInfo;
      } else if (attr.attrType === ID_MESSAGE_DIGEST) {
        const tlv = readTlv(bytesOf(v), 0);
        digestOk = equal(bytesOf(v).subarray(tlv.start, tlv.end), await sha256(eContentBytes));
      }
    }
    if (!contentTypeOk) throw new Error('token content-type attribute is wrong');
    if (!digestOk) throw new Error('token message-digest attribute does not match the content');
    // The signature is over the DER of the signed attributes as a SET (tag
    // 0x31), not as the [0] IMPLICIT the structure carries. Re-serialising each
    // attribute and wrapping the set by hand reproduces those bytes exactly for
    // a DER token, and does not depend on the parser keeping the raw slice.
    const attrDers = si.signedAttrs.map((a) => new Uint8Array(AsnConvert.serialize(a)));
    const signedAttrsDer = derSet(attrDers);
    const sigAlg = signatureAlgorithmFor(si.signatureAlgorithm.algorithm, si.digestAlgorithm.algorithm, signer);
    if (!(await verifySignature(signer, sigAlg, signedAttrsDer, bytesOf(si.signature.buffer), true))) {
      throw new Error('token signature does not verify');
    }

    await chainToAnchor(signer, certs, opts.anchors, genTime);
    return { status: 'confirmed', genTime, tsa: signer.subject };
  } catch (e) {
    return { status: 'unconfirmed', reason: e instanceof Error ? e.message : String(e) };
  }
}

function findSigner(si: SignedData['signerInfos'][number], certs: ParsedCert[]): ParsedCert | undefined {
  if (si.sid.issuerAndSerialNumber) {
    const serial = toHex(bytesOf(si.sid.issuerAndSerialNumber.serialNumber));
    const issuerDer = new Uint8Array(AsnConvert.serialize(si.sid.issuerAndSerialNumber.issuer));
    return certs.find((c) => c.serialHex === serial && equal(c.issuerDer, issuerDer));
  }
  if (si.sid.subjectKeyIdentifier) {
    const ski = toHex(bytesOf(si.sid.subjectKeyIdentifier.buffer));
    return certs.find((c) => subjectKeyIdOf(c) === ski);
  }
  return undefined;
}

function subjectKeyIdOf(c: ParsedCert): string | undefined {
  // Subject key identifier extension: OCTET STRING inside the extension value.
  const tbs = c.tbs;
  const seq = readTlv(tbs, 0);
  for (const child of children(tbs, seq)) {
    if (child.tag !== 0xa3) continue;
    const exts = readTlv(tbs, child.start);
    for (const ext of children(tbs, exts)) {
      const parts = children(tbs, ext);
      const oid = parts[0];
      if (!oid) continue;
      const oidStr = decodeOidValue(tbs.subarray(oid.headerStart, oid.end));
      if (oidStr !== '2.5.29.14') continue;
      const value = parts[parts.length - 1]!;
      const inner = readTlv(tbs, value.start);
      return toHex(tbs.subarray(inner.start, inner.end));
    }
  }
  return undefined;
}

function decodeOidValue(der: Uint8Array): string {
  const tlv = readTlv(der, 0);
  const body = der.subarray(tlv.start, tlv.end);
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < body.length; i++) {
    v = v * 128 + (body[i]! & 0x7f);
    if ((body[i]! & 0x80) === 0) {
      if (parts.length === 0) {
        const first = Math.min(2, Math.floor(v / 40));
        parts.push(first, v - 40 * first);
      } else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

/** CMS names the signature algorithm as the bare key algorithm for RSA; combine it with the digest. */
function signatureAlgorithmFor(sigAlg: string, digestAlg: string, signer: ParsedCert): string {
  if (sigAlg === '1.2.840.113549.1.1.1') {
    if (digestAlg === ID_SHA256) return '1.2.840.113549.1.1.11';
    if (digestAlg === '2.16.840.1.101.3.4.2.2') return '1.2.840.113549.1.1.12';
    throw new Error(`unsupported RSA digest ${digestAlg}`);
  }
  if (sigAlg === '1.2.840.10045.2.1') {
    // ecPublicKey named as the signature algorithm: pick by the signer's curve.
    return signer.key.kind === 'ec' && signer.key.curve === 'P-384' ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2';
  }
  return sigAlg;
}

/**
 * Walks from the signer through the certificates in the token until a
 * certificate whose SPKI digest is a pinned timestamping anchor is reached,
 * verifying each signature and each validity as of `asOf`. The anchor need
 * not be self-signed: a cross-signed root is still the root that was pinned.
 */
async function chainToAnchor(signer: ParsedCert, pool: ParsedCert[], anchors: string[], asOf: Date): Promise<void> {
  let current = signer;
  for (let depth = 0; depth < 8; depth++) {
    if (asOf < current.notBefore || asOf > current.notAfter) throw new Error(`${current.subject} was not valid at the token's time`);
    if (anchors.includes(current.spkiSha256)) return;
    const issuer = pool.find((c) => equal(c.subjectDer, current.issuerDer) && c !== current);
    if (!issuer) throw new Error(`no anchor reached: ${current.issuer} is not in the token and is not pinned`);
    if (!issuer.isCa) throw new Error(`${issuer.subject} is not a CA`);
    if (!(await verifySignature(issuer, current.signatureAlgorithm, current.tbs, current.signatureValue, true))) {
      throw new Error(`signature on ${current.subject} does not verify under ${issuer.subject}`);
    }
    current = issuer;
  }
  throw new Error('timestamping chain too long');
}

function derSet(items: Uint8Array[]): Uint8Array {
  const body = items.reduce((n, i) => n + i.length, 0);
  const len = body < 128 ? [body] : body < 256 ? [0x81, body] : [0x82, body >> 8, body & 255];
  const out = new Uint8Array(1 + len.length + body);
  out[0] = 0x31;
  out.set(len, 1);
  let o = 1 + len.length;
  for (const i of items) { out.set(i, o); o += i.length; }
  return out;
}
