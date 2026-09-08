/**
 * Generates the conformance fixtures: a test hierarchy that mirrors the
 * production one (two roots, issuing CA pairs, a holder pair over one device
 * key, a presence signer pair, a record service pair, a test timestamping
 * authority), then one record per case. Every failure case fails exactly one
 * verification step, so a verifier that skips that step passes a record it
 * must reject; that is what the cases are for.
 *
 * Keys are regenerated on every run and never written to disk. The records,
 * the anchors and the index are what the tests read.
 *
 * Run after `npm run build`: the generator uses the built library for the
 * canonicalisation, the Merkle tree and the byte helpers, so the fixtures are
 * produced by the same code that verifies them.
 */
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import * as x509 from '@peculiar/asn1-x509';
import * as cms from '@peculiar/asn1-cms';
import * as tsp from '@peculiar/asn1-tsp';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  textHash, normaliseUrl, siteOf, jcs, jcsHash, leafHash, treeRoot, inclusionProof, coseKeyThumbprintP256,
  toBase64, toBase64Url, fromBase64Url, toHex, sha256, utf8, OID, MARK_AUDIENCE, recordCore,
} from '../dist/index.js';
import { randomBytes as rb } from 'node:crypto';

const subtle = crypto.subtle;
const OUT = new URL('../fixtures/', import.meta.url).pathname;
const ARC = '1.3.6.1.4.1.66655';
const ALG = {
  ecdsaSha256: '1.2.840.10045.4.3.2', ecdsaSha384: '1.2.840.10045.4.3.3',
  mlDsa65: '2.16.840.1.101.3.4.3.18', mlDsa87: '2.16.840.1.101.3.4.3.19',
  sha256: '2.16.840.1.101.3.4.2.1',
};
const EKU = { documentSigning: '1.3.6.1.5.5.7.3.36', clientAuth: '1.3.6.1.5.5.7.3.2', timeStamping: '1.3.6.1.5.5.7.3.8' };
const STATUS_URI = (batch) => `https://ca.test.invalid/pki/status/${batch}`;

// ---------- helpers ----------
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const newId = () => Array.from(rb(24), (b) => CROCKFORD[b % 32]).join('');
const iso = (d) => new Date(Math.floor(d.getTime() / 1000) * 1000).toISOString().replace(/\.000Z$/, 'Z');
const b64u = (s) => toBase64Url(utf8(typeof s === 'string' ? s : JSON.stringify(s)));

function derLen(n) { return n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]; }
function derUtf8(json) { const b = utf8(JSON.stringify(sortKeys(json))); return new Uint8Array([0x0c, ...derLen(b.length), ...b]); }
function derOctet(bytes) { return new Uint8Array([0x04, ...derLen(bytes.length), ...bytes]); }
function encodeOid(oid) {
  const p = oid.split('.').map(Number); const out = [p[0] * 40 + p[1]];
  for (const v of p.slice(2)) { const s = []; let x = v; do { s.unshift(x & 127); x = Math.floor(x / 128); } while (x > 0); for (let i = 0; i < s.length - 1; i++) s[i] |= 128; out.push(...s); }
  return new Uint8Array([0x06, ...derLen(out.length), ...out]);
}
function sortKeys(v) { if (Array.isArray(v)) return v.map(sortKeys); if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])); return v; }
function ecdsaRawToDer(raw) {
  const w = raw.length / 2;
  const int = (v) => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let b = v.subarray(i); if (b[0] & 0x80) b = new Uint8Array([0, ...b]); return new Uint8Array([0x02, b.length, ...b]); };
  const r = int(raw.subarray(0, w)), s = int(raw.subarray(w)); const len = r.length + s.length;
  return new Uint8Array([0x30, ...derLen(len), ...r, ...s]);
}
function pem(der) { return `-----BEGIN CERTIFICATE-----\n${toBase64(der).match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`; }

// ---------- keys and signers ----------
async function ecSigner(curve) {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
  const hash = curve === 'P-256' ? 'SHA-256' : 'SHA-384';
  return {
    kind: 'ec', curve, spki, jose: curve === 'P-256' ? 'ES256' : 'ES384', certAlg: curve === 'P-256' ? ALG.ecdsaSha256 : ALG.ecdsaSha384,
    signRaw: async (msg) => new Uint8Array(await subtle.sign({ name: 'ECDSA', hash }, kp.privateKey, msg)),
    signDer: async (msg) => ecdsaRawToDer(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash }, kp.privateKey, msg))),
    jwk: async () => { const j = await subtle.exportKey('jwk', kp.publicKey); return { kty: j.kty, crv: j.crv, x: j.x, y: j.y }; },
  };
}
function mlSigner(level) {
  const dsa = level === 65 ? ml_dsa65 : ml_dsa87;
  const { publicKey, secretKey } = dsa.keygen(rb(32));
  const spki = new Uint8Array(AsnConvert.serialize(new x509.SubjectPublicKeyInfo({ algorithm: new x509.AlgorithmIdentifier({ algorithm: level === 65 ? ALG.mlDsa65 : ALG.mlDsa87 }), subjectPublicKey: publicKey.buffer.slice(publicKey.byteOffset, publicKey.byteOffset + publicKey.byteLength) })));
  const sign = (msg) => dsa.sign(msg, secretKey);
  return { kind: 'ml-dsa', level, spki, jose: `ML-DSA-${level}`, certAlg: level === 65 ? ALG.mlDsa65 : ALG.mlDsa87, signRaw: async (m) => sign(m), signDer: async (m) => sign(m) };
}

// ---------- certificates ----------
function dn(cn) {
  const atv = (type, v, printable) => new x509.AttributeTypeAndValue({ type, value: new x509.AttributeValue(printable ? { printableString: v } : { utf8String: v }) });
  return new x509.Name([
    new x509.RelativeDistinguishedName([atv('2.5.4.3', cn, false)]),
    new x509.RelativeDistinguishedName([atv('2.5.4.10', 'ZOREAL Mark conformance fixtures', false)]),
    new x509.RelativeDistinguishedName([atv('2.5.4.6', 'US', true)]),
  ]);
}
let serial = 1000;
const ext = (oid, critical, value) => new x509.Extension({ extnID: oid, critical, extnValue: new OctetString(value) });
const bc = (ca, pathLen) => ext(x509.id_ce_basicConstraints, true, AsnConvert.serialize(new x509.BasicConstraints({ cA: ca, ...(pathLen !== undefined ? { pathLenConstraint: pathLen } : {}) })));
const ku = (flags) => ext(x509.id_ce_keyUsage, true, AsnConvert.serialize(new x509.KeyUsage(flags)));
const eku = (oids) => ext(x509.id_ce_extKeyUsage, false, AsnConvert.serialize(new x509.ExtendedKeyUsage(oids)));
const policies = (oids) => ext(x509.id_ce_certificatePolicies, false, AsnConvert.serialize(new x509.CertificatePolicies(oids.map((o) => new x509.PolicyInformation({ policyIdentifier: o })))));
const zx = (oid, critical, json) => ext(oid, critical, derUtf8(json));

async function makeCert({ cn, subjectSpki, issuer, extensions, notBefore, notAfter }) {
  const signer = issuer ? issuer.signer : null;
  const self = !issuer;
  const sigAlg = new x509.AlgorithmIdentifier({ algorithm: self ? subjectSpki.signer.certAlg : signer.certAlg });
  const tbs = new x509.TBSCertificate({
    version: x509.Version.v3,
    serialNumber: new Uint8Array([0x01, ...rb(8)]).buffer,
    signature: sigAlg,
    issuer: self ? dn(cn) : issuer.name,
    validity: new x509.Validity({ notBefore, notAfter }),
    subject: dn(cn),
    subjectPublicKeyInfo: AsnConvert.parse(subjectSpki.spki, x509.SubjectPublicKeyInfo),
    extensions: new x509.Extensions(extensions),
  });
  const tbsDer = new Uint8Array(AsnConvert.serialize(tbs));
  const sig = await (self ? subjectSpki.signer : signer).signDer(tbsDer);
  const der = new Uint8Array(AsnConvert.serialize(new x509.Certificate({ tbsCertificate: tbs, signatureAlgorithm: sigAlg, signatureValue: sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength) })));
  return { der, name: dn(cn), signer: subjectSpki.signer, b64: toBase64(der), sha256: toHex(await sha256(der)), spkiSha256: toBase64(await sha256(subjectSpki.spki)) };
}

const NOW = new Date();
const NB = new Date(NOW.getTime() - 400 * 24 * 3600 * 1000);
const NA = new Date(NOW.getTime() + 365 * 24 * 3600 * 1000);
const NA_ROOT = new Date(NOW.getTime() + 20 * 365 * 24 * 3600 * 1000);
const paired = (q) => zx(OID.pairedChain, false, { sibling_cert_sha256: q.sha256 });

/** A CA pair: post-quantum first, then the classical half naming it. */
async function caPair(cnBase, roots, pathLen) {
  const kq = mlSigner(roots ? 65 : 87), kc = await ecSigner('P-384');
  const q = await makeCert({ cn: roots ? `ZOREAL Post-Quantum ${cnBase} CA 1` : cnBase, subjectSpki: { spki: kq.spki, signer: kq }, issuer: roots?.q ?? null, extensions: [bc(true, pathLen), ku(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign)], notBefore: NB, notAfter: roots ? NA : NA_ROOT });
  const c = await makeCert({ cn: roots ? `ZOREAL ${cnBase} CA 1` : cnBase.replace('Post-Quantum ', ''), subjectSpki: { spki: kc.spki, signer: kc }, issuer: roots?.c ?? null, extensions: [bc(true, pathLen), ku(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign), paired(q)], notBefore: NB, notAfter: roots ? NA : NA_ROOT });
  return { c, q, kc, kq };
}

/** A leaf pair. Holder pairs share one P-256 key; signer pairs have their own ML-DSA-65 half. */
async function leafPair({ cn, ca, key, pqKey, extensionsC, extensionsQ, notBefore = NB, notAfter = NA }) {
  const q = await makeCert({ cn: `${cn} (post-quantum)`, subjectSpki: { spki: (pqKey ?? key).spki, signer: pqKey ?? key }, issuer: ca.q, extensions: extensionsQ, notBefore, notAfter });
  const c = await makeCert({ cn, subjectSpki: { spki: key.spki, signer: key }, issuer: ca.c, extensions: [...extensionsC, paired(q)], notBefore, notAfter });
  return { c, q, key, pqKey: pqKey ?? key };
}

// ---------- JWS ----------
async function jwsGeneral(claims, signers, typ) {
  const payload = b64u(claims);
  const signatures = [];
  for (const s of signers) {
    const prot = b64u({ alg: s.key.jose, typ, x5c: s.x5c });
    const sig = await s.key.signRaw(utf8(`${prot}.${payload}`));
    signatures.push({ protected: prot, signature: toBase64Url(sig) });
  }
  return { payload, signatures };
}
async function jwsCompact(claims, key, header) {
  const prot = b64u({ alg: key.jose, ...header });
  const payload = b64u(claims);
  return `${prot}.${payload}.${toBase64Url(await key.signRaw(utf8(`${prot}.${payload}`)))}`;
}

// ---------- status lists ----------
async function statusList(ca, batch, revokedIndexes, at = NOW) {
  const size = 256, bits = 2;
  const bytes = new Uint8Array((size * bits) / 8);
  for (const i of revokedIndexes) bytes[Math.floor(i / 4)] |= 1 << ((i % 4) * bits);
  const iat = Math.floor(at.getTime() / 1000) - 600;
  return jwsCompact({ iss: 'fixture CA', sub: STATUS_URI(batch), iat, exp: iat + 7200, ttl: 3600, status_list: { bits, lst: toBase64Url(new Uint8Array(deflateSync(bytes))) } }, ca.signer, { typ: 'statuslist+jwt', kid: batch });
}

// ---------- the hierarchy ----------
const roots = await caPair('ZOREAL Post-Quantum Root CA 1 (fixture)', null, undefined);
roots.c = await makeCert({ cn: 'ZOREAL Root CA 1 (fixture)', subjectSpki: { spki: roots.kc.spki, signer: roots.kc }, issuer: null, extensions: [bc(true), ku(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign), paired(roots.q)], notBefore: NB, notAfter: NA_ROOT });
const humanCa = await caPair('Human Identity', roots, 0);
const presenceCa = await caPair('Verified Presence EU', roots, 0);
const docCa = await caPair('Document Signing EU', roots, 0);
const rogueRoots = await caPair('Rogue Post-Quantum Root (fixture)', null, undefined);
rogueRoots.c = await makeCert({ cn: 'Rogue Root (fixture)', subjectSpki: { spki: rogueRoots.kc.spki, signer: rogueRoots.kc }, issuer: null, extensions: [bc(true), ku(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign), paired(rogueRoots.q)], notBefore: NB, notAfter: NA_ROOT });
const rogueHumanCa = await caPair('Human Identity', rogueRoots, 0);

const BATCH_C = 'human-c-202609', BATCH_Q = 'human-q-202609';
const holderExts = (idx, purpose = 'document_signing') => ({
  extensionsC: [
    bc(false),
    ku(purpose === 'document_signing' ? x509.KeyUsageFlags.nonRepudiation : x509.KeyUsageFlags.digitalSignature),
    eku([purpose === 'document_signing' ? EKU.documentSigning : EKU.clientAuth]),
    policies([`${ARC}.1.1`]),
    zx(OID.presenceRequired, true, { audience_binding: 'required', grade_min: 'recent' }),
    zx(OID.enrollmentAssurance, false, { uniqueness: 'personal_number', verified_on: '2026-08', chip_liveness_proven: true, trust_tier: 'high', key_protection: 'strongbox' }),
    zx(OID.statusList, false, { idx, uri: STATUS_URI(BATCH_C) }),
  ],
  extensionsQ: [
    bc(false),
    ku(purpose === 'document_signing' ? x509.KeyUsageFlags.nonRepudiation : x509.KeyUsageFlags.digitalSignature),
    eku([purpose === 'document_signing' ? EKU.documentSigning : EKU.clientAuth]),
    policies([`${ARC}.1.1`]),
    zx(OID.presenceRequired, true, { audience_binding: 'required', grade_min: 'recent' }),
    zx(OID.statusList, false, { idx, uri: STATUS_URI(BATCH_Q) }),
  ],
});
const PERSONA = 'HUMAN 7QK3-9F2M-XR84-B5NP';
const deviceKey = await ecSigner('P-256');
const holder = await leafPair({ cn: PERSONA, ca: humanCa, key: deviceKey, ...holderExts(5) });
const revokedHolder = await leafPair({ cn: PERSONA, ca: humanCa, key: await ecSigner('P-256'), ...holderExts(6) });
const authHolder = await leafPair({ cn: PERSONA, ca: humanCa, key: await ecSigner('P-256'), ...holderExts(7, 'authentication') });
const otherHolder = await leafPair({ cn: 'HUMAN 2ZZZ-9F2M-XR84-B5NP', ca: humanCa, key: await ecSigner('P-256'), ...holderExts(8) });
const rogueHolder = await leafPair({ cn: PERSONA, ca: rogueHumanCa, key: deviceKey, ...holderExts(5) });
const statusC = await statusList(humanCa.c, BATCH_C, [6]);
const statusQ = await statusList(humanCa.q, BATCH_Q, [6]);

const presenceSigner = await leafPair({ cn: 'ZOREAL Verified Presence EU signer 2026Q3', ca: presenceCa, key: await ecSigner('P-256'), pqKey: mlSigner(65),
  extensionsC: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), eku([OID.ekuPresenceSigning])], extensionsQ: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), eku([OID.ekuPresenceSigning])] });
const recordService = await leafPair({ cn: 'ZOREAL Mark record service 2026', ca: docCa, key: await ecSigner('P-256'), pqKey: mlSigner(65),
  extensionsC: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), eku([OID.ekuRecordService])], extensionsQ: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), eku([OID.ekuRecordService])] });
// A holder-like leaf under the presence CA but without the presence EKU: the "any valid chain" attack.
const impostorPresence = await leafPair({ cn: 'not a presence signer', ca: presenceCa, key: await ecSigner('P-256'), pqKey: mlSigner(65),
  extensionsC: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), eku([EKU.clientAuth])], extensionsQ: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), eku([EKU.clientAuth])] });

const tsaRootKey = await ecSigner('P-256');
const tsaRoot = await makeCert({ cn: 'Fixture Timestamping Root', subjectSpki: { spki: tsaRootKey.spki, signer: tsaRootKey }, issuer: null, extensions: [bc(true), ku(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign)], notBefore: NB, notAfter: NA_ROOT });
const tsaKey = await ecSigner('P-256');
const tsaSigner = await makeCert({ cn: 'Fixture Timestamp Responder', subjectSpki: { spki: tsaKey.spki, signer: tsaKey }, issuer: tsaRoot, extensions: [bc(false), ku(x509.KeyUsageFlags.digitalSignature), ext(x509.id_ce_extKeyUsage, true, AsnConvert.serialize(new x509.ExtendedKeyUsage([EKU.timeStamping])))], notBefore: NB, notAfter: NA });

const chainC = (leaf, ca = humanCa, rt = roots) => [leaf.b64, ca.c.b64, rt.c.b64];
const chainQ = (leaf, ca = humanCa, rt = roots) => [leaf.b64, ca.q.b64, rt.q.b64];

// ---------- the timestamp ----------
async function timestampToken(rootBytes, genTime) {
  const imprint = await sha256(rootBytes);
  const tst = new tsp.TSTInfo({
    version: tsp.TSTInfoVersion.v1, policy: `${ARC}.99.1`,
    messageImprint: new tsp.MessageImprint({ hashAlgorithm: new x509.AlgorithmIdentifier({ algorithm: ALG.sha256 }), hashedMessage: new OctetString(imprint) }),
    serialNumber: new Uint8Array([0x01, ...rb(8)]).buffer, genTime, ordering: false,
  });
  const tstDer = new Uint8Array(AsnConvert.serialize(tst));
  const signedAttrs = [
    new cms.Attribute({ attrType: '1.2.840.113549.1.9.3', attrValues: [encodeOid(tsp.id_ct_tstInfo).buffer] }),
    new cms.Attribute({ attrType: '1.2.840.113549.1.9.4', attrValues: [derOctet(await sha256(tstDer)).buffer] }),
  ];
  // The signature is over the attributes as a SET; serialising each attribute
  // and wrapping them in 0x31 by hand keeps the bytes identical to what the
  // [0] IMPLICIT encoding carries.
  const attrDers = signedAttrs.map((a) => new Uint8Array(AsnConvert.serialize(a)));
  const body = attrDers.reduce((acc, a) => new Uint8Array([...acc, ...a]), new Uint8Array(0));
  const setDer = new Uint8Array([0x31, ...derLen(body.length), ...body]);
  const sig = await tsaKey.signDer(setDer);
  const tsaTbs = AsnConvert.parse(tsaSigner.der, x509.Certificate).tbsCertificate;
  const si = new cms.SignerInfo({
    version: cms.CMSVersion.v1,
    sid: new cms.SignerIdentifier({ issuerAndSerialNumber: new cms.IssuerAndSerialNumber({ issuer: tsaTbs.issuer, serialNumber: tsaTbs.serialNumber }) }),
    digestAlgorithm: new cms.DigestAlgorithmIdentifier({ algorithm: ALG.sha256 }),
    signedAttrs, signatureAlgorithm: new cms.SignatureAlgorithmIdentifier({ algorithm: ALG.ecdsaSha256 }), signature: new OctetString(sig),
  });
  const sd = new cms.SignedData({
    version: cms.CMSVersion.v3, digestAlgorithms: new cms.DigestAlgorithmIdentifiers([new cms.DigestAlgorithmIdentifier({ algorithm: ALG.sha256 })]),
    encapContentInfo: new cms.EncapsulatedContentInfo({ eContentType: tsp.id_ct_tstInfo, eContent: new cms.EncapsulatedContent({ single: new OctetString(tstDer) }) }),
    certificates: new cms.CertificateSet([tsaSigner.der, tsaRoot.der].map((d) => new cms.CertificateChoices({ certificate: AsnConvert.parse(d, x509.Certificate) }))),
    signerInfos: new cms.SignerInfos([si]),
  });
  const ci = new cms.ContentInfo({ contentType: cms.id_signedData, content: AsnConvert.serialize(sd) });
  return toBase64(new Uint8Array(AsnConvert.serialize(ci)));
}

/** Puts the record in a three-leaf minute tree at index 1 and timestamps the root. */
async function timestamp(record, genTime = NOW, opts = {}) {
  const coreHash = await jcsHash(recordCore(record));
  const leaf = await leafHash(record.id, coreHash);
  const leaves = [rb(32), leaf, rb(32)];
  const root = await treeRoot(leaves);
  const proof = await inclusionProof(leaves, 1);
  const token = await timestampToken(opts.tamperRoot ? rb(32) : root, genTime);
  record.timestamp = { status: 'confirmed', tsa: 'https://tsa.test.invalid', token, merkle: { root: toHex(root), proof: proof.map(toHex), index: 1, size: 3 }, gen_time: iso(genTime) };
  return record;
}

// ---------- records ----------
const RECORD_SIGNERS = [{ key: recordService.key, x5c: chainC(recordService.c, docCa) }, { key: recordService.pqKey, x5c: chainQ(recordService.q, docCa) }];
const PRESENCE_SIGNERS = [{ key: presenceSigner.key, x5c: chainC(presenceSigner.c, presenceCa) }, { key: presenceSigner.pqKey, x5c: chainQ(presenceSigner.q, presenceCa) }];

async function presenceFor({ holderLeaf, deviceSig, order, grade = 'recent', channel = 'native_attested', verdict = 'pass', extra = {}, signers = PRESENCE_SIGNERS, iatOffset = -20, expOffset = 100, ckt, sub, nonce, countersigOver }) {
  const t = Math.floor(NOW.getTime() / 1000);
  const claims = {
    iss: 'https://ca.zoreal.com/presence/eu',
    sub: sub ?? toBase64Url(await sha256(holderLeaf.der)),
    aud: MARK_AUDIENCE, iat: t + iatOffset, exp: t + expOffset, cti: newId(),
    cnf: { ckt: ckt ?? (await coseKeyThumbprintP256(deviceKeyOf(holderLeaf))) },
    zoreal: { grade, countersig_over: countersigOver ?? toBase64Url(await sha256(deviceSig)), nonce: nonce ?? order, verdict, trust_tier: 'high', channel, scoring_profile: 'sp-2026.07-3', cell: 'eu-central-1', session_ref: newId() },
    ...extra,
  };
  return jwsGeneral(claims, signers, 'presence+jwt');
}
const spkiByLeaf = new Map();
function deviceKeyOf(leaf) { return spkiByLeaf.get(leaf.b64); }
for (const h of [holder, revokedHolder, authHolder, otherHolder, rogueHolder]) spkiByLeaf.set(h.c.b64, h.key.spki);

const ASSURANCE = { uniqueness: 'personal_number', verified_on: '2026-08', chip_liveness_proven: true, trust_tier: 'high', key_protection: 'strongbox' };

async function makeRecord({ text, url, binding = 'page', kind = 'text', holderPair = holder, identity = 'persona', subject = PERSONA, email, presence, presenceOpts = {}, dataExtra = {}, chains }) {
  const id = newId();
  const order = newId();
  const hash = await textHash(text);
  const site = url ? siteOf(url) : (email ? email.from.split('@')[1] : 'example.com');
  const data = { kind, hash_algorithm: 'SHA-256', hash, url: url ? normaliseUrl(url) : null, site, binding, ...(email ? { email } : {}), ...dataExtra };
  const payload = {
    v: 1, order, purpose: 'content', context: binding === 'email' ? `mailto:${site}` : `https://${site}`, identity, subject,
    cert: toBase64Url(await sha256(holderPair.c.der)),
    visible: { hash, canonical: 'mark-text-v1', format: 'plaintext' }, data,
    requester: { name: 'ZOREAL Mark', origin: MARK_AUDIENCE }, aud: MARK_AUDIENCE, iat: iso(NOW),
  };
  const message = new Uint8Array([...(await jcsHash(payload)), ...utf8(order), ...utf8(MARK_AUDIENCE)]);
  const deviceSig = await holderPair.key.signRaw(message);
  const record = {
    v: 1, id, kind, payload,
    signature: { device: toBase64Url(deviceSig), certificate_chain: chains?.c ?? chainC(holderPair.c), paired_chain: chains?.q ?? chainQ(holderPair.q), revocation: { classical: statusC, post_quantum: statusQ } },
    presence: presence ?? (await presenceFor({ holderLeaf: holderPair.c, deviceSig, order, ...presenceOpts })),
    assurance: ASSURANCE, timestamp: { status: 'pending' }, withdrawn: null, created_at: iso(NOW),
  };
  return { record, text, deviceSig, order };
}

async function appended(claims) { return jwsGeneral(claims, RECORD_SIGNERS, 'mark-event+jwt'); }
function flipByteInB64u(s) { const b = fromBase64Url(s); b[10] ^= 0xff; return toBase64Url(b); }
function flipByteInB64(s) { const b = Uint8Array.from(Buffer.from(s, 'base64')); b[b.length - 40] ^= 0xff; return toBase64(b); }

const PAGE = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&utm_source=share';
const TEXT = 'I was at the launch and the demo was real.';
const cases = [];
const records = {};
async function emit(name, made, expect, extra = {}) {
  records[made.record.id] = made.record;
  cases.push({ name, id: made.record.id, text: extra.text ?? made.text, marker: extra.marker ?? 'signed', pageUrl: extra.pageUrl === undefined ? PAGE : extra.pageUrl, email: extra.email, expect });
  return made;
}

// Happy paths
const okPage = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(okPage.record);
await emit('ok-page', okPage, { verdict: 'verified_here', time: 'confirmed' });
cases.push({ name: 'ok-page-elsewhere', id: okPage.record.id, text: TEXT, marker: 'signed', pageUrl: 'https://example.org/repost', expect: { verdict: 'verified_other_page' } });
cases.push({ name: 'ok-page-unknown-location', id: okPage.record.id, text: TEXT, marker: 'signed', pageUrl: null, expect: { verdict: 'verified_other_page' } });
cases.push({ name: 'ok-page-platform-rewritten', id: okPage.record.id, text: 'I was at  the launch and the demo was real.\n', marker: 'signed', pageUrl: PAGE.replace('&utm_source=share', '#comments'), expect: { verdict: 'verified_here' } });
cases.push({ name: 'fail-13-text-altered', id: okPage.record.id, text: 'I was NOT at the launch and the demo was real.', marker: 'signed', pageUrl: PAGE, expect: { verdict: 'not_verified', failedStep: 13 } });
cases.push({ name: 'fail-16-human-under-delegated-marker', id: okPage.record.id, text: TEXT, marker: 'delegated', pageUrl: PAGE, expect: { verdict: 'not_verified', failedStep: 16 } });
cases.push({ name: 'fail-2-unknown-id', id: newId(), text: TEXT, marker: 'signed', pageUrl: PAGE, expect: { verdict: 'not_verified', failedStep: 2 } });
cases.push({ name: 'fail-1-bad-id', id: 'NOTANID', text: TEXT, marker: 'signed', pageUrl: PAGE, expect: { verdict: 'no_signature', failedStep: 1 } });

const pending = await makeRecord({ text: TEXT, url: PAGE });
await emit('ok-pending-timestamp', pending, { verdict: 'verified_here', time: 'unconfirmed' });

const unbound = await makeRecord({ text: TEXT, url: null, binding: 'none' });
unbound.record.payload.data.site = 'whatsapp.com'; unbound.record.payload.context = 'https://whatsapp.com';
// re-sign after editing the payload
{ const m = new Uint8Array([...(await jcsHash(unbound.record.payload)), ...utf8(unbound.order), ...utf8(MARK_AUDIENCE)]); const s = await holder.key.signRaw(m); unbound.record.signature.device = toBase64Url(s); unbound.record.presence = await presenceFor({ holderLeaf: holder.c, deviceSig: s, order: unbound.order }); }
await timestamp(unbound.record);
await emit('ok-unbound', unbound, { verdict: 'verified_unbound' });

const channel = await makeRecord({ text: TEXT, url: 'https://app.slack.com/client/T0/C0', binding: 'channel' });
await timestamp(channel.record);
await emit('ok-channel', channel, { verdict: 'verified_in_channel' }, { pageUrl: 'https://app.slack.com/client/T0/C0' });

const toHash = toHex(await sha256(utf8(['anna@example.com', 'bo@example.com'].sort().join(','))));
const mail = await makeRecord({ text: TEXT, url: null, binding: 'email', email: { from: 'sender@example.net', to_hash: toHash } });
await timestamp(mail.record);
await emit('ok-email', mail, { verdict: 'verified_email' }, { pageUrl: null, email: { from: 'Sender@Example.net', recipients: ['bo@example.com', 'anna@example.com'] } });
cases.push({ name: 'ok-email-forwarded', id: mail.record.id, text: TEXT, marker: 'signed', pageUrl: null, email: { from: 'sender@example.net', recipients: ['carl@example.com'] }, expect: { verdict: 'verified_email_other_recipients' } });
cases.push({ name: 'ok-email-other-sender', id: mail.record.id, text: TEXT, marker: 'signed', pageUrl: null, email: { from: 'imposter@example.net', recipients: ['bo@example.com', 'anna@example.com'] }, expect: { verdict: 'verified_email_other_sender' } });

const live = await makeRecord({ text: TEXT, url: PAGE, presenceOpts: { grade: 'live', extra: { age_over_18: true, nationality: 'SWE' } } });
await timestamp(live.record);
await emit('ok-live-with-claims', live, { verdict: 'verified_here', grade: 'live', claims: { age_over: [18], nationality: 'SWE' } });

const withdrawn = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(withdrawn.record);
withdrawn.record.withdrawn = { at: iso(NOW), jws: await appended({ id: withdrawn.record.id, at: iso(NOW) }) };
await emit('ok-withdrawn', withdrawn, { verdict: 'withdrawn' });

const badWithdrawal = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(badWithdrawal.record);
badWithdrawal.record.withdrawn = { at: iso(NOW), jws: await appended({ id: badWithdrawal.record.id, at: iso(NOW) }) };
badWithdrawal.record.withdrawn.jws.signatures[0].signature = flipByteInB64u(badWithdrawal.record.withdrawn.jws.signatures[0].signature);
await emit('fail-15-withdrawal-bad-signature', badWithdrawal, { verdict: 'not_verified', failedStep: 15 });

const appendedOk = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(appendedOk.record);
appendedOk.record.co_signers = { count: 4000, first_at: iso(NOW), last_at: iso(NOW), jws: await appended({ id: appendedOk.record.id, count: 4000, first_at: iso(NOW), last_at: iso(NOW) }) };
appendedOk.record.reports = { count: 2, reasons: { spam: 2 }, jws: await appended({ id: appendedOk.record.id, count: 2, reasons: { spam: 2 } }) };
appendedOk.record.log = { tree_size: 3, sth: await appended({ tree_size: 3, root: appendedOk.record.timestamp.merkle.root }) };
await emit('ok-appended-events', appendedOk, { verdict: 'verified_here', coSignerCount: 4000, reports: 2 });

const badCount = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(badCount.record);
badCount.record.co_signers = { count: 9999, first_at: iso(NOW), last_at: iso(NOW), jws: await appended({ id: badCount.record.id, count: 4000, first_at: iso(NOW), last_at: iso(NOW) }) };
await emit('fail-18-cosigner-count-mismatch', badCount, { verdict: 'not_verified', failedStep: 18 });

// Co-signing
const original = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(original.record);
await emit('ok-cosign-original', original, { verdict: 'verified_here' });
const cosign = await makeRecord({ text: TEXT, url: PAGE, holderPair: otherHolder, subject: 'HUMAN 2ZZZ-9F2M-XR84-B5NP', dataExtra: { co_signs: original.record.id } });
await timestamp(cosign.record);
await emit('ok-cosign', cosign, { verdict: 'verified_here', coSigns: original.record.id });
const badCosign = await makeRecord({ text: 'Different words entirely.', url: PAGE, holderPair: otherHolder, subject: 'HUMAN 2ZZZ-9F2M-XR84-B5NP', dataExtra: { co_signs: original.record.id } });
await timestamp(badCosign.record);
await emit('fail-17-cosign-different-text', badCosign, { verdict: 'not_verified', failedStep: 17 }, { text: 'Different words entirely.' });

// Delegated
async function makeDelegated({ expiresInHours = 12, site, marker = 'delegated', text = 'Summary of the standup, posted by Aura for Anna.' }) {
  const agent = await ecSigner('P-256');
  const delegationOrder = newId();
  const statement = await jwsCompact({ order: delegationOrder, agent_public_key: await agent.jwk(), agent_name: 'Aura', site: site ?? 'youtube.com', expires_at: iso(new Date(NOW.getTime() + expiresInHours * 3600 * 1000)), max_marks: 50, iat: iso(new Date(NOW.getTime() - 3600 * 1000)) }, holder.key, { typ: 'delegation+jwt' });
  const stSig = fromBase64Url(statement.split('.')[2]);
  const made = await makeRecord({ text, url: PAGE, presence: await presenceFor({ holderLeaf: holder.c, deviceSig: stSig, order: delegationOrder }) });
  // The agent signs the payload with its own key.
  const m = new Uint8Array([...(await jcsHash(made.record.payload)), ...utf8(made.order), ...utf8(MARK_AUDIENCE)]);
  made.record.signature.device = toBase64Url(await agent.signRaw(m));
  made.record.delegation = { statement, human_subject: PERSONA, agent_name: 'Aura' };
  made.text = text;
  return made;
}
const delegated = await makeDelegated({});
await timestamp(delegated.record);
await emit('ok-delegated', delegated, { verdict: 'delegated' }, { marker: 'delegated' });
cases.push({ name: 'fail-16-delegated-under-signed-marker', id: delegated.record.id, text: delegated.text, marker: 'signed', pageUrl: PAGE, expect: { verdict: 'not_verified', failedStep: 16 } });
const expiredDelegation = await makeDelegated({ expiresInHours: -1 });
await timestamp(expiredDelegation.record);
await emit('fail-16-delegation-expired', expiredDelegation, { verdict: 'not_verified', failedStep: 16 }, { marker: 'delegated' });
const otherSiteDelegation = await makeDelegated({ site: 'example.com' });
await timestamp(otherSiteDelegation.record);
await emit('fail-16-delegation-other-site', otherSiteDelegation, { verdict: 'not_verified', failedStep: 16 }, { marker: 'delegated' });

// Chains
const rogue = await makeRecord({ text: TEXT, url: PAGE, holderPair: rogueHolder, chains: { c: chainC(rogueHolder.c, rogueHumanCa, rogueRoots), q: chainQ(rogueHolder.q, rogueHumanCa, rogueRoots) } });
await timestamp(rogue.record);
await emit('fail-3-unpinned-root', rogue, { verdict: 'not_verified', failedStep: 3 });
const tamperedCa = await makeRecord({ text: TEXT, url: PAGE });
tamperedCa.record.signature.certificate_chain[1] = flipByteInB64(tamperedCa.record.signature.certificate_chain[1]);
await timestamp(tamperedCa.record);
await emit('fail-3-tampered-ca-certificate', tamperedCa, { verdict: 'not_verified', failedStep: 3 });
const noPq = await makeRecord({ text: TEXT, url: PAGE });
noPq.record.signature.paired_chain = [];
await timestamp(noPq.record);
await emit('fail-4-missing-post-quantum-chain', noPq, { verdict: 'not_verified', failedStep: 4 });
const wrongPq = await makeRecord({ text: TEXT, url: PAGE, chains: { q: chainQ(otherHolder.q) } });
await timestamp(wrongPq.record);
await emit('fail-4-post-quantum-leaf-other-key', wrongPq, { verdict: 'not_verified', failedStep: 4 });
const classicalOnly = await makeRecord({ text: TEXT, url: PAGE, chains: { q: chainC(holder.c) } });
await timestamp(classicalOnly.record);
await emit('fail-4-classical-chain-presented-twice', classicalOnly, { verdict: 'not_verified', failedStep: 4 });

// Revocation, key usage, presence
const revoked = await makeRecord({ text: TEXT, url: PAGE, holderPair: revokedHolder });
await timestamp(revoked.record);
await emit('fail-5-revoked', revoked, { verdict: 'not_verified', failedStep: 5 });
const noStatus = await makeRecord({ text: TEXT, url: PAGE });
noStatus.record.signature.revocation = { classical: statusC, post_quantum: '' };
await timestamp(noStatus.record);
await emit('fail-5-missing-status-list', noStatus, { verdict: 'not_verified', failedStep: 5 });
const auth = await makeRecord({ text: TEXT, url: PAGE, holderPair: authHolder });
await timestamp(auth.record);
await emit('fail-6-authentication-certificate', auth, { verdict: 'not_verified', failedStep: 6 });
const noPresence = await makeRecord({ text: TEXT, url: PAGE });
noPresence.record.presence = null;
await timestamp(noPresence.record);
await emit('fail-7-no-presence', noPresence, { verdict: 'not_verified', failedStep: 7 });
const badPresenceSig = await makeRecord({ text: TEXT, url: PAGE });
badPresenceSig.record.presence.signatures[1].signature = flipByteInB64u(badPresenceSig.record.presence.signatures[1].signature);
await timestamp(badPresenceSig.record);
await emit('fail-8-presence-ml-dsa-signature', badPresenceSig, { verdict: 'not_verified', failedStep: 8 });
const impostor = await makeRecord({ text: TEXT, url: PAGE, presenceOpts: { signers: [{ key: impostorPresence.key, x5c: chainC(impostorPresence.c, presenceCa) }, { key: impostorPresence.pqKey, x5c: chainQ(impostorPresence.q, presenceCa) }] } });
await timestamp(impostor.record);
await emit('fail-8-presence-signer-without-eku', impostor, { verdict: 'not_verified', failedStep: 8 });
for (const [name, presenceOpts] of [
  ['fail-9-presence-wrong-nonce', { nonce: newId() }],
  ['fail-9-presence-expired', { iatOffset: -400, expOffset: -280 }],
  ['fail-9-presence-other-device-key', { ckt: await coseKeyThumbprintP256(otherHolder.key.spki) }],
  ['fail-9-presence-detached', { countersigOver: toBase64Url(rb(32)) }],
  ['fail-9-presence-other-holder', { sub: toBase64Url(await sha256(otherHolder.c.der)) }],
  ['fail-10-presence-web-channel', { channel: 'web' }],
  ['fail-10-presence-delegated-grade-on-human-mark', { grade: 'delegated' }],
]) {
  const r = await makeRecord({ text: TEXT, url: PAGE, presenceOpts });
  await timestamp(r.record);
  await emit(name, r, { verdict: 'not_verified', failedStep: Number(name.split('-')[1]) });
}

// Device signature, timestamp
const badDevice = await makeRecord({ text: TEXT, url: PAGE });
badDevice.record.signature.device = flipByteInB64u(badDevice.record.signature.device);
badDevice.record.presence = await presenceFor({ holderLeaf: holder.c, deviceSig: fromBase64Url(badDevice.record.signature.device), order: badDevice.order });
await timestamp(badDevice.record);
await emit('fail-11-device-signature', badDevice, { verdict: 'not_verified', failedStep: 11 });
const otherCert = await makeRecord({ text: TEXT, url: PAGE });
otherCert.record.payload.cert = toBase64Url(await sha256(otherHolder.c.der));
{ const m = new Uint8Array([...(await jcsHash(otherCert.record.payload)), ...utf8(otherCert.order), ...utf8(MARK_AUDIENCE)]); const s = await holder.key.signRaw(m); otherCert.record.signature.device = toBase64Url(s); otherCert.record.presence = await presenceFor({ holderLeaf: holder.c, deviceSig: s, order: otherCert.order }); }
await timestamp(otherCert.record);
await emit('fail-11-payload-names-other-certificate', otherCert, { verdict: 'not_verified', failedStep: 11 });
const badTs = await makeRecord({ text: TEXT, url: PAGE });
await timestamp(badTs.record, NOW, { tamperRoot: true });
await emit('ok-12-timestamp-unverifiable', badTs, { verdict: 'verified_here', time: 'unconfirmed' });
const expiredCertButTimestamped = await (async () => {
  const old = await leafPair({ cn: PERSONA, ca: humanCa, key: deviceKey, ...holderExts(5), notBefore: new Date(NOW.getTime() - 400 * 86400000), notAfter: new Date(NOW.getTime() - 10 * 86400000) });
  spkiByLeaf.set(old.c.b64, deviceKey.spki);
  const r = await makeRecord({ text: TEXT, url: PAGE, holderPair: old });
  return r;
})();
// Signed 30 days ago, timestamped then: valid as of the timestamp although the certificate has since expired.
{
  const then = new Date(NOW.getTime() - 30 * 86400000);
  const t = Math.floor(then.getTime() / 1000);
  // Revocation material is what the service fetched at emission, thirty days ago.
  expiredCertButTimestamped.record.signature.revocation = { classical: await statusList(humanCa.c, BATCH_C, [6], then), post_quantum: await statusList(humanCa.q, BATCH_Q, [6], then) };
  expiredCertButTimestamped.record.presence = await presenceFor({ holderLeaf: expiredCertButTimestamped.record.signature.certificate_chain[0] && { der: fromBase64Url(expiredCertButTimestamped.record.signature.certificate_chain[0].replace(/\+/g, '-').replace(/\//g, '_')), b64: expiredCertButTimestamped.record.signature.certificate_chain[0] }, deviceSig: expiredCertButTimestamped.deviceSig, order: expiredCertButTimestamped.order, iatOffset: t - Math.floor(NOW.getTime() / 1000) - 20, expOffset: t - Math.floor(NOW.getTime() / 1000) + 100 });
  await timestamp(expiredCertButTimestamped.record, then);
}
await emit('ok-certificate-expired-after-signing', expiredCertButTimestamped, { verdict: 'verified_here', time: 'confirmed' });

// ---------- write ----------
rmSync(`${OUT}records`, { recursive: true, force: true });
mkdirSync(`${OUT}records`, { recursive: true });
for (const [id, r] of Object.entries(records)) writeFileSync(`${OUT}records/${id}.json`, JSON.stringify(r, null, 2) + '\n');
writeFileSync(`${OUT}index.json`, JSON.stringify(cases, null, 2) + '\n');
writeFileSync(`${OUT}anchors.json`, JSON.stringify({
  classical: [roots.c.spkiSha256], postQuantum: [roots.q.spkiSha256], timestamping: [tsaRoot.spkiSha256],
  rootCertificates: [pem(roots.c.der), pem(roots.q.der)],
  generated_at: iso(NOW),
}, null, 2) + '\n');
console.log(`${Object.keys(records).length} records, ${cases.length} cases, written to fixtures/`);
