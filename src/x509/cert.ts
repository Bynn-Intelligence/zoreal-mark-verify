import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  BasicConstraints,
  Certificate,
  CertificatePolicies,
  ExtendedKeyUsage,
  KeyUsage,
  Name,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_certificatePolicies,
  id_ce_extKeyUsage,
  id_ce_keyUsage,
  id_ce_subjectKeyIdentifier,
} from '@peculiar/asn1-x509';
import { bytesOf, fromBase64, fromUtf8, sha256, toBase64, toHex } from '../bytes.js';
import { UNDERSTOOD_ZOREAL_EXTENSIONS } from '../roots.js';
import { decodeOid, readTlv, tbsCertificateBytes } from './der.js';

/** Signature and key algorithm OIDs this verifier knows. Anything else is rejected. */
export const ALG = Object.freeze({
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
  mlDsa44: '2.16.840.1.101.3.4.3.17',
  mlDsa65: '2.16.840.1.101.3.4.3.18',
  mlDsa87: '2.16.840.1.101.3.4.3.19',
  sha256WithRsa: '1.2.840.113549.1.1.11',
  sha384WithRsa: '1.2.840.113549.1.1.12',
  ecPublicKey: '1.2.840.10045.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  curveP256: '1.2.840.10045.3.1.7',
  curveP384: '1.3.132.0.34',
});

export const EKU = Object.freeze({
  documentSigning: '1.3.6.1.5.5.7.3.36',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  clientAuth: '1.3.6.1.5.5.7.3.2',
});

/**
 * Standard extensions a conforming verifier understands. A critical extension
 * outside this set or the ZOREAL set is a rejection (RFC 5280 section 4.2).
 * nameConstraints is deliberately absent: it is not implemented here, so a
 * certificate carrying it critically is refused rather than half-checked.
 */
const UNDERSTOOD_STANDARD = new Set([
  id_ce_basicConstraints,
  id_ce_keyUsage,
  id_ce_extKeyUsage,
  id_ce_certificatePolicies,
  id_ce_subjectKeyIdentifier,
  id_ce_authorityKeyIdentifier,
]);

export type KeyKind =
  | { kind: 'ec'; curve: 'P-256' | 'P-384'; width: 32 | 48 }
  | { kind: 'ml-dsa'; level: 44 | 65 | 87 }
  | { kind: 'rsa' };

export interface KeyUsageFlags {
  digitalSignature: boolean;
  contentCommitment: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
}

export interface ParsedCert {
  der: Uint8Array;
  /** The exact `tbsCertificate` bytes, sliced from `der`. */
  tbs: Uint8Array;
  subjectDer: Uint8Array;
  issuerDer: Uint8Array;
  subject: string;
  issuer: string;
  serialHex: string;
  notBefore: Date;
  notAfter: Date;
  /** The DER `SubjectPublicKeyInfo`. */
  spkiDer: Uint8Array;
  /** The BIT STRING contents of the public key. */
  publicKeyBits: Uint8Array;
  key: KeyKind;
  signatureAlgorithm: string;
  signatureValue: Uint8Array;
  isCa: boolean;
  pathLen: number | undefined;
  keyUsage: KeyUsageFlags | undefined;
  extendedKeyUsage: string[] | undefined;
  policies: string[];
  /** Critical extension OIDs the verifier does not understand. */
  unknownCritical: string[];
  /** The ZOREAL private extensions, decoded from their JSON. */
  zoreal: Map<string, unknown>;
  /** Lowercase hex SHA-256 of `der`. */
  sha256Hex: string;
  /** Base64 SHA-256 of `spkiDer`: the pin form. */
  spkiSha256: string;
}

function nameToString(name: Name): string {
  const parts: string[] = [];
  for (const rdn of name) {
    for (const atv of rdn) {
      const v = atv.value;
      const s = v.printableString ?? v.utf8String ?? v.ia5String ?? v.bmpString ?? v.teletexString ?? v.universalString ?? '';
      parts.push(`${atv.type}=${s}`);
    }
  }
  return parts.join(', ');
}

function keyKindOf(spki: Certificate['tbsCertificate']['subjectPublicKeyInfo']): KeyKind {
  const alg = spki.algorithm.algorithm;
  if (alg === ALG.ecPublicKey) {
    const params = spki.algorithm.parameters;
    if (!params) throw new Error('EC key without curve parameters');
    const oid = decodeOid(bytesOf(params));
    if (oid === ALG.curveP256) return { kind: 'ec', curve: 'P-256', width: 32 };
    if (oid === ALG.curveP384) return { kind: 'ec', curve: 'P-384', width: 48 };
    throw new Error(`unsupported curve ${oid}`);
  }
  if (alg === ALG.mlDsa44) return { kind: 'ml-dsa', level: 44 };
  if (alg === ALG.mlDsa65) return { kind: 'ml-dsa', level: 65 };
  if (alg === ALG.mlDsa87) return { kind: 'ml-dsa', level: 87 };
  if (alg === ALG.rsaEncryption) return { kind: 'rsa' };
  throw new Error(`unsupported key algorithm ${alg}`);
}

function decodeKeyUsage(bits: KeyUsage): KeyUsageFlags {
  const b = bytesOf(bits.value);
  const first = b[0] ?? 0;
  return {
    digitalSignature: (first & 0x80) !== 0,
    contentCommitment: (first & 0x40) !== 0,
    keyCertSign: (first & 0x04) !== 0,
    cRLSign: (first & 0x02) !== 0,
  };
}

export async function parseCertificate(der: Uint8Array): Promise<ParsedCert> {
  const cert = AsnConvert.parse(der, Certificate);
  const tbs = cert.tbsCertificate;
  const tbsBytes = tbsCertificateBytes(der);
  const spkiDer = new Uint8Array(AsnConvert.serialize(tbs.subjectPublicKeyInfo));
  const key = keyKindOf(tbs.subjectPublicKeyInfo);

  let isCa = false;
  let pathLen: number | undefined;
  let keyUsage: KeyUsageFlags | undefined;
  let eku: string[] | undefined;
  const policies: string[] = [];
  const unknownCritical: string[] = [];
  const zoreal = new Map<string, unknown>();
  const seen = new Set<string>();

  for (const ext of tbs.extensions ?? []) {
    if (seen.has(ext.extnID)) throw new Error(`duplicate extension ${ext.extnID}`);
    seen.add(ext.extnID);
    const value = bytesOf(ext.extnValue.buffer);
    switch (ext.extnID) {
      case id_ce_basicConstraints: {
        const bc = AsnConvert.parse(value, BasicConstraints);
        isCa = bc.cA;
        pathLen = bc.pathLenConstraint;
        break;
      }
      case id_ce_keyUsage:
        keyUsage = decodeKeyUsage(AsnConvert.parse(value, KeyUsage));
        break;
      case id_ce_extKeyUsage:
        eku = [...AsnConvert.parse(value, ExtendedKeyUsage)];
        break;
      case id_ce_certificatePolicies:
        for (const p of AsnConvert.parse(value, CertificatePolicies)) policies.push(p.policyIdentifier);
        break;
      default:
        if (UNDERSTOOD_ZOREAL_EXTENSIONS.includes(ext.extnID)) {
          // A DER UTF8String holding JSON with sorted keys.
          const tlv = readTlv(value, 0);
          if (tlv.tag !== 0x0c) throw new Error(`extension ${ext.extnID} is not a UTF8String`);
          zoreal.set(ext.extnID, JSON.parse(fromUtf8(value.subarray(tlv.start, tlv.end))));
        } else if (ext.critical && !UNDERSTOOD_STANDARD.has(ext.extnID)) {
          unknownCritical.push(ext.extnID);
        }
    }
  }

  const spkiDigest = await sha256(spkiDer);
  const certDigest = await sha256(der);
  return {
    der,
    tbs: tbsBytes,
    subjectDer: new Uint8Array(AsnConvert.serialize(tbs.subject)),
    issuerDer: new Uint8Array(AsnConvert.serialize(tbs.issuer)),
    subject: nameToString(tbs.subject),
    issuer: nameToString(tbs.issuer),
    serialHex: toHex(bytesOf(tbs.serialNumber)),
    notBefore: tbs.validity.notBefore.getTime(),
    notAfter: tbs.validity.notAfter.getTime(),
    spkiDer,
    publicKeyBits: bytesOf(tbs.subjectPublicKeyInfo.subjectPublicKey),
    key,
    signatureAlgorithm: cert.signatureAlgorithm.algorithm,
    signatureValue: bytesOf(cert.signatureValue),
    isCa,
    pathLen,
    keyUsage,
    extendedKeyUsage: eku,
    policies,
    unknownCritical,
    zoreal,
    sha256Hex: toHex(certDigest),
    spkiSha256: toBase64(spkiDigest),
  };
}

/** Parses base64 DER (x5c style) or PEM. */
export async function parseCertificateText(text: string): Promise<ParsedCert> {
  const body = text.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  return parseCertificate(fromBase64(body));
}

export function octetStringOf(bytes: Uint8Array): OctetString {
  return new OctetString(bytes);
}
