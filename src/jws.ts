import { fromBase64Url, fromUtf8, utf8 } from './bytes.js';
import type { JwsGeneral } from './types.js';
import type { ParsedCert } from './x509/cert.js';
import { verifyJose } from './x509/verify.js';

export interface JwsProtectedHeader {
  alg: string;
  typ?: string;
  kid?: string;
  x5c?: string[];
  x5u?: string;
  [k: string]: unknown;
}

export interface ParsedJwsSignature {
  /** The protected header, which the signature covers. */
  header: JwsProtectedHeader;
  /** The unprotected header member, which it does not. Carries x5c here: see `x5cOf`. */
  unprotected: Record<string, unknown>;
  protectedB64: string;
  signature: Uint8Array;
}

/**
 * The certificate chain a signature is verified under. It may sit in the
 * protected header or in the unprotected one; the record service puts it in
 * the unprotected member because the post-quantum chain alone is over ten
 * kilobytes and an ML-DSA signing message is capped at four. Nothing is lost:
 * the chain is not trusted for being in the header, it is validated to the
 * pinned roots, and the signature binds the leaf whichever member named it.
 */
export function x5cOf(sig: ParsedJwsSignature): string[] | undefined {
  const c = sig.header.x5c ?? sig.unprotected.x5c;
  return Array.isArray(c) && c.length > 0 && c.every((x) => typeof x === 'string') ? (c as string[]) : undefined;
}

export interface ParsedJws {
  payloadB64: string;
  payload: Uint8Array;
  signatures: ParsedJwsSignature[];
}

function parseHeader(protectedB64: string): JwsProtectedHeader {
  const h = JSON.parse(fromUtf8(fromBase64Url(protectedB64))) as unknown;
  if (!h || typeof h !== 'object' || typeof (h as { alg?: unknown }).alg !== 'string') {
    throw new Error('JWS protected header has no alg');
  }
  return h as JwsProtectedHeader;
}

/** RFC 7515 section 7.1. */
export function parseCompactJws(compact: string): ParsedJws {
  const parts = compact.split('.');
  if (parts.length !== 3) throw new Error('not a compact JWS');
  const [p, payloadB64, s] = parts as [string, string, string];
  return {
    payloadB64,
    payload: fromBase64Url(payloadB64),
    signatures: [{ header: parseHeader(p), unprotected: {}, protectedB64: p, signature: fromBase64Url(s) }],
  };
}

/** RFC 7515 section 7.2.1, protected headers only: an unprotected header is ignored. */
export function parseGeneralJws(jws: unknown): ParsedJws {
  const j = jws as Partial<JwsGeneral> | null;
  if (!j || typeof j.payload !== 'string' || !Array.isArray(j.signatures) || j.signatures.length === 0) {
    throw new Error('not a JWS in General JSON Serialization');
  }
  return {
    payloadB64: j.payload,
    payload: fromBase64Url(j.payload),
    signatures: j.signatures.map((s) => {
      if (typeof s?.protected !== 'string' || typeof s?.signature !== 'string') throw new Error('JWS signature entry is malformed');
      const unprotected = (s as { header?: unknown }).header;
      return { header: parseHeader(s.protected), unprotected: unprotected && typeof unprotected === 'object' ? (unprotected as Record<string, unknown>) : {}, protectedB64: s.protected, signature: fromBase64Url(s.signature) };
    }),
  };
}

/** The signing input of RFC 7515 section 5.1. */
export function signingInput(protectedB64: string, payloadB64: string): Uint8Array {
  return utf8(`${protectedB64}.${payloadB64}`);
}

export async function verifyJwsSignature(jws: ParsedJws, sig: ParsedJwsSignature, signer: ParsedCert): Promise<boolean> {
  return verifyJose(signer, sig.header.alg, signingInput(sig.protectedB64, jws.payloadB64), sig.signature);
}

export function jwsClaims<T>(jws: ParsedJws): T {
  return JSON.parse(fromUtf8(jws.payload)) as T;
}
