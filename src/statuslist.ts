import { fromBase64Url } from './bytes.js';
import { jwsClaims, parseCompactJws, verifyJwsSignature } from './jws.js';
import type { ParsedCert } from './x509/cert.js';

export interface StatusListClaims {
  iss?: string;
  sub: string;
  iat: number;
  exp: number;
  ttl?: number;
  status_list: { bits: number; lst: string };
}

export interface StatusResult {
  /** 0 is valid; anything else is the published status value. */
  value: number;
  claims: StatusListClaims;
}

/**
 * Checks one certificate's slot in an IETF Token Status List, as of `asOf`.
 *
 * The list is a compact JWS signed by the issuing CA; `sub` must equal the
 * `uri` the certificate names; `iat <= asOf < exp`; `lst` is a zlib-compressed
 * bit array with `bits` bits per entry packed little-endian within each byte.
 * Anything malformed, unsigned or out of its window is a rejection: a list the
 * verifier cannot read is not a list that says "valid".
 */
export async function checkStatusList(jwt: string, issuer: ParsedCert, idx: number, uri: string, asOf: Date): Promise<StatusResult> {
  const jws = parseCompactJws(jwt);
  const sig = jws.signatures[0]!;
  if (sig.header.typ !== undefined && sig.header.typ !== 'statuslist+jwt') {
    throw new Error(`status list has typ ${sig.header.typ}`);
  }
  if (!(await verifyJwsSignature(jws, sig, issuer))) throw new Error('status list signature does not verify under the issuing CA');
  const claims = jwsClaims<StatusListClaims>(jws);
  if (claims.sub !== uri) throw new Error(`status list is for ${claims.sub}, certificate names ${uri}`);
  const t = asOf.getTime() / 1000;
  if (!(claims.iat <= t && t < claims.exp)) throw new Error('status list is outside its validity window');
  const bits = claims.status_list?.bits;
  if (![1, 2, 4, 8].includes(bits)) throw new Error(`status list has ${bits} bits per entry`);
  const bytes = await inflate(fromBase64Url(claims.status_list.lst));
  const perByte = 8 / bits;
  const byte = bytes[Math.floor(idx / perByte)];
  if (byte === undefined) throw new Error(`status list has no entry ${idx}`);
  const shift = (idx % perByte) * bits;
  const value = (byte >> shift) & ((1 << bits) - 1);
  return { value, claims };
}

async function inflate(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  void writer.write(data as BufferSource);
  void writer.close();
  const chunks: Uint8Array[] = [];
  const reader = ds.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}
