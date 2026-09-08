import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ALG, type KeyKind, type ParsedCert } from './cert.js';
import { ecdsaDerToRaw } from './der.js';

/**
 * Verifies `signature` over `message` under `signer`'s key, for the algorithm
 * named by `algorithmOid`. ECDSA and RSA go through Web Crypto; ML-DSA through
 * noble, because no browser exposes it yet. `derEcdsa` says whether an ECDSA
 * signature arrives as DER (certificates, CMS) or raw r||s (JOSE, the device).
 *
 * Returns false rather than throwing on a bad signature; throws only when the
 * algorithm and the key do not go together, which is a malformed input rather
 * than a failed check.
 */
export async function verifySignature(
  signer: Pick<ParsedCert, 'spkiDer' | 'publicKeyBits' | 'key'>,
  algorithmOid: string,
  message: Uint8Array,
  signature: Uint8Array,
  derEcdsa: boolean,
): Promise<boolean> {
  const key = signer.key;
  switch (algorithmOid) {
    case ALG.ecdsaWithSha256:
    case ALG.ecdsaWithSha384: {
      if (key.kind !== 'ec') throw new Error('ECDSA signature under a non-EC key');
      const hash = algorithmOid === ALG.ecdsaWithSha256 ? 'SHA-256' : 'SHA-384';
      return verifyEcdsa(signer.spkiDer, key, hash, message, derEcdsa ? ecdsaDerToRaw(signature, key.width) : signature);
    }
    case ALG.mlDsa44:
    case ALG.mlDsa65:
    case ALG.mlDsa87: {
      if (key.kind !== 'ml-dsa') throw new Error('ML-DSA signature under a non-ML-DSA key');
      const expected = algorithmOid === ALG.mlDsa44 ? 44 : algorithmOid === ALG.mlDsa65 ? 65 : 87;
      if (key.level !== expected) throw new Error(`ML-DSA-${expected} signature under an ML-DSA-${key.level} key`);
      return verifyMlDsa(key.level, signer.publicKeyBits, message, signature);
    }
    case ALG.sha256WithRsa:
    case ALG.sha384WithRsa: {
      if (key.kind !== 'rsa') throw new Error('RSA signature under a non-RSA key');
      const hash = algorithmOid === ALG.sha256WithRsa ? 'SHA-256' : 'SHA-384';
      const k = await crypto.subtle.importKey('spki', signer.spkiDer as BufferSource, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
      return crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, signature as BufferSource, message as BufferSource);
    }
    default:
      throw new Error(`unsupported signature algorithm ${algorithmOid}`);
  }
}

export async function verifyEcdsa(
  spkiDer: Uint8Array,
  key: Extract<KeyKind, { kind: 'ec' }>,
  hash: 'SHA-256' | 'SHA-384',
  message: Uint8Array,
  rawSignature: Uint8Array,
): Promise<boolean> {
  if (rawSignature.length !== key.width * 2) return false;
  const k = await crypto.subtle.importKey('spki', spkiDer as BufferSource, { name: 'ECDSA', namedCurve: key.curve }, false, ['verify']);
  return crypto.subtle.verify({ name: 'ECDSA', hash }, k, rawSignature as BufferSource, message as BufferSource);
}

export function verifyMlDsa(level: 44 | 65 | 87, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const dsa = level === 44 ? ml_dsa44 : level === 65 ? ml_dsa65 : ml_dsa87;
  if (publicKey.length !== dsa.lengths.publicKey || signature.length !== dsa.lengths.signature) return false;
  try {
    return dsa.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** The JOSE algorithm names this verifier accepts, mapped to what they need. */
export const JOSE_ALG = Object.freeze({
  ES256: { kind: 'ec', curve: 'P-256', hash: 'SHA-256' },
  ES384: { kind: 'ec', curve: 'P-384', hash: 'SHA-384' },
  'ML-DSA-44': { kind: 'ml-dsa', level: 44 },
  'ML-DSA-65': { kind: 'ml-dsa', level: 65 },
  'ML-DSA-87': { kind: 'ml-dsa', level: 87 },
} as const);

export type JoseAlg = keyof typeof JOSE_ALG;

/** Verifies a JOSE signature (raw r||s for ECDSA) under a certificate's key. */
export async function verifyJose(signer: ParsedCert, alg: string, signingInput: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const spec = JOSE_ALG[alg as JoseAlg];
  if (!spec) throw new Error(`unsupported JOSE algorithm ${alg}`);
  if (spec.kind === 'ec') {
    if (signer.key.kind !== 'ec' || signer.key.curve !== spec.curve) throw new Error(`${alg} under a key that is not ${spec.curve}`);
    return verifyEcdsa(signer.spkiDer, signer.key, spec.hash, signingInput, signature);
  }
  if (signer.key.kind !== 'ml-dsa' || signer.key.level !== spec.level) throw new Error(`${alg} under a key that is not ML-DSA-${spec.level}`);
  return verifyMlDsa(spec.level, signer.publicKeyBits, signingInput, signature);
}
