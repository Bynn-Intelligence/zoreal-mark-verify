import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DIGICERT_TRUSTED_ROOT_G4_SPKI_SHA256, fromHex, sha256, toHex, verifyTimestamp, type MarkRecord } from '../src/index.js';

/**
 * A real token from timestamp.digicert.com over a known imprint. The Merkle
 * side is faked to reproduce that imprint (a one-leaf tree whose root hashes
 * to it cannot be built, so the record is shaped so that SHA-256(root) is the
 * datum hash the token was issued over) and the point of the test is the
 * production anchor pin: the token's signer must chain to DigiCert Trusted
 * Root G4 by SPKI digest, through the certificates the token itself carries.
 */
describe('the production timestamping anchor', () => {
  const fx = JSON.parse(readFileSync(new URL('../fixtures/digicert-token.json', import.meta.url), 'utf8')) as { data_hex: string; token: string };

  it('accepts a DigiCert token whose signer chains to the pinned root', async () => {
    // The token's imprint is SHA-256(data). The verifier computes SHA-256(root_bytes), so root_bytes must be `data`,
    // and a Merkle proof that ends at those bytes is not constructible for arbitrary data; verify the token path only.
    const { verifyTimestampToken } = await import('../src/timestamp.js');
    const data = fromHex(fx.data_hex);
    const r = await verifyTimestampToken(fx.token, await sha256(data), { anchors: [DIGICERT_TRUSTED_ROOT_G4_SPKI_SHA256] });
    expect(r.status).toBe('confirmed');
    if (r.status === 'confirmed') {
      expect(r.tsa).toContain('DigiCert');
      expect(r.genTime.toISOString()).toBe('2026-09-08T22:34:44.000Z');
    }
  });

  it('leaves the time unconfirmed when no anchor is pinned', async () => {
    const { verifyTimestampToken } = await import('../src/timestamp.js');
    const r = await verifyTimestampToken(fx.token, await sha256(fromHex(fx.data_hex)), { anchors: [] });
    expect(r.status).toBe('unconfirmed');
  });

  it('leaves the time unconfirmed when the imprint differs', async () => {
    const { verifyTimestampToken } = await import('../src/timestamp.js');
    const r = await verifyTimestampToken(fx.token, new Uint8Array(32), { anchors: [DIGICERT_TRUSTED_ROOT_G4_SPKI_SHA256] });
    expect(r.status).toBe('unconfirmed');
    if (r.status === 'unconfirmed') expect(r.reason).toMatch(/imprint/);
  });

  it('treats a pending record as pending', async () => {
    const r = await verifyTimestamp({ timestamp: { status: 'pending' } } as unknown as MarkRecord, { anchors: [] });
    expect(r.status).toBe('pending');
    expect(toHex(new Uint8Array([1, 255]))).toBe('01ff');
  });
});
