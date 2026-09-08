import { describe, expect, it } from 'vitest';
import { OID, PQ_ROOT_CA_1, PQ_ROOT_CA_1_SPKI_SHA256, ROOT_CA_1, ROOT_CA_1_SPKI_SHA256, parseCertificateText, validateChain, PRODUCTION_ANCHORS } from '../src/index.js';

describe('the pinned production roots', () => {
  it('hash to the digests published in the DNS tripwire', async () => {
    const c = await parseCertificateText(ROOT_CA_1);
    const q = await parseCertificateText(PQ_ROOT_CA_1);
    expect(c.spkiSha256).toBe(ROOT_CA_1_SPKI_SHA256);
    expect(q.spkiSha256).toBe(PQ_ROOT_CA_1_SPKI_SHA256);
    expect(c.key).toEqual({ kind: 'ec', curve: 'P-384', width: 48 });
    expect(q.key).toEqual({ kind: 'ml-dsa', level: 87 });
  });

  it('are self-signed under their own algorithms, and the classical root names the post-quantum one', async () => {
    const c = await parseCertificateText(ROOT_CA_1);
    const q = await parseCertificateText(PQ_ROOT_CA_1);
    const pair = c.zoreal.get(OID.pairedChain) as { sibling_cert_sha256: string };
    expect(pair.sibling_cert_sha256).toBe(q.sha256Hex);
    // A one-certificate "chain" is refused by design; validate root-only chains through a two-element list of the root twice is not meaningful,
    // so check the self-signatures directly through the chain validator's signature path.
    const { verifySignature } = await import('../src/x509/verify.js');
    expect(await verifySignature(c, c.signatureAlgorithm, c.tbs, c.signatureValue, true)).toBe(true);
    expect(await verifySignature(q, q.signatureAlgorithm, q.tbs, q.signatureValue, true)).toBe(true);
  });

  it('are what the default anchors pin', () => {
    expect(PRODUCTION_ANCHORS.classical).toEqual([ROOT_CA_1_SPKI_SHA256]);
    expect(PRODUCTION_ANCHORS.postQuantum).toEqual([PQ_ROOT_CA_1_SPKI_SHA256]);
    expect(PRODUCTION_ANCHORS.rootCertificates).toHaveLength(2);
  });

  it('refuse a chain to a root that is not pinned', async () => {
    await expect(validateChain([ROOT_CA_1, ROOT_CA_1], { anchors: ['nope'], asOf: new Date('2030-01-01'), family: 'classical' })).rejects.toThrow(/not a pinned/);
  });
});
