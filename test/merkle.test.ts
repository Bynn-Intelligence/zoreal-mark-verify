import { describe, expect, it } from 'vitest';
import { inclusionProof, leafHash, treeRoot, verifyInclusion } from '../src/index.js';

describe('Merkle tree', () => {
  it('proves inclusion for every leaf of trees of every small size', async () => {
    for (let n = 1; n <= 9; n++) {
      const leaves: Uint8Array[] = [];
      for (let i = 0; i < n; i++) leaves.push(await leafHash(`ID${i}`, new Uint8Array(32).fill(i)));
      const root = await treeRoot(leaves);
      for (let m = 0; m < n; m++) {
        const proof = await inclusionProof(leaves, m);
        expect(await verifyInclusion(leaves[m]!, m, n, proof, root), `n=${n} m=${m}`).toBe(true);
        expect(await verifyInclusion(leaves[m]!, (m + 1) % n, n, proof, root)).toBe(n === 1);
      }
      // A proof that reaches the root is accepted whatever size is claimed: the
      // root is what the timestamp signs, and the size is checked against the
      // signed tree head separately.
      expect(await verifyInclusion(leaves[0]!, 0, n, [new Uint8Array(32), ...(await inclusionProof(leaves, 0))], root)).toBe(false);
    }
  });
});
