import { describe, expect, it } from 'vitest';
import { canonicalText, textHash } from '../src/index.js';

describe('canonical text', () => {
  it('folds what platforms rewrite and nothing else', () => {
    expect(canonicalText('  “Hello” — it’s   fine…\n\tok 　')).toBe('"Hello" - it\'s fine... ok');
    expect(canonicalText('Åström')).toBe('Åström'.normalize('NFC'));
    expect(canonicalText('CASE and 123')).toBe('CASE and 123');
    expect(canonicalText('a–b−c—d')).toBe('a-b-c-d');
  });

  it('gives one hash for the platform-rewritten forms of one text', async () => {
    const a = await textHash('I was at the launch and the demo was real.');
    const b = await textHash('I was at  the launch and the demo was real.\n');
    const c = await textHash('I was at the launch and the demo was real. ');
    expect(a).toBe(b);
    expect(a).toBe(c);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not fold letters, digits or order', async () => {
    expect(await textHash('abc')).not.toBe(await textHash('ABC'));
    expect(await textHash('1 2')).not.toBe(await textHash('2 1'));
  });
});
