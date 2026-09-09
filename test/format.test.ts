import { describe, expect, it } from 'vitest';
import { findBrokenMarkers, findMarks, wrap } from '../src/index.js';

const ID = '7QK39F2MXR84B5NPD4T6HW2A';

describe('markers', () => {
  it('wraps and finds a Mark', () => {
    const s = wrap('I was there.', ID);
    expect(s).toBe(`::ZOREAL-MARK:: I was there. ::ZOREAL-SIGNATURE:${ID}::`);
    expect(findMarks(`before ${s} after`)).toEqual([{ marker: 'signed', text: 'I was there.', id: ID, start: 7, end: 7 + s.length }]);
  });

  it('finds several Marks and treats an inner opening marker as text', () => {
    const s = `${wrap('one', ID)} and ${wrap('two ::ZOREAL-MARK:: inner', ID)}`;
    const found = findMarks(s);
    expect(found.map((f) => f.text)).toEqual(['one', 'two ::ZOREAL-MARK:: inner']);
  });

  it('finds a delegated Mark under its own marker', () => {
    expect(findMarks(wrap('posted by an agent', ID, 'delegated'))[0]?.marker).toBe('delegated');
  });

  it('reports a truncated Mark and a bad id as broken, not as found', () => {
    expect(findMarks('::ZOREAL-MARK:: cut off by the platform')).toEqual([]);
    expect(findBrokenMarkers('::ZOREAL-MARK:: cut off by the platform')).toEqual([{ marker: 'signed', start: 0, reason: 'no_closing_marker' }]);
    expect(findMarks('::ZOREAL-MARK:: x ::ZOREAL-SIGNATURE:NOTANID::')).toEqual([]);
    expect(findBrokenMarkers('::ZOREAL-MARK:: x ::ZOREAL-SIGNATURE:NOTANID::')[0]?.reason).toBe('bad_id');
  });

  it('refuses to wrap with an id of the wrong shape', () => {
    expect(() => wrap('x', 'nope')).toThrow();
    expect(() => wrap('x', ID.replace('7', 'I'))).toThrow();
  });
});
