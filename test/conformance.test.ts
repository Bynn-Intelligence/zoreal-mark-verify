import { describe, expect, it } from 'vitest';
import { verifyMark } from '../src/index.js';
import { anchors, cases, fetchRecord } from './helpers.js';

/**
 * Every fixture case is a record that fails exactly one step, or passes with
 * a particular verdict. A verifier that skips a step passes a record it must
 * reject, and this suite is where that shows.
 */
describe('conformance cases', () => {
  for (const c of cases) {
    it(c.name, async () => {
      const result = await verifyMark(
        { marker: c.marker, text: c.text, id: c.id },
        { fetchRecord, anchors, pageUrl: c.pageUrl ?? undefined, email: c.email },
      );
      const failed = result.steps.filter((s) => !s.ok);
      const detail = failed.map((s) => `step ${s.step} ${s.name}: ${s.detail}`).join('; ');
      expect(result.verdict, detail).toBe(c.expect.verdict);
      if (c.expect.failedStep !== undefined) expect(result.failedStep, detail).toBe(c.expect.failedStep);
      else expect(result.failedStep, detail).toBeUndefined();
      if (c.expect.time) expect(result.time?.status).toBe(c.expect.time);
      if (c.expect.grade) expect(result.grade).toBe(c.expect.grade);
      if (c.expect.claims) expect(result.claims).toEqual(c.expect.claims);
      if (c.expect.coSigns) expect(result.relation?.coSigns).toBe(c.expect.coSigns);
      if (c.expect.coSignerCount) expect(result.relation?.coSignerCount).toBe(c.expect.coSignerCount);
      if (c.expect.reports) expect(result.reports?.count).toBe(c.expect.reports);
    });
  }

  it('reports every step in order on a passing record', async () => {
    const c = cases.find((x) => x.name === 'ok-page')!;
    const result = await verifyMark({ marker: 'signed', text: c.text, id: c.id }, { fetchRecord, anchors, pageUrl: c.pageUrl! });
    expect(result.steps.map((s) => s.step)).toEqual(Array.from({ length: 18 }, (_, i) => i + 1));
    expect(result.steps.every((s) => s.ok)).toBe(true);
  });

  it('says cannot verify now, never not verified, when the record cannot be fetched', async () => {
    const c = cases.find((x) => x.name === 'ok-page')!;
    const result = await verifyMark({ marker: 'signed', text: c.text, id: c.id }, { anchors, pageUrl: c.pageUrl!, fetchRecord: async () => ({ status: 'unavailable', reason: 'offline' }) });
    expect(result.verdict).toBe('cannot_verify_now');
    expect(result.failedStep).toBe(2);
  });

  it('rejects a record whose roots are not the pinned ones, even when they are self-consistent', async () => {
    const c = cases.find((x) => x.name === 'ok-page')!;
    const result = await verifyMark({ marker: 'signed', text: c.text, id: c.id }, { fetchRecord, pageUrl: c.pageUrl!, anchors: { ...anchors, classical: ['AAAA'], postQuantum: ['BBBB'] } });
    expect(result.verdict).toBe('not_verified');
    expect(result.failedStep).toBe(3);
  });
});
