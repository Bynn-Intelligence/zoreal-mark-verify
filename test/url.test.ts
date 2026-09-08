import { describe, expect, it } from 'vitest';
import { normaliseUrl, siteOf } from '../src/index.js';

describe('URL normalisation', () => {
  it('drops tracking, fragments, credentials, default ports and trailing slashes, and sorts the rest', () => {
    expect(normaliseUrl('HTTPS://User:pw@WWW.YouTube.com:443/watch/?v=dQw4w9WgXcQ&utm_source=x&fbclid=1&a=2&si=z#t=10'))
      .toBe('https://www.youtube.com/watch?a=2&v=dQw4w9WgXcQ');
    expect(normaliseUrl('https://example.com/')).toBe('https://example.com/');
    expect(normaliseUrl('https://example.com')).toBe('https://example.com/');
    expect(normaliseUrl('https://example.com/path/')).toBe('https://example.com/path');
  });

  it('keeps parameters that carry meaning, in a stable order', () => {
    expect(normaliseUrl('https://x.com/a?b=2&a=1&b=1')).toBe('https://x.com/a?a=1&b=1&b=2');
  });

  it('refuses a non-web URL', () => {
    expect(() => normaliseUrl('mailto:a@b.c')).toThrow();
    expect(() => normaliseUrl('not a url')).toThrow();
  });
});

describe('site', () => {
  it('is the registrable domain', () => {
    expect(siteOf('https://www.youtube.com/watch?v=1')).toBe('youtube.com');
    expect(siteOf('https://m.youtube.com/')).toBe('youtube.com');
    expect(siteOf('https://alice.github.io/post')).toBe('alice.github.io');
    expect(siteOf('https://news.bbc.co.uk/x')).toBe('bbc.co.uk');
    expect(siteOf('http://localhost:4820/demo')).toBe('localhost');
  });
});
