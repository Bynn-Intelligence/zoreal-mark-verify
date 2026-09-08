import { getDomain } from 'tldts';

/**
 * Tracking parameters are removed before the URL enters the payload, because
 * the same page arrives with a different `utm_source` from every link, and a
 * Mark signed for one of them must verify on all of them. The list is fixed
 * and short on purpose: a verifier that strips more than the signer did, or
 * less, produces "Verified for another page" on the page it was signed for.
 */
export const TRACKING_PARAMS = new Set(['fbclid', 'gclid', 'si', 'ref', 'feature']);

function isTracking(name: string): boolean {
  return name.startsWith('utm_') || TRACKING_PARAMS.has(name);
}

/**
 * Normalises a page URL to the form that goes inside the signed payload, and
 * that a verifier compares against. Scheme and host lower-cased, default port
 * removed, credentials and fragment removed, tracking parameters removed,
 * remaining parameters sorted by name then value, and a trailing slash removed
 * from any path other than "/".
 *
 * Throws on anything that is not an absolute http(s) URL: a Mark is bound to a
 * page, and a page has one of those.
 */
export function normaliseUrl(input: string): string {
  const u = new URL(input);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new Error(`not a web URL: ${u.protocol}`);
  }
  u.username = '';
  u.password = '';
  u.hash = '';
  const kept: [string, string][] = [];
  for (const [k, v] of u.searchParams) if (!isTracking(k)) kept.push([k, v]);
  kept.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  u.search = '';
  const q = new URLSearchParams();
  for (const [k, v] of kept) q.append(k, v);
  const qs = q.toString();
  let path = u.pathname;
  if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
  return `${u.protocol}//${u.host}${path}${qs ? `?${qs}` : ''}`;
}

/**
 * The site: the registrable domain of the URL's host per the Public Suffix
 * List, which is the persona context. `www.youtube.com` and `m.youtube.com`
 * are one site. Private suffixes count: `github.io` is one, so `alice.github.io`
 * and `bob.github.io` are two sites, because they are two publishers. A bare
 * host with no registrable domain (an IP address, localhost) is its own site.
 */
export function siteOf(url: string): string {
  const host = new URL(url).hostname.toLowerCase();
  return getDomain(host, { allowPrivateDomains: true }) ?? host;
}

/** The relying party identifier a persona derives from: `https://` + site. */
export function personaContext(site: string): string {
  return `https://${site}`;
}
