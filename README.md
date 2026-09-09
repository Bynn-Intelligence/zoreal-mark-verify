# @zoreal/mark-verify

[![npm](https://img.shields.io/npm/v/@zoreal/mark-verify)](https://www.npmjs.com/package/@zoreal/mark-verify) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-mark-verify/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-mark-verify/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Verify a ZOREAL Mark: a real human, verified by ZOREAL, vouched for exactly this
text, on exactly this page, at exactly this time.

```text
::ZOREAL-MARK:: I was at the launch and the demo was real. ::ZOREAL-SIGNATURE:7QK39F2MXR84B5NPD4T6HW2A::
```

This is the one verifier implementation. The Chrome and Safari extensions, the
verify page and the badge script all call it; none of them re-implements a
step. It runs wherever Web Crypto runs: browsers, extension service workers,
Node 22 and later.

## Status

**Not yet usable against live records.** The record service that serves
`https://zoreal.com/mark/<id>` is being built. Until it serves records, this
package verifies its own conformance fixtures and nothing else. This section is
kept true.

## Install

```sh
npm install @zoreal/mark-verify
```

Dependencies: `@noble/post-quantum` (ML-DSA, which no browser exposes yet),
`@peculiar/asn1-*` (X.509, CMS and RFC 3161 parsing), `canonicalize` (RFC 8785)
and `tldts` (the Public Suffix List). ESM and CJS.

## Use

```ts
import { findMarks, verifyMark } from '@zoreal/mark-verify';

const marks = findMarks(commentText);
for (const mark of marks) {
  const result = await verifyMark(mark, {
    pageUrl: location.href,
    fetchRecord: async (id) => {
      const res = await fetch(`https://zoreal.com/mark/${id}`, { headers: { Accept: 'application/json' }, credentials: 'omit' });
      if (res.status === 404) return { status: 'not_found' };
      if (!res.ok) return { status: 'unavailable', reason: `HTTP ${res.status}` };
      return { status: 'ok', record: await res.json() };
    },
  });
  console.log(result.verdict, result.reason ?? '', result.subject, result.time);
}
```

`verdict` is one of:

| Verdict | Meaning |
|---|---|
| `verified_here` | Everything checks and the record was signed for this page |
| `verified_in_channel` | Same, for a chat channel binding |
| `verified_email` | Same, for an email binding: this sender, these recipients |
| `verified_email_other_recipients`, `verified_email_other_sender` | The email was forwarded, or the From differs |
| `verified_other_page` | Everything checks; the record names a different page, in `signedUrl` |
| `verified_unbound` | Everything checks; the Mark was made without a page |
| `delegated` | Posted by an agent operated by a verified human; `delegation` names them |
| `withdrawn` | The signer withdrew it; `withdrawn.at` says when. The signature is still valid |
| `cannot_verify_now` | The record could not be fetched and is not cached. Never shown as a failure |
| `not_verified` | A check failed; `reason` says which in one line and `failedStep` which step |
| `no_signature` | The id is not 24 Crockford base32 characters |

Only a URL match earns the strong badge. A UI must draw `verified_other_page`
and `verified_unbound` in a visibly weaker style, and must never draw
`delegated` as a human verdict.

`fetchRecord` is yours, so caching and mirrors are yours: records are
immutable once their timestamp is confirmed. Fetch without credentials.

## What is checked, in order, failing closed

1. The markers and the id.
2. The record. Unreachable is `cannot_verify_now`, never `not_verified`.
3. The classical certificate chain to the pinned ECDSA P-384 root.
4. The post-quantum chain to the pinned ML-DSA-87 root, and that the two chains are the pair the issuer bound together.
5. Revocation, from the Token Status Lists the record carries, judged as of the timestamp.
6. Key usage: a content-commitment certificate with the document-signing purpose. An authentication certificate is refused.
7. The certificate demands a presence attestation and one is present.
8. The attestation's two signatures (ES256 and ML-DSA-65), each under a chain to its root, both leaves carrying the presence-signing key purpose.
9. The attestation's bindings: audience, nonce, expiry as of the timestamp, single-use id, the device key thumbprint, and that it countersigns exactly this device signature.
10. The presence grade and channel.
11. The device signature over the signed envelope, and that the envelope names the exact certificate.
12. The RFC 3161 timestamp: the Merkle inclusion proof, the token's imprint, its signature, and its chain to a pinned timestamping anchor. A token that fails leaves the time unconfirmed; it never confirms it.
13. The text on the page, canonicalised, hashes to what was signed.
14. The binding: the page URL, the channel, the email sender and recipients, or none.
15. A withdrawal, if any, under the record service key.
16. A delegation, if any: the human's signed statement, its window, its site, the agent's key.
17. Co-signing and reply relations.
18. Appended events (co-signer count, report count, tree head) under the record service key.

Every certificate validity is judged **as of the confirmed timestamp**, never
as of the verifier's clock. A Mark made in 2027 verifies in 2032 against a
certificate that expired in 2031.

## The trust anchors

Both root SubjectPublicKeyInfo SHA-256 digests are compiled into
`src/roots.ts` and are never fetched:

| Root | Algorithm | SPKI SHA-256 |
|---|---|---|
| ZOREAL Root CA 1 | ECDSA P-384 | `Q6N1FDet9QG5T9UztVKbsXvQylB3eNiN5UIKxDp1p3k=` |
| ZOREAL Post-Quantum Root CA 1 | ML-DSA-87 | `rxr4sieLvSvCB/jCnoA56LaZQdqNuC7nq01uHuDnm/0=` |

The same digests are published in the DNSSEC-signed record
`_zoreal-pki.zoreal.com` and on the ZOREAL ID app's about screen. A record
whose chains do not reach both is invalid from any source, ZOREAL's own
included. There is no fallback that accepts an unpinned anchor when the pinned
one fails; that fallback is the attack.

Timestamps are anchored to DigiCert Trusted Root G4
(`Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNkcpw=`), which is what
`timestamp.digicert.com` chained to when measured. Pass your own
`anchors.timestamping` to change it.

## Canonical text

What is signed is the canonical form of the text, so a Mark survives the
rewriting platforms do on save. The fold, applied identically by the signer
and every verifier: Unicode NFC; curly quotes to straight; en dash, em dash and
the minus sign to `-`; the ellipsis character to three periods; every run of
whitespace (including Unicode spaces and line breaks) to one space; trim. It
reaches punctuation and spacing and nothing else: no case folding, no letter
folding, no digit folding, no reordering. `canonicalText` and `textHash` are
exported so a signer uses the same code.

`normaliseUrl` and `siteOf` are exported for the same reason: the URL inside
the signed payload and the page a verifier compares it to must be normalised
by one implementation.

## Conformance fixtures

`fixtures/` holds a generated test hierarchy mirroring production and one
record per case, 48 cases in all: every happy path and a record that fails
each verification step alone. `fixtures/index.json` lists the cases with their
expected verdicts; `fixtures/anchors.json` pins the fixture roots. A verifier
implementation in another language can run the same cases. Regenerate with
`npm run fixtures`; keys are made fresh each run and never written.

## Development

```sh
npm install
npm run build      # tsup, ESM and CJS into dist/
npm run fixtures   # rebuild and regenerate fixtures/
npm test           # vitest
npm run typecheck
```

## What a Mark asserts, and does not

A Mark asserts that a human verified by ZOREAL vouched for this text, that a live
human was present when it was signed at the stated grade, that it was signed
for this page, and that it was signed at this time. It does not assert that the
human wrote the text, that the text is true, that the persona is one person
across sites, or anything about the platform account that posted it. Every
surface built on this library says **vouched for**; none says written by.

## Security

See [SECURITY.md](./SECURITY.md).

## License

MIT
