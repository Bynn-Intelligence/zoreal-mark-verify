import { sha256, toHex, utf8 } from './bytes.js';

/**
 * The canonical text: what is signed, because the bytes in the box are not
 * what the platform stores. Platforms normalise Unicode on save, curl straight
 * quotes, collapse double spaces, rewrite line breaks, strip trailing
 * whitespace and swap en dashes for em dashes. The fold below survives all of
 * that and reaches nothing else: no case folding, no letter folding, no digit
 * folding, no reordering. What an attacker can change inside the fold is
 * exactly what the fold lists, and nothing more.
 *
 * The signer and every verifier apply this identically, in this order:
 *
 *   1. Unicode NFC.
 *   2. Curly single quotes to ', curly double quotes to ".
 *   3. En dash, em dash and the minus sign to -.
 *   4. The ellipsis character to three periods.
 *   5. Non-breaking and other Unicode spaces to a space.
 *   6. Every run of whitespace, including line breaks and tabs, to one space.
 *   7. Trim.
 *
 * Steps 5 and 6 overlap on purpose: 6 uses ECMAScript's WhiteSpace and
 * LineTerminator classes, which already include every Unicode space, so an
 * implementation in another language must match THAT set, listed here so it
 * can: U+0009-000D, U+0020, U+00A0, U+1680, U+2000-200A, U+2028, U+2029,
 * U+202F, U+205F, U+3000 and U+FEFF.
 */
export function canonicalText(raw: string): string {
  return raw
    .normalize('NFC')
    .replace(/[‘’‚‛]/g, "'")
    .replace(/[“”„‟]/g, '"')
    .replace(/[–—−]/g, '-')
    .replace(/…/g, '...')
    .replace(/[   -   　]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Lowercase hex SHA-256 of the UTF-8 canonical text: `payload.hash`. */
export async function textHash(raw: string): Promise<string> {
  return toHex(await sha256(utf8(canonicalText(raw))));
}
