/**
 * The inline format.
 *
 *   ::ZOREAL-SIGNED:: <text> ::ZOREAL-SIGNATURE:<id>::
 *   ::ZOREAL-DELEGATED:: <text> ::ZOREAL-SIGNATURE:<id>::
 *
 * Both markers are ASCII so no platform re-encodes them, and the id is 24
 * characters of Crockford base32 so it survives being selected, copied and
 * typed. The markers are also the search key: searching a platform for
 * `::ZOREAL-SIGNATURE:` finds every Mark on it.
 */

export const OPEN_SIGNED = '::ZOREAL-SIGNED::';
export const OPEN_DELEGATED = '::ZOREAL-DELEGATED::';
export const CLOSE_PREFIX = '::ZOREAL-SIGNATURE:';
export const CLOSE_SUFFIX = '::';

/** Crockford base32: digits and letters without I, L, O and U. */
export const ID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{24}$/;

export type Marker = 'signed' | 'delegated';

export interface FoundMark {
  marker: Marker;
  /** The text between the markers, exactly as found, before canonicalisation. */
  text: string;
  id: string;
  /** Offsets of the whole Mark, opening marker to closing marker inclusive. */
  start: number;
  end: number;
}

export interface BrokenMarker {
  marker: Marker;
  start: number;
  /** Why the scanner could not complete it. */
  reason: 'no_closing_marker' | 'bad_id';
}

export function isValidId(id: string): boolean {
  return ID_PATTERN.test(id);
}

const OPEN_RE = /::ZOREAL-(SIGNED|DELEGATED)::/g;
const CLOSE_RE = /::ZOREAL-SIGNATURE:([0-9A-Za-z]{1,64})::/g;

/**
 * Finds every complete Mark in a string. A Mark opens at a marker and closes at
 * the FIRST closing marker after it; an opening marker inside that span is
 * text, never a nested Mark. Multiple Marks in one string are independent.
 */
export function findMarks(input: string): FoundMark[] {
  const out: FoundMark[] = [];
  let from = 0;
  for (;;) {
    OPEN_RE.lastIndex = from;
    const open = OPEN_RE.exec(input);
    if (!open) break;
    CLOSE_RE.lastIndex = open.index + open[0].length;
    const close = CLOSE_RE.exec(input);
    if (!close) break;
    const id = close[1]!;
    if (isValidId(id)) {
      const raw = input.slice(open.index + open[0].length, close.index);
      out.push({
        marker: open[1] === 'DELEGATED' ? 'delegated' : 'signed',
        text: trimSingleSeparators(raw),
        id,
        start: open.index,
        end: close.index + close[0].length,
      });
    }
    from = close.index + close[0].length;
  }
  return out;
}

/**
 * Opening markers that never became a Mark: no closing marker followed, or the
 * id after the closing marker is not 24 Crockford characters. A truncating
 * platform produces the first; a typo produces the second. Both render as
 * "no signature found", and a UI needs the position to say so in place.
 */
export function findBrokenMarkers(input: string): BrokenMarker[] {
  const out: BrokenMarker[] = [];
  let from = 0;
  for (;;) {
    OPEN_RE.lastIndex = from;
    const open = OPEN_RE.exec(input);
    if (!open) break;
    CLOSE_RE.lastIndex = open.index + open[0].length;
    const close = CLOSE_RE.exec(input);
    const marker: Marker = open[1] === 'DELEGATED' ? 'delegated' : 'signed';
    if (!close) {
      out.push({ marker, start: open.index, reason: 'no_closing_marker' });
      break;
    }
    if (!isValidId(close[1]!)) out.push({ marker, start: open.index, reason: 'bad_id' });
    from = close.index + close[0].length;
  }
  return out;
}

/** Wraps text in the markers, the way a signer inserts it. */
export function wrap(text: string, id: string, marker: Marker = 'signed'): string {
  if (!isValidId(id)) throw new Error('id is not 24 Crockford base32 characters');
  const open = marker === 'delegated' ? OPEN_DELEGATED : OPEN_SIGNED;
  return `${open} ${text} ${CLOSE_PREFIX}${id}${CLOSE_SUFFIX}`;
}

/**
 * The format puts one space between each marker and the text. Canonicalisation
 * trims anyway, so this only affects what a UI shows as "the text".
 */
function trimSingleSeparators(raw: string): string {
  let s = raw;
  if (s.startsWith(' ')) s = s.slice(1);
  if (s.endsWith(' ')) s = s.slice(0, -1);
  return s;
}
