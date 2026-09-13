/**
 * What a read door may be asked, checked once and the same way everywhere.
 *
 * Every listing here used to read its own parameters. The result was that one
 * query meant four things depending on which door it was sent to (the QA of
 * 2026-09-12): `GET /read/{id}` ignored every parameter while its query twin
 * refused unknown ones; the read door took the first of a parameter given twice
 * where the delta stream refuses two values outright; `GET /events` accepted
 * both, where `/sync` and the entries listing refuse both; and
 * `/anchors?after=2026-13-45` passed a shape test that four digits, two digits
 * and two digits is all it asked, and answered an empty page about a day that
 * does not exist.
 *
 * So the rules live here, and a door names its own words for them. Refusing
 * rather than ignoring is the posture the frozen reader already had: a caller
 * who mistyped a filter and got the unfiltered answer back would believe they
 * had filtered it, and a caller who sent two values for one parameter asked two
 * questions, of which picking one is guessing.
 *
 * It lives beside the kernel rather than under src/worker/ because the frozen
 * reader's own query parser (src/read.ts) is one of its callers: the rules are
 * about what a question may look like, not about how a Worker answers one.
 *
 * Pure: no I/O, no clock, no storage. The bare integers in the date check are
 * the Gregorian calendar's own and not policy numbers.
 */

/** The words one door refuses a malformed query in. */
export interface QueryWords {
  /** A parameter this door does not take. */
  readonly unknown: string;
  /** A parameter given twice. */
  readonly repeated: string;
  /**
   * A value this door cannot read: a position that is not a position, a date
   * that is not a date, a limit outside the published page size. Defaults to
   * `unknown` where a door has only the one word.
   */
  readonly bad?: string;
}

/** Either the query held up, or the word this door refuses it in. */
export type QueryCheck = { ok: true } | { ok: false; reason: string };

/** A non-negative integer position, in plain decimal with no sign or padding. */
const NON_NEGATIVE_INTEGER = /^(?:0|[1-9][0-9]*)$/;

/** A positive integer page size, same spelling rule. */
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;

/** The shape of a UTC calendar day. Whether it is a real one is checked below. */
const CALENDAR_SHAPE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Month lengths, and February in a common year. The calendar's own numbers. */
const MONTH_LENGTHS: readonly number[] = Object.freeze([
  31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
]);

/** The Gregorian leap rule. */
function leapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

/**
 * Whether a string is a day that exists.
 *
 * The shape test alone accepted `2026-13-45`, which is four digits, two digits
 * and two digits and is not a day. An anchor is keyed by a real UTC day, so a
 * query naming one that never happens is a refusal rather than an empty page
 * that looks like a day with nothing in it.
 */
export function isCalendarDate(value: string): boolean {
  const match = CALENDAR_SHAPE.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > MONTH_LENGTHS.length) return false;
  const length =
    month === 2 && leapYear(year) ? MONTH_LENGTHS[1]! + 1 : MONTH_LENGTHS[month - 1]!;
  return day >= 1 && day <= length;
}

/**
 * The two rules every door shares: a parameter it does not take, and a
 * parameter given twice.
 *
 * `known` empty is a door that takes no query at all, which is most of the
 * reads: `GET /read/{id}`, `GET /standing`, `GET /ledger` and the two operator
 * reads answer one question about one path and have nothing to narrow.
 */
export function checkParameters(
  params: URLSearchParams,
  known: readonly string[],
  words: QueryWords,
): QueryCheck {
  const allowed = new Set(known);
  for (const name of params.keys()) {
    if (!allowed.has(name)) return { ok: false, reason: words.unknown };
  }
  for (const name of allowed) {
    if (params.getAll(name).length > 1) {
      return { ok: false, reason: words.repeated };
    }
  }
  return { ok: true };
}

/** The word a door reads a bad value in, which is its `unknown` where it has one. */
function badWord(words: QueryWords): string {
  return words.bad ?? words.unknown;
}

/** A non-negative position, or the caller's own default when it is absent. */
export function readPosition(
  params: URLSearchParams,
  name: string,
  fallback: number,
  words: QueryWords,
): { ok: true; value: number } | { ok: false; reason: string } {
  const raw = params.get(name);
  if (raw === null) return { ok: true, value: fallback };
  if (!NON_NEGATIVE_INTEGER.test(raw)) {
    return { ok: false, reason: badWord(words) };
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) return { ok: false, reason: badWord(words) };
  return { ok: true, value };
}

/** A real UTC calendar day, or the caller's own default when it is absent. */
export function readDate(
  params: URLSearchParams,
  name: string,
  fallback: string,
  words: QueryWords,
): { ok: true; value: string } | { ok: false; reason: string } {
  const raw = params.get(name);
  if (raw === null) return { ok: true, value: fallback };
  if (!isCalendarDate(raw)) return { ok: false, reason: badWord(words) };
  return { ok: true, value: raw };
}

/**
 * A page size inside the published bound, or that bound when it is absent.
 *
 * One rule for every listing: a positive integer, at most `max`, which is
 * `LIST_PAGE_LIMIT` everywhere it is asked. Zero and a negative are refused by
 * the spelling, and a limit above the ceiling is refused rather than clamped —
 * a caller who asked for five hundred rows and was handed a hundred would
 * believe they had seen them all.
 */
export function readLimit(
  params: URLSearchParams,
  max: number,
  words: QueryWords,
): { ok: true; value: number } | { ok: false; reason: string } {
  const raw = params.get("limit");
  if (raw === null) return { ok: true, value: max };
  if (!POSITIVE_INTEGER.test(raw)) return { ok: false, reason: badWord(words) };
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > max) {
    return { ok: false, reason: badWord(words) };
  }
  return { ok: true, value };
}
