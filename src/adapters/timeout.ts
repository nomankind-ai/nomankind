/**
 * The deadline every outbound call is made under, and the timer cleared the
 * moment the call is done.
 *
 * `AbortSignal.timeout(ms)` looks like the same thing and is not: the timer it
 * schedules cannot be cancelled, and on workerd a pending timer keeps the
 * invocation alive until it fires. A sweep whose one network call answered in
 * fifty milliseconds still held its alarm open for the whole thirty-second
 * window, which is exactly what the demo deployment showed — thirty seconds of
 * wall time against forty-six milliseconds of CPU, on a run whose report said
 * nothing was wrong. Every timeout in this system is therefore a controller and
 * a timer that is cleared in a `finally`, the way src/adapters/fetch.ts's
 * capture has always done it.
 *
 * The number is never this module's: each caller passes src/policy.ts's own.
 */

/**
 * Why a call was given up on, in the word `AbortSignal.timeout` uses.
 *
 * The reason travels: `fetch` rejects with whatever the signal was aborted
 * with, so a caller reading `error.name` sees "TimeoutError" here exactly as it
 * did before, and the records that name a silent endpoint keep saying the thing
 * that happened rather than the mechanism that noticed it.
 */
function timedOut(timeoutMs: number): DOMException {
  return new DOMException(
    `the call ran past its ${timeoutMs}ms deadline`,
    "TimeoutError",
  );
}

/**
 * Run one call under a deadline. The signal is aborted when the window runs
 * out, and the timer is cleared whether the call answered, threw, or was the
 * one that timed out — so nothing outlives the call.
 */
export async function withDeadline<T>(
  timeoutMs: number,
  call: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(timedOut(timeoutMs)), timeoutMs);
  try {
    return await call(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}
