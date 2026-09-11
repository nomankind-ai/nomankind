import { defineConfig } from "vitest/config";

/**
 * On macOS the full suite runs out of loopback ports, so it runs two workers
 * wide there and full width everywhere else.
 *
 * The storage tests talk to a real D1 and R2 through wrangler's
 * `getPlatformProxy`, and every proxied binding call is one HTTP request from
 * the vitest worker to miniflare's workerd. miniflare's own dispatcher sets
 * undici's `reset: true` on each of those requests, which sends
 * `connection: close`, so the socket is torn down after every call instead of
 * being kept alive in the pool it already holds. One call, one connection, one
 * socket left in TIME_WAIT for about thirty seconds.
 *
 * Measured on an Apple laptop, 2026-09-11, against the 16,384 ephemeral ports
 * macOS hands out (49152 to 65535): one storage file alone leaves about 1,100
 * sockets in TIME_WAIT; a full run at default width leaves about 15,200 to
 * 15,800, near enough the ceiling that a handful of storage-backed files fail
 * with `connect EADDRNOTAVAIL 127.0.0.1:<port>` depending on timing. Four
 * workers leaves about 8,700 and passes, but that is barely half the ceiling
 * and the machine is shared with whatever else is running. Two workers leaves
 * about 2,900, roughly a fifth of the ceiling, and takes about 105 seconds
 * against 32 at full width — the extra minute buys the headroom.
 *
 * Linux does not run out (a far larger ephemeral range and a shorter
 * TIME_WAIT), so CI keeps every core.
 */
const isMacOS = process.platform === "darwin";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    ...(isMacOS ? { minWorkers: 1, maxWorkers: 2 } : {}),
  },
});
