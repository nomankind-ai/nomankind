/**
 * The day's write counters, cleared between tests.
 *
 * Decision D-130 charges a bare key and a probation operator at the
 * probationary per-agent cap (`WRITES_PER_AGENT_PER_DAY_PROBATION`), which is
 * deliberately small: a key nobody vouches for gets a day's honest work and no
 * more. A suite that drives a door with one bare key under one frozen clock is
 * one caller writing all day, so without this every long fixture would spend
 * that cap on itself and every later case would be answered 429 by the quota
 * rather than by the rule it is about.
 *
 * So each test starts the day fresh. Nothing about the cap is weakened: what
 * the caps are and which tier each door applies is pinned in
 * test/write-quota.test.ts and test/standing-tiers.test.ts, where the counters
 * are the subject rather than the fixture.
 */

import type { D1Like } from "../../src/storage/d1.js";

/** Forget every write the day has counted, in either bucket. */
export async function clearWriteQuota(db: D1Like): Promise<void> {
  await db.prepare(`DELETE FROM quota WHERE scope LIKE 'write:%'`).run();
}
