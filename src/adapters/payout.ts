/**
 * Payout onboarding, the second joining step.
 *
 * Whitepaper Section 11: "Complete payout onboarding with the payment provider,
 * business verification for a company or identity verification for a person."
 * Section 5 says why it is a joining step at all: every payout lands on a real
 * legal entity, so a burned operator loses a payment record that does not
 * respawn for the cost of a domain.
 *
 * Decision D-013 as amended: the real provider is M25's. Until then demo and
 * local run a mock, and production runs a stub that refuses. The stub answers
 * "unavailable", never "verified": the PoC retrospective's rule is that a stub
 * fails loud, and a stub that quietly passed everyone would let production
 * register operators whose money was never checked — the one thing this step
 * exists to prevent.
 */

/**
 * What the payment provider says about an onboarding reference. "unavailable"
 * is the adapter's own answer, not the provider's: it means nobody asked.
 */
export type PayoutStatus = "verified" | "pending" | "failed" | "unavailable";

/** Somewhere to ask whether an operator's payout onboarding is complete. */
export interface PayoutAdapter {
  status(reference: string): Promise<PayoutStatus>;
}

/**
 * The prefixes the mock reads. They are the mock's own wire format, not policy:
 * they exist so a demo can walk all three outcomes without a payment provider,
 * and they are meaningless to the adapter M25 replaces this with.
 */
export const MOCK_VERIFIED_PREFIX = "mock-verified-";
export const MOCK_PENDING_PREFIX = "mock-pending-";

/**
 * The mock for demo and local. A reference says its own outcome, so a caller
 * can exercise the pending and failed paths as easily as the happy one, and
 * every reference that says nothing is failed rather than verified.
 */
export class MockPayoutAdapter implements PayoutAdapter {
  async status(reference: string): Promise<PayoutStatus> {
    if (reference.startsWith(MOCK_VERIFIED_PREFIX)) return "verified";
    if (reference.startsWith(MOCK_PENDING_PREFIX)) return "pending";
    return "failed";
  }
}

/**
 * Production, until M25 wires the real provider. It answers "unavailable" to
 * everything, which the Worker turns into a 503: the door is shut and says so,
 * rather than pretending to have checked.
 */
export class UnavailablePayoutAdapter implements PayoutAdapter {
  async status(_reference: string): Promise<PayoutStatus> {
    return "unavailable";
  }
}

/**
 * The only environment name written down in src/, and it is here because the
 * refusal is the point: production must not be able to fall through to a mock
 * by a missing branch elsewhere, so production is named and everything else
 * gets the mock.
 */
const PRODUCTION = "production";

/** The adapter this environment runs (decision D-013 as amended). */
export function payoutAdapterFor(environment: string): PayoutAdapter {
  return environment === PRODUCTION
    ? new UnavailablePayoutAdapter()
    : new MockPayoutAdapter();
}
