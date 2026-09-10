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

/**
 * What a transfer attempt says. `unavailable` is the adapter's own answer again
 * — nobody asked, because no provider is wired — and it is deliberately not the
 * same as `failed`: a payout that was never attempted must be retried next
 * cycle, and one the provider refused must not be retried until somebody looks.
 */
export type PayoutTransfer =
  | { readonly ok: true; readonly transfer: string }
  | { readonly ok: false; readonly reason: "unavailable" | "failed" };

/**
 * Somewhere to ask whether an operator's payout onboarding is complete, and
 * somewhere to send a cycle's money once it is.
 *
 * `transfer` takes micro-USD because that is the unit the ledger counts in
 * (src/ledger.ts); converting to whatever a provider wants is the adapter's job
 * and never the ledger's. It takes the onboarding reference rather than an
 * operator id: the adapter knows nothing about operators, and the reference is
 * the only thing the provider has ever heard of.
 */
export interface PayoutAdapter {
  status(reference: string): Promise<PayoutStatus>;
  transfer(reference: string, amountMicros: number): Promise<PayoutTransfer>;
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
  /** How many transfers this instance has made: the mock's own receipt number. */
  #transfers = 0;

  async status(reference: string): Promise<PayoutStatus> {
    if (reference.startsWith(MOCK_VERIFIED_PREFIX)) return "verified";
    if (reference.startsWith(MOCK_PENDING_PREFIX)) return "pending";
    return "failed";
  }

  /**
   * Money "moves" only for a reference the mock would also call verified, so a
   * demo cannot pay an operator whose onboarding it just said was pending. The
   * transfer id is a counter and nothing more: it is the mock's wire format, the
   * same as the prefixes above, and it is meaningless to the adapter M25
   * replaces this with.
   */
  async transfer(
    reference: string,
    _amountMicros: number,
  ): Promise<PayoutTransfer> {
    if (!reference.startsWith(MOCK_VERIFIED_PREFIX)) {
      return { ok: false, reason: "failed" };
    }
    this.#transfers += 1;
    return { ok: true, transfer: `mock-transfer-${this.#transfers}` };
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

  /**
   * Nothing leaves in production until M25 wires the provider. "unavailable"
   * and never "failed": the cycle that meets this must carry the accrual
   * forward untouched, and a failure would say the money was refused.
   */
  async transfer(
    _reference: string,
    _amountMicros: number,
  ): Promise<PayoutTransfer> {
    return { ok: false, reason: "unavailable" };
  }
}

/**
 * The only environment name written down in src/, and it is here because the
 * refusal is the point: production must not be able to fall through to a mock
 * by a missing branch elsewhere, so production is named and everything else
 * gets the mock. The witness and anchor adapters import it from here for the
 * same reason, so the name exists once.
 */
export const PRODUCTION = "production";

/** The adapter this environment runs (decision D-013 as amended). */
export function payoutAdapterFor(environment: string): PayoutAdapter {
  return environment === PRODUCTION
    ? new UnavailablePayoutAdapter()
    : new MockPayoutAdapter();
}
