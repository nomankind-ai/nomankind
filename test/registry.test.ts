/**
 * The registry's two doors, tested against real keys.
 *
 * Every attestation here is signed by a real Ed25519 key through WebCrypto and
 * verified back through the agent id, so a test that passes says the signature
 * holds and not that a fake agreed with itself.
 */

import { describe, expect, it } from "vitest";

import { appendEvent, type Event } from "../src/events.js";
import { agentOperatorsAt } from "../src/derive.js";
import { base64urlDecode, base64urlEncode } from "../src/encoding.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  REQUEST_CLOCK_SKEW_SECONDS,
  excludedPartyDomains,
} from "../src/policy.js";
import {
  AGENT_BIND_REFUSALS,
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  DNS_LABEL_MAX_LENGTH,
  DNS_NAME_MAX_LENGTH,
  GENESIS_REFUSALS,
  HASH_TAG_ATTESTATION,
  REGISTRATION_REFUSALS,
  TXT_RECORD_PREFIX,
  attestationSigningBytes,
  checkAgentBind,
  checkGenesisNaming,
  checkRegistration,
  isOperatorDomain,
  isProviderDomain,
  parseAgentBindBody,
  parseGenesisBody,
  parseRegistrationBody,
  signAttestation,
  txtMatches,
  txtRecordName,
  verifyAttestation,
} from "../src/registry.js";

const OPERATOR = "lattice.example";
const OTHER_OPERATOR = "beacon.example";
const SIGNED_AT = "2026-09-07T12:00:00Z";

interface Agent {
  readonly id: string;
  readonly privateKey: CryptoKey;
}

async function makeAgent(): Promise<Agent> {
  const pair = await generateKeypair();
  const raw = await exportPublicKeyRaw(pair.publicKey);
  return { id: agentIdFromPublicKey(raw), privateKey: pair.privateKey };
}

const agent = await makeAgent();
const maintainerAgent = await makeAgent();
const otherAgent = await makeAgent();

const attestation = await signAttestation(agent.privateKey, {
  operator: OPERATOR,
  agent: agent.id,
  signed_at: SIGNED_AT,
});

/** A second key for the same operator, and the sentence it signed itself. */
const secondAgent = await makeAgent();
const secondAttestation = await signAttestation(secondAgent.privateKey, {
  operator: OPERATOR,
  agent: secondAgent.id,
  signed_at: SIGNED_AT,
});

/** A registration that passes every check, so each test can spoil one thing. */
function registration(overrides: Partial<Parameters<typeof checkRegistration>[0]> = {}) {
  return {
    operator: OPERATOR,
    agent: agent.id,
    attestation: attestation as unknown,
    maintainerAgentId: maintainerAgent.id,
    operatorExists: false,
    agentOperator: null,
    ...overrides,
  };
}

/** A genesis naming that passes every check. */
function genesis(overrides: Partial<Parameters<typeof checkGenesisNaming>[0]> = {}) {
  return {
    signer: maintainerAgent.id,
    maintainerAgentId: maintainerAgent.id,
    operator: OPERATOR,
    registered: true,
    maintainerOperator: false,
    provider: false,
    trusted: false,
    ...overrides,
  };
}

describe("the independence attestation", () => {
  it("signs the Section 10 sentence under the one version there is", () => {
    expect(ATTESTATION_VERSION).toBe("nomankind-independence-v1");
    expect(ATTESTATION_TEXT).toBe(
      "No model provider holds control of, or a beneficial stake in, this operator.",
    );
    expect(attestation.version).toBe(ATTESTATION_VERSION);
    expect(attestation.signed_at).toBe(SIGNED_AT);
    expect(() => base64urlDecode(attestation.signature)).not.toThrow();
  });

  it("signs the tag, the sentence and the bound facts, in canonical order", () => {
    const bytes = attestationSigningBytes({
      operator: OPERATOR,
      agent: agent.id,
      version: ATTESTATION_VERSION,
      signed_at: SIGNED_AT,
    });
    expect(new TextDecoder().decode(bytes)).toBe(
      `${HASH_TAG_ATTESTATION}\n` +
        JSON.stringify({
          agent: agent.id,
          operator: OPERATOR,
          signed_at: SIGNED_AT,
          text: ATTESTATION_TEXT,
          version: ATTESTATION_VERSION,
        }),
    );
  });

  it("verifies what it signed", async () => {
    expect(await verifyAttestation(OPERATOR, agent.id, attestation)).toBe(true);
  });

  it("refuses a flipped signature byte", async () => {
    const bytes = base64urlDecode(attestation.signature);
    bytes[0] = bytes[0]! ^ 0x01;
    const tampered = { ...attestation, signature: base64urlEncode(bytes) };
    expect(await verifyAttestation(OPERATOR, agent.id, tampered)).toBe(false);
  });

  it("refuses a changed operator", async () => {
    expect(await verifyAttestation(OTHER_OPERATOR, agent.id, attestation)).toBe(
      false,
    );
  });

  it("refuses a changed agent", async () => {
    expect(await verifyAttestation(OPERATOR, otherAgent.id, attestation)).toBe(
      false,
    );
  });

  it("refuses an unknown version", async () => {
    const other = { ...attestation, version: "nomankind-independence-v2" };
    expect(await verifyAttestation(OPERATOR, agent.id, other)).toBe(false);
  });

  it("refuses a non-ISO signed_at", async () => {
    const undated = await signAttestation(agent.privateKey, {
      operator: OPERATOR,
      agent: agent.id,
      signed_at: "yesterday",
    });
    expect(await verifyAttestation(OPERATOR, agent.id, undated)).toBe(false);
  });

  it("answers false, never throws, on a malformed object", async () => {
    for (const bad of [
      null,
      undefined,
      "attested",
      42,
      [],
      {},
      { version: ATTESTATION_VERSION },
      { ...attestation, signature: "not base64url!" },
      { ...attestation, signature: "" },
      { ...attestation, signature: 7 },
      { ...attestation, signed_at: null },
    ]) {
      await expect(
        verifyAttestation(OPERATOR, agent.id, bad),
      ).resolves.toBe(false);
    }
    // An agent id that carries no key is a "no" as well, not an exception.
    await expect(
      verifyAttestation(OPERATOR, "not-an-agent", attestation),
    ).resolves.toBe(false);
  });
});

describe("domain control", () => {
  it("names the record an operator publishes", () => {
    expect(TXT_RECORD_PREFIX).toBe("_nomankind");
    expect(txtRecordName(OPERATOR)).toBe(`_nomankind.${OPERATOR}`);
  });

  it("accepts the exact agent id among several values, and nothing else", () => {
    expect(txtMatches(["v=spf1 -all", agent.id, "other"], agent.id)).toBe(true);
    expect(txtMatches([`  ${agent.id}\n`], agent.id)).toBe(true);
    expect(txtMatches([], agent.id)).toBe(false);
    expect(txtMatches(["v=spf1 -all"], agent.id)).toBe(false);
    expect(txtMatches([otherAgent.id], agent.id)).toBe(false);
    expect(txtMatches([`nomankind=${agent.id}`], agent.id)).toBe(false);
    expect(txtMatches([`${agent.id}extra`], agent.id)).toBe(false);
  });

  it("accepts a lowercase hostname of at least two labels", () => {
    for (const domain of [
      "example.com",
      "a.b",
      "sub.domain.example.co.uk",
      "x-1.example",
      "01.ai",
    ]) {
      expect(isOperatorDomain(domain)).toBe(true);
    }
  });

  it("refuses anything that is not one", () => {
    for (const bad of [
      "Example.com",
      "example",
      "example.com.",
      ".example.com",
      "example..com",
      "-example.com",
      "example-.com",
      "exa mple.com",
      "https://example.com",
      "example.com/path",
      "café.example",
      "",
      42,
      null,
      undefined,
      ["example.com"],
    ]) {
      expect(isOperatorDomain(bad)).toBe(false);
    }
  });

  it("holds the RFC 1035 lengths, and refuses names that break them", () => {
    expect(DNS_LABEL_MAX_LENGTH).toBe(63);
    expect(DNS_NAME_MAX_LENGTH).toBe(253);
    expect(isOperatorDomain(`${"a".repeat(63)}.com`)).toBe(true);
    expect(isOperatorDomain(`${"a".repeat(64)}.com`)).toBe(false);

    const labels: string[] = [];
    while (labels.join(".").length <= DNS_NAME_MAX_LENGTH) {
      labels.push("a".repeat(9));
    }
    expect(labels.join(".").length).toBeGreaterThan(DNS_NAME_MAX_LENGTH);
    expect(isOperatorDomain(labels.join("."))).toBe(false);
  });

  it("knows a provider domain and every subdomain of one", () => {
    expect(isProviderDomain("openai.com")).toBe(true);
    expect(isProviderDomain("research.openai.com")).toBe(true);
    expect(isProviderDomain("anthropic.com")).toBe(true);
    expect(isProviderDomain("lattice.example")).toBe(false);
    // Not a suffix at a label boundary, so not a provider.
    expect(isProviderDomain("notopenai.com")).toBe(false);
    expect(isProviderDomain("openai.com.example")).toBe(false);
    for (const provider of excludedPartyDomains(DEFAULT_DOMAIN)) {
      expect(isProviderDomain(provider)).toBe(true);
    }
    // A fork runs its own list.
    expect(isProviderDomain("openai.com", ["only.example"])).toBe(false);
    expect(isProviderDomain("sub.only.example", ["only.example"])).toBe(true);
  });
});

describe("request bodies", () => {
  const body = {
    operator: OPERATOR,
    attestation,
    payout: { reference: "acct_123" },
  };

  it("reads a registration body", () => {
    const parsed = parseRegistrationBody(body);
    expect(parsed).toEqual({
      ok: true,
      value: {
        operator: OPERATOR,
        domain: null,
        attestation,
        payout: { reference: "acct_123" },
      },
    });
  });

  it("refuses extra keys and wrong types", () => {
    for (const bad of [
      null,
      undefined,
      "body",
      [],
      {},
      { ...body, extra: true },
      { operator: OPERATOR, attestation },
      { ...body, operator: 42 },
      { ...body, attestation: "signed" },
      { ...body, attestation: 42 },
      { ...body, attestation: [] },
      { ...body, payout: "acct_123" },
      { ...body, payout: {} },
      { ...body, payout: { reference: "" } },
      { ...body, payout: { reference: 42 } },
    ]) {
      expect(parseRegistrationBody(bad)).toEqual({
        ok: false,
        reason: "bad_body",
      });
    }
  });

  it("parses an absent or null attestation as none, not as a bad body", async () => {
    // The parser's job is shape, not judgement: a body that simply left the
    // attestation out is well formed and refused by name one step later, which
    // is the refusal REGISTRATION_REFUSALS lists.
    const { attestation: _omitted, ...withoutAttestation } = body;
    for (const missing of [withoutAttestation, { ...body, attestation: null }]) {
      const parsed = parseRegistrationBody(missing);
      expect(parsed).toEqual({
        ok: true,
        value: {
          operator: OPERATOR,
          domain: null,
          attestation: null,
          payout: { reference: "acct_123" },
        },
      });
    }

    // And what the parser hands on is what checkRegistration names.
    const parsed = parseRegistrationBody(withoutAttestation);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(
        await checkRegistration(
          registration({ attestation: parsed.value.attestation }),
        ),
      ).toEqual({ ok: false, reason: "missing_attestation" });
    }
  });

  it("reads a genesis body, and refuses extra keys and wrong types", () => {
    expect(parseGenesisBody({ operator: OPERATOR })).toEqual({
      ok: true,
      value: { operator: OPERATOR },
    });
    for (const bad of [
      null,
      undefined,
      "operator",
      [],
      {},
      { operator: OPERATOR, extra: 1 },
      { operator: 42 },
    ]) {
      expect(parseGenesisBody(bad)).toEqual({ ok: false, reason: "bad_body" });
    }
  });
});

describe("checkRegistration", () => {
  it("names its refusals in check order", () => {
    expect(REGISTRATION_REFUSALS).toEqual([
      "bad_domain",
      "unregistered_domain",
      "provider_operator",
      "missing_attestation",
      "bad_attestation",
      "attestation_domain_mismatch",
      "operator_exists",
      "agent_bound",
    ]);
  });

  it("admits an operator that passes every check", async () => {
    expect(await checkRegistration(registration())).toEqual({
      ok: true,
      maintainer: false,
      domain: DEFAULT_DOMAIN,
    });
  });

  it("marks the maintainer's own registration, and no one else's", async () => {
    const theirs = await signAttestation(maintainerAgent.privateKey, {
      operator: OPERATOR,
      agent: maintainerAgent.id,
      signed_at: SIGNED_AT,
    });
    expect(
      await checkRegistration(
        registration({ agent: maintainerAgent.id, attestation: theirs }),
      ),
    ).toEqual({ ok: true, maintainer: true, domain: DEFAULT_DOMAIN });
    expect(await checkRegistration(registration())).toEqual({
      ok: true,
      maintainer: false,
      domain: DEFAULT_DOMAIN,
    });
    // No maintainer configured: nobody is the maintainer.
    expect(
      await checkRegistration(registration({ maintainerAgentId: null })),
    ).toEqual({ ok: true, maintainer: false, domain: DEFAULT_DOMAIN });
  });

  it("refuses a bad domain", async () => {
    for (const operator of [
      "Lattice.example",
      "lattice",
      "lattice.example.",
      `${"a".repeat(64)}.example`,
    ]) {
      expect(await checkRegistration(registration({ operator }))).toEqual({
        ok: false,
        reason: "bad_domain",
      });
    }
  });

  it("refuses a model provider and any subdomain of one", async () => {
    for (const operator of ["openai.com", "labs.anthropic.com"]) {
      expect(await checkRegistration(registration({ operator }))).toEqual({
        ok: false,
        reason: "provider_operator",
      });
    }
    expect(
      await checkRegistration(
        registration({ operator: OPERATOR, providers: [OPERATOR] }),
      ),
    ).toEqual({ ok: false, reason: "provider_operator" });
  });

  it("refuses a missing attestation", async () => {
    for (const missing of [null, undefined]) {
      expect(
        await checkRegistration(registration({ attestation: missing })),
      ).toEqual({ ok: false, reason: "missing_attestation" });
    }
  });

  it("refuses an attestation that does not verify", async () => {
    for (const bad of [
      {},
      "signed",
      { ...attestation, version: "nomankind-independence-v2" },
      await signAttestation(otherAgent.privateKey, {
        operator: OPERATOR,
        agent: agent.id,
        signed_at: SIGNED_AT,
      }),
    ]) {
      expect(await checkRegistration(registration({ attestation: bad }))).toEqual(
        { ok: false, reason: "bad_attestation" },
      );
    }
  });

  it("refuses an operator that already exists", async () => {
    expect(
      await checkRegistration(registration({ operatorExists: true })),
    ).toEqual({ ok: false, reason: "operator_exists" });
  });

  it("refuses an agent already bound to an operator", async () => {
    expect(
      await checkRegistration(registration({ agentOperator: OTHER_OPERATOR })),
    ).toEqual({ ok: false, reason: "agent_bound" });
  });

  it("reports the first refusal when several apply, in that order", async () => {
    // Everything is wrong at once; each case removes the failure above it.
    const allWrong = {
      operator: "OpenAI.com",
      attestation: null as unknown,
      operatorExists: true,
      agentOperator: OTHER_OPERATOR,
    };
    expect(await checkRegistration(registration(allWrong))).toEqual({
      ok: false,
      reason: "bad_domain",
    });
    expect(
      await checkRegistration(registration({ ...allWrong, operator: "openai.com" })),
    ).toEqual({ ok: false, reason: "provider_operator" });
    expect(
      await checkRegistration(
        registration({ ...allWrong, operator: OPERATOR }),
      ),
    ).toEqual({ ok: false, reason: "missing_attestation" });
    expect(
      await checkRegistration(
        registration({ ...allWrong, operator: OPERATOR, attestation: {} }),
      ),
    ).toEqual({ ok: false, reason: "bad_attestation" });
    expect(
      await checkRegistration(
        registration({ ...allWrong, operator: OPERATOR, attestation }),
      ),
    ).toEqual({ ok: false, reason: "operator_exists" });
    expect(
      await checkRegistration(
        registration({
          ...allWrong,
          operator: OPERATOR,
          attestation,
          operatorExists: false,
        }),
      ),
    ).toEqual({ ok: false, reason: "agent_bound" });
  });
});

describe("binding a second agent", () => {
  /**
   * The agent the operator is about to bind, and its attestation: the operator's
   * registration domain's sentence, signed by the new key itself.
   */
  const newAgent = secondAgent;
  const bindAttestation = secondAttestation;

  /** A bind that passes every check, so each test can spoil one thing. */
  function bind(
    overrides: Partial<Parameters<typeof checkAgentBind>[0]> = {},
  ): Parameters<typeof checkAgentBind>[0] {
    return {
      operator: OPERATOR,
      signer: agent.id,
      agent: newAgent.id,
      attestation: bindAttestation as unknown,
      registered: true,
      registrationDomain: DEFAULT_DOMAIN,
      agents: [agent.id],
      agentOperator: null,
      now: new Date(SIGNED_AT),
      ...overrides,
    };
  }

  it("reads a bind body, and refuses extra keys and wrong types", () => {
    expect(
      parseAgentBindBody({ agent: newAgent.id, attestation: bindAttestation }),
    ).toEqual({
      ok: true,
      value: { agent: newAgent.id, attestation: bindAttestation },
    });
    for (const bad of [
      null,
      undefined,
      "agent",
      [],
      {},
      { agent: newAgent.id, attestation: bindAttestation, operator: OPERATOR },
      { agent: 42, attestation: bindAttestation },
      { agent: newAgent.id, attestation: "signed" },
      { agent: newAgent.id, attestation: [] },
    ]) {
      expect(parseAgentBindBody(bad)).toEqual({ ok: false, reason: "bad_body" });
    }
  });

  it("parses an absent or null attestation as none, not as a bad body", async () => {
    for (const missing of [
      { agent: newAgent.id },
      { agent: newAgent.id, attestation: null },
    ]) {
      const parsed = parseAgentBindBody(missing);
      expect(parsed).toEqual({
        ok: true,
        value: { agent: newAgent.id, attestation: null },
      });
      if (parsed.ok) {
        expect(
          await checkAgentBind(bind({ attestation: parsed.value.attestation })),
        ).toEqual({ ok: false, reason: "missing_attestation" });
      }
    }
  });

  it("names its refusals in check order", () => {
    expect(AGENT_BIND_REFUSALS).toEqual([
      "unregistered_operator",
      "not_operator_agent",
      "agent_bound",
      "bad_agent",
      "missing_attestation",
      "bad_attestation",
      "attestation_domain_mismatch",
    ]);
  });

  it("binds a second key an existing agent asked for (Section 5)", async () => {
    expect(await checkAgentBind(bind())).toEqual({ ok: true });
  });

  it("refuses an operator the registry does not hold", async () => {
    expect(await checkAgentBind(bind({ registered: false }))).toEqual({
      ok: false,
      reason: "unregistered_operator",
    });
  });

  it("refuses a request signed by an agent of another operator", async () => {
    // The operator vouches for the new key by signing with one of its own; a
    // key that answers for somebody else is not the operator asking.
    expect(await checkAgentBind(bind({ signer: otherAgent.id }))).toEqual({
      ok: false,
      reason: "not_operator_agent",
    });
    expect(await checkAgentBind(bind({ agents: [] }))).toEqual({
      ok: false,
      reason: "not_operator_agent",
    });
  });

  it("refuses a key already bound, to this operator or to any other", async () => {
    for (const held of [OPERATOR, OTHER_OPERATOR]) {
      expect(await checkAgentBind(bind({ agentOperator: held }))).toEqual({
        ok: false,
        reason: "agent_bound",
      });
    }
  });

  it("refuses a new agent that is not a 1F916 id", async () => {
    // A id that carries too few key bytes, one with no prefix at all, and one
    // that is not base64url: none of them spells a key, so none is an agent.
    for (const bad of ["", "not-an-agent", "1F916:zzz", "1F916:not base64url!"]) {
      expect(await checkAgentBind(bind({ agent: bad }))).toEqual({
        ok: false,
        reason: "bad_agent",
      });
    }
  });

  it("refuses a missing attestation", async () => {
    for (const missing of [null, undefined]) {
      expect(await checkAgentBind(bind({ attestation: missing }))).toEqual({
        ok: false,
        reason: "missing_attestation",
      });
    }
  });

  it("refuses an attestation the new key did not sign", async () => {
    for (const bad of [
      {},
      "signed",
      // The operator's own first agent signed it, not the key being bound.
      attestation,
      // The right key, the wrong operator.
      await signAttestation(newAgent.privateKey, {
        operator: OTHER_OPERATOR,
        agent: newAgent.id,
        signed_at: SIGNED_AT,
      }),
    ]) {
      expect(await checkAgentBind(bind({ attestation: bad }))).toEqual({
        ok: false,
        reason: "bad_attestation",
      });
    }
  });

  it("refuses an attestation signed outside the request window", async () => {
    // The request signature carries its own window, but it is made by the key
    // the operator already has. Without this, a sentence signed long ago by a
    // key that has since changed hands would still bind it today.
    const skew = REQUEST_CLOCK_SKEW_SECONDS * 1000;
    const at = new Date(SIGNED_AT).getTime();
    for (const now of [new Date(at + skew), new Date(at - skew)]) {
      expect(await checkAgentBind(bind({ now }))).toEqual({ ok: true });
    }
    for (const now of [new Date(at + skew + 1000), new Date(at - skew - 1000)]) {
      expect(await checkAgentBind(bind({ now }))).toEqual({
        ok: false,
        reason: "bad_attestation",
      });
    }
  });

  it("refuses a sentence signed for a domain the operator did not register in", async () => {
    // ai-ecosystem is the one registered domain today (src/policy.ts), so this
    // refusal is unreachable through the door and is pinned here on the check's
    // own context: the sentence verifies, and it is the wrong domain's.
    expect(
      await checkAgentBind(bind({ registrationDomain: "biotech" })),
    ).toEqual({ ok: false, reason: "attestation_domain_mismatch" });
  });

  it("reports the first refusal when several apply, in that order", async () => {
    const allWrong = {
      registered: false,
      signer: otherAgent.id,
      agentOperator: OTHER_OPERATOR,
      agent: "not-an-agent",
      attestation: null as unknown,
      registrationDomain: "biotech",
    };
    expect(await checkAgentBind(bind(allWrong))).toEqual({
      ok: false,
      reason: "unregistered_operator",
    });
    expect(
      await checkAgentBind(bind({ ...allWrong, registered: true })),
    ).toEqual({ ok: false, reason: "not_operator_agent" });
    expect(
      await checkAgentBind(
        bind({ ...allWrong, registered: true, signer: agent.id }),
      ),
    ).toEqual({ ok: false, reason: "agent_bound" });
    expect(
      await checkAgentBind(
        bind({
          ...allWrong,
          registered: true,
          signer: agent.id,
          agentOperator: null,
        }),
      ),
    ).toEqual({ ok: false, reason: "bad_agent" });
    expect(
      await checkAgentBind(
        bind({
          ...allWrong,
          registered: true,
          signer: agent.id,
          agentOperator: null,
          agent: newAgent.id,
        }),
      ),
    ).toEqual({ ok: false, reason: "missing_attestation" });
    expect(
      await checkAgentBind(
        bind({
          ...allWrong,
          registered: true,
          signer: agent.id,
          agentOperator: null,
          agent: newAgent.id,
          attestation: {},
        }),
      ),
    ).toEqual({ ok: false, reason: "bad_attestation" });
    expect(
      await checkAgentBind(
        bind({
          ...allWrong,
          registered: true,
          signer: agent.id,
          agentOperator: null,
          agent: newAgent.id,
          attestation: bindAttestation,
        }),
      ),
    ).toEqual({ ok: false, reason: "attestation_domain_mismatch" });
  });
});

describe("checkGenesisNaming", () => {
  it("names its refusals in check order", () => {
    expect(GENESIS_REFUSALS).toEqual([
      "maintainer_not_configured",
      "not_maintainer",
      "unregistered_operator",
      "maintainer_operator",
      "provider_operator",
      "already_trusted",
    ]);
  });

  it("lets the maintainer name a registered, independent operator", () => {
    expect(checkGenesisNaming(genesis())).toEqual({ ok: true });
  });

  it("refuses when no maintainer is configured", () => {
    expect(
      checkGenesisNaming(genesis({ maintainerAgentId: null })),
    ).toEqual({ ok: false, reason: "maintainer_not_configured" });
  });

  it("refuses a signer who is not the maintainer", () => {
    expect(checkGenesisNaming(genesis({ signer: agent.id }))).toEqual({
      ok: false,
      reason: "not_maintainer",
    });
  });

  it("refuses an operator that never registered", () => {
    expect(checkGenesisNaming(genesis({ registered: false }))).toEqual({
      ok: false,
      reason: "unregistered_operator",
    });
  });

  it("refuses the maintainer's own operator (Section 11)", () => {
    expect(checkGenesisNaming(genesis({ maintainerOperator: true }))).toEqual({
      ok: false,
      reason: "maintainer_operator",
    });
  });

  it("refuses a model provider (Section 10)", () => {
    expect(checkGenesisNaming(genesis({ provider: true }))).toEqual({
      ok: false,
      reason: "provider_operator",
    });
  });

  it("refuses an operator already trusted", () => {
    expect(checkGenesisNaming(genesis({ trusted: true }))).toEqual({
      ok: false,
      reason: "already_trusted",
    });
  });

  it("reports the first refusal when several apply", () => {
    expect(
      checkGenesisNaming(
        genesis({
          maintainerAgentId: null,
          signer: agent.id,
          registered: false,
          maintainerOperator: true,
          provider: true,
          trusted: true,
        }),
      ),
    ).toEqual({ ok: false, reason: "maintainer_not_configured" });
    expect(
      checkGenesisNaming(
        genesis({
          signer: agent.id,
          registered: false,
          maintainerOperator: true,
          provider: true,
          trusted: true,
        }),
      ),
    ).toEqual({ ok: false, reason: "not_maintainer" });
    expect(
      checkGenesisNaming(
        genesis({
          registered: false,
          maintainerOperator: true,
          provider: true,
          trusted: true,
        }),
      ),
    ).toEqual({ ok: false, reason: "unregistered_operator" });
    expect(
      checkGenesisNaming(
        genesis({ maintainerOperator: true, provider: true, trusted: true }),
      ),
    ).toEqual({ ok: false, reason: "maintainer_operator" });
    expect(checkGenesisNaming(genesis({ provider: true, trusted: true }))).toEqual(
      { ok: false, reason: "provider_operator" },
    );
  });
});

describe("agentOperatorsAt", () => {
  async function bind(
    log: Event[],
    operator: string,
    agentId: string,
    at: string,
  ): Promise<Event[]> {
    return appendEvent(log, {
      at,
      type: "agent_bound",
      entry_id: null,
      payload: { operator, agent: agentId, attestation },
    });
  }

  it("maps agents at a position and ignores what comes after", async () => {
    let log: Event[] = [];
    log = await bind(log, OPERATOR, agent.id, "2026-09-07T00:00:00Z");
    log = await bind(log, OTHER_OPERATOR, otherAgent.id, "2026-09-07T01:00:00Z");
    log = await appendEvent(log, {
      at: "2026-09-07T02:00:00Z",
      type: "operator_trusted",
      entry_id: null,
      payload: { operator: OPERATOR },
    });
    log = await bind(
      log,
      OTHER_OPERATOR,
      maintainerAgent.id,
      "2026-09-07T03:00:00Z",
    );

    expect(agentOperatorsAt(log, -1)).toEqual(new Map());
    expect(agentOperatorsAt(log, 0)).toEqual(new Map([[agent.id, OPERATOR]]));
    expect(agentOperatorsAt(log, 2)).toEqual(
      new Map([
        [agent.id, OPERATOR],
        [otherAgent.id, OTHER_OPERATOR],
      ]),
    );
    expect(agentOperatorsAt(log, 3)).toEqual(
      new Map([
        [agent.id, OPERATOR],
        [otherAgent.id, OTHER_OPERATOR],
        [maintainerAgent.id, OTHER_OPERATOR],
      ]),
    );
  });

  it("lets a later binding of the same agent win", async () => {
    let log: Event[] = [];
    log = await bind(log, OPERATOR, agent.id, "2026-09-07T00:00:00Z");
    log = await bind(log, OTHER_OPERATOR, agent.id, "2026-09-07T01:00:00Z");
    expect(agentOperatorsAt(log, 0).get(agent.id)).toBe(OPERATOR);
    expect(agentOperatorsAt(log, 1).get(agent.id)).toBe(OTHER_OPERATOR);
  });
});
