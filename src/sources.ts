/**
 * The source policy: who may be cited for what, and what class a citation earns.
 *
 * Whitepaper Section 4, and Section 12's "stated entries are about the source,
 * not the world". A stated entry is verified when independent operators confirm
 * the source said what the entry says, and nothing in that sentence asks whether
 * the source is one that should be believed about that subject -- so a site made
 * yesterday could carry a pricing claim to verified. Decision D-080 closes that
 * gap in the one place it can be closed mechanically: some categories have an
 * authoritative source by nature, and an entry in one of them must cite the
 * subject's own official source or it does not enter the log at all. Everywhere
 * else the class is a label, published beside the entry, and the validators'
 * judgment is untouched.
 *
 * Nothing here is a new field in the signed core. The citation was always there;
 * the class is a reading of it, derived the same way from the same bytes by
 * everyone, which is why `deriveEntry` can put it in the sidecar and why an
 * offline verifier re-deriving from the mirror gets the same answer.
 *
 * Pure: no I/O, no clock, no storage, and no table of its own. Every host, every
 * category and every provider row comes from src/policy.ts, because a second
 * list of who is authoritative would be a second published policy.
 *
 * What this module deliberately does not do: say whether the cited page supports
 * the claim. That is the validator's judgment, it is the thing the policy cannot
 * automate, and the registry document says so in as many words.
 */

import {
  isOfficialRequiredCategory,
  providerSources,
  recognizedHosts,
} from "./policy.js";

/**
 * What a citation's host earned.
 *
 * `official`: the subject's own provider published this host. `recognized`: a
 * source with an editorial process, a standards body, a court or regulator, a
 * journal or a preprint server -- a label, never a gate. `other`: everything
 * else, which is not an accusation. It says this log publishes no authority for
 * this subject, and the reader is told exactly that.
 */
export type SourceClass = "official" | "recognized" | "other";

/** Every class, strongest first. */
export const SOURCE_CLASSES: readonly SourceClass[] = Object.freeze([
  "official",
  "recognized",
  "other",
]);

/**
 * The order the classes sort in: official > recognized > other.
 *
 * A rank and not a score. It answers exactly one question -- whether a class
 * meets a reader's minimum -- and nothing weights on the numbers themselves.
 */
export const SOURCE_CLASS_ORDER: Readonly<Record<SourceClass, number>> =
  Object.freeze({ official: 2, recognized: 1, other: 0 });

/**
 * The classes a reader may demand as a minimum: official, or recognized.
 *
 * `other` is not among them, and not by oversight: a demand for "at least other"
 * is a demand nothing fails, so writing it would be asking for the unfiltered
 * answer in a way that looks like a filter. The entries listing's `source=`
 * chip is a different question -- exact class, `other` included -- and carries
 * its own values.
 */
export const MIN_SOURCE_VALUES: readonly SourceClass[] = Object.freeze([
  "official",
  "recognized",
]);

/** Whether a value is one of the three classes. */
export function isSourceClass(value: unknown): value is SourceClass {
  return (
    typeof value === "string" &&
    (SOURCE_CLASSES as readonly string[]).includes(value)
  );
}

/**
 * What the sidecar carries about an entry's citation: the class, the listed host
 * that matched it, and the provider its subject names.
 *
 * `matched_host` is null exactly when the class is other, because no listed host
 * matched. `provider` is the subject's first path segment and is null when the
 * subject carries none -- it is reported either way, so a reader can see whether
 * a claim was even about a named provider.
 */
export interface SourceClassification {
  readonly class: SourceClass;
  readonly matched_host: string | null;
  readonly provider: string | null;
}

/** The classification of a citation nothing in the tables matched. */
function otherThan(provider: string | null): SourceClassification {
  return { class: "other", matched_host: null, provider };
}

/**
 * The provider a subject names: the first segment before `/`, lowercased.
 *
 * The subject convention is `<provider>/<model or product>`
 * (schema/nomankind-domain-registry-v1.md), so the provider is a fact about the
 * subject string and never a lookup. A subject with no slash names no provider
 * and answers null -- which for an official-required category is a refusal, and
 * everywhere else is simply a subject the tables have no opinion about.
 */
export function providerOf(subject: unknown): string | null {
  if (typeof subject !== "string") return null;
  const slash = subject.indexOf("/");
  if (slash <= 0) return null;
  return subject.slice(0, slash).toLowerCase();
}

/**
 * The host a citation may be classified by, or null when it may not be.
 *
 * The rule, in full: https and nothing else, no userinfo, no port. Each of the
 * three is a way of making a URL look like one host while being another, and a
 * citation the log cannot read unambiguously is `other` rather than a guess.
 *
 * http is excluded because a plaintext fetch is a source anybody on the path can
 * rewrite, so "the official page said so" is not something an http citation can
 * establish -- the snapshot would pin whatever the network handed the capture.
 *
 * The port is checked twice: `URL` normalizes an explicit `:443` away, so the
 * authority is also read out of the text. A citation that spelt the default port
 * is still a citation with a port in it, and the rule says what it says.
 */
function hostOf(citation: unknown): string | null {
  if (typeof citation !== "string") return null;
  if (!/^https:\/\//i.test(citation)) return null;

  let url: URL;
  try {
    url = new URL(citation);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.port !== "") return null;

  const authority = citation.slice("https://".length).split(/[/?#]/)[0] ?? "";
  if (authority.includes("@")) return null;
  // A colon after any IPv6 literal's closing bracket is a port.
  if (authority.indexOf(":", authority.lastIndexOf("]") + 1) >= 0) return null;

  const host = url.hostname.toLowerCase();
  return host.length === 0 ? null : host;
}

/**
 * Whether a host is a listed one, or a subdomain of it.
 *
 * `docs.anthropic.com` matches `anthropic.com`; `anthropic.com.evil.tld` does
 * not, and that is the whole point of the dot. A suffix test without it would
 * hand every lookalike domain in the world the official badge of whatever it
 * ended with.
 */
function hostMatches(host: string, listed: string): boolean {
  const lower = listed.toLowerCase();
  return host === lower || host.endsWith(`.${lower}`);
}

/**
 * The longest listed host this host matches, or null.
 *
 * Longest, so `platform.openai.com` reports itself rather than the `openai.com`
 * it is also a subdomain of: the matched host published beside an entry should
 * be the most specific thing the tables actually say.
 */
function longestMatch(host: string, listed: readonly string[]): string | null {
  let best: string | null = null;
  for (const candidate of listed) {
    if (!hostMatches(host, candidate)) continue;
    if (best === null || candidate.length > best.length) best = candidate;
  }
  return best;
}

/**
 * The class one entry's citation earns, in one domain, for one subject.
 *
 * Official first: a host the subject's own provider published outranks anything
 * else, and a provider page about its own product is the strongest source there
 * is for what that product costs or when it was deprecated. Recognized next,
 * from the domain's list. Otherwise other.
 *
 * Deterministic and total. Every input is data -- an unregistered domain, a
 * subject with no provider, a citation that is not a URL at all -- and each of
 * them answers `other` rather than throwing, because this runs over stored rows
 * that may have been written by an older Worker and over a stranger's file in
 * the offline verifier.
 */
export function sourceClassOf(
  domain: string,
  subject: unknown,
  citation: unknown,
): SourceClassification {
  const provider = providerOf(subject);
  const host = hostOf(citation);
  if (host === null) return otherThan(provider);

  if (provider !== null) {
    const row = providerSources(domain, provider);
    if (row !== null) {
      const matched = longestMatch(host, row.hosts);
      if (matched !== null) {
        return { class: "official", matched_host: matched, provider };
      }
    }
  }

  const recognized = longestMatch(host, recognizedHosts(domain));
  if (recognized !== null) {
    return { class: "recognized", matched_host: recognized, provider };
  }

  return otherThan(provider);
}

/** Why a submission's citation was refused. */
export type SourceRefusal = "unknown_provider" | "source_not_official";

/** Both source refusals, in check order: the first one wins. */
export const SOURCE_REFUSALS: readonly SourceRefusal[] = Object.freeze([
  "unknown_provider",
  "source_not_official",
]);

/** Passed the source gate, or refused with the one reason that decided it. */
export type SourceVerdict =
  | { ok: true }
  | { ok: false; reason: SourceRefusal };

/**
 * The source gate, for one submission.
 *
 * A category the domain does not require an official source for passes
 * unconditionally: the class is still derived and still published, but it is a
 * label there and the validators decide the rest.
 *
 * For an official-required category, in order:
 *
 * unknown_provider: the subject names no provider, or names one the domain's
 * table has no row for. The refusal is deliberate and it is not a shrug -- the
 * log has published no official source for this subject, so it cannot tell an
 * official page from a lookalike, and accepting the claim from anywhere is
 * exactly the hole this policy exists to close. A row is added by decision.
 *
 * source_not_official: there is a row, and the citation is not one of its hosts.
 * An http citation of an official host lands here too, by way of the host rule.
 */
export function checkSource(
  domain: string,
  category: unknown,
  subject: unknown,
  citation: unknown,
): SourceVerdict {
  if (!isOfficialRequiredCategory(domain, category)) return { ok: true };

  const provider = providerOf(subject);
  if (provider === null || providerSources(domain, provider) === null) {
    return { ok: false, reason: "unknown_provider" };
  }

  if (sourceClassOf(domain, subject, citation).class !== "official") {
    return { ok: false, reason: "source_not_official" };
  }

  return { ok: true };
}

/**
 * Whether a class meets a reader's minimum demand.
 *
 * No demand is met by anything, including by a class the log could not work out.
 * A demand that was made is met only by a class at least as strong, and a null
 * class fails it -- for the reason `tierSatisfies` gives about a null effective
 * tier: answering "probably" to a reader who asked where the claim came from is
 * the one thing this must never do.
 */
export function sourceClassSatisfies(
  sourceClass: SourceClass | null,
  min: SourceClass | null | undefined,
): boolean {
  if (min === undefined || min === null) return true;
  if (sourceClass === null) return false;
  return SOURCE_CLASS_ORDER[sourceClass] >= SOURCE_CLASS_ORDER[min];
}
