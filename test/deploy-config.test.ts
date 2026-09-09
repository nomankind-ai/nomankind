/**
 * The deploy pipeline is configuration, so it is pinned as configuration.
 *
 * Decision D-005 and D-022: demo deploys on merge to main, production only
 * from an annotated tag, previews are uploaded versions of the demo
 * environment, migrations run before the Worker goes live, and no deploy is
 * ever started by hand. Nothing here talks to Cloudflare or runs wrangler; it
 * reads wrangler.jsonc and the workflow files off disk.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ZERO_UUID = "00000000-0000-0000-0000-000000000000";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Strip line and block comments that fall outside string literals. */
function stripJsonComments(text: string): string {
  let out = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
      continue;
    }
    if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
      out += "\n";
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      i += 1;
      continue;
    }
    out += c;
  }
  return out;
}

const config = JSON.parse(
  stripJsonComments(readFileSync(join(ROOT, "wrangler.jsonc"), "utf8")),
) as Record<string, any>;
const read = (name: string): string =>
  readFileSync(join(ROOT, ".github", "workflows", name), "utf8");
const demoYml = read("deploy-demo.yml");
const productionYml = read("deploy-production.yml");
const previewYml = read("preview.yml");
const ciYml = read("ci.yml");

describe("wrangler.jsonc databases", () => {
  const ids: string[] = [];
  for (const env of ["demo", "production"]) {
    it(`${env} binds one real D1 database`, () => {
      const dbs = config.env[env].d1_databases;
      expect(dbs).toHaveLength(1);
      expect(dbs[0].binding).toBe("DB");
      expect(dbs[0].migrations_dir).toBe("migrations");
      expect(dbs[0].database_id).toMatch(UUID);
      expect(dbs[0].database_id).not.toBe(ZERO_UUID);
      expect(dbs[0].database_id).not.toContain("REPLACE");
      ids.push(dbs[0].database_id);
    });
  }

  it("gives the two environments different databases", () => {
    expect(new Set(ids).size).toBe(2);
  });

  it("leaves the local placeholder alone", () => {
    expect(config.d1_databases).toHaveLength(1);
    expect(config.d1_databases[0].binding).toBe("DB");
    expect(config.d1_databases[0].database_id).toBe(ZERO_UUID);
  });
});

describe("wrangler.jsonc snapshot archive", () => {
  /**
   * The archive is where the raw captures live (norm-v1.2 step 2), so which
   * bucket each environment writes to is a deploy fact and is pinned here for
   * the same reason the databases are. One binding name everywhere, because
   * src/ names the binding and never the environment.
   */
  const buckets: string[] = [];
  for (const [name, section, bucket] of [
    ["local", () => config, "nomankind-local-captures"],
    ["demo", () => config.env.demo, "nomankind-demo-captures"],
    ["production", () => config.env.production, "nomankind-production-captures"],
  ] as const) {
    it(`binds ${name} to its own captures bucket`, () => {
      expect(section().r2_buckets).toEqual([
        { binding: "CAPTURES", bucket_name: bucket },
      ]);
      buckets.push(bucket);
    });
  }

  it("gives the three environments three different buckets", () => {
    expect(new Set(buckets).size).toBe(3);
  });
});

describe("wrangler.jsonc routes and hostnames", () => {
  it("serves demo from demo.nomankind.ai only", () => {
    expect(config.env.demo.routes).toEqual([
      { pattern: "demo.nomankind.ai", custom_domain: true },
    ]);
  });

  it("serves production from app.nomankind.ai and the apex", () => {
    expect(config.env.production.routes).toEqual([
      { pattern: "app.nomankind.ai", custom_domain: true },
      { pattern: "nomankind.ai", custom_domain: true },
    ]);
  });

  it("opens no workers.dev route anywhere", () => {
    expect(config.workers_dev).toBe(false);
    expect(config.env.demo.workers_dev).toBe(false);
    expect(config.env.production.workers_dev).toBe(false);
  });

  it("allows preview URLs on demo only", () => {
    expect(config.preview_urls).toBe(false);
    expect(config.env.demo.preview_urls).toBe(true);
    expect(config.env.production.preview_urls).toBe(false);
  });

  it("names each environment in its vars", () => {
    expect(config.vars.ENVIRONMENT).toBe("local");
    expect(config.env.demo.vars.ENVIRONMENT).toBe("demo");
    expect(config.env.production.vars.ENVIRONMENT).toBe("production");
  });

  /**
   * The maintainer's agent id is a var and not a secret: it is a public key,
   * and Section 11's genesis naming is a power the public has to be able to
   * check the holder of. Pinned here because which key holds it in which
   * environment is a deploy fact (D-016).
   */
  it("gives local and demo their own throwaway maintainer keys", () => {
    expect(config.vars.MAINTAINER_AGENT_ID).toBe(
      "1F916:t2clwNKCX9MD246hQJgDKVoqhC7Q-ybl4x7xvRGWt40",
    );
    expect(config.env.demo.vars.MAINTAINER_AGENT_ID).toBe(
      "1F916:C-5gOmupEFPPWU-QfHTwvFNG6tdY4mqFdkKCyFPdtjs",
    );
    // Two environments, two keys: one shared with a laptop is one anyone can
    // claim to be.
    expect(config.env.demo.vars.MAINTAINER_AGENT_ID).not.toBe(
      config.vars.MAINTAINER_AGENT_ID,
    );
  });

  /**
   * The sealing agent's handle at the founding registry (D-054). A handle is
   * public, so it is a var; the two secrets that go with it are never in this
   * file, and this pins that they are not.
   */
  it("pins production's sealing handle to the registered citizen", () => {
    expect(config.env.production.vars.SEALING_AGENT_HANDLE).toBe("nomankind");
    // Local and demo run the mock witness set and have no registry track, so
    // they carry no handle at all.
    expect(config.vars.SEALING_AGENT_HANDLE).toBeUndefined();
    expect(config.env.demo.vars.SEALING_AGENT_HANDLE).toBeUndefined();
  });

  /**
   * The apex hostname (D-021): which host serves the landing page rather than
   * the app's home. Production routes two hostnames and is the only environment
   * that has an apex at all, so this pins that the other two carry none — an
   * APEX_HOST on demo would turn demo's only door into a front door.
   */
  it("names the apex on production only", () => {
    expect(config.env.production.vars.APEX_HOST).toBe("nomankind.ai");
    expect(config.vars.APEX_HOST).toBeUndefined();
    expect(config.env.demo.vars.APEX_HOST).toBeUndefined();
    // The apex is routed there, so the var and the route agree.
    expect(config.env.production.routes).toEqual(
      expect.arrayContaining([{ pattern: "nomankind.ai", custom_domain: true }]),
    );
  });

  it("keeps every sealing secret out of the repository", () => {
    const raw = readFileSync(join(ROOT, "wrangler.jsonc"), "utf8");
    // Named in a comment as things `wrangler secret put` sets, and nowhere as
    // a key: a secret in this file is a secret in the git history.
    for (const section of [config.vars, config.env.demo.vars, config.env.production.vars]) {
      expect(section.SEALING_AGENT_KEY).toBeUndefined();
      expect(section.REGISTRY_CREDENTIAL).toBeUndefined();
    }
    expect(raw).not.toMatch(/"SEALING_AGENT_KEY"\s*:/);
    expect(raw).not.toMatch(/"REGISTRY_CREDENTIAL"\s*:/);
  });

  it("leaves production's maintainer unset until M25", () => {
    // Empty means no maintainer is configured, and the Worker refuses genesis
    // naming outright rather than granting it to whoever asks first.
    expect(config.env.production.vars.MAINTAINER_AGENT_ID).toBe("");
  });
});

describe("wrangler.jsonc scheduled sweep", () => {
  /**
   * The sweep (src/worker/sweep.ts) is the one thing this system does on a
   * clock rather than on a request, so how often it runs is a deploy fact and is
   * pinned here for the same reason the routes are. The cadence is NOT a policy
   * number: it says how often the Worker looks, never how long an assigned
   * validator has (ASSIGNMENT_WINDOW_HOURS, src/policy.ts).
   */
  it("runs every five minutes", () => {
    expect(config.triggers).toEqual({ crons: ["*/5 * * * *"] });
  });

  it("states the schedule once, because triggers are inherited", () => {
    // Verified against wrangler's own config reader: `unstable_readConfig` with
    // --env demo and --env production both resolve this one block, so a second
    // copy per environment would be a second place for it to drift.
    expect(config.env.demo.triggers).toBeUndefined();
    expect(config.env.production.triggers).toBeUndefined();
  });
});

describe("wrangler.jsonc sweeper durable object", () => {
  /**
   * The sweep's own timer (src/worker/sweeper.ts). The cron above never fired
   * on the demo Worker across an hour and six deploys, so the cadence moved
   * onto a Durable Object alarm, which is a timer this project controls. Pinned
   * per environment because a binding that exists only on local is a timer that
   * exists only on a laptop.
   */
  const binding = { name: "SWEEPER", class_name: "Sweeper" };

  for (const [name, section] of [
    ["local", () => config],
    ["demo", () => config.env.demo],
    ["production", () => config.env.production],
  ] as const) {
    it(`binds SWEEPER to the Sweeper class in ${name}`, () => {
      expect(section().durable_objects).toEqual({ bindings: [binding] });
    });
  }

  it("repeats the binding per environment, because it is not inherited", () => {
    // The config schema says so in as many words: durable_objects "is not
    // automatically inherited from the top level environment, and so must be
    // specified in every named environment". Verified against wrangler's own
    // `unstable_readConfig` for --env demo and --env production.
    expect(config.durable_objects).toBeDefined();
    expect(config.env.demo.durable_objects).toBeDefined();
    expect(config.env.production.durable_objects).toBeDefined();
  });

  it("creates the class once, on the SQLite backend the free plan allows", () => {
    expect(config.migrations).toEqual([
      { tag: "v1", new_sqlite_classes: ["Sweeper"] },
    ]);
  });

  it("states the migration once, because migrations are inherited", () => {
    // Verified the same way the trigger inheritance above was: --env demo and
    // --env production both resolve this one block.
    expect(config.env.demo.migrations).toBeUndefined();
    expect(config.env.production.migrations).toBeUndefined();
  });
});

describe("workflow triggers", () => {
  it("deploys demo on merge to main and nothing else", () => {
    expect(demoYml).toMatch(/on:\n {2}push:\n {4}branches: \[main\]\n/);
    expect(demoYml).not.toMatch(/workflow_dispatch/);
    expect(demoYml).not.toMatch(/pull_request/);
  });

  it("deploys production from a version tag and nothing else", () => {
    expect(productionYml).toMatch(/on:\n {2}push:\n {4}tags:\n {6}- 'v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+'\n/);
    expect(productionYml).not.toMatch(/workflow_dispatch/);
    expect(productionYml).not.toMatch(/branches:/);
  });

  it("previews on pull requests only", () => {
    expect(previewYml).toMatch(/on:\n {2}pull_request:\n/);
    expect(previewYml).not.toMatch(/workflow_dispatch/);
    expect(previewYml).not.toMatch(/\n {2}push:/);
  });
});

describe("workflow commands", () => {
  for (const [name, yml, env, other] of [
    ["demo", demoYml, "demo", "production"],
    ["production", productionYml, "production", "demo"],
  ] as const) {
    it(`migrates ${name} before deploying it`, () => {
      const migrate = yml.indexOf(`d1 migrations apply DB --env ${env} --remote`);
      const deploy = yml.indexOf(`wrangler deploy --env ${env}`);
      expect(migrate).toBeGreaterThan(-1);
      expect(deploy).toBeGreaterThan(migrate);
      expect(yml).not.toContain(`--env ${other}`);
    });
  }

  /**
   * actions/checkout recreates the tag ref pointing at the commit, so the
   * workspace copy of an annotated tag is lightweight and `git cat-file -t`
   * against it can never say "tag". The guard has to fetch the real ref from
   * origin first; pinned so a future edit cannot quietly drop the fetch and
   * turn the annotated-tag rule back into an unpassable one.
   */
  it("fetches the tag from origin before testing it", () => {
    const fetch = productionYml.indexOf(
      'git fetch --force origin "+refs/tags/$GITHUB_REF_NAME:refs/tags/$GITHUB_REF_NAME"',
    );
    const test = productionYml.indexOf(
      '[ "$(git cat-file -t "refs/tags/$GITHUB_REF_NAME")" != "tag" ]',
    );
    expect(fetch).toBeGreaterThan(-1);
    expect(test).toBeGreaterThan(fetch);
  });

  it("uploads a demo version for previews", () => {
    expect(previewYml).toContain("versions upload --env demo");
    expect(previewYml).toContain('--preview-alias "pr-$PR_NUMBER"');
    expect(previewYml).toContain(
      "if: github.event.pull_request.head.repo.full_name == github.repository",
    );
  });

  /**
   * Decision D-050: the demo Worker implements a Durable Object, and
   * Cloudflare prints no preview URL for such a Worker. A successful upload
   * without one is a third green outcome, so the old red path must not creep
   * back; a failed upload, read as a missing version id, still fails.
   */
  it("does not fail a preview upload that printed no preview URL", () => {
    expect(previewYml).not.toContain("wrangler printed no version preview URL");
    expect(previewYml).not.toMatch(/no version preview URL[\s\S]{0,80}?exit 1/);
  });

  it("fails a preview upload that produced no version id", () => {
    expect(previewYml).toContain("grep 'Worker Version ID:' upload.log");
    expect(previewYml).toMatch(
      /if \[ -z "\$version_id" \]; then\n(?: *#[^\n]*\n)* *echo [^\n]*\n *exit 1\n/,
    );
    expect(previewYml).toContain("set -euo pipefail");
  });

  it("comments the version id and the Durable Object reason with no preview URL", () => {
    const branch = previewYml.indexOf('elif [ -z "$PREVIEW_URL" ]; then');
    expect(branch).toBeGreaterThan(-1);
    expect(previewYml).toContain('"$VERSION_ID"');
    expect(previewYml).toContain("VERSION_ID: ${{ steps.upload.outputs.version_id }}");
    expect(previewYml).toMatch(
      /no preview URL for a Worker that implements a Durable Object/,
    );
    // The same marker-based upsert still carries all three outcomes.
    expect(previewYml).toContain("marker='<!-- nomankind-preview -->'");
    expect(previewYml.indexOf("marker='<!-- nomankind-preview -->'")).toBeLessThan(branch);
  });

  it("keeps the required build check in CI", () => {
    expect(ciYml).toMatch(/\n {2}build:\n/);
  });
});

describe("smoke test hostnames", () => {
  /** The one `url=https://<host>/health` line of a deploy workflow. */
  const smokeHost = (yml: string): string => {
    const matches = [...yml.matchAll(/^ *url=https:\/\/([^/\s]+)\/health *$/gm)];
    expect(matches).toHaveLength(1);
    return matches[0][1];
  };

  it("smoke tests demo at the demo custom domain route", () => {
    const routes = config.env.demo.routes;
    expect(routes).toHaveLength(1);
    expect(routes[0].custom_domain).toBe(true);
    expect(smokeHost(demoYml)).toBe(routes[0].pattern);
  });

  it("smoke tests production at the app.nomankind.ai route", () => {
    const route = config.env.production.routes[0];
    expect(route.pattern).toBe("app.nomankind.ai");
    expect(route.custom_domain).toBe(true);
    expect(smokeHost(productionYml)).toBe(route.pattern);
  });
});
