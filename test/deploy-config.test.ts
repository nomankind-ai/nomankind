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

  it("uploads a demo version for previews", () => {
    expect(previewYml).toContain("versions upload --env demo");
    expect(previewYml).toContain(
      "if: github.event.pull_request.head.repo.full_name == github.repository",
    );
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
