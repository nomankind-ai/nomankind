/**
 * The mirror, read from the outside.
 *
 * Whitepaper Section 11, "Deployment and status": the sealed log is exported
 * daily to a public repository under CC0, and the Conclusion says why — "the
 * exit is not a promise, it is a copy". `GET /mirror/latest` is the pointer at
 * the newest copy: which repository, which branch, which directory, and the one
 * commit a reader can clone or fetch `mirror.json` from.
 *
 * Two doors, one answer. The HTML form is src/worker/pages.ts's, which reads the
 * same row through the same `latestMirror` and asks `mirrorKindFor` the same
 * question, exactly as `/policy` and `/status` split: a reader who curls the
 * path and a reader who opens it are looking at the same export.
 *
 * Nothing is exported by asking. This route reads one row and answers it; the
 * export itself is the sweep's own step, once per UTC day, and a page load
 * cannot make one happen or make one look newer than it is.
 *
 * No policy number lives here: the repository, the branch and the web origin
 * come from src/policy.ts's MIRROR, and the bare integers are HTTP status codes.
 */

import { mirrorKindFor } from "../adapters/mirror.js";
import { MIRROR } from "../policy.js";
import type { D1Like } from "../storage/d1.js";
import { latestMirror, type MirrorRecord } from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  READ_METHODS,
  isRead,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** The repository as a person opens it, rather than as the API names it. */
function repositoryUrl(): string {
  return `${MIRROR.web}/${MIRROR.repository}`;
}

/** One export, as this route serves it. */
function record(latest: MirrorRecord): Record<string, unknown> {
  return {
    date: latest.date,
    exported_at: latest.exported_at,
    commit: latest.commit,
    tree: latest.tree,
    head: latest.head,
    seal_seq: latest.seal_seq,
    entries: latest.entries,
    files_changed: latest.files_changed,
    url: latest.url,
    raw_url: latest.raw_url,
  };
}

/**
 * The newest export, or the two reasons there is not one.
 *
 * The 404 carries the repository, the branch and the path anyway, because a
 * reader who asked before the first sweep of a new environment still wants to
 * know where the export will appear — and because the two reasons are different
 * things to do about it: `mirror_not_configured` is a secret the maintainer has
 * not set, `no_export_yet` is a day that has not come round.
 */
async function latest(db: D1Like, env: Env): Promise<Response> {
  const configured = mirrorKindFor(env) !== "unavailable";
  const path = env.ENVIRONMENT;
  const found = await latestMirror(db);

  if (found === null) {
    return json(
      {
        error: "no_export",
        reason: configured ? "no_export_yet" : "mirror_not_configured",
        configured,
        repository: repositoryUrl(),
        branch: MIRROR.branch,
        path,
      },
      404,
    );
  }

  return json(
    {
      environment: env.ENVIRONMENT,
      repository: repositoryUrl(),
      branch: MIRROR.branch,
      path,
      configured,
      latest: record(found),
    },
    200,
  );
}

/**
 * Route one request to the mirror pointer, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched. A browser asking for
 * `/mirror/latest` never reaches here: src/worker/pages.ts answers the page
 * ahead of this and hands everything else on.
 */
export async function handleMirror(
  request: Request,
  env: Env,
): Promise<Response | null> {
  const { pathname } = new URL(request.url);
  if (pathname !== "/mirror/latest") return null;
  if (!isRead(request)) return methodNotAllowed(READ_METHODS);

  try {
    return await latest(guardDatabase(env.DB), env);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`mirror: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}
