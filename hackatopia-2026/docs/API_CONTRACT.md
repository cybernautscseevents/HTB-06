# API contract (frozen at hour 2)

Base URL: `http://localhost:8000`. CORS allows `http://localhost:5173`.

## Endpoints

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/audit` | `{ "repo_url": "https://github.com/org/repo" }` | `{ "run_id": "abc123" }`; 422 if the URL is not a GitHub repo URL |
| GET | `/audit/{id}/stream` | none | SSE of `AgentEvent` (event name `agent`), closed by a `done` event |
| GET | `/audit/{id}` | none | `AuditSnapshot`; 404 for an unknown id |
| POST | `/audit/{id}/decision` | `{ "approved": true }` | `{ "status": "resumed" }`; 409 if the run is not `awaiting_approval` |
| GET | `/audits` | none | `[{ run_id, repo_url, status }]` |
| GET | `/health` | none | `{ ok, offline, stubs }` |

## Types (TypeScript form; Python mirror in `backend/app/schemas.py`)

```ts
type ReachLevel = "L0" | "L1" | "L2";
type AgentName = "sbom" | "vuln_intel" | "risk_analysis" | "remediation"
               | "code_fix" | "human_gate" | "open_pr";
type AgentStatus = "running" | "done" | "failed" | "waiting" | "retry";
type RunStatus = "running" | "awaiting_approval" | "completed" | "rejected" | "failed";

interface Component { name: string; version: string; direct: boolean; parents: string[]; }

interface Finding {
  id: string;            // primary id, e.g. "GHSA-..." or CVE
  cve: string | null;
  aliases: string[];
  package: string;
  version: string;
  summary: string;
  cvss: number;          // 0-10
  epss: number;          // 0-1
  kev: boolean;
  fixed_in: string[];
  direct: boolean;
}

interface Evidence { file: string; line: number; snippet: string; }

interface Reachability {
  finding_id: string;
  level: ReachLevel;
  functions: string[];
  evidence: Evidence[];
  note: string | null;   // e.g. "downgraded: SafeLoader"
}

interface ScoredFinding {
  finding: Finding;
  reach: Reachability;
  score: number;
  breakdown: { cvss: number; reach_weight: number; epss_factor: number; kev_boost: number; direct_boost: number; };
  rank: number;
  explanation: string | null;   // top 5 only
}

interface PackageChange { package: string; old: string; new: string; cves_closed: string[]; }

interface Remediation {
  changes: PackageChange[];
  manual_review: PackageChange[];   // major bumps
  not_patched: string[];            // finding ids, L0
  diff: string;                     // unified diff of requirements.txt
  pr_title: string;
  pr_body: string;
}

interface Verification { ok: boolean; notes: string[]; attempt: number; }

interface AgentEvent {
  agent: AgentName;
  status: AgentStatus;
  worker_id: string | null;   // reachability workers: finding id
  detail: string;
  ts: number;                 // unix seconds
}

interface AuditSnapshot {
  run_id: string;
  repo_url: string;
  status: RunStatus;
  components: Component[];
  findings: Finding[];
  scored: ScoredFinding[];
  remediation: Remediation | null;
  verification: Verification | null;
  pr_url: string | null;
  error: string | null;        // set when status is "failed"
  events: AgentEvent[];
}
```

## Notes
- SSE: `event: agent` with `data: <AgentEvent JSON>`. Every agent emits `running` when it starts and `done` / `retry` / `failed` when it ends; `running` may repeat with a progress message in `detail`.
- The stream always replays past events first, then closes with `event: done`, `data: {"status": "..."}`. It closes when the run pauses at the human gate **and** when it finishes, so after `POST /decision` open the stream again, then refresh `GET /audit/{id}`.
- Reachability workers share `agent: "reachability"` and are told apart by `worker_id` (the finding id).
- At the human gate a `human_gate` event with status `waiting` is sent and `AuditSnapshot.status` is `awaiting_approval`.
- A verifier failure emits `verifier` status `retry`, then `remediation` `running` again. `Verification.notes` lines start with `FAIL:`, `warning:` or `note:`.
- Runs that end without a PR: `completed` with empty `remediation.changes` (nothing safe to patch, see `manual_review` / `not_patched`), `rejected`, or `failed` with `error`.
- Runs live in memory; restarting the backend forgets them.

## GitHub sign-in (OAuth)

All browser requests use `credentials: "include"`; the session is an HttpOnly cookie and the GitHub token never reaches the browser.

| Method | Path | Response |
|---|---|---|
| GET | `/auth/github/login?next=/path` | 302 to GitHub (full-page navigation); 503 if no OAuth app is configured |
| GET | `/auth/github/callback` | GitHub returns here; 302 back to `FRONTEND_URL + next`, with `?auth_error=<code>` on failure |
| GET | `/auth/me` | `{ oauth_configured, authenticated, user: { login, name, avatar_url, html_url } \| null, server_token }` |
| POST | `/auth/logout` | `{ ok: true }` |
| GET | `/auth/repos` | `[{ full_name, html_url, language, can_push }]`; 401 if not signed in |

- `POST /audit/{id}/decision` with `approved: true` returns 401 when nobody is signed in and the server has no `GITHUB_TOKEN`. The run stays at the gate.
- The PR is opened as whoever approves. Without push access to the repository it is opened from that user's fork.
- Setup: create an OAuth App at https://github.com/settings/developers (homepage `http://localhost:5173`, callback `http://localhost:8000/auth/github/callback`) and put the client id and secret in `backend/.env`. Open the app on `localhost`, not `127.0.0.1`, or the cookie is not sent.

## Dashboard, history and code fixes

- `GET /audits` returns `AuditSummary[]`, newest first: `{ run_id, repo_url, status, created_at, user, components, findings, l2, l1, l0, changes, code_fixes, pr_url }`. Optional `?repo_url=` filter. Audits are saved under `backend/data/audits/`, so the list survives restarts.
- `GET /audit/{id}` and `/stream` also serve audits from before a restart (read-only). One that was still waiting for approval is reported as `failed` with an explanatory `error`; `POST /decision` on it returns 404.
- `GET /auth/repos` rows also carry `description`, `private`, `pushed_at`, `stars`, `default_branch`.
- `AuditSnapshot` adds `created_at`, `user` and `code_fixes: CodeFix[]`:
  `CodeFix { file, diff, changes: [{ function, line, issues: [{ kind: "vulnerable" | "deprecated", api, line, detail }], explanation, source: "llm" | "rule" }] }`.
- New agent name `code_fix` (runs after the verifier, before the human gate). The PR commits the rewritten files along with `requirements.txt`.
- `Reachability.path: string[]` is set for indirect L2: the call chain from the application's call down to the vulnerable function. `Evidence.call` is the resolved name of the call on that line.
- `Component.source` is `"pypi" | "vcs" | "url"` with `source_url`. Packages installed from another repository or a URL are listed in the SBOM but not checked against OSV.
- Frontend routes: `/` (landing), `/dashboard`, `/history`, `/audit/:runId`.

## Storage, checkpoints, logs and tracing

- Everything is stored in one database: `DATABASE_URL` (Neon / PostgreSQL) when set, otherwise a local SQLite file at `backend/data/app.db`. Tables: `audits`, `logs`, `sessions`, `cache`, `memory`, plus LangGraph's checkpoint tables.
- Graph state is checkpointed after every step. An audit that is `awaiting_approval` can still be decided after a backend restart: `POST /audit/{id}/decision` restores it from its checkpoint. One that was `running` when the backend stopped is reported as `failed`.
- `GET /audit/{id}/logs` returns `LogLine[]` (`{ ts, level, logger, run_id, agent, message }`), oldest first. `GET /logs?limit=` returns recent lines across audits. The same lines go to the console and `backend/logs/app.log`.
- `AuditSnapshot.since_last` (`{ previous_run_id, previous_at, new, resolved, unchanged }`) compares with the previous audit of the same repository; null on a first audit.
- `AuditSnapshot.trace_url` is the LangSmith trace when `LANGSMITH_API_KEY` is set. Each audit is one trace containing every agent, tool step and LLM call.
- `GET /health` adds `storage` (`"postgres" | "sqlite"`), `langsmith` and `workspace_ttl_days`.
- Cloned repositories and their virtualenvs are deleted `WORKSPACE_TTL_DAYS` (default 30) after their last audit; checked at startup and every six hours.
- The audit page keeps its tab in the URL: `/audit/:runId?tab=findings|fix|sbom|activity`.

## Agents (seven)

`sbom`, `vuln_intel`, `risk_analysis`, `remediation`, `code_fix`, `human_gate`, `open_pr`.

- `risk_analysis` covers reachability and scoring. Its parallel workers emit events with a `worker_id` (the finding id); the agent is finished when its own event without a `worker_id` reports `done`.
- `remediation` covers proposing and verifying. It emits `running` with detail `proposed ...; verifying`, then `retry` if the check fails (and proposes again), and a single `done` once a proposal is verified.
- Audits stored under the older names (`reachability`, `triage`, `verifier`) are mapped to the new ones when loaded.
