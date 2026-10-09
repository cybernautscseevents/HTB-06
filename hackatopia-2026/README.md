# Threat Pilot

Agentic SBOM Risk Auditor · Hackatopia 2026, problem statement CB-02.

Dependency scanners flag every known CVE in every package. Threat Pilot works out which of those your
code can actually reach, ranks them by real risk, and opens a verified pull request after a human approves it.

On a public 59-package Python project, a scanner-style count gives 133 vulnerabilities. Threat Pilot found
that 130 are in packages the code never imports and 1 is reachable, with the file, line and call chain as evidence.

- [Architecture guide (PDF)](Threat_Pilot_Architecture_Guide.pdf): architecture, file reference, tech-stack reasoning, judge questions
- [API contract](docs/API_CONTRACT.md): endpoints and data shapes shared by backend and frontend
- [PRD](PRD_Agentic_SBOM_Risk_Auditor.md): the original requirements

## What it does

1. **SBOM**: clones the repo, finds its requirements file, installs it into an isolated virtualenv, lists every direct and transitive package with Syft.
2. **Vulnerability data**: OSV.dev for advisories, EPSS for exploit probability, CISA KEV for known exploitation.
3. **Risk analysis**: for each vulnerability, in parallel, is the package imported (L1) and is the vulnerable function called (L2), directly or through the library's own code. Otherwise L0. Then every finding is scored: `CVSS × reach weight × (1 + EPSS) × KEV boost × direct boost`, with every factor shown.
4. **Remediation**: proposes the smallest safe upgrades and verifies them (OSV re-queried at the new versions, `pip install --dry-run` must resolve). A failed check loops back for another proposal.
5. **Code fix**: rewrites functions that call vulnerable or deprecated APIs.
6. **Human gate**: nothing is written to GitHub until someone approves.
7. **Open PR**: the pull request is opened as the approver.

The LLM only reads and writes text (advisory prose, explanations, PR text, function rewrites). Every fact comes from a
deterministic tool, each LLM output is checked in code, and the whole pipeline runs without a model.

## Layout

```
backend/    Python, FastAPI, LangGraph
  app/agents/   the seven agents (sbom, vuln_intel, risk_analysis, remediation, code_fix, human_gate, open_pr)
  app/tools/    OSV, EPSS, KEV, Syft, AST scanner, call graph, deprecations, LLM, GitHub
  app/          graph.py (pipeline), runs.py (run manager), main.py (API), auth.py (OAuth), db.py (storage)
  tests/        55 tests, no network needed
frontend/   React, TypeScript, Vite, Tailwind, shadcn/ui
  src/pages/    Landing, Dashboard, History, AuditPage
docs/       API_CONTRACT.md
```

## Quick start

Needs Python 3.11+, Node 18+ and `git` on PATH.

```bash
# Backend (http://localhost:8000)
cd backend
python -m venv .venv && .venv\Scripts\activate     # source .venv/bin/activate on mac/linux
pip install -r requirements.txt
cp .env.example .env                               # then fill in the keys below
uvicorn app.main:app --reload

# Frontend (http://localhost:5173)
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:5173` (use `localhost`, not `127.0.0.1`, or the sign-in cookie is not sent).

With an empty `backend/.env` the app still runs: local SQLite storage, no LLM, no sign-in, audits of public repos by URL.

## Configuration (`backend/.env`)

| Setting | What it enables | If left empty |
|---|---|---|
| `LLM_MODEL`, `GOOGLE_API_KEY` | LLM steps. Default model `google_genai:gemini-3.5-flash`. | Deterministic templates and rules are used. |
| `OLLAMA_API_KEY`, `OLLAMA_BASE_URL` | Ollama instead of Gemini: set `LLM_MODEL=ollama:<model>`. Local server by default, Ollama Cloud with a key. | |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | Sign in with GitHub; the PR is opened as the signed-in user. | No sign-in. |
| `GITHUB_TOKEN` | Opens PRs when nobody is signed in. | Approving requires sign-in. |
| `GITHUB_OAUTH_SCOPE` | `public_repo` (default) or `repo` to audit private repos and private git dependencies. | `public_repo` |
| `DATABASE_URL` | Neon / PostgreSQL for audits, logs, sessions, cache and checkpoints. Use the pooled connection string. | A local SQLite file at `backend/data/app.db`. |
| `LANGSMITH_API_KEY`, `LANGSMITH_PROJECT` | A LangSmith trace of every audit: each agent, tool step and LLM call. | Tracing is off. |
| `WORKSPACE_TTL_DAYS` | Days before a cloned repo and its virtualenv are deleted. | 30 |

For GitHub sign-in, create an OAuth App at https://github.com/settings/developers with homepage
`http://localhost:5173` and callback `http://localhost:8000/auth/github/callback`.

### Syft

Syft generates the SBOM; without it the backend falls back to `pipdeptree`. Install it with
`winget install Anchore.Syft` (or see the Syft docs), or drop the binary into `backend/bin/`, or set `SYFT_BIN`.
`GET /health` reports which one is in use.

### Repositories that already have an SBOM

If the repository contains a CycloneDX (JSON or XML) or SPDX (JSON) SBOM, it is used as it is and none is generated.
It is found wherever it is and whatever it is called: every `.json` / `.xml` file in the repository is checked by content
(only version-control, virtualenv and `node_modules` folders are skipped). When there are several, the shallowest
conventionally named one wins (`bom.json`, `*.cdx.json`, anything in an `sbom/` folder).

- Only its PyPI packages are audited; other ecosystems are counted and skipped.
- SBOMs inside `tests`, `fixtures`, `examples` or `samples` folders describe sample data, not the project. They are used
  only when the repository has no requirements file to generate a real SBOM from.
- A repo with an SBOM but no requirements file can still be audited, but upgrades are then listed as advice instead of a pull request.
- Set `USE_EXISTING_SBOM=false` to always generate.

### Demo and development switches

- `USE_STUBS=true`: every agent returns canned data. No network, no installs.
- `OFFLINE=true`: only cached responses are used.
- `FORCE_BAD_VERSION=pyyaml==5.3.1`: the first fix attempt uses that still-vulnerable version, so the verifier visibly rejects it and the retry loop recovers.
- `VITE_USE_MOCKS=true` in `frontend/.env`: the UI runs on sample data with no backend.

## Using it

1. Sign in with GitHub (optional) and open the dashboard.
2. Pick one of your repositories or paste a public GitHub URL. The repo needs a pip requirements file somewhere in it (see below).
3. Watch the pipeline. The audit page fills in as each agent finishes:
   - **Overview**: how many alerts are reachable, charts, top risks.
   - **Findings**: every vulnerability, sortable by risk or CVSS, with evidence and the score breakdown.
   - **Fix**: upgrades, the manifest diff, rewritten functions, verifier notes and the PR preview.
   - **SBOM**, **Activity** (timeline and backend log), **History** (all audits of this repo).
4. Approve or reject on the Fix tab. Approving opens the pull request; if you cannot push to the repo, it is opened from your fork.

## Tests

```bash
cd backend
pytest          # 55 tests, no network; uses a throwaway SQLite file and never calls an LLM
```

```bash
cd frontend
npx tsc && npm run build
```

## Limitations

- Python projects with a pip requirements file only (no Poetry, `pyproject.toml` or other ecosystems). The file is looked for in this order: `requirements.txt` at the root; otherwise every `requirements.txt` at the shallowest folder depth it occurs (a monorepo with `backend/` and `worker/` gets both); otherwise one differently named file such as `requirements/base.txt` or `requirements-prod.txt`. Files included with `-r` are followed. `docs`, `tests`, `examples` and vendored folders are not searched.
- Reachability is static analysis. It misses dynamic calls, and the indirect call chain is matched by name, so it is evidence for review, not proof. L0 means "not imported by your code", not "safe".
- Installing a target repo's requirements runs that project's install scripts. Isolation is a virtualenv, not a sandbox.
- Rewritten functions are checked for syntax, signature and the flagged call. They are not run against the project's tests.
- Old pins may have no prebuilt wheel for the backend's Python version and fail to install; those packages are then taken from the manifest only.
- An audit that is waiting for approval survives a backend restart; one that is mid-run does not.
- There is no access control on audits and no rate limiting.
