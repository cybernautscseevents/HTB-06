# Task split: 2 people

The frozen contract between you is [API_CONTRACT.md](API_CONTRACT.md). Backend: `backend/app/schemas.py`. Frontend: `frontend/src/types.ts`. **Keep these two in sync; change them together.**

## Person 1: Backend (agents, graph, API)

Owns PRD sections 5, 6.1 to 6.6, 6.7 (API half), NFR-1 to NFR-6.

| Phase (PRD hours) | Tasks | Files |
|---|---|---|
| 0–2 Skeleton | Freeze `schemas.py` / `state.py`. Stubs already run the graph end to end. Push demo repo, record `demo/` notes. | `app/schemas.py`, `app/state.py`, `app/graph.py` |
| 2–6 Real data | SBOM agent (clone, venv, Syft, pipdeptree fallback). OSV batch client, dedupe, CVSS parse, EPSS, KEV, disk cache. AST import scanner. | `agents/sbom.py`, `agents/vuln_intel.py`, `tools/osv.py`, `tools/cvss.py`, `tools/epss.py`, `tools/kev.py`, `tools/cache.py`, `tools/ast_scanner.py` |
| 6–10 Core | Call-level reachability with alias handling, safe-pattern downgrade. Score formula. Semver fix selection, manifest patcher. First PR via script. | `agents/reachability.py`, `agents/triage.py`, `agents/remediation.py`, `tools/versions.py`, `tools/github.py` |
| 10–14 Agent loop | LLM function extraction + validation against package source. Verifier (OSV re-query + `pip install --dry-run`), retry loop. `interrupt()` / resume. | `tools/llm.py`, `agents/verifier.py`, `agents/human_gate.py`, `agents/open_pr.py` |
| 14–24 | Integration, forced-bad-version demo, warm caches, offline mode, LLM explanations for top 5. | `data/curated_vuln_functions.json`, `tests/` |

Backend deliverables the frontend depends on: `POST /audit`, SSE stream, `GET /audit/{id}`, `POST /audit/{id}/decision` (shapes in API_CONTRACT.md).

## Person 2: Frontend (UI, UX, demo, pitch)

Owns PRD sections 6.7 (UI half), FR-28 to FR-30, AC-5, plus the demo repo and pitch.

| Phase | Tasks | Files |
|---|---|---|
| 0–2 | Vite app boots, types mirror contract, mock data + mock stream so the UI works with no backend. | `src/types.ts`, `src/mocks/*`, `src/api/*` |
| 2–6 | URL form, `useAuditStream` SSE hook, agent timeline (parallel workers side by side, retries visible). | `components/UrlForm.tsx`, `hooks/useAuditStream.ts`, `components/AgentTimeline.tsx` |
| 6–10 | Risk table: CVSS / EPSS / KEV badge / reach level / score, sort toggle CVSS vs risk score, expandable evidence rows with file:line, score breakdown. | `components/RiskTable.tsx`, `components/EvidenceRow.tsx`, `components/ScoreBreakdown.tsx` |
| 10–14 | Approval panel: manifest diff, PR preview, Approve / Reject, PR link. Dependency tree view (stretch). | `components/ApprovalPanel.tsx`, `components/DiffViewer.tsx` |
| 14–22 | Integrate against the real backend, polish states (loading, error, rejected, retry), second test repo, backup video. | everything |
| 22–24 | Slides, backup video, rehearsals. | `demo/` |

Frontend can build 100% against mocks first, then flip `VITE_USE_MOCKS=false`.

## Handoff checkpoints

1. **Hour 2:** contract frozen, both sides boot, backend streams stub events, frontend renders them.
2. **Hour 6:** real components/vulns in `GET /audit/{id}`; UI shows real risk table.
3. **Hour 10:** first PR opened from script; UI approval panel wired to `/decision`.
4. **Hour 14:** full run from UI, 3 times in a row.
