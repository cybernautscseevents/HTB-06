# PRD: Agentic SBOM Risk Auditor

| | |
|---|---|
| **Event** | Hackatopia 2026, Cyber Security + Blockchain track |
| **Problem statement** | CB-02 (original code CS-04): Automated Software Bill of Materials (SBOM) Risk Auditor |
| **Build window** | 24 hours, team of 4 |
| **Status** | Draft v1.0, 8 Oct 2026 |
| **Architecture** | LangGraph multi-agent system, Python backend, React frontend |

---

## 1. Summary

Modern applications are mostly open-source code. Existing dependency scanners flag every known CVE in every package, so teams receive hundreds of alerts and cannot tell which ones matter. The Agentic SBOM Risk Auditor is a set of specialised AI agents, orchestrated with LangGraph, that:

1. builds an SBOM for a repository,
2. maps every component to live vulnerability data,
3. proves whether the vulnerable code is actually reachable from the application,
4. ranks findings by real risk, and
5. opens a verified remediation pull request after a human approves it.

## 2. Problem

- **Alert fatigue.** A typical Python service pulls in 50 to 200 packages. Scanners report every CVE regardless of whether the application uses the affected code.
- **Severity is not risk.** A critical CVE in a package that is never imported is less urgent than a medium CVE in a function called on user input. CVSS alone cannot express this.
- **Fixing is manual.** Engineers must work out which version fixes which CVE, check for conflicts and write the PR by hand.
- **Blind automation is dangerous.** Auto-bumping versions without checks can break builds or fail to close the vulnerability.

## 3. Goals and non-goals

### Goals
- **G1:** Generate an accurate SBOM, including transitive dependencies, for a Python repository from a GitHub URL.
- **G2:** Enrich every vulnerable component with live data: CVSS, EPSS exploit probability, CISA KEV status and fixed-in versions.
- **G3:** Classify each vulnerability by reachability (L0 not imported, L1 imported, L2 vulnerable function called), with file:line evidence.
- **G4:** Rank findings with a transparent, reproducible risk score.
- **G5:** Produce a remediation PR that is verified before it is offered and that requires human approval before it is opened.
- **G6:** Make agent behaviour visible in real time in the UI.

### Non-goals (for the 24-hour build)
- Ecosystems other than PyPI (npm, Maven, Go). The architecture supports them, but they are out of scope.
- Full inter-procedural call-graph analysis. Reachability is import-level and direct-call-level only.
- Private repositories, multi-user accounts, authentication, persistent databases.
- Running the target project's test suite as part of verification (stretch goal only).

## 4. Users

| Persona | Need | How the product serves them |
|---|---|---|
| **Application developer** | "Tell me the 3 things I must fix today, and fix them for me." | Ranked list with plain-English explanations and a ready PR |
| **Security engineer** | "Show me evidence, not guesses." | Reachability level with file:line evidence, score breakdown, source advisories |
| **Engineering lead** | "Don't let a bot break production." | Verifier checks, no major-version bumps, mandatory human approval |

### User stories
- **US1:** As a developer, I paste a GitHub URL and see an audit start within 5 seconds.
- **US2:** As a developer, I watch each agent run so I know what the system is doing.
- **US3:** As a security engineer, I sort findings by CVSS and by risk score to see how reachability changes priorities.
- **US4:** As a security engineer, I expand a finding to see the exact line that calls the vulnerable function.
- **US5:** As a lead, I review the proposed diff and PR text, then approve or reject it.
- **US6:** As a developer, I get a link to the opened PR after approval.

## 5. System overview

The system is a LangGraph `StateGraph`. Eight agent nodes share one typed state object and never call each other directly.

| # | Agent | Uses LLM? | Responsibility |
|---|---|---|---|
| 1 | SBOM Agent | No | Clone repo, install into a temp venv, run Syft, output components with direct/transitive flag |
| 2 | Vuln Intel Agent | No | Query OSV batch API, fetch EPSS and CISA KEV, parse CVSS vectors, extract fixed-in versions |
| 3 | Reachability Worker (×N, parallel) | Yes | Identify vulnerable functions, validate them, scan source with `ast`, assign L0/L1/L2 |
| 4 | Risk Triage Agent | Yes | Compute deterministic score, rank, write explanations for the top 5 |
| 5 | Remediation Agent | Yes | Choose safe versions, patch the manifest, draft PR title and body |
| 6 | Verifier (Critic) | No | Re-query OSV at new versions, run `pip install --dry-run`; send failures back to agent 5 |
| 7 | Human Gate | No | Pause the graph with `interrupt()` until the user approves or rejects |
| 8 | Open PR | No | Create branch, commit and PR through the GitHub API |

**Key LangGraph mechanisms**
- **Parallel fan-out:** `Send()` launches one reachability worker per vulnerability. Results merge through an `operator.add` reducer.
- **Critic loop:** the Verifier routes back to Remediation on failure, with a maximum of 2 retries before falling back to a report.
- **Human-in-the-loop:** `interrupt()` plus a checkpointer saves state; the API resumes with `Command(resume=...)`.

**Design principle:** all facts (versions, CVE IDs, scores, fixed-in versions) come from deterministic tools. The LLM is used only to read advisory prose, write explanations and write PR text. Every LLM output that affects results is validated by code.

## 6. Functional requirements

### 6.1 Ingestion and SBOM
- **FR-1:** Accept a public GitHub repository URL containing a `requirements.txt`.
- **FR-2:** Install dependencies into an isolated virtual environment and generate a CycloneDX JSON SBOM using Syft.
- **FR-3:** Mark each component as direct or transitive, and record parent links for the dependency tree view.
- **FR-4:** If Syft fails, fall back to `pipdeptree --json` with the same output shape.

### 6.2 Vulnerability intelligence
- **FR-5:** Query OSV.dev `/v1/querybatch` for all components in one request, then fetch full records for each vulnerability ID.
- **FR-6:** De-duplicate records that share aliases (for example a GHSA and a PYSEC record for the same CVE).
- **FR-7:** Convert CVSS vector strings to numeric base scores; fall back to severity labels when no vector exists.
- **FR-8:** Attach EPSS probability and CISA KEV membership for each CVE alias.
- **FR-9:** Cache every external response locally so the full demo can run offline.

### 6.3 Reachability analysis
- **FR-10:** Run one reachability worker per finding in parallel.
- **FR-11:** Look up vulnerable function names from a curated map first; otherwise extract them from the advisory with the LLM using structured output.
- **FR-12:** Discard any LLM-extracted name that is not defined in the installed package's source.
- **FR-13:** Detect imports and calls including aliases (`import x as y`, `from x import f`, `from x import f as g`).
- **FR-14:** Assign L0, L1 or L2 and record file:line evidence for every L1 and L2 result.
- **FR-15:** Downgrade known-safe call patterns (for example `yaml.load` with `SafeLoader`) from L2 to L1 by rule.

### 6.4 Risk triage
- **FR-16:** Compute `score = CVSS × reach_weight × (1 + EPSS) × KEV_boost × direct_boost`, where reach weights are L0 = 0.2, L1 = 0.6, L2 = 1.0, KEV boost = 2.0 and direct boost = 1.2.
- **FR-17:** Rank all findings by score and expose the component values so any score can be recomputed by hand.
- **FR-18:** Generate a two-sentence explanation for each of the top 5 findings using only facts present in state.

### 6.5 Remediation and verification
- **FR-19:** For each package, choose the highest fixed-in version across its vulnerabilities, using semantic version comparison.
- **FR-20:** Patch only L1, L2 or KEV-listed findings. Report L0 findings without patching them.
- **FR-21:** Exclude major-version bumps from the PR and list them as "manual review".
- **FR-22:** Verify that no known vulnerabilities remain at the new versions and that the patched manifest resolves.
- **FR-23:** On verification failure, return to remediation with the failure notes; stop after 2 retries.

### 6.6 Approval and PR
- **FR-24:** Pause before any write to GitHub and show the diff, PR text and top findings.
- **FR-25:** On approval, create a branch, commit the manifest change and open a PR containing a table of package, old version, new version, CVEs closed and reachability evidence.
- **FR-26:** On rejection, end the run with a report and make no changes to the repository.

### 6.7 API and UI
- **FR-27:** `POST /audit` starts a run; `GET /audit/{id}/stream` streams agent updates over SSE; `GET /audit/{id}` returns current state; `POST /audit/{id}/decision` resumes the graph.
- **FR-28:** Agent timeline view showing each agent's status, with parallel workers side by side and retries visible.
- **FR-29:** Risk table with CVSS, EPSS, KEV badge, reachability level and score; toggle to sort by CVSS or by risk score; expandable evidence rows.
- **FR-30:** Approval panel showing the manifest diff and PR preview, with Approve and Reject buttons and the resulting PR link.

## 7. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | End-to-end audit time on the demo repo | Under 90 seconds online, under 30 seconds from cache |
| NFR-2 | Offline resilience | Full demo runs with network disabled, using cached API and LLM responses |
| NFR-3 | LLM usage | At most 3 call sites; failure of any LLM call falls back to deterministic behaviour |
| NFR-4 | Security | GitHub token from an environment variable, scoped to the demo repo; never logged or committed |
| NFR-5 | Isolation | Target repos are cloned and installed in temporary directories and virtual environments |
| NFR-6 | Scale guard | Fan-out capped at the top 30 findings by CVSS |
| NFR-7 | Provider flexibility | LLM selected through one configuration string via `init_chat_model` |

## 8. Success metrics

### Demo acceptance criteria
- **AC-1:** On the demo repo, the reachable PyYAML finding is ranked first by risk score, even though an unreachable finding has a higher CVSS.
- **AC-2:** Every L2 finding shows the correct file and line.
- **AC-3:** The verifier loop is triggered at least once by a forced bad version, and recovers.
- **AC-4:** Rejecting at the human gate makes no change to GitHub; approving opens a real PR.
- **AC-5:** The full flow completes from the UI without touching a terminal.

### Quality targets
- Reachability level correct for 100% of curated demo CVEs.
- Zero unvalidated LLM-extracted function names reach the scanner.
- PR passes `pip install` cleanly.

## 9. Milestones

| Hours | Milestone | Exit criterion |
|---|---|---|
| 0–2 | Skeleton | Frozen state schema; all 8 nodes stubbed; graph runs end to end; demo repo pushed |
| 2–6 | Real data | Real components and vulnerabilities flow through; import scanner works |
| 6–10 | Core features | Call-level reachability, enrichment, SSE timeline, first PR opened from a script |
| 10–14 | Agent loop | LLM extraction with validation, verifier loop, interrupt/resume through the UI |
| 14–16 | Integration | Full demo run 3 times; bug list created |
| 16–19 | Rest | Sleep in two shifts; fix listed bugs only |
| 19–22 | Polish | Explanations, second test repo, warm caches; feature freeze at hour 22 |
| 22–24 | Pitch | Slides, backup video, two timed rehearsals |

**Owners:** A builds data agents (1, 2). B builds reachability (3). C owns orchestration, API and UI. D owns triage, remediation, verifier, PR and the demo.

## 10. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Venue internet fails | High | Local JSON cache for all APIs and LLM outputs; recorded backup video |
| LLM invents function names | Medium | Validation against package source; curated map for demo CVEs |
| LLM rate limits | Medium | LLM in 3 places only, top-5 explanations only, cached outputs |
| Syft unavailable on demo machine | Low | `pipdeptree` fallback |
| Auto PR breaks the build | Low | Dry-run resolution, no major bumps, human approval |
| Team members blocked on each other | Medium | Stubs and frozen schema in hour 0–2 |

## 11. Open questions
1. Which LLM provider and free tier does the team have reliable keys for?
2. Should L0 transitive findings appear in the PR description as "not fixed, not reachable", or only in the report?
3. Does the venue machine have pip 22.2 or later for `--dry-run`?
4. Is a second demo repository needed to show the system generalises?

## 12. Future scope
- GitHub Action that comments the risk delta on every pull request.
- SBOM diff between commits ("this PR introduced 3 new reachable vulnerabilities").
- JavaScript reachability worker using tree-sitter.
- Signed SBOM attestations, linking to the blockchain half of the track.
