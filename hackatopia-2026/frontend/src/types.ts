// Mirrors backend/app/schemas.py and docs/API_CONTRACT.md. Change all three together.
export type ReachLevel = "L0" | "L1" | "L2";
export type AgentName =
  | "sbom" | "vuln_intel" | "risk_analysis" | "remediation" | "code_fix" | "human_gate" | "open_pr";
export type AgentStatus = "running" | "done" | "failed" | "waiting" | "retry";
export type RunStatus = "running" | "awaiting_approval" | "completed" | "rejected" | "failed";

export interface Component {
  name: string; version: string; direct: boolean; parents: string[];
  source: "pypi" | "vcs" | "url";      // vcs/url packages come from another repository and are not checked against OSV
  source_url: string | null;
}

export interface Finding {
  id: string; cve: string | null; aliases: string[]; package: string; version: string;
  summary: string; cvss: number; epss: number; kev: boolean; fixed_in: string[]; direct: boolean;
}

export interface Evidence { file: string; line: number; snippet: string; call: string | null; }

export interface Reachability {
  finding_id: string; level: ReachLevel; functions: string[]; evidence: Evidence[]; note: string | null;
  path: string[];   // indirect L2: call chain from the app's call down to the vulnerable function
}

export interface ScoreBreakdown {
  cvss: number; reach_weight: number; epss_factor: number; kev_boost: number; direct_boost: number;
}

export interface ScoredFinding {
  finding: Finding; reach: Reachability; score: number; breakdown: ScoreBreakdown;
  rank: number; explanation: string | null;
}

export interface PackageChange { package: string; old: string; new: string; cves_closed: string[]; }

export interface Remediation {
  changes: PackageChange[]; manual_review: PackageChange[]; not_patched: string[];
  diff: string; pr_title: string; pr_body: string;
}

export interface Verification { ok: boolean; notes: string[]; attempt: number; }

export interface CodeIssue { kind: "vulnerable" | "deprecated"; api: string; line: number; detail: string; }
export interface CodeChange { function: string; line: number; issues: CodeIssue[]; explanation: string; source: "llm" | "rule"; }
/** All function rewrites proposed for one source file. */
export interface CodeFix { file: string; diff: string; changes: CodeChange[]; }

export interface AgentEvent {
  agent: AgentName; status: AgentStatus; worker_id: string | null; detail: string; ts: number;
}

export interface AuditSnapshot {
  run_id: string; repo_url: string; status: RunStatus; components: Component[]; findings: Finding[];
  scored: ScoredFinding[]; remediation: Remediation | null; verification: Verification | null;
  code_fixes: CodeFix[]; pr_url: string | null; error: string | null;
  created_at: number; user: string | null; events: AgentEvent[];
  since_last: SinceLast | null;
  trace_url: string | null;   // LangSmith trace, when tracing is enabled on the backend
}

/** Per-repository memory: what changed compared with the previous audit of the same repo. */
export interface SinceLast { previous_run_id: string; previous_at: number; new: string[]; resolved: string[]; unchanged: number; }

export interface LogLine { ts: number; level: string; logger: string; run_id: string | null; agent: string | null; message: string; }

/** One row of the audit history (GET /audits). */
export interface AuditSummary {
  run_id: string; repo_url: string; status: RunStatus; created_at: number; user: string | null;
  components: number; findings: number; l2: number; l1: number; l0: number;
  changes: number; code_fixes: number; pr_url: string | null;
}

// --- GitHub OAuth (backend/app/auth.py) ---
export interface GitHubUser { login: string; name: string | null; avatar_url: string | null; html_url: string | null; }

export interface AuthState {
  oauth_configured: boolean;
  authenticated: boolean;
  user: GitHubUser | null;
  server_token: boolean;   // a PR can be opened without signing in
}

export interface RepoOption {
  full_name: string; html_url: string; language: string | null; can_push: boolean;
  description: string | null; private: boolean; pushed_at: string | null; stars: number; default_branch: string | null;
}

export interface Health {
  ok: boolean; offline: boolean; stubs: string[]; sbom_tool?: string;
  llm?: { provider: string; model: string; enabled: boolean; reason: string | null };
  storage?: "postgres" | "sqlite"; langsmith?: boolean; workspace_ttl_days?: number;
}
