import type { AgentEvent, AuditSnapshot, AuditSummary, Component, GitHubUser, RepoOption } from "../types";

export const mockUser: GitHubUser = {
  login: "octo-dev", name: "Octo Dev", avatar_url: null, html_url: "https://github.com/octo-dev",
};

const repo = (full_name: string, language: string, description: string, daysAgo: number, extra: Partial<RepoOption> = {}): RepoOption => ({
  full_name, html_url: `https://github.com/${full_name}`, language, can_push: true, description, private: false,
  pushed_at: new Date(Date.now() - daysAgo * 86400e3).toISOString(), stars: 0, default_branch: "main", ...extra,
});

export const mockRepos: RepoOption[] = [
  repo("example/demo-repo", "Python", "Demo service with a reachable PyYAML vulnerability", 0, { stars: 12 }),
  repo("example/billing-service", "Python", "Invoices, payments and dunning", 2, { stars: 4 }),
  repo("example/resume-checker", "Python", "Streamlit app that scores resumes against a job description", 6),
  repo("example/internal-utils", "Python", "Shared helpers used by other services", 21, { private: true }),
  repo("example/docs-site", "TypeScript", "Public documentation", 40, { stars: 31 }),
];

const pypi = (name: string, version: string, direct: boolean, parents: string[] = []): Component =>
  ({ name, version, direct, parents, source: "pypi", source_url: null });

export const mockSnapshot: AuditSnapshot = {
  run_id: "mock0001",
  repo_url: "https://github.com/example/demo-repo",
  status: "awaiting_approval",
  created_at: Date.now() / 1000 - 90,
  user: "octo-dev",
  components: [
    pypi("certifi", "2020.12.5", false, ["requests"]),
    { name: "internal-utils", version: "0.4.0", direct: true, parents: [], source: "vcs", source_url: "git+https://github.com/example/internal-utils@v0.4.0" },
    pypi("jinja2", "2.11.2", true),
    pypi("markupsafe", "1.1.1", false, ["jinja2"]),
    pypi("pillow", "8.0.0", false, ["reportlab"]),
    pypi("pyyaml", "5.3", true),
    pypi("reportlab", "3.5.55", true),
    pypi("requests", "2.25.0", true),
    pypi("urllib3", "1.26.2", false, ["requests"]),
  ],
  findings: [],
  scored: [
    {
      rank: 1, score: 14.58,
      finding: { id: "GHSA-8q59-q68h-6hv4", cve: "CVE-2020-14343", aliases: ["CVE-2020-14343", "PYSEC-2021-142"], package: "pyyaml", version: "5.3",
        summary: "Improper input validation in PyYAML allows arbitrary code execution via yaml.load.", cvss: 7.5, epss: 0.62, kev: false, fixed_in: ["5.4"], direct: true },
      reach: { finding_id: "GHSA-8q59-q68h-6hv4", level: "L2", functions: ["yaml.load", "yaml.full_load"],
        evidence: [{ file: "app/config_loader.py", line: 12, snippet: "data = yaml.load(f)", call: "yaml.load" }], note: null, path: [] },
      breakdown: { cvss: 7.5, reach_weight: 1.0, epss_factor: 1.62, kev_boost: 1.0, direct_boost: 1.2 },
      explanation: "pyyaml 5.3 is affected by CVE-2020-14343 and app/config_loader.py:12 calls yaml.load on file input, so the vulnerable code is reachable. Upgrade to 5.4 or later.",
    },
    {
      rank: 2, score: 7.54,
      finding: { id: "GHSA-j8r2-6x86-q33q", cve: "CVE-2023-32681", aliases: ["CVE-2023-32681"], package: "requests", version: "2.25.0",
        summary: "Unintended leak of Proxy-Authorization header in requests.", cvss: 6.1, epss: 0.03, kev: false, fixed_in: ["2.31.0"], direct: true },
      reach: { finding_id: "GHSA-j8r2-6x86-q33q", level: "L2", functions: ["requests.sessions.Session.rebuild_proxies"],
        evidence: [{ file: "app/client.py", line: 9, snippet: "resp = requests.get(url, timeout=10)", call: "requests.get" }],
        note: "reached indirectly through requests.get",
        path: ["requests.get", "requests.sessions.Session.request", "requests.sessions.Session.send",
               "requests.sessions.Session.resolve_redirects", "requests.sessions.Session.rebuild_proxies"] },
      breakdown: { cvss: 6.1, reach_weight: 1.0, epss_factor: 1.03, kev_boost: 1.0, direct_boost: 1.2 },
      explanation: "requests 2.25.0 is affected by CVE-2023-32681 and app/client.py:9 calls requests.get, which reaches the vulnerable redirect handling. Upgrade to 2.31.0 or later.",
    },
    {
      rank: 3, score: 4.12,
      finding: { id: "GHSA-3f63-hfp8-52jq", cve: "CVE-2021-25289", aliases: ["CVE-2021-25289"], package: "pillow", version: "8.0.0",
        summary: "Heap-based buffer overflow in TiffDecode.c in Pillow.", cvss: 9.8, epss: 0.05, kev: true, fixed_in: ["8.1.1"], direct: false },
      reach: { finding_id: "GHSA-3f63-hfp8-52jq", level: "L0", functions: [], evidence: [], note: "not imported", path: [] },
      breakdown: { cvss: 9.8, reach_weight: 0.2, epss_factor: 1.05, kev_boost: 2.0, direct_boost: 1.0 },
      explanation: null,
    },
    {
      rank: 4, score: 1.07,
      finding: { id: "GHSA-g4mx-q9vg-27p4", cve: "CVE-2023-45803", aliases: ["CVE-2023-45803"], package: "urllib3", version: "1.26.2",
        summary: "urllib3's request body not stripped after redirect from 303 status.", cvss: 5.3, epss: 0.01, kev: false, fixed_in: ["1.26.18", "2.0.7"], direct: false },
      reach: { finding_id: "GHSA-g4mx-q9vg-27p4", level: "L0", functions: [], evidence: [], note: "not imported", path: [] },
      breakdown: { cvss: 5.3, reach_weight: 0.2, epss_factor: 1.01, kev_boost: 1.0, direct_boost: 1.0 },
      explanation: null,
    },
  ],
  remediation: {
    changes: [
      { package: "pyyaml", old: "5.3", new: "5.4", cves_closed: ["CVE-2020-14343"] },
      { package: "requests", old: "2.25.0", new: "2.31.0", cves_closed: ["CVE-2023-32681"] },
      { package: "pillow", old: "8.0.0", new: "8.1.1", cves_closed: ["CVE-2021-25289"] },
    ],
    manual_review: [],
    not_patched: ["GHSA-g4mx-q9vg-27p4"],
    diff: "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1,4 +1,5 @@\n-PyYAML==5.3\n-requests==2.25.0\n+PyYAML==5.4\n+requests==2.31.0\n Jinja2==2.11.2\n reportlab==3.5.55\n+pillow==8.1.1  # transitive dependency pinned by security audit\n",
    pr_title: "fix(deps): security updates for 3 packages",
    pr_body: "## Security dependency updates\n\nUpdates 3 package(s) in `requirements.txt` to close 3 known vulnerabilities that are reachable from this application or actively exploited.\n\n| Package | Old | New | CVEs closed | Reachability evidence |\n|---|---|---|---|---|\n| pyyaml | 5.3 | 5.4 | CVE-2020-14343 | L2 `app/config_loader.py:12` |\n| requests | 2.25.0 | 2.31.0 | CVE-2023-32681 | L2 `app/client.py:9` |\n| pillow | 8.0.0 | 8.1.1 | CVE-2021-25289 | L0 |\n\n### Not patched\n- urllib3 1.26.2: CVE-2023-45803, not reachable (L0)\n\n### Code changes\n- `app/config_loader.py`: rewrote `load_config` (yaml.load). Replaced yaml.load with yaml.safe_load, which parses the same config files without constructing arbitrary objects.\n- `app/audit_log.py`: rewrote `record` (datetime.datetime.utcnow). Uses a timezone-aware UTC timestamp.\n\n_Generated by Agentic SBOM Risk Auditor._",
  },
  verification: {
    ok: true, attempt: 2,
    notes: ["pip install --dry-run resolved the patched manifest"],
  },
  code_fixes: [
    {
      file: "app/config_loader.py",
      diff: "--- a/app/config_loader.py\n+++ b/app/config_loader.py\n@@ -9,5 +9,5 @@\n def load_config(path):\n     \"\"\"Read the service configuration.\"\"\"\n     with open(path) as f:\n-        data = yaml.load(f)\n+        data = yaml.safe_load(f)\n     return data or {}\n",
      changes: [{
        function: "load_config", line: 9, source: "llm",
        issues: [{ kind: "vulnerable", api: "yaml.load", line: 12, detail: "CVE-2020-14343: arbitrary code execution via yaml.load. Fixed in pyyaml 5.4." }],
        explanation: "Replaced yaml.load with yaml.safe_load, which parses the same config files without constructing arbitrary objects.",
      }],
    },
    {
      file: "app/audit_log.py",
      diff: "--- a/app/audit_log.py\n+++ b/app/audit_log.py\n@@ -1,4 +1,4 @@\n-from datetime import datetime\n+from datetime import datetime, timezone\n \n \n def record(event):\n@@ -6,3 +6,3 @@\n-    event[\"at\"] = datetime.utcnow()\n+    event[\"at\"] = datetime.now(timezone.utc)\n     return event\n",
      changes: [{
        function: "record", line: 4, source: "rule",
        issues: [{ kind: "deprecated", api: "datetime.datetime.utcnow", line: 6, detail: "Deprecated since Python 3.12 and returns a naive datetime. Use datetime.now(timezone.utc)." }],
        explanation: "Uses a timezone-aware UTC timestamp.",
      }],
    },
  ],
  pr_url: null,
  error: null,
  events: [],
  since_last: { previous_run_id: "7c0d9e11", previous_at: Date.now() / 1000 - 50 * 3600, new: ["GHSA-j8r2-6x86-q33q"], resolved: ["GHSA-old1-old2-old3"], unchanged: 3 },
  trace_url: null,
};

const ev = (agent: AgentEvent["agent"], status: AgentEvent["status"], detail = "", worker_id: string | null = null): AgentEvent =>
  ({ agent, status, detail, worker_id, ts: 0 });

export const mockEvents: AgentEvent[] = [
  ev("sbom", "running"),
  ev("sbom", "running", "Cloning repository"),
  ev("sbom", "running", "Installing dependencies into an isolated venv"),
  ev("sbom", "done", "9 components (5 direct, 1 from other repositories) via syft"),
  ev("vuln_intel", "running"),
  ev("vuln_intel", "done", "4 vulnerabilities in 4 packages (1 in CISA KEV)"),
  ev("risk_analysis", "running", "", "GHSA-8q59-q68h-6hv4"),
  ev("risk_analysis", "running", "", "GHSA-j8r2-6x86-q33q"),
  ev("risk_analysis", "running", "", "GHSA-3f63-hfp8-52jq"),
  ev("risk_analysis", "running", "", "GHSA-g4mx-q9vg-27p4"),
  ev("risk_analysis", "done", "pillow: L0", "GHSA-3f63-hfp8-52jq"),
  ev("risk_analysis", "done", "pyyaml: L2 at app/config_loader.py:12", "GHSA-8q59-q68h-6hv4"),
  ev("risk_analysis", "done", "urllib3: L0", "GHSA-g4mx-q9vg-27p4"),
  ev("risk_analysis", "done", "requests: L2 at app/client.py:9", "GHSA-j8r2-6x86-q33q"),
  ev("risk_analysis", "running"),
  ev("risk_analysis", "done", "L2: 2, L1: 0, L0: 2; top risk pyyaml CVE-2020-14343; 1 new, 1 resolved since last audit"),
  ev("remediation", "running"),
  ev("remediation", "running", "proposed pyyaml 5.3 -> 5.3.1, requests 2.25.0 -> 2.31.0, pillow 8.0.0 -> 8.1.1; verifying"),
  ev("remediation", "running"),
  ev("remediation", "retry", "attempt 1: pyyaml 5.3.1 is still affected by GHSA-8q59-q68h-6hv4; fixed in 5.4"),
  ev("remediation", "running"),
  ev("remediation", "running", "proposed retry 1: pyyaml 5.3 -> 5.4, requests 2.25.0 -> 2.31.0, pillow 8.0.0 -> 8.1.1; verifying"),
  ev("remediation", "running"),
  ev("remediation", "done", "pyyaml 5.3 -> 5.4, requests 2.25.0 -> 2.31.0, pillow 8.0.0 -> 8.1.1; verified on attempt 2"),
  ev("code_fix", "running"),
  ev("code_fix", "done", "rewrote 2 functions in 2 files"),
  ev("human_gate", "waiting", "Awaiting approval"),
];

export const mockPrEvents = (approved: boolean): AgentEvent[] => approved
  ? [ev("human_gate", "done", "approved"), ev("open_pr", "running"),
     ev("open_pr", "done", "https://github.com/example/demo-repo/pull/1")]
  : [ev("human_gate", "done", "rejected")];

/** History rows: the live mock run plus a few older audits. */
export function mockHistory(current: AuditSnapshot): AuditSummary[] {
  const now = Date.now() / 1000;
  const row = (run_id: string, name: string, status: AuditSummary["status"], hoursAgo: number, n: Partial<AuditSummary>): AuditSummary => ({
    run_id, repo_url: `https://github.com/example/${name}`, status, created_at: now - hoursAgo * 3600, user: "octo-dev",
    components: 0, findings: 0, l2: 0, l1: 0, l0: 0, changes: 0, code_fixes: 0, pr_url: null, ...n,
  });
  return [
    row(current.run_id, "demo-repo", current.status, 0.02, { components: 9, findings: 4, l2: 2, l0: 2, changes: 3, code_fixes: 2, pr_url: current.pr_url }),
    row("a41b2115", "billing-service", "completed", 5, { components: 41, findings: 17, l2: 1, l1: 4, l0: 12, changes: 3, pr_url: "https://github.com/example/billing-service/pull/42" }),
    row("935ee608", "resume-checker", "rejected", 26, { components: 59, findings: 132, l1: 3, l0: 129, changes: 2 }),
    row("7c0d9e11", "demo-repo", "completed", 50, { components: 9, findings: 4, l2: 1, l1: 1, l0: 2, changes: 2, code_fixes: 1, pr_url: "https://github.com/example/demo-repo/pull/1" }),
    row("5f2a0b3c", "internal-utils", "failed", 75, { components: 12 }),
  ];
}
