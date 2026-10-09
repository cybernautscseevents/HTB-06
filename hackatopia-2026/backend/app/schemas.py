"""API / state data shapes. Mirrors frontend/src/types.ts and docs/API_CONTRACT.md.
Change all three together."""
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

ReachLevel = Literal["L0", "L1", "L2"]
AgentName = Literal[
    "sbom", "vuln_intel", "risk_analysis", "remediation", "code_fix", "human_gate", "open_pr",
]
# Audits stored before reachability+triage and remediation+verifier were merged still load.
LEGACY_AGENTS = {"reachability": "risk_analysis", "triage": "risk_analysis", "verifier": "remediation"}
AgentStatus = Literal["running", "done", "failed", "waiting", "retry"]
RunStatus = Literal["running", "awaiting_approval", "completed", "rejected", "failed"]


class Component(BaseModel):
    name: str
    version: str
    direct: bool
    parents: list[str] = Field(default_factory=list)
    source: Literal["pypi", "vcs", "url"] = "pypi"   # vcs/url packages are not checked against OSV
    source_url: Optional[str] = None


class Finding(BaseModel):
    id: str
    cve: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)
    package: str
    version: str
    summary: str = ""
    cvss: float = 0.0
    epss: float = 0.0
    kev: bool = False
    fixed_in: list[str] = Field(default_factory=list)
    direct: bool = False


class Evidence(BaseModel):
    file: str
    line: int
    snippet: str
    call: Optional[str] = None    # resolved name of the call on that line, e.g. requests.Session.get


class Reachability(BaseModel):
    finding_id: str
    level: ReachLevel
    functions: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    note: Optional[str] = None
    # Indirect L2 only: the call chain from the application's call down to the vulnerable function.
    path: list[str] = Field(default_factory=list)


class ScoreBreakdown(BaseModel):
    cvss: float
    reach_weight: float
    epss_factor: float
    kev_boost: float
    direct_boost: float


class ScoredFinding(BaseModel):
    finding: Finding
    reach: Reachability
    score: float
    breakdown: ScoreBreakdown
    rank: int
    explanation: Optional[str] = None


class PackageChange(BaseModel):
    package: str
    old: str
    new: str
    cves_closed: list[str] = Field(default_factory=list)


class Remediation(BaseModel):
    changes: list[PackageChange] = Field(default_factory=list)
    manual_review: list[PackageChange] = Field(default_factory=list)
    not_patched: list[str] = Field(default_factory=list)
    diff: str = ""
    pr_title: str = ""
    pr_body: str = ""


class Verification(BaseModel):
    ok: bool
    notes: list[str] = Field(default_factory=list)
    attempt: int = 0


class CodeIssue(BaseModel):
    kind: Literal["vulnerable", "deprecated"]
    api: str                      # e.g. yaml.load
    line: int
    detail: str = ""


class CodeChange(BaseModel):
    function: str                 # rewritten function, or "<module>" for top-level code
    line: int
    issues: list[CodeIssue] = Field(default_factory=list)
    explanation: str = ""
    source: Literal["llm", "rule"] = "llm"


class CodeFix(BaseModel):
    """All rewrites proposed for one source file."""
    file: str
    diff: str
    changes: list[CodeChange] = Field(default_factory=list)


class AgentEvent(BaseModel):
    agent: AgentName

    @field_validator("agent", mode="before")
    @classmethod
    def _legacy_name(cls, value):
        return LEGACY_AGENTS.get(value, value)

    status: AgentStatus
    worker_id: Optional[str] = None
    detail: str = ""
    ts: float = 0.0


class SinceLast(BaseModel):
    """What changed compared with the previous audit of the same repository (per-repo memory)."""
    previous_run_id: str
    previous_at: float = 0.0
    new: list[str] = Field(default_factory=list)        # finding ids not seen last time
    resolved: list[str] = Field(default_factory=list)   # finding ids that are gone
    unchanged: int = 0


class LogLine(BaseModel):
    ts: float
    level: str
    logger: str
    run_id: Optional[str] = None
    agent: Optional[str] = None
    message: str


class AuditSnapshot(BaseModel):
    run_id: str
    repo_url: str
    status: RunStatus
    components: list[Component] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    scored: list[ScoredFinding] = Field(default_factory=list)
    remediation: Optional[Remediation] = None
    verification: Optional[Verification] = None
    code_fixes: list[CodeFix] = Field(default_factory=list)
    pr_url: Optional[str] = None
    error: Optional[str] = None
    created_at: float = 0.0
    user: Optional[str] = None    # GitHub login of whoever started the audit
    since_last: Optional[SinceLast] = None
    trace_url: Optional[str] = None   # LangSmith trace of this audit, when tracing is on
    events: list[AgentEvent] = Field(default_factory=list)


class AuditRequest(BaseModel):
    repo_url: str


class DecisionRequest(BaseModel):
    approved: bool


class AuditSummary(BaseModel):
    """One row of the audit history."""
    run_id: str
    repo_url: str
    status: RunStatus
    created_at: float = 0.0
    user: Optional[str] = None
    components: int = 0
    findings: int = 0
    l2: int = 0
    l1: int = 0
    l0: int = 0
    changes: int = 0
    code_fixes: int = 0
    pr_url: Optional[str] = None
