"""Shared LangGraph state. Values are plain dicts (model_dump of schemas.*) so the
checkpointer can serialise them. Agents never call each other; they only read/write this."""
import operator
from typing import Annotated, Optional, TypedDict


class AuditState(TypedDict, total=False):
    repo_url: str
    repo_dir: Optional[str]            # clone path, set by sbom agent
    venv_dir: Optional[str]            # isolated venv path, set by sbom agent
    sbom_source: str                   # syft | pipdeptree | manifest | cache
    manifests: list[str]               # requirements files that were audited, primary first
    sbom_ignored: int                  # non-Python components in a shipped SBOM that were left out
    components: list[dict]             # schemas.Component
    findings: list[dict]               # schemas.Finding
    # parallel reachability workers append here; reducer merges (PRD section 5)
    reach_results: Annotated[list[dict], operator.add]   # schemas.Reachability
    scored: list[dict]                 # schemas.ScoredFinding
    remediation: Optional[dict]        # schemas.Remediation
    patched_manifest: Optional[str]    # full text of the patched requirements.txt
    patched_manifests: dict[str, str]  # every changed requirements file (root and -r includes) -> new text
    flat_manifest: Optional[str]       # patched manifest with includes inlined, for the resolver check
    verification: Optional[dict]       # schemas.Verification
    verifier_attempts: int
    # versions the verifier rejected: {"package", "version", "reason", "suggest"}
    bad_versions: list[dict]
    code_fixes: list[dict]             # schemas.CodeFix
    patched_files: dict[str, str]      # repo-relative path -> full rewritten source
    since_last: Optional[dict]         # schemas.SinceLast
    approved: Optional[bool]
    pr_url: Optional[str]
    status: str                        # schemas.RunStatus
    error: Optional[str]
