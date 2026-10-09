"""Agent 8: Open PR (no LLM). FR-25. The only node that writes to GitHub; reached only after approval."""
import httpx

from app import auth, config
from app.state import AuditState
from app.tools import github
from app.tools.syft import MANIFEST


def open_pr_node(state: AuditState) -> dict:
    if config.STUBS["open_pr"]:
        return {"pr_url": "https://github.com/example/demo-repo/pull/1", "status": "completed"}
    r = state["remediation"]
    try:
        files = dict(state.get("patched_files") or {})
        if r["changes"]:       # every requirements file that changed, wherever the pin lives
            files.update(state.get("patched_manifests") or {MANIFEST: state["patched_manifest"]})
        # The token is looked up by run id, so it never enters graph state or the checkpointer.
        url = github.create_branch_commit_pr(state["repo_url"], files, r["pr_title"], r["pr_body"],
                                             auth.current_run_token())
    except (github.GitHubError, httpx.HTTPError) as e:
        return {"status": "failed", "error": f"Could not open the pull request: {e}"}
    return {"pr_url": url, "status": "completed"}


def describe(_state: dict, update: dict) -> tuple[str, str]:
    if update.get("pr_url"):
        return "done", update["pr_url"]
    return "failed", update.get("error", "")
