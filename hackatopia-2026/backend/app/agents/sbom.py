"""Agent 1: SBOM (no LLM). FR-1..FR-4."""
from app import auth, config, stubs
from app.events import emit
from app.state import AuditState
from app.tools import syft


def sbom_node(state: AuditState) -> dict:
    if config.STUBS["sbom"]:
        return {"components": stubs.COMPONENTS, "sbom_source": "stub", "repo_dir": None, "venv_dir": None}
    result = syft.components_for(state["repo_url"], progress=lambda msg: emit("sbom", "running", msg),
                                 token=auth.current_run_token())
    return {
        "components": result["components"],
        "sbom_source": result["source"],
        "manifests": result.get("manifests", []),
        "sbom_ignored": result.get("ignored", 0),
        "repo_dir": result["repo_dir"],
        "venv_dir": result["venv_dir"] if result["installed"] else None,
    }


def describe(_state: dict, update: dict) -> tuple[str, str]:
    comps = update["components"]
    direct = sum(c["direct"] for c in comps)
    external = sum(c.get("source", "pypi") != "pypi" for c in comps)
    extra = f", {external} from other repositories" if external else ""
    manifests = update.get("manifests") or []
    where = f" from {', '.join(manifests)}" if manifests and manifests != ["requirements.txt"] else ""
    ignored = update.get("sbom_ignored") or 0
    skipped = f"; {ignored} non-Python components in it were not checked" if ignored else ""
    return "done", f"{len(comps)} components ({direct} direct{extra}) via {update['sbom_source']}{where}{skipped}"
