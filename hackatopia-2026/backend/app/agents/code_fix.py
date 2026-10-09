"""Agent 7: Code Fix (LLM call site 4). Rewrites whole functions that call a vulnerable API
directly or a deprecated API, so the pull request fixes the code and not only the pin.

The LLM proposes the rewritten function; code decides whether to keep it. A rewrite is used only
if it parses, keeps the function's name and parameters, leaves the file importable as a whole and
no longer contains the flagged call. Simple renames have a deterministic rule as a fallback.
"""
import ast
import difflib
import logging
import textwrap
from pathlib import Path

from langsmith import traceable

from app import config
from app.state import AuditState
from app.tools import ast_scanner, deprecations, llm
from app.tools.textio import read_source, to_source

log = logging.getLogger(__name__)

# Deterministic fallback: {api: (new attribute name, required import or None, arguments or None)}
RULES: dict[str, tuple[str, str | None, str | None]] = {
    "yaml.load": ("safe_load", None, None),
    "logging.warn": ("warning", None, None),
    "logging.getLogger.warn": ("warning", None, None),
    "time.clock": ("perf_counter", None, None),
    "base64.encodestring": ("encodebytes", None, None),
    "base64.decodestring": ("decodebytes", None, None),
    "inspect.getargspec": ("getfullargspec", None, None),
    "streamlit.experimental_rerun": ("rerun", None, None),
    "streamlit.experimental_memo": ("cache_data", None, None),
    "streamlit.experimental_singleton": ("cache_resource", None, None),
    "streamlit.beta_columns": ("columns", None, None),
    "datetime.datetime.utcnow": ("now", "from datetime import timezone", "timezone.utc"),
}


# --- 1. What needs fixing ------------------------------------------------------------------------

@traceable(name="find_deprecated_and_vulnerable_calls", run_type="tool")
def collect_issues(repo_dir: str, scored: list[dict], venv_dir: str | None = None,
                   components: list[dict] | None = None) -> dict[str, list[dict]]:
    """{file: [issue]} where issue = {line, kind, api, detail}. A vulnerable call outranks a
    deprecation notice on the same line.

    Deprecated APIs are discovered from the installed versions of what the application imports
    (see tools/deprecations.py), not from a fixed list.
    """
    found: dict[tuple[str, int], dict] = {}

    index = deprecations.Index(ast_scanner.imported_roots(repo_dir), venv_dir, components or [])
    for path in ast_scanner.iter_source_files(repo_dir):
        rel = path.relative_to(repo_dir).as_posix()
        scanner = ast_scanner.scan_file(read_source(path)[0], index.roots, None)
        for c in (scanner.calls if scanner else []):
            hit = None if c.safe else index.lookup(c.name)
            if hit:
                found[(rel, c.line)] = {"line": c.line, "kind": "deprecated", "api": c.name, "detail": hit[1]}

    for s in scored:
        f, r = s["finding"], s["reach"]
        if r["level"] != "L2" or r.get("path"):     # indirect reachability is fixed by the upgrade, not here
            continue
        fix = f"Fixed in {f['package']} {f['fixed_in'][0]}." if f["fixed_in"] else ""
        for e in r["evidence"]:
            found[(e["file"], e["line"])] = {
                "line": e["line"], "kind": "vulnerable", "api": e.get("call") or r["functions"][0],
                "detail": f"{f['cve'] or f['id']}: {f['summary']} {fix}".strip()}

    by_file: dict[str, list[dict]] = {}
    for (rel, _line), issue in sorted(found.items()):
        by_file.setdefault(rel, []).append(issue)
    log.info("code fix: %d deprecated APIs known for this app's imports, %d call sites to fix",
             index.size, len(found))
    return by_file


# --- 2. The unit to rewrite: the enclosing function, or one top-level statement ---------------------

def enclosing_unit(tree: ast.Module, line: int) -> tuple[str, int, int] | None:
    """(name, first line, last line) of the innermost function around `line`, decorators included."""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or 0):
            start = min([node.lineno, *[d.lineno for d in node.decorator_list]])
            if best is None or start >= best[1]:
                best = (node.name, start, node.end_lineno)
    if best:
        return best
    for node in tree.body:
        if node.lineno <= line <= (node.end_lineno or node.lineno):
            return "<module>", node.lineno, node.end_lineno or node.lineno
    return None


def _signature(node) -> tuple:
    a = node.args
    return (type(node).__name__, node.name, [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs],
            a.vararg and a.vararg.arg, a.kwarg and a.kwarg.arg)


# --- 3. Two ways to produce a rewrite --------------------------------------------------------------

def rule_rewrite(lines: list[str], start: int, end: int, issues: list[dict], calls) -> tuple[list[str], list[str]] | None:
    """Rename-style fixes applied straight to the source text. None unless every issue has a rule."""
    edits, imports = [], []
    for issue in issues:
        rule = RULES.get(issue["api"])
        call = next((c for c in calls if c.line == issue["line"] and c.name == issue["api"]), None)
        if not rule or not call or not isinstance(call.node.func, ast.Attribute):
            return None
        new_attr, needs_import, new_args = rule
        node, func = call.node, call.node.func
        has_args = bool(node.args or node.keywords)
        if issue["api"] == "yaml.load" and (len(node.args) != 1 or node.keywords):
            return None                              # an explicit unsafe Loader needs a real rewrite
        if new_args is not None:
            if has_args or node.end_lineno != func.end_lineno:
                return None
            edits.append((func.end_lineno, func.end_col_offset, node.end_col_offset, f"({new_args})"))
        edits.append((func.end_lineno, func.end_col_offset - len(func.attr), func.end_col_offset, new_attr))
        if needs_import:
            imports.append(needs_import)
    out = list(lines)
    for line_no, col_a, col_b, text in sorted(edits, reverse=True):
        row = out[line_no - 1]
        # ast columns are utf-8 byte offsets
        raw = row.encode("utf-8")
        out[line_no - 1] = (raw[:col_a] + text.encode("utf-8") + raw[col_b:]).decode("utf-8")
    return out[start - 1:end], imports


def llm_rewrite(source: str, name: str, issues: list[dict], imports: list[str]) -> tuple[str, list[str], str] | None:
    out = llm.rewrite_function({
        "function_name": name,
        "source": source,
        "file_imports": imports[:40],
        "problems": [{"api": i["api"], "kind": i["kind"], "what_to_do": i["detail"]} for i in issues],
    })
    if not out or not out.changed or not out.code.strip():
        return None
    return out.code.strip("\n"), [i.strip() for i in out.new_imports if i.strip()], out.explanation.strip()


# --- 4. Apply to one file, keeping only rewrites that pass the checks --------------------------------

def _valid_imports(imports: list[str]) -> bool:
    for line in imports:
        try:
            body = ast.parse(line).body
        except SyntaxError:
            return False
        if len(body) != 1 or not isinstance(body[0], (ast.Import, ast.ImportFrom)):
            return False
    return True


def _insert_imports(lines: list[str], imports: list[str]) -> list[str]:
    new = [i for i in dict.fromkeys(imports) if i not in {ln.strip() for ln in lines}]
    if not new:
        return lines
    tree = ast.parse("\n".join(lines))
    last = max((n.end_lineno for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))), default=0)
    if not last and tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        last = tree.body[0].end_lineno          # keep a module docstring first
    return lines[:last] + new + lines[last:]


@traceable(name="rewrite_functions_in_file", run_type="chain")
def fix_file(rel: str, text: str, issues: list[dict], budget: int) -> tuple[str, list[dict]]:
    """Returns (new text, [schemas.CodeChange dict]). `text` uses \\n line endings."""
    apis = {i["api"] for i in issues}
    roots = {a.split(".")[0] for a in apis}
    targets = {a.split(".")[-1] for a in apis}
    tree = ast.parse(text)
    scanner = ast_scanner.scan_file(text, roots, targets)
    file_imports = [ast.get_source_segment(text, n) or "" for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]

    units: dict[tuple[str, int, int], list[dict]] = {}
    for issue in issues:
        unit = enclosing_unit(tree, issue["line"])
        if unit:
            units.setdefault(unit, []).append(issue)

    lines = text.split("\n")
    changes, pending_imports = [], []
    # Bottom-up, so earlier line numbers stay valid while the file is being edited.
    for (name, start, end), unit_issues in sorted(units.items(), key=lambda u: -u[0][1])[:budget]:
        block = lines[start - 1:end]
        indent = block[0][: len(block[0]) - len(block[0].lstrip())]
        original = textwrap.dedent("\n".join(block))

        candidates = []
        proposal = llm_rewrite(original, name, unit_issues, file_imports)
        if proposal:
            code, imports, why = proposal
            candidates.append((textwrap.indent(code, indent).split("\n"), imports, why, "llm"))
        ruled = rule_rewrite(lines, start, end, unit_issues, scanner.calls)
        if ruled:
            why = "Replaced " + ", ".join(sorted({f"{i['api']} with {RULES[i['api']][0]}" for i in unit_issues})) + "."
            candidates.append((ruled[0], ruled[1], why, "rule"))

        for new_block, imports, why, source in candidates:
            if not _accept(lines, start, end, name, new_block, imports, apis, roots, targets):
                continue
            lines = lines[:start - 1] + new_block + lines[end:]
            pending_imports += imports
            changes.append({"function": name, "line": start, "issues": unit_issues, "explanation": why, "source": source})
            break

    if not changes:
        return text, []
    lines = _insert_imports(lines, pending_imports)
    return "\n".join(lines), sorted(changes, key=lambda c: c["line"])


def _accept(lines, start, end, name, new_block, imports, apis, roots, targets) -> bool:
    """The checks a rewrite must pass before a human ever sees it."""
    if new_block == lines[start - 1:end] or not _valid_imports(imports):
        return False
    try:
        new_tree = ast.parse(textwrap.dedent("\n".join(new_block)))
        old_tree = ast.parse(textwrap.dedent("\n".join(lines[start - 1:end])))
    except SyntaxError:
        return False
    if name != "<module>":
        if len(new_tree.body) != 1 or not isinstance(new_tree.body[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        if _signature(new_tree.body[0]) != _signature(old_tree.body[0]):
            return False                            # callers must keep working
    candidate = "\n".join(lines[:start - 1] + new_block + lines[end:])
    scanner = ast_scanner.scan_file(candidate, roots, targets)
    if scanner is None:                             # the whole file must still parse
        return False
    new_end = start + len(new_block) - 1
    return not any(c.name in apis and not c.safe and start <= c.line <= new_end for c in scanner.calls)


# --- Node ------------------------------------------------------------------------------------------------

def code_fix_node(state: AuditState) -> dict:
    repo_dir = state.get("repo_dir")
    if config.STUBS["code_fix"] or not repo_dir:
        return {"code_fixes": [], "patched_files": {}}

    fixes, patched, budget = [], {}, config.MAX_CODE_FIXES
    found = collect_issues(repo_dir, state.get("scored", []), state.get("venv_dir"), state.get("components"))
    for rel, issues in found.items():
        if budget <= 0:
            break
        path = Path(repo_dir) / rel
        try:
            text, newline = read_source(path)
            new_text, changes = fix_file(rel, text, issues, budget)
        except (OSError, SyntaxError, ValueError):
            continue
        if not changes:
            continue
        budget -= len(changes)
        diff = "".join(difflib.unified_diff(text.splitlines(keepends=True), new_text.splitlines(keepends=True),
                                            fromfile=f"a/{rel}", tofile=f"b/{rel}"))
        fixes.append({"file": rel, "diff": diff, "changes": changes})
        patched[rel] = to_source(new_text, newline)

    update: dict = {"code_fixes": fixes, "patched_files": patched}
    remediation = state.get("remediation")
    if fixes and remediation:
        body = remediation["pr_body"].replace("\n\n_Generated by Agentic SBOM Risk Auditor._", "")
        body += "\n\n### Code changes\n" + "\n".join(
            f"- `{f['file']}`: rewrote `{c['function']}` ({', '.join(sorted({i['api'] for i in c['issues']}))}). {c['explanation']}"
            for f in fixes for c in f["changes"])
        title = remediation["pr_title"] if remediation["changes"] else "fix: replace deprecated and vulnerable API calls"
        update["remediation"] = {**remediation, "pr_title": title,
                                 "pr_body": body + "\n\n_Generated by Agentic SBOM Risk Auditor._"}
    return update


def route_after_code_fix(state: AuditState) -> str:
    has_work = state["remediation"]["changes"] or state.get("code_fixes")
    return "human_gate" if has_work else "report"


def describe(_state: dict, update: dict) -> tuple[str, str]:
    fixes = update.get("code_fixes", [])
    count = sum(len(f["changes"]) for f in fixes)
    if not count:
        return "done", "no code changes needed"
    return "done", f"rewrote {count} function{'s' if count != 1 else ''} in {len(fixes)} file{'s' if len(fixes) != 1 else ''}"
