"""AST scanner for the application source: imports and calls, alias aware (FR-13), with
safe-pattern rules (FR-15).

Calls are resolved through import aliases and through simple instance tracking, so
`s = requests.Session(); s.get(url)` resolves to `requests.Session.get`. Anything more dynamic
(values passed between functions, attributes on self) is not followed.
"""
import ast
from pathlib import Path

from langsmith import traceable

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__",
             "build", "dist", ".tox", ".eggs"}
MAX_EVIDENCE = 20


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


# --- FR-15: call patterns known to be safe ------------------------------------------------------

def _yaml_safe_loader(call: ast.Call) -> bool:
    loader = next((k.value for k in call.keywords if k.arg == "Loader"), None)
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    name = _dotted(loader) if loader is not None else None
    return bool(name) and name.split(".")[-1] in {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


# {(import root, function name): (predicate, note)}
SAFE_PATTERNS = {
    ("yaml", "load"): (_yaml_safe_loader, "yaml.load with SafeLoader"),
    ("yaml", "load_all"): (_yaml_safe_loader, "yaml.load_all with SafeLoader"),
}


class Call:
    """One resolved call site in the application."""
    __slots__ = ("line", "end_line", "name", "safe", "note", "node")

    def __init__(self, node: ast.Call, name: str, safe: bool, note: str | None):
        self.line, self.end_line = node.lineno, node.end_lineno or node.lineno
        self.name, self.safe, self.note, self.node = name, safe, note, node


class _FileScanner(ast.NodeVisitor):
    def __init__(self, roots: set[str], targets: set[str] | None):
        self.roots = roots
        self.targets = targets              # bare function names to record; None records every call
        self.aliases: dict[str, str] = {}   # local name -> fully qualified name
        self.imports: list[int] = []
        self.calls: list[Call] = []

    def visit_Import(self, node: ast.Import):
        for a in node.names:
            root = a.name.split(".")[0]
            if root not in self.roots:
                continue
            self.imports.append(node.lineno)
            if a.asname:
                self.aliases[a.asname] = a.name      # import x.y as z
            else:
                self.aliases[root] = root            # import x.y binds x

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.level or not node.module or node.module.split(".")[0] not in self.roots:
            return
        self.imports.append(node.lineno)
        for a in node.names:
            if a.name != "*":
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"  # from x import f as g

    def resolve(self, node: ast.AST) -> str | None:
        """Qualified name of an expression, or None when it does not come from a tracked package."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):           # requests.Session().get -> requests.Session.get
            return self.resolve(node.func)
        if isinstance(node, ast.Await):
            return self.resolve(node.value)
        return None

    def _bind(self, target: ast.AST, value: ast.AST | None):
        """x = pkg.Thing(...) makes x an instance of pkg.Thing for later x.method() calls."""
        if isinstance(target, ast.Name) and isinstance(value, (ast.Call, ast.Await)):
            name = self.resolve(value)
            if name:
                self.aliases[target.id] = name

    def visit_Assign(self, node: ast.Assign):
        self.generic_visit(node)
        for target in node.targets:
            self._bind(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        self.generic_visit(node)
        self._bind(node.target, node.value)

    def _visit_with(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, item.context_expr)
        for stmt in node.body:
            self.visit(stmt)

    visit_With = visit_AsyncWith = _visit_with

    def visit_Call(self, node: ast.Call):
        qualified = self.resolve(node.func)
        if qualified:
            root, func = qualified.split(".")[0], qualified.split(".")[-1]
            if self.targets is None or func in self.targets:
                rule = SAFE_PATTERNS.get((root, func))
                safe = bool(rule and rule[0](node))
                self.calls.append(Call(node, qualified, safe, rule[1] if safe else None))
        self.generic_visit(node)


def iter_source_files(repo_dir: str):
    root = Path(repo_dir)
    for path in sorted(root.rglob("*.py")):
        if not SKIP_DIRS & set(path.relative_to(root).parts[:-1]):
            yield path


def imported_roots(repo_dir: str) -> set[str]:
    """Every top-level module name the application imports anywhere (absolute imports only)."""
    roots: set[str] = set()
    for path in iter_source_files(repo_dir):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                roots.add(node.module.split(".")[0])
    return roots


def scan_file(text: str, roots: set[str], targets: set[str] | None) -> _FileScanner | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    scanner = _FileScanner(roots, targets)
    scanner.visit(tree)
    return scanner


@traceable(name="scan_application_source", run_type="tool")
def scan(repo_dir: str, import_roots: list[str], functions: list[str] | None) -> dict:
    """Scan the application source.

    Returns {"imports": [Evidence], "calls": [Evidence], "safe_calls": [Evidence], "safe_notes": [str]}.
    Call evidence carries an extra "call" key with the resolved name, e.g. "requests.Session.get".
    `functions` may be qualified ("yaml.load") or bare ("load"); matching is by final name,
    restricted to names that resolve to one of `import_roots`. None records every call into them.
    """
    roots = set(import_roots)
    targets = None if functions is None else {f.split(".")[-1].strip("() ") for f in functions if f}
    out = {"imports": [], "calls": [], "safe_calls": [], "safe_notes": []}
    for path in iter_source_files(repo_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanner = scan_file(text, roots, targets)
        if not scanner or not scanner.imports:
            continue
        lines = text.splitlines()
        rel = path.relative_to(repo_dir).as_posix()

        def ev(line: int, **extra) -> dict:
            return {"file": rel, "line": line, "snippet": lines[line - 1].strip()[:200], **extra}

        out["imports"] += [ev(n) for n in scanner.imports]
        for c in scanner.calls:
            out["safe_calls" if c.safe else "calls"].append(ev(c.line, call=c.name))
            if c.note and c.note not in out["safe_notes"]:
                out["safe_notes"].append(c.note)
    for key in ("imports", "calls", "safe_calls"):
        out[key] = out[key][:MAX_EVIDENCE]
    return out
