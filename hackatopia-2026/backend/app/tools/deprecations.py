"""Deprecated APIs, discovered rather than listed by hand.

For every module the application imports, the source that is actually installed (the target
venv's packages, and this interpreter's standard library) is scanned for functions that
unconditionally announce their own deprecation: a `@deprecated` style decorator, or a
`warnings.warn(..., DeprecationWarning)` / `warn_deprecated(...)` call at the top of the body.
The library's own message becomes the advice given to the rewrite step.

So the list follows the versions in use: upgrade a dependency and its newly deprecated functions
appear without anyone editing a file. `data/deprecated_apis.json` only adds the few cases a
scan cannot see (APIs already removed, or deprecated by behaviour rather than by a warning).
"""
import ast
import json
import sys
import sysconfig
from functools import lru_cache
from pathlib import Path

from app import config
from app.tools import cache, packages
from app.tools.versions import normalize

MAX_FILES = 900
AMBIGUITY_LIMIT = 3
STDLIB = sys.stdlib_module_names


def _text(node: ast.AST | None) -> str:
    """Best-effort literal text of a message expression (plain, concatenated or f-string)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_text(v) if isinstance(v, ast.Constant) else "…" for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _text(node.left) + (_text(node.right) if isinstance(node.op, ast.Add) else "")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _text(node.func.value)
    return ""


def _name(node: ast.AST) -> str:
    while isinstance(node, ast.Call):
        node = node.func
    return node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""


def _deprecation_message(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """The function's own deprecation message, or None when it is not unconditionally deprecated."""
    for dec in func.decorator_list:
        label = _name(dec).lower()
        if any(part in label for part in ("param", "arg", "option")):
            continue                             # @deprecated_params(...): an argument is deprecated, not the function
        if "deprecat" in label:
            arg = dec.args[0] if isinstance(dec, ast.Call) and dec.args else None
            return " ".join(_text(arg).split()) or "Marked as deprecated by the library."
    for stmt in func.body:                       # only the top of the body: no branches, so unconditional
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue                             # docstring
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
            return None
        call = stmt.value
        callee = _name(call).lower()
        categories = [_name(a) for a in call.args[1:2]] + [_name(k.value) for k in call.keywords if k.arg == "category"]
        is_warn = callee == "warn" and any("Deprecat" in c for c in categories)
        if is_warn or "deprecat" in callee:
            return " ".join(_text(call.args[0] if call.args else None).split()) or "Deprecated by the library."
        return None
    return None


def _scan(files: list[tuple[str, Path]]) -> dict:
    """{"deprecated": {name: [{"qualified", "cls", "message"}]}, "defs": {name: count}}"""
    deprecated: dict[str, list[dict]] = {}
    defs: dict[str, int] = {}

    def visit(func, module: str, cls: str | None):
        name = func.name
        if name == "__init__" and cls:
            name, owner = cls, None              # a deprecated constructor deprecates the class
        elif name.startswith("_"):
            return
        else:
            owner = cls
        defs[name] = defs.get(name, 0) + 1
        message = _deprecation_message(func)
        if message:
            qualified = ".".join(p for p in (module, owner, name) if p)
            deprecated.setdefault(name, []).append({"qualified": qualified, "cls": owner, "message": message[:400]})

    for module, path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(node, module, None)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        visit(item, module, node.name)
    return {"deprecated": deprecated, "defs": defs}


def _module_files(base: Path, mod: str) -> list[tuple[str, Path]]:
    files = []
    if (base / mod).is_dir():
        for f in (base / mod).rglob("*.py"):
            parts = f.relative_to(base).with_suffix("").parts
            if not {"tests", "test", "testing"} & set(parts):
                files.append((".".join(p for p in parts if p != "__init__"), f))
    elif (base / f"{mod}.py").exists():
        files.append((mod, base / f"{mod}.py"))
    return files


@lru_cache(maxsize=128)
def for_stdlib(module: str) -> dict:
    """Deprecated functions of one standard-library module, for this interpreter's version."""
    def scan():
        base = Path(sysconfig.get_path("stdlib"))
        # C-accelerated modules keep a pure-Python twin (datetime -> _pydatetime) that carries the warnings.
        files = _module_files(base, module) + [(module, p) for _, p in _module_files(base, f"_py{module}")]
        return _scan(files[:MAX_FILES])

    return cache.cached("deprecations", f"stdlib:{sys.version_info[:3]}:{module}", scan)


def for_package(venv_dir: str | None, package: str, version: str) -> dict:
    """Deprecated functions of one installed package at the installed version."""
    def scan():
        sp = packages.site_packages(venv_dir)
        files = [f for mod in packages.import_names(venv_dir, package) for f in _module_files(sp, mod)] if sp else []
        return _scan(files) if 0 < len(files) <= MAX_FILES else {"deprecated": {}, "defs": {}}

    if not venv_dir:
        return {"deprecated": {}, "defs": {}}
    return cache.cached("deprecations", f"pkg:{normalize(package)}=={version}", scan)


@lru_cache(maxsize=1)
def curated() -> dict[str, str]:
    return json.loads((config.DATA_DIR / "deprecated_apis.json").read_text(encoding="utf-8"))


class Index:
    """Everything known to be deprecated in the modules one application imports."""

    def __init__(self, imported_roots: set[str], venv_dir: str | None, components: list[dict]):
        self.by_root: dict[str, dict] = {}
        owner = {root: c for c in components for root in packages.import_names(venv_dir, c["name"])}
        for root in imported_roots:
            if root in STDLIB:
                self.by_root[root] = for_stdlib(root)
            elif root in owner:
                self.by_root[root] = for_package(venv_dir, owner[root]["name"], owner[root]["version"])
        self.curated = {k: v for k, v in curated().items() if k.split(".")[0] in imported_roots}
        self.roots = set(self.by_root) | {k.split(".")[0] for k in self.curated}

    @property
    def size(self) -> int:
        return sum(len(v) for r in self.by_root.values() for v in r["deprecated"].values()) + len(self.curated)

    def lookup(self, call: str) -> tuple[str, str] | None:
        """(canonical API name, advice) when `call` (a resolved name such as
        `datetime.datetime.utcnow` or `logging.getLogger.warn`) is a deprecated API."""
        if call in self.curated:
            return call, self.curated[call]
        parts = call.split(".")
        scan = self.by_root.get(parts[0])
        candidates = scan["deprecated"].get(parts[-1], []) if scan else []
        if not candidates:
            return None
        tail = parts[1:]
        for entry in candidates:                 # the call names the class or module: exact match
            if entry["qualified"].split(".")[-len(tail):] == tail:
                return entry["qualified"], entry["message"]
        if len(parts) == 2:                      # pkg.func(): only a module-level function can match
            entry = next((e for e in candidates if not e["cls"]), None)
            return (entry["qualified"], entry["message"]) if entry else None
        # A method on an object whose class is unknown (logger = logging.getLogger(); logger.warn()):
        # accept only when every definition of that name in the package is deprecated.
        total = scan["defs"].get(parts[-1], 0)
        if len(candidates) == total <= AMBIGUITY_LIMIT:
            return candidates[0]["qualified"], candidates[0]["message"]
        return None
