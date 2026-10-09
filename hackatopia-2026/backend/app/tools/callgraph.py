"""Static call graph of an installed package, used for indirect (transitive) reachability:
the application calls `requests.get`, which reaches `requests.utils.extract_zipped_paths`.

The graph is name based, so it over-approximates: a call on an unknown receiver (`adapter.send`)
is linked to every method of that name in the package, unless the name is too common to mean
anything (AMBIGUITY_LIMIT). Results are evidence for a human reviewer, not a proof.
"""
import ast
import threading
from collections import deque
from functools import lru_cache
from pathlib import Path

from langsmith import traceable

from app.tools import packages

AMBIGUITY_LIMIT = 3      # ignore unknown-receiver calls to names defined more often than this
MAX_DEPTH = 8
MAX_FILES = 900          # very large packages (numpy, pandas) are skipped
_lock = threading.Lock()


class Graph:
    def __init__(self):
        self.simple: dict[str, str] = {}          # node id -> function name
        self.meta: dict[str, tuple[str, str | None]] = {}   # node id -> (module, class)
        self.by_name: dict[str, list[str]] = {}   # function name -> node ids
        self.methods: dict[tuple[str, str], dict[str, str]] = {}   # (module, class) -> {name: id}
        self.module_funcs: dict[str, dict[str, str]] = {}          # module -> {name: id}
        self.classes: dict[str, list[tuple[str, str]]] = {}        # class name -> [(module, class)]
        self.raw_calls: dict[str, list[tuple[str, str]]] = {}      # id -> [(kind, name)]
        self.callers: dict[str, set[str]] = {}    # callee id -> caller ids

    def add(self, node_id: str, name: str, module: str, cls: str | None):
        self.simple[node_id] = name
        self.meta[node_id] = (module, cls)
        self.by_name.setdefault(name, []).append(node_id)
        if cls:
            self.methods.setdefault((module, cls), {})[name] = node_id
            if (module, cls) not in self.classes.setdefault(cls, []):
                self.classes[cls].append((module, cls))
        else:
            self.module_funcs.setdefault(module, {})[name] = node_id

    def _resolve(self, caller: str, kind: str, name: str) -> list[str]:
        module, cls = self.meta[caller]
        if kind == "self" and cls:
            own = self.methods[(module, cls)].get(name)
            if own:
                return [own]
        if kind == "name":
            local = self.module_funcs.get(module, {}).get(name)
            if local:
                return [local]
            if name in self.classes:      # Thing(...) runs Thing.__init__
                return [i for key in self.classes[name] if (i := self.methods[key].get("__init__"))]
        candidates = self.by_name.get(name, [])
        if kind in ("self", "attr"):      # a call on an object is a method call when one exists
            candidates = [c for c in candidates if self.meta[c][1]] or candidates
        return candidates if len(candidates) <= AMBIGUITY_LIMIT else []

    def link(self):
        for caller, calls in self.raw_calls.items():
            for kind, name in calls:
                for callee in self._resolve(caller, kind, name):
                    if callee != caller:
                        self.callers.setdefault(callee, set()).add(caller)


class _Collector(ast.NodeVisitor):
    def __init__(self, graph: Graph, module: str):
        self.graph, self.module = graph, module
        self.cls: str | None = None
        self.func: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef):
        if self.func or self.cls:      # nested classes are folded into what contains them
            return self.generic_visit(node)
        self.cls = node.name
        self.generic_visit(node)
        self.cls = None

    def _function(self, node):
        if self.func:                  # nested function: its calls belong to the outer function
            return self.generic_visit(node)
        self.func = f"{self.module}.{self.cls}.{node.name}" if self.cls else f"{self.module}.{node.name}"
        self.graph.add(self.func, node.name, self.module, self.cls)
        self.graph.raw_calls[self.func] = []
        self.generic_visit(node)
        self.func = None

    visit_FunctionDef = visit_AsyncFunctionDef = _function

    def visit_Call(self, node: ast.Call):
        if self.func:
            f = node.func
            if isinstance(f, ast.Name):
                self.graph.raw_calls[self.func].append(("name", f.id))
            elif isinstance(f, ast.Attribute):
                own = isinstance(f.value, ast.Name) and f.value.id in ("self", "cls")
                self.graph.raw_calls[self.func].append(("self" if own else "attr", f.attr))
        self.generic_visit(node)


@lru_cache(maxsize=64)
def _build(venv_dir: str, package: str) -> Graph | None:
    sp = packages.site_packages(venv_dir)
    if not sp:
        return None
    files: list[tuple[str, Path]] = []
    for mod in packages.import_names(venv_dir, package):
        if (sp / mod).is_dir():
            for f in (sp / mod).rglob("*.py"):
                parts = f.relative_to(sp).with_suffix("").parts
                if "tests" in parts or "testing" in parts:
                    continue
                files.append((".".join(p for p in parts if p != "__init__"), f))
        elif (sp / f"{mod}.py").exists():
            files.append((mod, sp / f"{mod}.py"))
    if not files or len(files) > MAX_FILES:
        return None
    graph = Graph()
    for module, f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        _Collector(graph, module).visit(tree)
    graph.link()
    return graph


def build(venv_dir: str | None, package: str) -> Graph | None:
    if not venv_dir:
        return None
    with _lock:     # parallel reachability workers share one build per package
        return _build(venv_dir, package)


@traceable(name="library_call_graph", run_type="tool")
def entry_points(venv_dir: str | None, package: str, functions: list[str]) -> dict[str, list[str]]:
    """{entry function name: call path down to a vulnerable function}.

    Every function of the package that can reach one of `functions` within MAX_DEPTH calls,
    keyed by its bare name (what the application would call), with the shortest path found.
    """
    graph = build(venv_dir, package)
    if not graph:
        return {}
    targets = []
    for fn in functions:
        parts = fn.strip("() ").split(".")
        ids = graph.by_name.get(parts[-1], [])
        if len(parts) > 1:      # prefer the definition whose class/module matches the advisory
            ids = [i for i in ids if i.split(".")[-2] == parts[-2]] or ids
        targets += ids
    if not targets:
        return {}

    next_hop: dict[str, str | None] = {t: None for t in targets}
    queue = deque((t, 0) for t in targets)
    while queue:
        node, depth = queue.popleft()
        if depth >= MAX_DEPTH:
            continue
        for caller in graph.callers.get(node, ()):
            if caller not in next_hop:
                next_hop[caller] = node
                queue.append((caller, depth + 1))

    def path(node: str) -> list[str]:
        out = [node]
        while next_hop[out[-1]] is not None:
            out.append(next_hop[out[-1]])
        return out

    entries: dict[str, list[str]] = {}
    for node in next_hop:
        if next_hop[node] is None:
            continue                                  # the vulnerable function itself: a direct call
        name, is_method = graph.simple[node], bool(graph.meta[node][1])
        if name == "__init__":
            name, is_method = node.split(".")[-2], False   # reached by instantiating the class
        elif name.startswith("_"):
            continue                                  # private helpers are not application entry points
        p = path(node)
        # Keyed twice: "get" for pkg.get(...) and ".get" for a method call on an instance.
        key = f".{name}" if is_method else name
        if key not in entries or len(p) < len(entries[key]):
            entries[key] = p
    return entries


def path_for(entries: dict[str, list[str]], called: str) -> list[str] | None:
    """The path for an application call such as `requests.get` or `requests.Session.get`."""
    parts = called.split(".")
    name = parts[-1]
    as_function, as_method = entries.get(name), entries.get(f".{name}")
    return (as_function or as_method) if len(parts) == 2 else (as_method or as_function)


def entry_names(entries: dict[str, list[str]]) -> list[str]:
    return sorted({k.lstrip(".") for k in entries})
