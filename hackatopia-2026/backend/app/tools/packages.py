"""Inspect packages installed in the target venv: import names and defined symbols (FR-12)."""
import ast
from functools import lru_cache
from pathlib import Path

from app.tools.versions import normalize

# Used only when the venv is unavailable (install failed / offline).
KNOWN_IMPORT_NAMES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"], "pyjwt": ["jwt"], "opencv-python": ["cv2"], "protobuf": ["google"],
    "python-jose": ["jose"], "pycryptodome": ["Crypto"], "msgpack-python": ["msgpack"],
}


def site_packages(venv_dir: str | None) -> Path | None:
    if not venv_dir:
        return None
    v = Path(venv_dir)
    for sp in [v / "Lib" / "site-packages", *v.glob("lib/python*/site-packages")]:
        if sp.is_dir():
            return sp
    return None


def _dist_info(sp: Path, package: str) -> Path | None:
    for d in sp.glob("*.dist-info"):
        if normalize(d.name.rsplit("-", 1)[0]) == normalize(package):
            return d
    return None


@lru_cache(maxsize=512)
def import_names(venv_dir: str | None, package: str) -> tuple[str, ...]:
    """Top-level importable module names of a distribution, e.g. pyyaml -> ("yaml", "_yaml")."""
    fallback = tuple(KNOWN_IMPORT_NAMES.get(normalize(package), [normalize(package).replace("-", "_")]))
    sp = site_packages(venv_dir)
    info = _dist_info(sp, package) if sp else None
    if not info:
        return fallback
    names: set[str] = set()
    top = info / "top_level.txt"
    if top.exists():
        names |= {n.strip() for n in top.read_text(errors="replace").splitlines() if n.strip()}
    record = info / "RECORD"
    if not names and record.exists():
        for line in record.read_text(errors="replace").splitlines():
            first = line.split(",")[0].replace("\\", "/")
            head = first.split("/")[0]
            if head.endswith((".dist-info", ".data")) or head.startswith(("..", "__pycache__")):
                continue
            if "/" in first:
                names.add(head)
            elif head.endswith(".py"):
                names.add(head[:-3])
            elif ".cp" in head or head.endswith((".pyd", ".so")):
                names.add(head.split(".")[0])
    return tuple(sorted(names)) or fallback


@lru_cache(maxsize=256)
def defined_symbols(venv_dir: str | None, package: str) -> frozenset[str] | None:
    """Every function/class/method name defined in the installed package source.

    None means the source is unavailable, so nothing can be validated against it.
    """
    sp = site_packages(venv_dir)
    if not sp:
        return None
    files: list[Path] = []
    for mod in import_names(venv_dir, package):
        if (sp / mod).is_dir():
            files += (sp / mod).rglob("*.py")
        elif (sp / f"{mod}.py").exists():
            files.append(sp / f"{mod}.py")
    if not files:
        return None
    symbols: set[str] = set()
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.add(node.name)
    return frozenset(symbols)


def validate_functions(venv_dir: str | None, package: str, candidates: list[str]) -> list[str]:
    """Keep only candidates whose final name is defined in the package source (FR-12).

    When the source cannot be read nothing is validated, so nothing is kept.
    """
    symbols = defined_symbols(venv_dir, package)
    if symbols is None:
        return []
    return [c for c in candidates if c.split(".")[-1].strip("() ") in symbols]
