"""Workspace + SBOM generation (FR-1..FR-4, NFR-5).

prepare_workspace(): clone the repo and install its requirements into an isolated venv.
generate_components(): Syft CycloneDX SBOM, falling back to pipdeptree, then to the pinned manifest.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from langsmith import traceable
from packaging.requirements import InvalidRequirement, Requirement

from app import config
from app.tools import cache, existing_sbom
from app.tools.versions import normalize

MANIFEST = "requirements.txt"
LAST_USED = ".last_used"
TOOLING = {"pip", "setuptools", "wheel", "pipdeptree", "distribute"}
GITHUB_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


class SbomError(RuntimeError):
    pass


def parse_repo_url(url: str) -> tuple[str, str]:
    m = GITHUB_URL.match(url.strip())
    if not m:
        raise SbomError("repo_url must look like https://github.com/<owner>/<repo>")
    return m.group(1), m.group(2)


def venv_python(venv_dir: str | Path) -> Path:
    v = Path(venv_dir)
    return v / "Scripts" / "python.exe" if os.name == "nt" else v / "bin" / "python"


def _run(cmd: list[str], timeout: int, cwd: str | None = None, token: str = "") -> subprocess.CompletedProcess:
    """Run a subprocess. With a GitHub token, git (also when pip calls it) authenticates to
    github.com through environment-only config, and the token is scrubbed from captured output."""
    env = None
    if token:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": f"url.https://x-access-token:{token}@github.com/.insteadOf",
               "GIT_CONFIG_VALUE_0": "https://github.com/"}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env,
                       encoding="utf-8", errors="replace")
    if token:
        r.stdout, r.stderr = (r.stdout or "").replace(token, "***"), (r.stderr or "").replace(token, "***")
    return r


def _rmtree(path: Path) -> None:
    def on_error(func, p, _exc):  # git objects are read-only on Windows
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if path.exists():
        shutil.rmtree(path, onerror=on_error)


def parse_manifest(text: str) -> list[Requirement]:
    reqs = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        try:
            reqs.append(Requirement(line))
        except InvalidRequirement:
            continue
    return reqs


VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
INCLUDE = re.compile(r"^\s*(?:-r|--requirement)[ =]\s*(\S+)")
MAX_MANIFEST_FILES = 20


SEARCH_SKIP = {".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", ".tox", ".eggs",
               "build", "dist", "docs", "doc", "tests", "test", "examples", "example"}
SEARCH_DEPTH = 4
MAX_ROOT_MANIFESTS = 5
PREFERRED_NAMES = ("base", "common", "prod", "production", "main", "app", "requirements")


def find_manifests(repo_dir: str | Path) -> list[str]:
    """Repo-relative paths of the requirements files to audit; the first is the primary one.

    1. `requirements.txt` at the root, when there is one.
    2. Otherwise every `requirements.txt` at the shallowest depth it occurs (a monorepo with
       backend/requirements.txt and worker/requirements.txt gets both).
    3. Otherwise one differently named file: requirements/base.txt, requirements-prod.txt and so on.
    Documentation, test, example and vendored directories are not searched.
    """
    root = Path(repo_dir)
    if (root / MANIFEST).is_file():
        return [MANIFEST]

    exact: list[Path] = []
    others: list[Path] = []
    stack = [(root, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if depth < SEARCH_DEPTH and entry.name.lower() not in SEARCH_SKIP and not entry.name.startswith("."):
                    stack.append((entry, depth + 1))
            elif entry.name == MANIFEST:
                exact.append(entry)
            elif entry.suffix == ".txt" and (entry.name.lower().startswith("requirements") or folder.name.lower() == "requirements"):
                others.append(entry)

    def rel(p: Path) -> str:
        return p.relative_to(root).as_posix()

    if exact:
        shallowest = min(len(p.relative_to(root).parts) for p in exact)
        return sorted(rel(p) for p in exact if len(p.relative_to(root).parts) == shallowest)[:MAX_ROOT_MANIFESTS]
    if others:
        def rank(p: Path) -> tuple:
            stem = p.stem.lower().replace("requirements", "").strip("-_.") or "requirements"
            order = PREFERRED_NAMES.index(stem) if stem in PREFERRED_NAMES else len(PREFERRED_NAMES)
            return (len(p.relative_to(root).parts), order, rel(p))
        return [rel(min(others, key=rank))]
    return []


def manifest_files(repo_dir: str | Path) -> dict[str, str]:
    """{repo-relative path: text} for the requirements file(s) found by find_manifests() and every
    file they include with `-r`, in include order; the first key is the primary manifest. Many
    projects keep the real pins in requirements/common.txt and leave the root file as a one-line
    include. Text uses \n line endings."""
    root = Path(repo_dir).resolve()
    found: dict[str, str] = {}

    def visit(path: Path):
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            return                                   # an include pointing outside the repository
        if rel in found or len(found) >= MAX_MANIFEST_FILES or not path.is_file():
            return
        text = path.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
        found[rel] = text
        for line in text.splitlines():
            m = INCLUDE.match(line)
            if m:
                visit(path.parent / m.group(1))

    for manifest in find_manifests(root):
        visit(root / manifest)
    return found


def flatten(files: dict[str, str]) -> str:
    """All requirement lines of a manifest and its includes as one file, without the include lines."""
    return "\n".join(line for text in files.values() for line in text.splitlines() if not INCLUDE.match(line)) + "\n"


def flat_manifest(repo_dir: str | Path) -> str:
    return flatten(manifest_files(repo_dir))


def requirement_lines(text: str) -> list[str]:
    """Installable lines of a requirements file: comments, blanks and pip options removed."""
    out = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if line.startswith("-e "):
            line = line[3:].strip()
        if line and not line.startswith(("#", "-")):
            out.append(line)
    return out


def repository_requirements(text: str) -> list[dict]:
    """Dependencies installed from a repository or URL instead of PyPI:
    `git+https://github.com/org/lib@v1#egg=lib`, `lib @ git+https://...`, `https://host/lib.whl`.
    Returns [{"name", "url", "source"}] with source "vcs" or "url"."""
    found = []
    for line in requirement_lines(text):
        name, _, url = line.partition(" @ ") if " @ " in line else ("", "", line)
        url = url.strip()
        if not url.startswith((*VCS_PREFIXES, "http://", "https://")):
            continue
        if "#egg=" in url:
            name = url.split("#egg=")[1].split("&")[0]
        if not name:
            tail = url.split("#")[0].rstrip("/").split("/")[-1]
            name = re.split(r"@|\.git|\.tar|\.zip|\.whl|-\d", tail)[0]
        found.append({"name": normalize(name.split("[")[0].strip()), "url": url.split("#")[0],
                      "source": "vcs" if url.startswith(VCS_PREFIXES) else "url"})
    return found


def cleanup_workspaces(max_age_days: float | None = None) -> int:
    """Delete clones and venvs whose last audit is older than WORKSPACE_TTL_DAYS. Returns how many."""
    ttl = (config.WORKSPACE_TTL_DAYS if max_age_days is None else max_age_days) * 86400
    if ttl <= 0 or not config.WORK_DIR.is_dir():
        return 0
    removed, cutoff = 0, time.time() - ttl
    for work in config.WORK_DIR.iterdir():
        if not work.is_dir():
            continue
        stamp = work / LAST_USED
        used = stamp.stat().st_mtime if stamp.exists() else work.stat().st_mtime
        if used < cutoff:
            _rmtree(work)
            removed += 1
    return removed


# The GitHub token must never reach a trace: only the repository URL is recorded as input.
@traceable(name="prepare_workspace", run_type="tool", process_inputs=lambda i: {"repo_url": i.get("repo_url")})
def prepare_workspace(repo_url: str, progress=lambda msg: None, token: str = "") -> dict:
    """Clone + install. Returns {"repo_dir", "venv_dir", "installed"}.

    The workspace is keyed by repo URL and reused: offline runs use the last clone, and the
    venv is rebuilt only when requirements.txt changed (NFR-1, NFR-2).
    """
    parse_repo_url(repo_url)
    work = config.WORK_DIR / hashlib.sha256(repo_url.encode()).hexdigest()[:12]
    repo_dir, venv_dir, stamp = work / "repo", work / "venv", work / "requirements.sha"
    work.mkdir(parents=True, exist_ok=True)
    (work / LAST_USED).write_text(repo_url, encoding="utf-8")   # mtime = last audit, read by cleanup_workspaces

    if not (config.OFFLINE and repo_dir.exists()):
        if config.OFFLINE:
            raise SbomError("OFFLINE=true but this repository was never cloned")
        progress("Cloning repository")
        _rmtree(repo_dir)
        # autocrlf off: the working tree must match the repository byte for byte, or a patch
        # would rewrite every line ending in the files it touches.
        r = _run(["git", "-c", "core.autocrlf=false", "clone", "--depth", "1", "--", repo_url, str(repo_dir)],
                 timeout=180, token=token)
        if r.returncode != 0:
            hint = "" if token else " (private repositories need GitHub sign-in with the repo scope)"
            raise SbomError(f"git clone failed{hint}: {r.stderr.strip()[-300:]}")

    manifests = find_manifests(repo_dir)
    if not manifests:
        if config.USE_EXISTING_SBOM and existing_sbom.candidates(repo_dir):
            # Nothing to install, but the repository ships its own SBOM: audit from that.
            return {"repo_dir": str(repo_dir), "venv_dir": str(venv_dir), "installed": False}
        raise SbomError("no requirements file was found anywhere in the repository "
                        "(looked for requirements.txt, requirements/*.txt and requirements-*.txt)")
    if manifests != [MANIFEST]:
        progress(f"Using {', '.join(manifests)}")

    # A venv built with credentials may hold private packages: never reuse it for an anonymous run.
    digest = hashlib.sha256(flat_manifest(repo_dir).encode() + (b"|auth" if token else b"")).hexdigest()
    fresh = venv_python(venv_dir).exists() and stamp.exists() and stamp.read_text() == digest
    if fresh:
        return {"repo_dir": str(repo_dir), "venv_dir": str(venv_dir), "installed": True}
    if config.OFFLINE:
        return {"repo_dir": str(repo_dir), "venv_dir": str(venv_dir), "installed": False}

    progress("Installing dependencies into an isolated venv")
    _rmtree(venv_dir)
    stamp.unlink(missing_ok=True)
    r = _run([sys.executable, "-m", "venv", str(venv_dir)], timeout=180)
    if r.returncode != 0:
        return {"repo_dir": str(repo_dir), "venv_dir": str(venv_dir), "installed": False}
    pip = [str(venv_python(venv_dir)), "-m", "pip", "install", "--disable-pip-version-check", "--no-input"]
    r = _run([*pip, *[arg for m in manifests for arg in ("-r", m)]],
             timeout=config.INSTALL_TIMEOUT, cwd=str(repo_dir), token=token)
    if r.returncode != 0:
        # One unbuildable pin (e.g. an old sdist with no wheel for this Python) must not hide
        # the rest of the tree: install what we can, the SBOM takes the others from the manifest.
        progress("Full install failed; installing packages one by one")
        for line in requirement_lines(flat_manifest(repo_dir)):
            _run([*pip, line], timeout=config.INSTALL_TIMEOUT, cwd=str(repo_dir), token=token)
    stamp.write_text(digest)
    return {"repo_dir": str(repo_dir), "venv_dir": str(venv_dir), "installed": True}


def _pipdeptree(venv_dir: str) -> list[dict]:
    r = _run([sys.executable, "-m", "pipdeptree", "--python", str(venv_python(venv_dir)),
              "--json", "--warn", "silence"], timeout=120)
    if r.returncode != 0:
        raise SbomError(f"pipdeptree failed: {r.stderr.strip()[-300:]}")
    return json.loads(r.stdout)


def syft_binary() -> str | None:
    """SYFT_BIN, else backend/bin/syft(.exe) dropped in by hand, else whatever is on PATH."""
    local = config.ROOT / "bin" / ("syft.exe" if os.name == "nt" else "syft")
    for candidate in (config.SYFT_BIN, str(local)):
        if candidate and Path(candidate).is_file():
            return candidate
    return shutil.which("syft")


def _syft(venv_dir: str) -> list[tuple[str, str]]:
    """[(name, version)] from a Syft CycloneDX SBOM of the venv (FR-2)."""
    binary = syft_binary()
    if not binary:
        raise SbomError("syft is not installed")
    r = _run([binary, f"dir:{venv_dir}", "-o", "cyclonedx-json", "-q"], timeout=180)
    if r.returncode != 0:
        raise SbomError(f"syft failed: {r.stderr.strip()[-300:]}")
    bom = json.loads(r.stdout)
    return [(c["name"], c["version"]) for c in bom.get("components", [])
            if c.get("purl", "").startswith("pkg:pypi/") and c.get("version")]


@traceable(name="generate_sbom", run_type="tool")
def generate_components(repo_dir: str, venv_dir: str, installed: bool) -> tuple[list[dict], str]:
    """Return (schemas.Component dicts, source) where source is syft | pipdeptree | manifest."""
    manifest_text = flat_manifest(repo_dir)        # the root file plus everything it includes with -r
    manifest_reqs = parse_manifest(manifest_text)
    external = {r["name"]: r for r in repository_requirements(manifest_text)}
    direct = {normalize(r.name) for r in manifest_reqs} | set(external)

    def tag(comps: list[dict]) -> list[dict]:
        """Mark packages that come from a repository or URL, and list the ones that never installed."""
        for c in comps:
            ext = external.get(c["name"])
            c.update(source=ext["source"] if ext else "pypi", source_url=ext["url"] if ext else None)
        have = {c["name"] for c in comps}
        comps += [{"name": n, "version": "unknown", "direct": True, "parents": [],
                   "source": e["source"], "source_url": e["url"]} for n, e in external.items() if n not in have]
        return sorted(comps, key=lambda c: c["name"])
    # Exactly pinned direct dependencies are known even when nothing could be installed.
    pinned = [{"name": normalize(r.name), "version": next(iter(r.specifier)).version,
               "direct": True, "parents": []}
              for r in manifest_reqs
              if not r.url and len(r.specifier) == 1 and next(iter(r.specifier)).operator == "=="]

    if not installed:
        return tag(pinned), "manifest"

    tree: list[dict] = []
    try:
        tree = _pipdeptree(venv_dir)
    except (SbomError, OSError, ValueError, subprocess.TimeoutExpired):
        pass
    parents: dict[str, set[str]] = {}
    for node in tree:
        for dep in node.get("dependencies", []):
            parents.setdefault(normalize(dep["package_name"]), set()).add(normalize(node["package"]["package_name"]))

    try:
        pairs, source = _syft(venv_dir), "syft"
    except (SbomError, OSError, ValueError, subprocess.TimeoutExpired):
        if not tree:
            raise SbomError("both syft and pipdeptree failed")  # noqa: B904
        pairs = [(n["package"]["package_name"], n["package"]["installed_version"]) for n in tree]
        source = "pipdeptree"

    seen, comps = set(), []
    for name, version in pairs:
        name = normalize(name)
        if name in TOOLING or (name, version) in seen:
            continue
        seen.add((name, version))
        comps.append({"name": name, "version": version, "direct": name in direct,
                      "parents": sorted(parents.get(name, set()) - TOOLING)})
    found = {c["name"] for c in comps}
    missing = [p for p in pinned if p["name"] not in found]   # pins that failed to install
    if missing:
        comps, source = comps + missing, f"{source}+manifest"
    return tag(comps), source


def components_for(repo_url: str, progress=lambda msg: None, token: str = "") -> dict:
    """Full SBOM step. Offline runs fall back to the cached component list for this repo."""
    ws = prepare_workspace(repo_url, progress, token)
    manifests = find_manifests(ws["repo_dir"])

    # An SBOM that is already in the repository is used as it is; one is generated only when missing.
    shipped = None
    if config.USE_EXISTING_SBOM:
        pinned = {normalize(r.name) for r in parse_manifest(flat_manifest(ws["repo_dir"]))} if manifests else set()
        # With a requirements file to generate from, an SBOM that only exists as a test fixture is not used.
        shipped = existing_sbom.load(ws["repo_dir"], pinned, allow_fixtures=not manifests)
    if shipped:
        progress(f"Using the repository's own SBOM: {shipped['path']}")
        return {**ws, "components": shipped["components"], "manifests": manifests, "sbom_file": shipped["path"],
                "ignored": shipped["ignored"], "source": f"existing {shipped['format']} SBOM ({shipped['path']})"}

    if not manifests:
        raise SbomError("no requirements file was found, and the SBOM files in the repository list no Python packages")

    progress("Generating SBOM")
    try:
        comps, source = generate_components(ws["repo_dir"], ws["venv_dir"], ws["installed"])
    except SbomError:
        comps = cache.get("sbom", repo_url)
        if comps is None:
            raise
        source = "cache"
    if source != "manifest":
        cache.put("sbom", repo_url, comps)
    return {**ws, "components": comps, "source": source, "manifests": manifests}
