"""Use the SBOM a repository already ships, instead of generating one.

Looks for a committed CycloneDX (JSON or XML) or SPDX (JSON) document anywhere in the repository,
recognised by its content rather than its name or location, reads its Python
packages, and returns them in the same shape the Syft step produces. Anything that is not a
PyPI package is counted and left out: the rest of the pipeline is Python-only.
"""
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree

from app.tools.versions import normalize

# Never searched: version control, virtualenvs and vendored packages.
NEVER = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", ".tox", ".eggs"}
# Searched, but only used when nothing better exists: an SBOM here is usually a fixture, not the project's own.
FIXTURE_DIRS = {"tests", "test", "testdata", "testing", "fixtures", "examples", "example", "samples", "sample",
                "snapshots", "_data"}
MAX_FIXTURES_PARSED = 2000
MAX_BYTES = 20_000_000
MAX_FILES = 20_000            # .json / .xml files looked at per repository
SNIFF_BYTES = 65_536
# bom.json, sbom.xml, app.cdx.json, project.spdx.json, cyclonedx.json, sbom-py3.11.json ...
NAME = re.compile(r"^(?:.*[._-])?(?:s?bom|cyclonedx|cdx|spdx)(?:[._-].*)?\.(?:json|xml)$", re.I)
SBOM_DIRS = {"sbom", "sboms", "bom", "boms"}
MARKERS = (b'"bomFormat"', b'"spdxVersion"', b"cyclonedx.org/schema/bom")
THIS_PYTHON = f"py{sys.version_info.major}.{sys.version_info.minor}"
PURL = re.compile(r"^pkg:pypi/([^@?#]+)@([^?#]+)", re.I)


def _is_sbom(path: Path) -> bool:
    """Recognise an SBOM by what it contains, whatever it is called and wherever it is."""
    try:
        with path.open("rb") as fh:
            head = fh.read(SNIFF_BYTES)
    except OSError:
        return False
    return any(marker in head for marker in MARKERS)


def candidates(repo_dir: str | Path) -> list[Path]:
    """Every SBOM in the repository, at any depth and under any name, best candidate first.

    Order: files outside test / example / docs folders, then shallowest, then conventionally named
    (bom.json, *.cdx.json, anything in an sbom/ folder), then the one built for this Python version.
    """
    root = Path(repo_dir)
    found: list[tuple[tuple, Path]] = []
    looked_at = 0
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in NEVER]
        here = Path(folder)
        parts = [p.lower() for p in here.relative_to(root).parts]
        for name in files:
            if not name.lower().endswith((".json", ".xml")):
                continue
            looked_at += 1
            if looked_at > MAX_FILES:
                break
            path = here / name
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            if not _is_sbom(path):
                continue
            named = bool(NAME.match(name)) or (parts and parts[-1] in SBOM_DIRS)
            fixture = any(part in FIXTURE_DIRS for part in parts)
            found.append(((fixture, len(parts), not named, THIS_PYTHON not in name.lower(),
                           "spdx" in name.lower(), path.as_posix()), path))
    return [path for _key, path in sorted(found)]


def _pypi(purl: str | None) -> tuple[str, str] | None:
    m = PURL.match(purl or "")
    return (normalize(unquote(m.group(1))), unquote(m.group(2))) if m else None


def _cyclonedx_json(doc: dict) -> dict | None:
    if doc.get("bomFormat") != "CycloneDX":
        return None
    packages: dict[str, tuple[str, str]] = {}     # bom-ref -> (name, version)
    other = 0

    def walk(items):
        nonlocal other
        for c in items or []:
            hit = _pypi(c.get("purl"))
            if hit:
                packages[c.get("bom-ref") or c.get("purl")] = hit
            elif c.get("type") in (None, "library", "framework") and c.get("purl"):
                other += 1
            walk(c.get("components"))

    walk(doc.get("components"))
    edges = {d.get("ref"): d.get("dependsOn") or [] for d in doc.get("dependencies") or []}
    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    return {"packages": packages, "edges": edges, "root": root, "other": other, "format": "CycloneDX"}


def _cyclonedx_xml(text: str) -> dict | None:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:      # no entity expansion from an untrusted file
        return None
    try:
        tree = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    if not tree.tag.endswith("}bom") and tree.tag != "bom":
        return None

    def local(el):
        return el.tag.rsplit("}", 1)[-1]

    packages, other = {}, 0
    for el in tree.iter():
        if local(el) != "component":
            continue
        fields = {local(ch): (ch.text or "").strip() for ch in el}
        hit = _pypi(fields.get("purl"))
        if hit:
            packages[el.get("bom-ref") or fields["purl"]] = hit
        elif fields.get("purl"):
            other += 1
    edges = {}
    for el in tree.iter():
        if local(el) == "dependency" and el.get("ref"):
            edges.setdefault(el.get("ref"), []).extend(ch.get("ref") for ch in el if local(ch) == "dependency")
    return {"packages": packages, "edges": edges, "root": None, "other": other, "format": "CycloneDX"}


def _spdx_json(doc: dict) -> dict | None:
    if not str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        return None
    packages, other = {}, 0
    for p in doc.get("packages") or []:
        purls = [r.get("referenceLocator") for r in p.get("externalRefs") or [] if r.get("referenceType") == "purl"]
        hit = next((h for h in map(_pypi, purls) if h), None)
        if hit:
            packages[p.get("SPDXID")] = hit
        elif purls:
            other += 1
    edges: dict[str, list[str]] = {}
    for r in doc.get("relationships") or []:
        if r.get("relationshipType") == "DEPENDS_ON":
            edges.setdefault(r.get("spdxElementId"), []).append(r.get("relatedSpdxElement"))
        elif r.get("relationshipType") == "DEPENDENCY_OF":
            edges.setdefault(r.get("relatedSpdxElement"), []).append(r.get("spdxElementId"))
    described = next((r.get("relatedSpdxElement") for r in doc.get("relationships") or []
                      if r.get("relationshipType") == "DESCRIBES"), None)
    return {"packages": packages, "edges": edges, "root": described, "other": other, "format": "SPDX"}


def _parse(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    if path.suffix.lower() == ".xml":
        return _cyclonedx_xml(text)
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return (_cyclonedx_json(doc) or _spdx_json(doc)) if isinstance(doc, dict) else None


def is_fixture(path: Path, root: Path) -> bool:
    return any(part.lower() in FIXTURE_DIRS for part in path.relative_to(root).parts[:-1])


def load(repo_dir: str | Path, manifest_names: set[str], allow_fixtures: bool = True) -> dict | None:
    """The best usable SBOM in the repository, or None.

    The project's own SBOM (anywhere outside test / example folders) is preferred, in candidate
    order. SBOMs inside test or example folders describe sample data, not the project, so they are
    considered only when `allow_fixtures` is set (the caller has nothing else to go on); among
    those the one listing the most Python packages is used.

    Returns {"path", "format", "components": [schemas.Component dicts], "ignored": int}.
    `manifest_names` (normalised names pinned in the requirements files) decide what is direct
    when there is a manifest; otherwise the SBOM's own dependency graph does.
    """
    root = Path(repo_dir)
    found = candidates(root)
    own = [p for p in found if not is_fixture(p, root)]
    chosen = None
    for path in own:
        parsed = _parse(path)
        if parsed and parsed["packages"]:
            chosen = (path, parsed)
            break
    if not chosen and allow_fixtures:
        best = 0
        for path in [p for p in found if is_fixture(p, root)][:MAX_FIXTURES_PARSED]:
            parsed = _parse(path)
            if parsed and len(parsed["packages"]) > best:
                chosen, best = (path, parsed), len(parsed["packages"])
    for path, parsed in ([chosen] if chosen else []):
        packages, edges = parsed["packages"], parsed["edges"]
        parents: dict[str, set[str]] = {}
        for ref, deps in edges.items():
            if ref in packages:
                for dep in deps:
                    if dep in packages:
                        parents.setdefault(packages[dep][0], set()).add(packages[ref][0])
        top = {packages[r][0] for r in edges.get(parsed["root"], []) if r in packages} if parsed["root"] else set()

        seen, components = set(), []
        for name, version in packages.values():
            if (name, version) in seen:
                continue
            seen.add((name, version))
            if manifest_names:
                direct = name in manifest_names
            elif top:
                direct = name in top
            else:
                direct = name not in parents          # nothing depends on it, as far as the SBOM says
            components.append({"name": name, "version": version, "direct": direct,
                               "parents": sorted(parents.get(name, set()) - {name}),
                               "source": "pypi", "source_url": None})
        return {"path": path.relative_to(root).as_posix(), "format": parsed["format"],
                "fixture": is_fixture(path, root),
                "components": sorted(components, key=lambda c: c["name"]), "ignored": parsed["other"]}
    return None
