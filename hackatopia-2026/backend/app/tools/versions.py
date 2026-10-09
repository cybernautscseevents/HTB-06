"""Version helpers (FR-19, FR-21) built on packaging.version."""
import re

from packaging.version import InvalidVersion, Version


def normalize(name: str) -> str:
    """PEP 503 normalised package name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse(v: str) -> Version | None:
    try:
        return Version(v)
    except (InvalidVersion, TypeError):
        return None


def sort_versions(versions: list[str]) -> list[str]:
    """Ascending, unique, unparseable versions dropped."""
    parsed = {p: v for v in versions if (p := parse(v)) is not None}
    return [parsed[p] for p in sorted(parsed)]


def highest(versions: list[str]) -> str | None:
    ordered = sort_versions(versions)
    return ordered[-1] if ordered else None


def newer_than(versions: list[str], current: str) -> list[str]:
    """Versions strictly greater than current, ascending. Pre-releases are skipped."""
    cur = parse(current)
    out = []
    for v in sort_versions(versions):
        p = parse(v)
        if p.is_prerelease or (cur is not None and p <= cur):
            continue
        out.append(v)
    return out


def is_major_bump(old: str, new: str) -> bool:
    o, n = parse(old), parse(new)
    if o is None or n is None:
        return True  # cannot prove it is safe
    return n.major > o.major
