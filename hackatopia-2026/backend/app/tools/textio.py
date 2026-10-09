"""Read and write repository files without disturbing their line endings, so a patch only
changes the lines it means to."""
from pathlib import Path


def read_source(path: str | Path) -> tuple[str, str]:
    """(text with \\n line endings, the file's own newline sequence)."""
    raw = Path(path).read_bytes().decode("utf-8", errors="replace")
    newline = "\r\n" if "\r\n" in raw else "\n"
    return raw.replace("\r\n", "\n"), newline


def to_source(text: str, newline: str) -> str:
    return text.replace("\n", newline) if newline != "\n" else text
