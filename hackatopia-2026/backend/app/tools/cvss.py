"""CVSS vector -> numeric base score, with severity-label fallback (FR-7)."""

LABEL_SCORES = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
UNKNOWN_SCORE = 5.0


def score_vector(vector: str) -> float | None:
    try:
        from cvss import CVSS2, CVSS3, CVSS4

        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
        return float(CVSS2(vector).base_score)
    except Exception:  # noqa: BLE001 - malformed vector or unsupported version
        return None


def base_score(vectors: list[str], severity_label: str | None = None) -> float:
    """Highest score among the vectors; else the label's midpoint; else a neutral default."""
    scores = [s for v in vectors if v and (s := score_vector(v)) is not None]
    if scores:
        return max(scores)
    return LABEL_SCORES.get((severity_label or "").upper(), UNKNOWN_SCORE)
