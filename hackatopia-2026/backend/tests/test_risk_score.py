from app.agents.risk_analysis import compute_score


def test_reachable_yaml_outranks_unreachable_high_cvss():
    yaml_f = {"cvss": 7.5, "epss": 0.62, "kev": False, "direct": True}
    pil_f = {"cvss": 9.8, "epss": 0.05, "kev": False, "direct": False}
    yaml_score, _ = compute_score(yaml_f, {"level": "L2"})
    pil_score, _ = compute_score(pil_f, {"level": "L0"})
    assert yaml_score > pil_score  # AC-1
