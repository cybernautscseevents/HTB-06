"""Fake-but-valid data so the whole graph and UI run before real agents exist.
Models the demo story: reachable PyYAML (CVSS 7.5) must outrank unreachable Pillow (CVSS 9.8)."""

COMPONENTS = [
    {"name": "pyyaml", "version": "5.3", "direct": True, "parents": []},
    {"name": "pillow", "version": "8.0.0", "direct": False, "parents": ["requests-toolbelt"]},
    {"name": "requests", "version": "2.25.0", "direct": True, "parents": []},
]

FINDINGS = [
    {"id": "GHSA-8q59-q68h-6hv4", "cve": "CVE-2020-14343", "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
     "package": "pyyaml", "version": "5.3", "summary": "Arbitrary code execution via yaml.load.",
     "cvss": 7.5, "epss": 0.62, "kev": False, "fixed_in": ["5.4"], "direct": True},
    {"id": "GHSA-pillow-fake", "cve": "CVE-2020-35653", "aliases": ["CVE-2020-35653"],
     "package": "pillow", "version": "8.0.0", "summary": "Buffer overflow in image parsing.",
     "cvss": 9.8, "epss": 0.05, "kev": False, "fixed_in": ["8.1.0"], "direct": False},
]

REACH = {
    "GHSA-8q59-q68h-6hv4": {
        "finding_id": "GHSA-8q59-q68h-6hv4", "level": "L2", "functions": ["yaml.load"],
        "evidence": [{"file": "app/config_loader.py", "line": 12, "snippet": "data = yaml.load(f)"}],
        "note": None,
    },
    "GHSA-pillow-fake": {
        "finding_id": "GHSA-pillow-fake", "level": "L0", "functions": [], "evidence": [], "note": "not imported",
    },
}

DIFF = """--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,2 @@
-pyyaml==5.3
+pyyaml==5.4
 requests==2.25.0
"""
