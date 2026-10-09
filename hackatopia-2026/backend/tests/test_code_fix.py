from types import SimpleNamespace

from app.agents import code_fix
from app.tools import callgraph, syft
from app.tools.ast_scanner import scan

SRC = '''import logging
from datetime import datetime

import yaml

log = logging.getLogger(__name__)


def stamp(record):
    """Add a timestamp."""
    record["at"] = datetime.utcnow()
    log.warn("stamped %s", record)
    return record


def read(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader)
'''


def issues_for(tmp_path, text=SRC):
    (tmp_path / "m.py").write_bytes(text.encode())
    return code_fix.collect_issues(str(tmp_path), [])["m.py"]


def test_collects_deprecated_calls_but_not_safe_ones(tmp_path):
    found = issues_for(tmp_path)
    assert [(i["api"], i["line"]) for i in found] == [
        ("datetime.datetime.utcnow", 11), ("logging.getLogger.warn", 12)]     # yaml.load with SafeLoader is fine


def test_rule_rewrite_fixes_the_function_and_adds_the_import(tmp_path):
    new, changes = code_fix.fix_file("m.py", SRC, issues_for(tmp_path), budget=8)
    assert 'record["at"] = datetime.now(timezone.utc)' in new and 'log.warning("stamped %s", record)' in new
    assert "from datetime import timezone" in new.split("def stamp")[0]
    assert [(c["function"], c["source"], len(c["issues"])) for c in changes] == [("stamp", "rule", 2)]
    compile(new, "m.py", "exec")


def test_llm_rewrite_is_used_only_when_it_passes_the_checks(tmp_path, monkeypatch):
    found = issues_for(tmp_path)

    def propose(code):
        monkeypatch.setattr(code_fix.llm, "rewrite_function", lambda facts: SimpleNamespace(
            changed=True, code=code, new_imports=["from datetime import timezone"], explanation="because"))
        return code_fix.fix_file("m.py", SRC, found, budget=8)

    good = 'def stamp(record):\n    record["at"] = datetime.now(timezone.utc)\n    log.warning("stamped %s", record)\n    return record'
    _, changes = propose(good)
    assert changes[0]["source"] == "llm" and changes[0]["explanation"] == "because"

    # each of these is rejected, and the deterministic rule is used instead
    for bad in (
        good.replace("def stamp(record)", "def stamp(record, extra)"),     # signature changed
        good.replace("log.warning", "log.warn"),                            # deprecated call still there
        "def stamp(record):\n    return record[",                           # does not parse
        good + "\n\ndef helper():\n    pass",                               # more than the one function
    ):
        _, changes = propose(bad)
        assert changes[0]["source"] == "rule", bad


def test_instance_method_calls_are_resolved(tmp_path):
    (tmp_path / "a.py").write_text(
        "import requests\n\ns = requests.Session()\ns.get('u')\nwith requests.Session() as t:\n    t.post('u')\n"
        "requests.Session().put('u')\n")
    calls = scan(str(tmp_path), ["requests"], ["get", "post", "put"])["calls"]
    assert [(c["line"], c["call"]) for c in calls] == [
        (4, "requests.Session.get"), (6, "requests.Session.post"), (7, "requests.Session.put")]


def test_call_graph_finds_indirect_path(tmp_path, monkeypatch):
    pkg = tmp_path / "Lib" / "site-packages" / "lib"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("from .api import fetch\n")
    (pkg / "api.py").write_text("from .core import Client\n\ndef fetch(u):\n    return Client().send(u)\n\ndef other():\n    return 1\n")
    (pkg / "core.py").write_text(
        "from .util import unzip\n\nclass Client:\n    def send(self, u):\n        return self._prepare(u)\n"
        "    def _prepare(self, u):\n        return unzip(u)\n")
    (pkg / "util.py").write_text("def unzip(u):\n    return u\n")
    monkeypatch.setattr("app.tools.packages.import_names", lambda venv, package: ("lib",))
    entries = callgraph.entry_points(str(tmp_path), "lib", ["lib.util.unzip"])
    assert entries["fetch"] == ["lib.api.fetch", "lib.core.Client.send", "lib.core.Client._prepare", "lib.util.unzip"]
    assert entries[".send"][0] == "lib.core.Client.send"            # a method entry, for client.send(...)
    assert callgraph.entry_names(entries) == ["fetch", "send"]      # no private helpers, not the target itself
    assert callgraph.path_for(entries, "lib.fetch")[0] == "lib.api.fetch"
    assert callgraph.path_for(entries, "lib.Client.send")[0] == "lib.core.Client.send"


def test_repository_dependencies_are_recognised():
    text = ("requests==2.31.0\n-e git+https://github.com/org/private-lib.git@v1.2#egg=private_lib\n"
            "shared @ git+https://github.com/org/shared-utils@main\nhttps://example.com/pkgs/wheelpkg-1.0-py3-none-any.whl\n")
    found = {r["name"]: r for r in syft.repository_requirements(text)}
    assert set(found) == {"private-lib", "shared", "wheelpkg"}
    assert found["private-lib"]["source"] == "vcs" and found["wheelpkg"]["source"] == "url"
    assert found["shared"]["url"] == "git+https://github.com/org/shared-utils@main"
