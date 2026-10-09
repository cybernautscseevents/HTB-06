from app.tools.ast_scanner import scan

FUNCS = ["yaml.load", "yaml.full_load"]


def _scan(tmp_path, source, funcs=FUNCS):
    (tmp_path / "app.py").write_text(source)
    return scan(str(tmp_path), ["yaml"], funcs)


def test_plain_import_call(tmp_path):
    r = _scan(tmp_path, "import yaml\n\ndata = yaml.load(open('f'))\n")
    assert [(e["file"], e["line"]) for e in r["calls"]] == [("app.py", 3)]


def test_module_alias(tmp_path):
    r = _scan(tmp_path, "import yaml as y\ny.load(s)\n")
    assert r["calls"][0]["line"] == 2


def test_from_import(tmp_path):
    r = _scan(tmp_path, "from yaml import load\nload(s)\n")
    assert r["calls"][0]["line"] == 2


def test_from_import_alias(tmp_path):
    r = _scan(tmp_path, "from yaml import full_load as fl\nx = fl(s)\n")
    assert r["calls"][0]["line"] == 2


def test_safe_loader_is_downgraded(tmp_path):
    r = _scan(tmp_path, "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\nyaml.load(s, yaml.SafeLoader)\n")
    assert r["calls"] == [] and len(r["safe_calls"]) == 2
    assert r["safe_notes"] == ["yaml.load with SafeLoader"]


def test_unsafe_loader_is_not_downgraded(tmp_path):
    r = _scan(tmp_path, "import yaml\nyaml.load(s, Loader=yaml.FullLoader)\n")
    assert len(r["calls"]) == 1


def test_import_only(tmp_path):
    r = _scan(tmp_path, "import yaml\nyaml.safe_load(s)\n")
    assert r["calls"] == [] and r["imports"][0]["line"] == 1


def test_same_name_from_other_package_is_ignored(tmp_path):
    r = _scan(tmp_path, "import json\njson.load(f)\nfrom pickle import load\nload(f)\n")
    assert r["calls"] == [] and r["imports"] == []


def test_vendored_dirs_are_skipped(tmp_path):
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "x.py").write_text("import yaml\nyaml.load(s)\n")
    assert scan(str(tmp_path), ["yaml"], FUNCS)["calls"] == []
