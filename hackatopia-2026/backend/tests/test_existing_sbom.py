import json

from app import config
from app.tools import existing_sbom, syft

CYCLONEDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"component": {"bom-ref": "app", "name": "app", "type": "application"}},
    "components": [
        {"bom-ref": "flask", "type": "library", "name": "Flask", "version": "1.0", "purl": "pkg:pypi/flask@1.0"},
        {"bom-ref": "jinja", "type": "library", "name": "Jinja2", "version": "2.10", "purl": "pkg:pypi/jinja2@2.10"},
        {"bom-ref": "left-pad", "type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    ],
    "dependencies": [{"ref": "app", "dependsOn": ["flask"]}, {"ref": "flask", "dependsOn": ["jinja"]}],
}
SPDX = {
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {"SPDXID": "SPDXRef-requests", "name": "requests", "versionInfo": "2.25.0",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.25.0"}]},
        {"SPDXID": "SPDXRef-urllib3", "name": "urllib3", "versionInfo": "1.26.2",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/urllib3@1.26.2"}]},
    ],
    "relationships": [{"spdxElementId": "SPDXRef-requests", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-urllib3"}],
}
XML_AS_JSON = {"bomFormat": "CycloneDX", "components": [
    {"bom-ref": "a", "type": "library", "name": "PyYAML", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"}]}
XML = """<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library" bom-ref="a"><name>PyYAML</name><version>5.3</version><purl>pkg:pypi/pyyaml@5.3</purl></component>
  </components>
</bom>"""


def test_cyclonedx_json_uses_its_dependency_graph(tmp_path):
    (tmp_path / "bom.json").write_text(json.dumps(CYCLONEDX))
    found = existing_sbom.load(tmp_path, set())
    assert found["path"] == "bom.json" and found["format"] == "CycloneDX" and found["ignored"] == 1   # the npm package
    assert found["components"] == [
        {"name": "flask", "version": "1.0", "direct": True, "parents": [], "source": "pypi", "source_url": None},
        {"name": "jinja2", "version": "2.10", "direct": False, "parents": ["flask"], "source": "pypi", "source_url": None},
    ]


def test_manifest_decides_what_is_direct_when_there_is_one(tmp_path):
    (tmp_path / "bom.json").write_text(json.dumps(CYCLONEDX))
    comps = {c["name"]: c["direct"] for c in existing_sbom.load(tmp_path, {"jinja2"})["components"]}
    assert comps == {"flask": False, "jinja2": True}


def test_spdx_json_and_cyclonedx_xml_are_read(tmp_path):
    (tmp_path / "sbom").mkdir()
    (tmp_path / "sbom" / "project.spdx.json").write_text(json.dumps(SPDX))
    spdx = existing_sbom.load(tmp_path, set())
    assert spdx["format"] == "SPDX" and [(c["name"], c["direct"], c["parents"]) for c in spdx["components"]] == [
        ("requests", True, []), ("urllib3", False, ["requests"])]

    (tmp_path / "bom.xml").write_text(XML)          # shallower, so it is preferred
    xml = existing_sbom.load(tmp_path, set())
    assert xml["path"] == "bom.xml" and [(c["name"], c["version"]) for c in xml["components"]] == [("pyyaml", "5.3")]


def test_files_that_only_look_like_sboms_are_ignored(tmp_path):
    (tmp_path / "bom.json").write_text('{"hello": "world"}')
    (tmp_path / "sbom.json").write_text("not json at all")
    (tmp_path / "bom.xml").write_text('<!DOCTYPE x [<!ENTITY a "b">]><bom xmlns="http://cyclonedx.org/schema/bom/1.4"/>')
    (tmp_path / "package.json").write_text('{"name": "app", "dependencies": {}}')
    assert existing_sbom.load(tmp_path, set()) is None


def test_sbom_is_found_wherever_it_is_and_whatever_it_is_called(tmp_path):
    deep = tmp_path / "deploy" / "release" / "artifacts" / "v2" / "security"
    deep.mkdir(parents=True)
    (deep / "inventory-2026.json").write_text(json.dumps(CYCLONEDX))        # five folders down, no "bom" in the name
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "bom.json").write_text(json.dumps(SPDX))   # vendored: never looked at
    found = existing_sbom.load(tmp_path, set())
    assert found["path"] == "deploy/release/artifacts/v2/security/inventory-2026.json"
    assert [c["name"] for c in found["components"]] == ["flask", "jinja2"]


def test_the_projects_own_sbom_beats_a_test_fixture(tmp_path):
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "small.json").write_text(json.dumps(XML_AS_JSON))
    (tmp_path / "tests" / "fixtures" / "bom.json").write_text(json.dumps(SPDX))
    # a fixture is only a last resort, and never used when the caller can generate a real SBOM
    assert existing_sbom.load(tmp_path, set(), allow_fixtures=False) is None
    last_resort = existing_sbom.load(tmp_path, set())
    assert last_resort["path"] == "tests/fixtures/bom.json" and last_resort["fixture"]     # the one with most packages
    (tmp_path / "docs" / "release").mkdir(parents=True)
    (tmp_path / "docs" / "release" / "app.cdx.json").write_text(json.dumps(CYCLONEDX))
    own = existing_sbom.load(tmp_path, set(), allow_fixtures=False)
    assert own["path"] == "docs/release/app.cdx.json" and not own["fixture"]                # the real one wins


def _workspace(tmp_path, monkeypatch, files):
    repo = tmp_path / "repo"
    repo.mkdir()
    for rel, text in files.items():
        (repo / rel).write_text(text)
    monkeypatch.setattr(syft, "prepare_workspace", lambda url, progress, token: {
        "repo_dir": str(repo), "venv_dir": str(tmp_path / "venv"), "installed": False})
    generated = []
    monkeypatch.setattr(syft, "generate_components", lambda *a: generated.append(1) or ([{"name": "generated", "version": "1"}], "syft"))
    return generated


def test_shipped_sbom_is_used_and_nothing_is_generated(tmp_path, monkeypatch):
    generated = _workspace(tmp_path, monkeypatch, {"bom.json": json.dumps(CYCLONEDX), "requirements.txt": "Flask==1.0\n"})
    result = syft.components_for("https://github.com/o/r")
    assert generated == [] and result["source"] == "existing CycloneDX SBOM (bom.json)"
    assert [c["name"] for c in result["components"]] == ["flask", "jinja2"] and result["ignored"] == 1


def test_sbom_is_generated_only_when_missing_or_switched_off(tmp_path, monkeypatch):
    generated = _workspace(tmp_path, monkeypatch, {"requirements.txt": "Flask==1.0\n"})
    assert syft.components_for("https://github.com/o/r")["source"] == "syft" and generated == [1]

    (tmp_path / "repo" / "bom.json").write_text(json.dumps(CYCLONEDX))
    monkeypatch.setattr(config, "USE_EXISTING_SBOM", False)
    assert syft.components_for("https://github.com/o/r")["source"] == "syft" and generated == [1, 1]
