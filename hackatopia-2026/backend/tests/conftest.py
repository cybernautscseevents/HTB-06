import os
import tempfile
from pathlib import Path

# Tests always use a throwaway SQLite file and never trace, whatever backend/.env says.
# (Set before the app is imported: load_dotenv does not override existing variables.)
_tmp = Path(tempfile.mkdtemp(prefix="auditor-tests-"))
os.environ["DATABASE_URL"] = ""
os.environ["SQLITE_PATH"] = str(_tmp / "test.db")
os.environ["LANGSMITH_API_KEY"] = ""
os.environ["LANGCHAIN_API_KEY"] = ""
os.environ["LANGSMITH_TRACING"] = "false"

import pytest  # noqa: E402

from app import config  # noqa: E402


@pytest.fixture
def stubs(monkeypatch):
    """Run every agent on canned data (no network, no subprocesses)."""
    monkeypatch.setattr(config, "STUBS", {k: True for k in config.STUBS})


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from app import db

    db.get().execute("DELETE FROM cache")      # no test sees another test's cached responses
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(config, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(config, "WORK_DIR", tmp_path / "work")
    monkeypatch.setattr(config, "FORCE_BAD_VERSION", "")
    # whatever backend/.env says, tests run with the defaults
    monkeypatch.setattr(config, "GITHUB_OAUTH_SCOPE", "public_repo")
    monkeypatch.setattr(config, "GITHUB_TOKEN", "")
    monkeypatch.setattr(config, "MAX_FANOUT", 30)
    monkeypatch.setattr(config, "MAX_VERIFIER_RETRIES", 2)
    monkeypatch.setattr("app.tools.llm.get_llm", lambda: None)  # tests never call a real model
