import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes")


ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Storage. Neon / PostgreSQL connection string, e.g.
#   postgresql://user:password@ep-xxxx-pooler.region.aws.neon.tech/dbname?sslmode=require
# Unset: a local SQLite file is used instead, so nothing needs configuring to run.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = Path(os.getenv("SQLITE_PATH") or ROOT / "data" / "app.db")
DATA_DIR = Path(__file__).resolve().parent / "data"
# Clones and venvs of target repos (NFR-5). Kept between runs so a warm run skips the install.
WORK_DIR = Path(os.getenv("WORK_DIR") or Path(tempfile.gettempdir()) / "sbom-auditor")

# "provider:model" for init_chat_model (NFR-7), e.g. google_genai:gemini-3.5-flash or ollama:llama3.1
LLM_MODEL = os.getenv("LLM_MODEL", "google_genai:gemini-3.5-flash").strip()
# langchain-google-genai reads GOOGLE_API_KEY; accept the name Google AI Studio uses too.
if os.getenv("GEMINI_API_KEY") and not os.getenv("GOOGLE_API_KEY"):
    os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]
# Ollama: local server by default; set OLLAMA_API_KEY (and https://ollama.com) for Ollama Cloud.
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "").strip()
OLLAMA_BASE_URL = (os.getenv("OLLAMA_BASE_URL", "").strip()
                   or ("https://ollama.com" if OLLAMA_API_KEY else "http://localhost:11434")).rstrip("/")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
OFFLINE = _flag("OFFLINE")
# NFR-6 scale guards. Every finding gets the cheap import/call scan; only the first MAX_FANOUT
# (imported packages first, then by CVSS) may spend an LLM call on function extraction.
MAX_FANOUT = int(os.getenv("MAX_FANOUT", "30"))
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "250"))
MAX_CODE_FIXES = int(os.getenv("MAX_CODE_FIXES", "8"))     # functions rewritten per audit
# Use a CycloneDX / SPDX SBOM committed in the repository instead of generating one.
USE_EXISTING_SBOM = os.getenv("USE_EXISTING_SBOM", "true").strip().lower() != "false"
# Cloned repositories and their virtualenvs are deleted this long after their last audit.
WORKSPACE_TTL_DAYS = float(os.getenv("WORKSPACE_TTL_DAYS", "30"))

# LangSmith: with an API key every audit is traced (each agent, tool and LLM call).
LANGSMITH_API_KEY = (os.getenv("LANGSMITH_API_KEY") or os.getenv("LANGCHAIN_API_KEY") or "").strip()
LANGSMITH_PROJECT = os.getenv("LANGSMITH_PROJECT", "threat-pilot").strip()
LANGSMITH_ENABLED = bool(LANGSMITH_API_KEY) and os.getenv("LANGSMITH_TRACING", "true").strip().lower() != "false"
if LANGSMITH_ENABLED:
    os.environ.update(LANGSMITH_TRACING="true", LANGSMITH_API_KEY=LANGSMITH_API_KEY, LANGSMITH_PROJECT=LANGSMITH_PROJECT)
else:
    os.environ["LANGSMITH_TRACING"] = "false"
MAX_VERIFIER_RETRIES = int(os.getenv("MAX_VERIFIER_RETRIES", "2"))
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "http://localhost:5173")
# GitHub OAuth App (optional). Callback URL to register: {BACKEND_URL}/auth/github/callback
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "").strip()
# "public_repo" opens PRs on public repositories. Set "repo" to also audit private repositories
# and install private git dependencies as the signed-in user.
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()   # encrypts stored sessions; defaults to the client secret
GITHUB_OAUTH_SCOPE = os.getenv("GITHUB_OAUTH_SCOPE", "public_repo").strip() or "public_repo"
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
FRONTEND_URL = os.getenv("FRONTEND_URL", CORS_ORIGIN).rstrip("/")
FORCE_BAD_VERSION = os.getenv("FORCE_BAD_VERSION", "").strip()
SYFT_BIN = os.getenv("SYFT_BIN", "").strip()   # optional explicit path to the syft executable

HTTP_TIMEOUT = 30
INSTALL_TIMEOUT = 600
DRY_RUN_TIMEOUT = 240

# USE_STUBS=true makes every agent return canned data (app/stubs.py); edit per agent to mix.
_stub = _flag("USE_STUBS")
STUBS = {
    "sbom": _stub,
    "vuln_intel": _stub,
    "risk_analysis": _stub,
    "remediation": _stub,
    "code_fix": _stub,
    "open_pr": _stub,
}

# PRD FR-16
REACH_WEIGHT = {"L0": 0.2, "L1": 0.6, "L2": 1.0}
KEV_BOOST = 2.0
DIRECT_BOOST = 1.2
TOP_EXPLAIN = 5
