"""The only LLM entry point (NFR-3, NFR-7).

Exactly 3 call sites use it: function extraction (reachability), top-5 explanations (triage)
and PR text (remediation). Every caller validates the output in code and has a deterministic
fallback, so `structured()` returning None is always safe. Outputs are cached for offline demos.
"""
import logging
import os
import time
from functools import lru_cache
from typing import TypeVar

from pydantic import BaseModel, Field

from app import config
from app.tools import cache

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)

BREAKER_THRESHOLD = 2
BREAKER_COOLDOWN = 120
_breaker = {"failures": 0, "open_until": 0.0}


PROVIDER_ALIASES = {"gemini": "google_genai", "google": "google_genai"}
# Hosted providers are skipped up front when their key is missing, instead of failing per call.
REQUIRED_KEY = {"google_genai": "GOOGLE_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def model_spec() -> tuple[str, str, dict]:
    """(provider, model, provider kwargs) from the single LLM_MODEL string, e.g.

    google_genai:gemini-3.5-flash   Gemini (GOOGLE_API_KEY or GEMINI_API_KEY)
    ollama:llama3.1                 local Ollama at OLLAMA_BASE_URL
    ollama:gpt-oss:120b             Ollama Cloud when OLLAMA_API_KEY is set
    """
    provider, _, model = config.LLM_MODEL.partition(":")
    provider = PROVIDER_ALIASES.get(provider, provider)
    kwargs: dict = {}
    if provider == "ollama":
        kwargs["base_url"] = config.OLLAMA_BASE_URL
        if config.OLLAMA_API_KEY:
            kwargs["client_kwargs"] = {"headers": {"Authorization": f"Bearer {config.OLLAMA_API_KEY}"}}
    else:
        kwargs.update(timeout=45, max_retries=1)
    return provider, model, kwargs


def status() -> dict:
    """What the UI and /health report about the LLM. Never includes a key."""
    provider, model, _ = model_spec()
    key = REQUIRED_KEY.get(provider)
    missing = bool(key) and not os.getenv(key)
    return {"provider": provider, "model": model,
            "enabled": bool(model) and not missing and not config.OFFLINE,
            "reason": f"{key} is not set" if missing else "OFFLINE=true" if config.OFFLINE else None}


@lru_cache(maxsize=1)
def get_llm():
    """Chat model from one config string, or None when no provider/key is usable."""
    provider, model, kwargs = model_spec()
    key = REQUIRED_KEY.get(provider)
    if not model or (key and not os.getenv(key)):
        log.warning("LLM disabled: %s", f"{key} is not set" if model else "LLM_MODEL has no model name")
        return None
    try:
        from langchain.chat_models import init_chat_model

        return init_chat_model(model, model_provider=provider, **kwargs)
    except Exception as e:  # noqa: BLE001 - missing provider package, bad model string
        log.warning("LLM disabled: %s", e)
        return None


def structured(namespace: str, key: str, schema: type[T], system: str, user: str) -> T | None:
    """One structured-output call, cached on disk. None on any failure."""
    cache_key = f"{config.LLM_MODEL}|{key}"
    hit = cache.get(f"llm_{namespace}", cache_key)
    if hit is not None:
        try:
            return schema.model_validate(hit)
        except ValueError:
            pass
    if config.OFFLINE:
        return None
    if time.monotonic() < _breaker["open_until"]:
        return None
    llm = get_llm()
    if llm is None:
        return None
    try:
        result = llm.with_structured_output(schema).invoke([("system", system), ("human", user)])
        if not isinstance(result, schema):
            result = schema.model_validate(result)
    except Exception as e:  # noqa: BLE001 - rate limit, network, auth, malformed output
        _breaker["failures"] += 1
        if _breaker["failures"] >= BREAKER_THRESHOLD:
            # Stop hammering a provider that is down, unauthenticated or rate limiting us.
            _breaker.update(failures=0, open_until=time.monotonic() + BREAKER_COOLDOWN)
            log.warning("LLM disabled for %ss after repeated failures: %s", BREAKER_COOLDOWN, str(e)[:200])
        return None
    _breaker["failures"] = 0
    cache.put(f"llm_{namespace}", cache_key, result.model_dump())
    return result


# --- Call site 1: vulnerable function extraction (FR-11) ----------------------------------------

class VulnerableFunctions(BaseModel):
    functions: list[str] = Field(
        description="Fully qualified names of the vulnerable public functions or methods, "
                    "e.g. 'yaml.load'. Empty if the advisory names none.")


def extract_functions(vuln_id: str, package: str, advisory_text: str) -> list[str]:
    """Candidate names only. The caller MUST validate them against the package source (FR-12)."""
    out = structured(
        "functions", vuln_id, VulnerableFunctions,
        "You read security advisories. List only the function or method names of the affected "
        "Python package that the advisory explicitly identifies as vulnerable. Do not guess. "
        "Return an empty list if none are named.",
        f"Package: {package}\nAdvisory {vuln_id}:\n{advisory_text[:6000]}",
    )
    return [f.strip() for f in out.functions if f.strip()][:10] if out else []


# --- Call site 2: explanations for the top findings (FR-18) -------------------------------------

class Explanation(BaseModel):
    finding_id: str
    text: str = Field(description="Exactly two plain-English sentences.")


class Explanations(BaseModel):
    items: list[Explanation]


def explain_findings(facts: list[dict]) -> dict[str, str]:
    """{finding_id: two-sentence explanation}. `facts` is the only information the model sees."""
    import json

    key = json.dumps(facts, sort_keys=True)
    out = structured(
        "explain", key, Explanations,
        "You explain dependency vulnerabilities to developers. For each finding write exactly two "
        "sentences: why it matters for this application, then what to do. Use ONLY the facts "
        "given. Never mention identifiers, versions, files or numbers that are not in the facts.",
        key,
    )
    return {i.finding_id: i.text.strip() for i in out.items} if out else {}


# --- Call site 3: pull request text (FR-25) -----------------------------------------------------

class PrText(BaseModel):
    title: str = Field(description="Conventional-commit style PR title, at most 72 characters.")
    summary: str = Field(description="Two to four sentences summarising the change for a reviewer.")


def draft_pr_text(facts: dict) -> PrText | None:
    import json

    key = json.dumps(facts, sort_keys=True)
    return structured(
        "pr", key, PrText,
        "You write pull request text for dependency security updates. Use ONLY the facts given. "
        "Never mention packages, versions or CVE ids that are not in the facts.",
        key,
    )


# --- Call site 4: rewrite one function (code_fix agent) --------------------------------------------------

class RewrittenFunction(BaseModel):
    changed: bool = Field(description="False if the problem cannot be fixed by editing this function.")
    code: str = Field(description="The complete rewritten function, starting at column 0, with its decorators.")
    new_imports: list[str] = Field(default_factory=list, description="Import statements the rewrite needs, one per item.")
    explanation: str = Field(description="One sentence on what changed and why behaviour is preserved.")


def rewrite_function(facts: dict) -> RewrittenFunction | None:
    """Proposal only. The caller checks syntax, signature and that the flagged call is gone."""
    import json

    key = json.dumps(facts, sort_keys=True)
    return structured(
        "rewrite", key, RewrittenFunction,
        "You are a careful Python engineer. Rewrite the given function so it no longer uses the listed "
        "problematic APIs, following the advice given for each. First understand what the function does; "
        "the rewrite must keep the same name, parameters, return values and observable behaviour. Change "
        "only what is needed. Return the whole function starting at column 0, including decorators. "
        "Put any new imports in new_imports, not inside the function, unless they were already inside. "
        "If the problem can only be fixed by upgrading the package and not by editing this code, "
        "set changed to false.",
        key,
    )
