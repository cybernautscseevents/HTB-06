import pytest

from app import config
from app.tools import llm

REAL_GET_LLM = llm.get_llm   # captured at import, before conftest stubs it per test


@pytest.fixture
def real_llm(monkeypatch):
    """Undo the conftest stub and capture what would be passed to init_chat_model."""
    calls = []

    def fake_init(model, **kwargs):
        calls.append((model, kwargs))
        return object()

    monkeypatch.setattr(llm, "get_llm", REAL_GET_LLM.__wrapped__)   # uncached, un-stubbed
    monkeypatch.setattr("langchain.chat_models.init_chat_model", fake_init)
    for var in ("GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(config, "OLLAMA_API_KEY", "")
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://localhost:11434")
    return calls


def test_gemini_needs_a_key_and_is_skipped_without_one(real_llm, monkeypatch):
    monkeypatch.setattr(config, "LLM_MODEL", "google_genai:gemini-3.5-flash")
    assert llm.get_llm() is None and real_llm == []
    assert llm.status() == {"provider": "google_genai", "model": "gemini-3.5-flash",
                            "enabled": False, "reason": "GOOGLE_API_KEY is not set"}

    monkeypatch.setenv("GOOGLE_API_KEY", "AIza-test")
    assert llm.get_llm() is not None
    model, kwargs = real_llm[0]
    assert model == "gemini-3.5-flash" and kwargs["model_provider"] == "google_genai"
    assert llm.status()["enabled"] and "AIza" not in str(llm.status())


def test_gemini_alias(real_llm, monkeypatch):
    monkeypatch.setattr(config, "LLM_MODEL", "gemini:gemini-3.5-flash")
    monkeypatch.setenv("GOOGLE_API_KEY", "k")
    llm.get_llm()
    assert real_llm[0][1]["model_provider"] == "google_genai"


def test_local_ollama_needs_no_key(real_llm, monkeypatch):
    monkeypatch.setattr(config, "LLM_MODEL", "ollama:llama3.1")
    llm.get_llm()
    model, kwargs = real_llm[0]
    assert model == "llama3.1"
    assert kwargs == {"model_provider": "ollama", "base_url": "http://localhost:11434"}


def test_ollama_cloud_sends_the_key_and_keeps_tagged_model_names(real_llm, monkeypatch):
    monkeypatch.setattr(config, "LLM_MODEL", "ollama:gpt-oss:120b")
    monkeypatch.setattr(config, "OLLAMA_API_KEY", "secret")
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "https://ollama.com")
    llm.get_llm()
    model, kwargs = real_llm[0]
    assert model == "gpt-oss:120b" and kwargs["base_url"] == "https://ollama.com"
    assert kwargs["client_kwargs"] == {"headers": {"Authorization": "Bearer secret"}}
    assert "secret" not in str(llm.status())
