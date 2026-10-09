from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from app import auth, config
from app.main import app
from tests.test_api import wait_for


@pytest.fixture
def oauth(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_CLIENT_ID", "cid")
    monkeypatch.setattr(config, "GITHUB_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "GITHUB_TOKEN", "")
    auth._session_cache.clear()
    auth.RUN_TOKENS.clear()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "github.com":
            assert b"client_secret=secret" in request.content and b"code=good" in request.content
            return httpx.Response(200, json={"access_token": "gho_user_token"})
        assert request.headers["authorization"] == "Bearer gho_user_token"
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "octo", "name": "Octo", "avatar_url": "a", "html_url": "h"})
        return httpx.Response(200, json=[{"full_name": "octo/demo", "html_url": "u", "language": "Python",
                                          "permissions": {"push": True}}])

    real = httpx.AsyncClient
    monkeypatch.setattr(auth.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


def sign_in(client, next_path="/?run=abc"):
    r = client.get("/auth/github/login", params={"next": next_path}, follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["client_id"] == ["cid"] and q["scope"] == ["public_repo"]
    assert q["redirect_uri"] == ["http://localhost:8000/auth/github/callback"]
    return client.get("/auth/github/callback", params={"code": "good", "state": q["state"][0]},
                      follow_redirects=False)


def test_login_roundtrip_keeps_token_server_side(oauth):
    with TestClient(app) as client:
        assert client.get("/auth/me").json() == {
            "oauth_configured": True, "authenticated": False, "user": None, "server_token": False}
        r = sign_in(client)
        assert r.headers["location"] == "http://localhost:5173/?run=abc"       # back to the same run
        assert "httponly" in r.headers["set-cookie"].lower()
        me = client.get("/auth/me").json()
        assert me["authenticated"] and me["user"]["login"] == "octo"
        assert "gho_user_token" not in client.get("/auth/me").text             # NFR-4
        repo = client.get("/auth/repos").json()[0]
        assert repo["full_name"] == "octo/demo" and repo["can_push"] and repo["private"] is False
        client.post("/auth/logout")
        assert not client.get("/auth/me").json()["authenticated"]
        assert client.get("/auth/repos").status_code == 401


def test_forged_state_and_open_redirect_are_rejected(oauth):
    with TestClient(app) as client:
        client.get("/auth/github/login", follow_redirects=False)
        r = client.get("/auth/github/callback", params={"code": "good", "state": "forged"}, follow_redirects=False)
        assert r.headers["location"].endswith("auth_error=state_mismatch")
        assert not client.get("/auth/me").json()["authenticated"]
        r = sign_in(client, next_path="//evil.example")
        assert r.headers["location"] == "http://localhost:5173/"


def test_login_unavailable_without_oauth_app(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_CLIENT_ID", "")
    with TestClient(app) as client:
        assert client.get("/auth/github/login", follow_redirects=False).status_code == 503
        assert client.get("/auth/me").json()["oauth_configured"] is False


def test_approval_needs_credentials_and_uses_the_token_of_the_approver(oauth, monkeypatch):
    monkeypatch.setattr(config, "STUBS", {**{k: True for k in config.STUBS}, "open_pr": False})
    used = []
    monkeypatch.setattr("app.tools.github.create_branch_commit_pr",
                        lambda url, manifest, title, body, token: used.append(token) or "https://github.com/o/r/pull/9")
    with TestClient(app) as client:
        run_id = client.post("/audit", json={"repo_url": "https://github.com/o/r"}).json()["run_id"]
        wait_for(client, run_id, {"awaiting_approval"})
        r = client.post(f"/audit/{run_id}/decision", json={"approved": True})
        assert r.status_code == 401 and used == []                # anonymous: nothing happens
        assert client.get(f"/audit/{run_id}").json()["status"] == "awaiting_approval"
        sign_in(client)
        assert client.post(f"/audit/{run_id}/decision", json={"approved": True}).status_code == 200
        snap = wait_for(client, run_id, {"completed", "failed"})
        assert snap["pr_url"] == "https://github.com/o/r/pull/9" and used == ["gho_user_token"]
        assert "gho_user_token" not in client.get(f"/audit/{run_id}").text
