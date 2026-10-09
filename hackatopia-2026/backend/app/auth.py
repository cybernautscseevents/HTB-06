"""GitHub OAuth (web application flow) and server-side sessions.

The access token never leaves the backend (NFR-4): the browser only holds an opaque, HttpOnly
session cookie. Sessions and per-run tokens live in memory and are never written to graph state.
"""
import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from cryptography.fernet import Fernet, InvalidToken

from app import config, db

router = APIRouter(prefix="/auth", tags=["auth"])

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API = "https://api.github.com"
SESSION_COOKIE = "sbom_session"
STATE_COOKIE = "sbom_oauth_state"
SESSION_TTL = 8 * 3600

# Sessions are stored in the database so sign-in survives a restart. The GitHub token is
# encrypted at rest with a key derived from the OAuth client secret, and decrypted only here.
_session_cache: dict[str, dict] = {}   # sid -> session, to avoid a database read per request
RUN_TOKENS: dict[str, str] = {}    # run id -> token of the user who started / approved the run


def oauth_configured() -> bool:
    return bool(config.GITHUB_CLIENT_ID and config.GITHUB_CLIENT_SECRET)


def _fernet() -> Fernet:
    secret = config.SESSION_SECRET or config.GITHUB_CLIENT_SECRET or "development-only-secret"
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def create_session(token: str, user: dict) -> str:
    sid = secrets.token_urlsafe(32)
    session = {"token": token, "user": user, "expires": time.time() + SESSION_TTL}
    _session_cache[sid] = session
    # Only a hash of the session id is stored: a database leak does not hand out usable cookies.
    db.save_session(_sid_key(sid), _fernet().encrypt(token.encode()).decode(), user, session["expires"])
    return sid


def _sid_key(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def drop_session(sid: str) -> None:
    _session_cache.pop(sid, None)
    if sid:
        db.delete_session(_sid_key(sid))


def session_of(request: Request) -> dict | None:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    session = _session_cache.get(sid)
    if session is None:
        try:
            stored = db.load_session(_sid_key(sid))
            if stored:
                stored["token"] = _fernet().decrypt(stored["token"].encode()).decode()
                session = _session_cache[sid] = stored
        except (InvalidToken, Exception):  # noqa: BLE001 - unreadable session = signed out
            session = None
    if session and session["expires"] < time.time():
        drop_session(sid)
        return None
    return session


def remember_run_token(run_id: str, request: Request) -> None:
    session = session_of(request)
    if session:
        RUN_TOKENS[run_id] = session["token"]


def token_for_run(run_id: str | None) -> str:
    """Token used to open the PR: the signed-in user's, else the server-wide GITHUB_TOKEN."""
    return RUN_TOKENS.get(run_id or "", "") or config.GITHUB_TOKEN


def current_run_token() -> str:
    """Inside a graph node: the token for the run being executed."""
    try:
        from langgraph.config import get_config

        return token_for_run(get_config()["configurable"].get("thread_id"))
    except Exception:  # noqa: BLE001 - not inside a graph run
        return config.GITHUB_TOKEN


def login_of(request: Request) -> str | None:
    session = session_of(request)
    return session["user"]["login"] if session else None


def _safe_next(path: str | None) -> str:
    """Only same-site relative paths are accepted as a post-login destination (no open redirect)."""
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return "/"


def _cookie(response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, samesite="lax",
                        secure=config.BACKEND_URL.startswith("https://"), path="/")


@router.get("/github/login")
def login(next: str | None = None):
    if not oauth_configured():
        raise HTTPException(503, "GitHub OAuth is not configured (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET)")
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": config.GITHUB_CLIENT_ID,
        "redirect_uri": f"{config.BACKEND_URL}/auth/github/callback",
        "scope": config.GITHUB_OAUTH_SCOPE,
        "state": state,
    }
    response = RedirectResponse(f"{AUTHORIZE_URL}?{urlencode(params)}", status_code=302)
    _cookie(response, STATE_COOKIE, f"{state}|{_safe_next(next)}", max_age=600)   # CSRF protection
    return response


@router.get("/github/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None,
                   error: str | None = None):
    expected, _, next_path = request.cookies.get(STATE_COOKIE, "").partition("|")
    target = config.FRONTEND_URL + _safe_next(next_path)

    def back(reason: str | None = None) -> RedirectResponse:
        sep = "&" if "?" in target else "?"
        response = RedirectResponse(target + (f"{sep}auth_error={reason}" if reason else ""), status_code=302)
        response.delete_cookie(STATE_COOKIE, path="/")
        return response

    if error or not code:
        return back("denied")
    if not expected or not state or not secrets.compare_digest(expected, state):
        return back("state_mismatch")

    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            r = await client.post(TOKEN_URL, headers={"Accept": "application/json"}, data={
                "client_id": config.GITHUB_CLIENT_ID,
                "client_secret": config.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{config.BACKEND_URL}/auth/github/callback",
            })
            token = r.json().get("access_token")
            if not token:
                return back("exchange_failed")
            u = await client.get(f"{API}/user", headers={"Authorization": f"Bearer {token}",
                                                         "Accept": "application/vnd.github+json"})
            u.raise_for_status()
            profile = u.json()
    except (httpx.HTTPError, ValueError):
        return back("github_unreachable")

    sid = create_session(token, {"login": profile["login"], "name": profile.get("name"),
                                 "avatar_url": profile.get("avatar_url"), "html_url": profile.get("html_url")})
    response = back()
    _cookie(response, SESSION_COOKIE, sid, max_age=SESSION_TTL)
    return response


@router.get("/me")
def me(request: Request):
    session = session_of(request)
    return {
        "oauth_configured": oauth_configured(),
        "authenticated": bool(session),
        "user": session["user"] if session else None,
        # True when a PR can be opened without signing in (server-wide token or stub mode).
        "server_token": bool(config.GITHUB_TOKEN) or config.STUBS["open_pr"],
    }


@router.post("/logout")
def logout(request: Request):
    from fastapi.responses import JSONResponse

    drop_session(request.cookies.get(SESSION_COOKIE, ""))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/repos")
async def repos(request: Request):
    """The signed-in user's public repositories, most recently pushed first (for the repo picker)."""
    session = session_of(request)
    if not session:
        raise HTTPException(401, "not signed in")
    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            r = await client.get(f"{API}/user/repos", params={
                "visibility": "all" if config.GITHUB_OAUTH_SCOPE == "repo" else "public",
                "sort": "pushed", "per_page": 100,
                "affiliation": "owner,collaborator,organization_member",
            }, headers={"Authorization": f"Bearer {session['token']}", "Accept": "application/vnd.github+json"})
            r.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(502, "could not list repositories from GitHub") from e
    return [{"full_name": x["full_name"], "html_url": x["html_url"], "language": x.get("language"),
             "can_push": bool((x.get("permissions") or {}).get("push")),
             "description": x.get("description"), "private": bool(x.get("private")),
             "pushed_at": x.get("pushed_at"), "stars": x.get("stargazers_count", 0),
             "default_branch": x.get("default_branch")} for x in r.json()]
