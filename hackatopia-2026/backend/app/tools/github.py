"""GitHub REST API: branch, commit, pull request (FR-25).

The token is the signed-in user's OAuth token or the server-wide GITHUB_TOKEN (NFR-4). It is only
ever sent in the Authorization header and never logged.
"""
import base64
import time

import httpx
from langsmith import traceable

from app import config
from app.tools.syft import MANIFEST, parse_repo_url

API = "https://api.github.com"
FORK_WAIT_SECONDS = 30


class GitHubError(RuntimeError):
    pass


def _client(token: str) -> httpx.Client:
    if not token:
        raise GitHubError("no GitHub credentials: sign in with GitHub or set GITHUB_TOKEN")
    return httpx.Client(base_url=API, timeout=config.HTTP_TIMEOUT, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })


def _check(r: httpx.Response, what: str) -> dict:
    if r.status_code >= 400:
        try:
            message = r.json().get("message", "")
        except ValueError:
            message = ""
        # The response body is safe to surface; the token is only ever in the request header.
        raise GitHubError(f"{what} failed ({r.status_code}): {message[:200]}")
    return r.json()


def _fork(gh: httpx.Client, base: str) -> dict:
    """Fork the repository into the user's account (or reuse their fork) and bring it up to date."""
    fork = _check(gh.post(f"{base}/forks"), "fork repository")
    work = f"/repos/{fork['full_name']}"
    branch = fork["default_branch"]
    deadline = time.time() + FORK_WAIT_SECONDS
    while gh.get(f"{work}/git/ref/heads/{branch}").status_code != 200:   # forking is asynchronous
        if time.time() > deadline:
            raise GitHubError("fork was not ready in time; try approving again")
        time.sleep(2)
    gh.post(f"{work}/merge-upstream", json={"branch": branch})   # best effort: an old fork may be stale
    return fork


@traceable(name="github_open_pull_request", run_type="tool", process_inputs=lambda i: {k: v for k, v in i.items() if k != "token"})
def create_branch_commit_pr(repo_url: str, files: dict[str, str], title: str, body: str, token: str) -> str:
    """Branch off the default branch, commit the changed files, open a PR. Returns the PR URL.

    `files` maps repo-relative paths to their full new content (the manifest and any rewritten source).

    Without push access to the repository the branch is created on the user's fork instead.
    """
    owner, repo = parse_repo_url(repo_url)
    base = f"/repos/{owner}/{repo}"
    branch = f"sbom-auditor/fix-{int(time.time())}"
    with _client(token) as gh:
        info = _check(gh.get(base), "read repository")
        default = info["default_branch"]
        if (info.get("permissions") or {}).get("push"):
            work, work_default, head = base, default, branch
        else:
            fork = _fork(gh, base)
            work, work_default = f"/repos/{fork['full_name']}", fork["default_branch"]
            head = f"{fork['owner']['login']}:{branch}"

        sha = _check(gh.get(f"{work}/git/ref/heads/{work_default}"), "read default branch")["object"]["sha"]
        _check(gh.post(f"{work}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha}), "create branch")
        for path, content in files.items():
            current = _check(gh.get(f"{work}/contents/{path}", params={"ref": branch}), f"read {path}")
            _check(gh.put(f"{work}/contents/{path}", json={
                "message": title if path == MANIFEST else f"{title} ({path})",
                "content": base64.b64encode(content.encode("utf-8")).decode(),
                "sha": current["sha"],
                "branch": branch,
            }), f"commit {path}")
        pr = _check(gh.post(f"{base}/pulls", json={
            "title": title, "body": body, "head": head, "base": default,
        }), "open pull request")
    return pr["html_url"]
