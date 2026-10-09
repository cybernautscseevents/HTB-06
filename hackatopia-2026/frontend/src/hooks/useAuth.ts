import { useCallback, useEffect, useState } from "react";
import { getMe, listRepos, signOut as apiSignOut } from "../api/client";
import type { AuthState, RepoOption } from "../types";

const AUTH_ERRORS: Record<string, string> = {
  denied: "GitHub sign-in was cancelled.",
  state_mismatch: "GitHub sign-in could not be verified. Please try again.",
  exchange_failed: "GitHub rejected the sign-in. Check the OAuth app's client secret.",
  github_unreachable: "GitHub could not be reached during sign-in.",
};

/** Reads ?auth_error=... left by the OAuth callback and removes it from the URL. */
function takeAuthError(): string | null {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("auth_error");
  if (!code) return null;
  url.searchParams.delete("auth_error");
  window.history.replaceState(null, "", url);
  return AUTH_ERRORS[code] ?? "GitHub sign-in failed.";
}

export function useAuth() {
  const [auth, setAuth] = useState<AuthState | null>(null);   // null = still loading / backend down
  const [repos, setRepos] = useState<RepoOption[]>([]);
  const [reposLoading, setReposLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(takeAuthError);

  const load = useCallback(async () => {
    try {
      const me = await getMe();
      setAuth(me);
      setRepos(me.authenticated ? await listRepos().catch(() => []) : []);
    } catch {
      setAuth(null);
    } finally {
      setReposLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const signOut = useCallback(async () => {
    await apiSignOut().catch(() => {});
    await load();
  }, [load]);

  return { auth, repos, reposLoading, authError, clearAuthError: () => setAuthError(null), signOut };
}
