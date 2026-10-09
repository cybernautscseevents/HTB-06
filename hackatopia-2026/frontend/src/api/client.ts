import type { AgentEvent, AuditSnapshot, AuditSummary, AuthState, Health, LogLine, RepoOption } from "../types";
import { mockEvents, mockHistory, mockPrEvents, mockRepos, mockSnapshot, mockUser } from "../mocks/mockAudit";

export const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === "true";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let r: Response;
  try {
    // credentials: the HttpOnly session cookie from GitHub sign-in must travel cross-origin
    r = await fetch(`${API}${path}`, { credentials: "include", ...init });
  } catch {
    throw new ApiError(0, `Cannot reach the backend at ${API}`);
  }
  if (!r.ok) {
    const body = await r.json().catch(() => null);
    throw new ApiError(r.status, typeof body?.detail === "string" ? body.detail : `Request failed (${r.status})`);
  }
  return r.json();
}

const json = (body: unknown): RequestInit => ({
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
});

// --- mock mode state (VITE_USE_MOCKS=true): the UI runs with no backend ---
let mockDecision: boolean | null = null;
let mockSignedIn = true;

function mockCurrent(): AuditSnapshot {
  if (mockDecision === null) return mockSnapshot;
  return mockDecision
    ? { ...mockSnapshot, status: "completed", pr_url: "https://github.com/example/demo-repo/pull/1" }
    : { ...mockSnapshot, status: "rejected" };
}

// --- audits ---
export async function startAudit(repoUrl: string): Promise<string> {
  if (USE_MOCKS) { mockDecision = null; return mockSnapshot.run_id; }
  return (await request<{ run_id: string }>("/audit", json({ repo_url: repoUrl }))).run_id;
}

export async function getSnapshot(runId: string): Promise<AuditSnapshot> {
  if (USE_MOCKS) return mockCurrent();
  return request(`/audit/${runId}`);
}

export async function sendDecision(runId: string, approved: boolean): Promise<void> {
  if (USE_MOCKS) { mockDecision = approved; return; }
  await request(`/audit/${runId}/decision`, json({ approved }));
}

/** All audits, newest first; pass a repository URL to get only that repository's audits. */
export async function listAudits(repoUrl?: string): Promise<AuditSummary[]> {
  if (USE_MOCKS) return mockHistory(mockCurrent()).filter((a) => !repoUrl || a.repo_url === repoUrl);
  return request(repoUrl ? `/audits?repo_url=${encodeURIComponent(repoUrl)}` : "/audits");
}

export async function getLogs(runId: string): Promise<LogLine[]> {
  if (USE_MOCKS) {
    return mockEvents.filter((e) => !e.worker_id && e.status !== "running").map((e, i) => ({
      ts: Date.now() / 1000 - 60 + i * 3, level: e.status === "retry" ? "WARNING" : "INFO", logger: "app.agents",
      run_id: runId, agent: e.agent, message: `${e.agent} ${e.status}: ${e.detail}`,
    }));
  }
  return request(`/audit/${runId}/logs`);
}

export async function getHealth(): Promise<Health> {
  if (USE_MOCKS) return { ok: true, offline: true, stubs: ["mock"], storage: "sqlite", langsmith: false };
  return request("/health");
}

/** Opens the SSE stream (it replays past events first). Returns a close function. */
export function openStream(
  runId: string, onEvent: (e: AgentEvent) => void, onDone: () => void,
): () => void {
  if (USE_MOCKS) {
    const script = mockDecision === null ? mockEvents
      : [...mockEvents, ...mockPrEvents(mockDecision)];
    const instant = mockDecision === null ? 0 : mockEvents.length;   // replayed part arrives at once
    const timers = script.map((e, i) =>
      setTimeout(() => onEvent({ ...e, ts: Date.now() / 1000 }), Math.max(0, i - instant + 1) * 450));
    timers.push(setTimeout(onDone, (script.length - instant + 1) * 450));
    return () => timers.forEach(clearTimeout);
  }
  const es = new EventSource(`${API}/audit/${runId}/stream`);
  let finished = false;
  const finish = () => { if (!finished) { finished = true; es.close(); onDone(); } };
  es.addEventListener("agent", (m) => onEvent(JSON.parse((m as MessageEvent).data)));
  es.addEventListener("done", finish);
  es.onerror = finish;   // backend gone or run unknown: stop and let the snapshot fetch report it
  return () => { finished = true; es.close(); };
}

// --- GitHub OAuth ---
export async function getMe(): Promise<AuthState> {
  if (USE_MOCKS) {
    return { oauth_configured: true, authenticated: mockSignedIn, user: mockSignedIn ? mockUser : null, server_token: true };
  }
  return request("/auth/me");
}

/** Full-page navigation target. `next` brings the user back to the same run after GitHub. */
export function loginUrl(): string {
  const next = window.location.pathname + window.location.search;
  return `${API}/auth/github/login?next=${encodeURIComponent(next)}`;
}

export function signIn(): void {
  if (USE_MOCKS) { mockSignedIn = true; window.location.reload(); return; }
  window.location.assign(loginUrl());
}

export async function signOut(): Promise<void> {
  if (USE_MOCKS) { mockSignedIn = false; return; }
  await request("/auth/logout", { method: "POST" });
}

export async function listRepos(): Promise<RepoOption[]> {
  if (USE_MOCKS) return mockRepos;
  return request("/auth/repos");
}
