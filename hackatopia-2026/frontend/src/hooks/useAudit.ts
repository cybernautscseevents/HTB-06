import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, getSnapshot, openStream, sendDecision } from "../api/client";
import type { AgentEvent, AuditSnapshot } from "../types";

/**
 * Follows one audit (the id comes from the /audit/:runId route, so a reload or the GitHub
 * sign-in round trip lands back on the same run): stream events -> refresh snapshot -> decide.
 */
export function useAudit(runId: string) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [snapshot, setSnapshot] = useState<AuditSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const close = useRef<() => void>(() => {});

  const refresh = useCallback(async () => {
    try {
      setSnapshot(await getSnapshot(runId));
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setNotFound(true);
      else setError(e instanceof Error ? e.message : String(e));
    }
  }, [runId]);

  const subscribe = useCallback(() => {
    close.current();
    setEvents([]);            // the stream replays everything from the start
    setStreaming(true);
    close.current = openStream(
      runId,
      (e) => {
        setEvents((prev) => [...prev, e]);
        // results appear as each agent finishes, not only at the end
        if (!e.worker_id && e.status !== "running") void refresh();   // not for each parallel worker
      },
      () => { setStreaming(false); void refresh(); },
    );
  }, [runId, refresh]);

  const decide = useCallback(async (approved: boolean) => {
    setError(null);
    setDeciding(true);
    try {
      await sendDecision(runId, approved);
      setSnapshot((s) => (s ? { ...s, status: "running" } : s));
      subscribe();            // the backend closed the stream at the gate; reopen it
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeciding(false);
    }
  }, [runId, subscribe]);

  useEffect(() => {
    setSnapshot(null); setNotFound(false); setError(null);
    subscribe();
    return () => close.current();
  }, [subscribe]);

  return { events, snapshot, error, notFound, streaming, deciding, decide, setError };
}
