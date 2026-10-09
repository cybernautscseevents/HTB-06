import { useEffect, useState } from "react";
import { listAudits } from "../api/client";
import type { AuditSummary } from "../types";

// Last result per query, kept for the life of the page: coming back to the dashboard or the
// history shows the previous list at once and refreshes it in the background.
const cache = new Map<string, AuditSummary[]>();

/**
 * Audit history, all of it or for one repository.
 * `audits` is null only on the very first load; `loading` is true while a request is in flight.
 */
export function useAudits(repoUrl?: string, refreshKey: string | number = "", enabled = true) {
  const key = repoUrl ?? "";
  const [audits, setAudits] = useState<AuditSummary[] | null>(() => cache.get(key) ?? null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!enabled) return;
    let current = true;
    setAudits(cache.get(key) ?? null);
    setLoading(true);
    listAudits(repoUrl)
      .then((rows) => {
        cache.set(key, rows);
        if (current) { setAudits(rows); setFailed(false); }
      })
      .catch(() => { if (current) { setFailed(true); setAudits((prev) => prev ?? []); } })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [key, repoUrl, refreshKey, enabled]);

  return { audits, loading, failed };
}
