import { useCallback, useEffect, useState } from "react";
import { ExternalLink, RefreshCw } from "lucide-react";
import { getLogs } from "../api/client";
import type { LogLine } from "../types";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

const LEVEL: Record<string, string> = {
  ERROR: "text-red-400", CRITICAL: "text-red-400", WARNING: "text-amber-400", INFO: "text-muted-foreground", DEBUG: "text-muted-foreground",
};

/** Backend log for one audit, read from the database. `refreshKey` changes when new events arrive. */
export default function LogsPanel({ runId, refreshKey, traceUrl }: { runId: string; refreshKey: number; traceUrl: string | null }) {
  const [lines, setLines] = useState<LogLine[] | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(() => {
    getLogs(runId).then((l) => { setLines(l); setFailed(false); }).catch(() => setFailed(true));
  }, [runId]);

  useEffect(() => { load(); }, [load, refreshKey]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Backend log</CardTitle>
        <CardDescription>Every step the backend recorded for this audit, with timings.</CardDescription>
        <CardAction className="flex gap-2">
          {traceUrl && (
            <a href={traceUrl} target="_blank" rel="noreferrer" className={buttonVariants({ variant: "outline", size: "sm" })}>
              LangSmith trace <ExternalLink />
            </a>
          )}
          <Button variant="outline" size="sm" onClick={load}><RefreshCw /> Refresh</Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {failed ? (
          <p className="text-sm text-muted-foreground">The log could not be loaded.</p>
        ) : !lines ? (
          <p className="text-sm text-muted-foreground">Loading</p>
        ) : lines.length === 0 ? (
          <p className="text-sm text-muted-foreground">No log lines yet.</p>
        ) : (
          <ScrollArea className="h-96 rounded-md border">
            <ul className="flex flex-col gap-0.5 p-3 font-mono text-[11px] leading-relaxed">
              {lines.map((l, i) => (
                <li key={i} className="grid grid-cols-[auto_58px_minmax(0,1fr)] gap-2">
                  <time className="text-muted-foreground">{new Date(l.ts * 1000).toLocaleTimeString([], { hour12: false })}</time>
                  <span className={cn(LEVEL[l.level] ?? "text-muted-foreground")}>{l.level}</span>
                  <span className="break-words">{l.message}</span>
                </li>
              ))}
            </ul>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
