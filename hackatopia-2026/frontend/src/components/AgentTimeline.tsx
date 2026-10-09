import { useEffect, useState } from "react";
import { Check, ChevronRight, LoaderCircle, Pause, RotateCw, X } from "lucide-react";
import type { AgentEvent, AgentName, AgentStatus, ReachLevel, ScoredFinding } from "../types";
import { Badge, badgeVariants } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { LEVEL_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

const AGENTS: { id: AgentName; label: string; llm?: boolean; hint: string }[] = [
  { id: "sbom", label: "SBOM", hint: "Clone, install, list components" },
  { id: "vuln_intel", label: "Vuln Intel", hint: "OSV, EPSS, CISA KEV" },
  { id: "risk_analysis", label: "Risk Analysis", llm: true, hint: "Reachability per vulnerability, then score and rank" },
  { id: "remediation", label: "Remediation", llm: true, hint: "Propose safe versions, then verify them" },
  { id: "code_fix", label: "Code Fix", llm: true, hint: "Rewrite vulnerable and deprecated calls" },
  { id: "human_gate", label: "Human Gate", hint: "Your approval" },
  { id: "open_pr", label: "Open PR", hint: "Branch, commit, pull request" },
];

type StepStatus = AgentStatus | "pending";
const STATUS_TEXT: Record<StepStatus, string> = {
  pending: "Pending", running: "Running", done: "Done", failed: "Failed", waiting: "Waiting", retry: "Retrying",
};
const MARKER: Record<StepStatus, string> = {
  pending: "border-border bg-card text-muted-foreground",
  running: "border-sky-500 bg-card text-sky-400",
  done: "border-emerald-500/60 bg-emerald-500/15 text-emerald-400",
  failed: "border-red-500/60 bg-red-500/15 text-red-400",
  waiting: "border-amber-500/60 bg-amber-500/15 text-amber-400",
  retry: "border-amber-500/60 bg-amber-500/15 text-amber-400",
};
const STATUS_TONE: Record<StepStatus, string> = {
  pending: "text-muted-foreground", running: "text-sky-400", done: "text-muted-foreground",
  failed: "text-red-400", waiting: "text-amber-400", retry: "text-amber-400",
};

function StepIcon({ status }: { status: StepStatus }) {
  const cls = "size-3.5";
  if (status === "running") return <LoaderCircle className={cn(cls, "animate-spin")} />;
  if (status === "done") return <Check className={cls} />;
  if (status === "failed") return <X className={cls} />;
  if (status === "retry") return <RotateCw className={cls} />;
  if (status === "waiting") return <Pause className={cls} />;
  return null;
}

function duration(seconds: number): string {
  return seconds < 60 ? `${seconds.toFixed(seconds < 10 ? 1 : 0)}s` : `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

interface Props { events: AgentEvent[]; scored: ScoredFinding[]; }

/** FR-28: every agent's status in real time, parallel workers side by side, retries visible. */
export default function AgentTimeline({ events, scored }: Props) {
  const [now, setNow] = useState(Date.now() / 1000);
  const anyRunning = events.length > 0 && events[events.length - 1].status === "running";
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => setNow(Date.now() / 1000), 500);
    return () => clearInterval(t);
  }, [anyRunning]);

  const levelOf = new Map<string, ReachLevel>(scored.map((s) => [s.finding.id, s.reach.level]));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Agents</CardTitle>
        <CardDescription>Agents sharing one state, orchestrated with LangGraph.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <ol>
          {AGENTS.map((agent, index) => {
            const evs = events.filter((e) => e.agent === agent.id);
            const last = evs[evs.length - 1];
            const isFanOut = agent.id === "risk_analysis";

            // Parallel workers: latest event per worker id.
            const workers = new Map<string, AgentEvent>();
            if (isFanOut) evs.forEach((e) => e.worker_id && workers.set(e.worker_id, e));
            const finished = [...workers.values()].filter((w) => w.status !== "running").length;

            // The agent's own events (no worker id) decide its status: the workers are only its first step.
            const own = evs.filter((e) => !e.worker_id);
            const status = (own.length ? own[own.length - 1].status : evs.length ? "running" : "pending") as StepStatus;
            const ownDetail = [...own].reverse().find((e) => e.detail)?.detail ?? "";
            const detail = ownDetail || (workers.size ? `Checking reachability: ${finished} of ${workers.size} done` : "");
            const retries = evs.filter((e) => e.status === "retry").length;
            const started = evs[0]?.ts;
            const ended = status === "running" ? now : last?.ts;
            const elapsed = started && ended ? Math.max(0, ended - started) : null;
            const isLast = index === AGENTS.length - 1;

            return (
              <li key={agent.id} className="relative grid grid-cols-[24px_minmax(0,1fr)] gap-3 pb-4 last:pb-0">
                {!isLast && (
                  <span className={cn("absolute bottom-0 left-[11px] top-6 w-0.5", status === "done" ? "bg-emerald-500/40" : "bg-border")} />
                )}
                <span className={cn("z-10 flex size-6 items-center justify-center rounded-full border-2", MARKER[status])}>
                  <StepIcon status={status} />
                </span>
                <div className="min-w-0">
                  <div className="flex min-h-6 flex-wrap items-center gap-1.5">
                    <span className={cn("text-sm font-medium", status === "pending" && "text-muted-foreground")}>{agent.label}</span>
                    {agent.llm && (
                      <Tooltip>
                        <TooltipTrigger render={<span className={cn(badgeVariants({ variant: "outline" }), "h-4 px-1.5 text-[10px] text-violet-400")} />}>LLM</TooltipTrigger>
                        <TooltipContent>Uses the LLM; its output is validated in code</TooltipContent>
                      </Tooltip>
                    )}
                    {isFanOut && workers.size > 0 && <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">×{workers.size}</Badge>}
                    {retries > 0 && (
                      <Badge variant="outline" className="h-4 border-amber-500/30 bg-amber-500/15 px-1.5 text-[10px] text-amber-400">
                        {retries} {retries === 1 ? "retry" : "retries"}
                      </Badge>
                    )}
                    <span className={cn("ml-auto whitespace-nowrap text-xs tabular-nums", STATUS_TONE[status])}>
                      {STATUS_TEXT[status]}{elapsed !== null && status !== "waiting" ? ` · ${duration(elapsed)}` : ""}
                    </span>
                  </div>
                  <p className="break-words text-xs text-muted-foreground">{detail || (status === "pending" ? agent.hint : "")}</p>

                  {isFanOut && workers.size > 0 && (
                    <div className="mt-2 flex flex-col gap-2">
                      {status === "running" && <Progress value={(finished / workers.size) * 100} />}
                      <div className="flex flex-wrap gap-1">
                        {[...workers.entries()].map(([id, w]) => {
                          const level = levelOf.get(id) ?? (w.detail.match(/: (L[012])/)?.[1] as ReachLevel | undefined);
                          const running = w.status === "running";
                          return (
                            <Tooltip key={id}>
                              <TooltipTrigger render={
                                <span className={cn(badgeVariants({ variant: "outline" }), "h-5 max-w-full gap-1 rounded-md px-1.5 font-normal", level && !running && LEVEL_CLASS[level])} />
                              }>
                                {running ? <LoaderCircle className="animate-spin" /> : <span className="font-semibold">{level}</span>}
                                <span className="truncate">{running ? id.replace(/^GHSA-/, "") : w.detail.split(":")[0]}</span>
                              </TooltipTrigger>
                              <TooltipContent>{id}{w.detail ? ` · ${w.detail}` : ""}</TooltipContent>
                            </Tooltip>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>

        {events.length > 0 && (
          <>
            <Separator />
            <Collapsible>
              <CollapsibleTrigger className="group flex w-full items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
                <ChevronRight className="size-3.5 transition-transform group-data-[panel-open]:rotate-90" />
                Event log ({events.length})
              </CollapsibleTrigger>
              <CollapsibleContent>
                <ScrollArea className="mt-2 h-56 rounded-md border">
                  <ul className="flex flex-col gap-1 p-2 font-mono text-[11px] leading-relaxed">
                    {events.map((e, i) => (
                      <li key={i} className="grid grid-cols-[auto_52px_minmax(0,1fr)] gap-2">
                        <time className="text-muted-foreground">{new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false })}</time>
                        <span className={STATUS_TONE[e.status]}>{e.status}</span>
                        <span className="break-words">{e.agent}{e.worker_id ? ` [${e.worker_id}]` : ""}{e.detail ? `: ${e.detail}` : ""}</span>
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
              </CollapsibleContent>
            </Collapsible>
          </>
        )}
      </CardContent>
    </Card>
  );
}
