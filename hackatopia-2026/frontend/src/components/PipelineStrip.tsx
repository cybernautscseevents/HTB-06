import { Check, LoaderCircle, Pause, RotateCw, X } from "lucide-react";
import type { AgentEvent, AgentName, AgentStatus } from "../types";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const STEPS: { id: AgentName; label: string }[] = [
  { id: "sbom", label: "SBOM" },
  { id: "vuln_intel", label: "Vuln intel" },
  { id: "risk_analysis", label: "Risk analysis" },
  { id: "remediation", label: "Remediation" },
  { id: "code_fix", label: "Code fix" },
  { id: "human_gate", label: "Approval" },
  { id: "open_pr", label: "Pull request" },
];

type StepStatus = AgentStatus | "pending";
const DOT: Record<StepStatus, string> = {
  pending: "border-border text-muted-foreground",
  running: "border-sky-500 text-sky-400",
  done: "border-emerald-500/60 bg-emerald-500/15 text-emerald-400",
  failed: "border-red-500/60 bg-red-500/15 text-red-400",
  waiting: "border-amber-500/60 bg-amber-500/15 text-amber-400",
  retry: "border-amber-500/60 bg-amber-500/15 text-amber-400",
};

function statusOf(events: AgentEvent[], id: AgentName): { status: StepStatus; extra: string } {
  const evs = events.filter((e) => e.agent === id);
  if (!evs.length) return { status: "pending", extra: "" };
  // An agent with parallel workers is finished when its own closing event arrives, not when the workers are.
  const workers = new Map<string, AgentEvent>();
  evs.forEach((e) => e.worker_id && workers.set(e.worker_id, e));
  const own = evs.filter((e) => !e.worker_id);
  const status: StepStatus = own.length ? own[own.length - 1].status : "running";
  if (workers.size) {
    const done = [...workers.values()].filter((w) => w.status !== "running").length;
    return { status, extra: `${done}/${workers.size} checked` };
  }
  const retries = evs.filter((e) => e.status === "retry").length;
  return { status, extra: retries ? `${retries} ${retries === 1 ? "retry" : "retries"}` : "" };
}

/** The whole pipeline on one line: where the audit is, at a glance. Details live in the Activity tab. */
export default function PipelineStrip({ events }: { events: AgentEvent[] }) {
  const last = [...events].reverse().find((e) => e.detail);
  return (
    <Card size="sm">
      <CardContent className="flex flex-col gap-3">
        <ol className="flex items-start overflow-x-auto pb-1">
          {STEPS.map((step, i) => {
            const { status, extra } = statusOf(events, step.id);
            return (
              <li key={step.id} className="flex min-w-[76px] flex-1 flex-col items-center gap-1.5 text-center">
                <div className="flex w-full items-center">
                  <span className={cn("h-0.5 flex-1", i === 0 ? "bg-transparent" : status === "pending" ? "bg-border" : "bg-emerald-500/40")} />
                  <span className={cn("flex size-6 shrink-0 items-center justify-center rounded-full border-2", DOT[status])}>
                    {status === "running" ? <LoaderCircle className="size-3.5 animate-spin" />
                      : status === "done" ? <Check className="size-3.5" />
                      : status === "failed" ? <X className="size-3.5" />
                      : status === "retry" ? <RotateCw className="size-3.5" />
                      : status === "waiting" ? <Pause className="size-3.5" />
                      : <span className="text-[10px] font-semibold">{i + 1}</span>}
                  </span>
                  <span className={cn("h-0.5 flex-1", i === STEPS.length - 1 ? "bg-transparent" : status === "done" ? "bg-emerald-500/40" : "bg-border")} />
                </div>
                <span className={cn("text-[11px] font-medium leading-tight", status === "pending" && "text-muted-foreground")}>{step.label}</span>
                {extra && <span className="text-[10px] tabular-nums text-muted-foreground">{extra}</span>}
              </li>
            );
          })}
        </ol>
        {last && (
          <p className="truncate border-t pt-2 text-xs text-muted-foreground" title={last.detail}>
            <span className="font-medium text-foreground">{STEPS.find((s) => s.id === last.agent)?.label}</span> · {last.detail}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
