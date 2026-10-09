import { ExternalLink, GitPullRequest, LoaderCircle, Plus, Waypoints } from "lucide-react";
import type { AuditSnapshot, RunStatus } from "../types";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { STATUS_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

const LABEL: Record<RunStatus, string> = {
  running: "Running",
  awaiting_approval: "Waiting for your approval",
  completed: "Completed",
  rejected: "Rejected",
  failed: "Stopped",
};

interface Props { runId: string; status: RunStatus; snapshot: AuditSnapshot | null; onNew: () => void; }

export default function RunBanner({ runId, status, snapshot, onNew }: Props) {
  const repo = snapshot?.repo_url.replace("https://github.com/", "");
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Badge variant="outline" className={cn("h-6 gap-1.5 px-2.5", STATUS_CLASS[status])}>
          {status === "running" && <LoaderCircle className="animate-spin" />}
          {LABEL[status]}
        </Badge>
        {repo && (
          <a href={snapshot!.repo_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-sm font-medium hover:underline">
            {repo} <ExternalLink className="size-3 text-muted-foreground" />
          </a>
        )}
        <span className="font-mono text-xs text-muted-foreground">run {runId}</span>
        <div className="ml-auto flex items-center gap-2">
          {snapshot?.trace_url && (
            <a href={snapshot.trace_url} target="_blank" rel="noreferrer" className={buttonVariants({ variant: "outline", size: "sm" })}
               title="Every agent, tool step and LLM call of this audit, in LangSmith">
              <Waypoints /> LangSmith trace
            </a>
          )}
          {snapshot?.pr_url && (
            <a href={snapshot.pr_url} target="_blank" rel="noreferrer" className={buttonVariants({ size: "sm" })}>
              <GitPullRequest /> View pull request
            </a>
          )}
          {status !== "running" && <Button variant="outline" size="sm" onClick={onNew}><Plus /> New audit</Button>}
        </div>
      </div>
      {snapshot?.error && (
        <Alert variant="destructive">
          <AlertTitle>The run stopped</AlertTitle>
          <AlertDescription>{snapshot.error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
