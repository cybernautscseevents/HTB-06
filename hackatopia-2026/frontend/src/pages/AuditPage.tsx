import { CircleAlert } from "lucide-react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useAudit } from "../hooks/useAudit";
import type { AuthState } from "../types";
import AgentTimeline from "../components/AgentTimeline";
import ApprovalPanel from "../components/ApprovalPanel";
import ComponentsPanel from "../components/ComponentsPanel";
import LogsPanel from "../components/LogsPanel";
import Overview from "../components/Overview";
import PipelineStrip from "../components/PipelineStrip";
import RepoHistory, { useRepoHistory } from "../components/RepoHistory";
import RiskTable from "../components/RiskTable";
import RunBanner from "../components/RunBanner";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const TABS = ["overview", "findings", "fix", "sbom", "activity", "history"] as const;
type Tab = (typeof TABS)[number];

function Count({ n }: { n: number }) {
  return <span className="rounded-full bg-muted px-1.5 text-[11px] tabular-nums text-muted-foreground">{n}</span>;
}

export default function AuditPage({ auth }: { auth: AuthState | null }) {
  const { runId = "" } = useParams();
  const navigate = useNavigate();
  const audit = useAudit(runId);
  // The tab is part of the URL (?tab=fix), so a view can be linked to and survives a reload.
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab") as Tab | null;
  const tab: Tab = requested && TABS.includes(requested) ? requested : "overview";
  const setTab = (next: Tab) => setParams(next === "overview" ? {} : { tab: next }, { replace: true });
  const { events, snapshot, streaming } = audit;
  const status = snapshot?.status ?? "running";
  // Anything worth showing: an SBOM, a proposed fix (code rewrites can exist with no SBOM), or a finished run.
  const hasResults = !!snapshot && (snapshot.components.length > 0 || !!snapshot.remediation || status !== "running");
  const repoAudits = useRepoHistory(snapshot?.repo_url, status);

  if (audit.notFound) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16 text-center">
        <h1 className="text-xl font-semibold">Audit not found</h1>
        <p className="mt-2 text-sm text-muted-foreground">There is no audit with the id <code className="font-mono">{runId}</code>.</p>
        <div className="mt-6 flex justify-center gap-2">
          <Link to="/dashboard" className={buttonVariants()}>Go to dashboard</Link>
          <Link to="/history" className={buttonVariants({ variant: "outline" })}>Audit history</Link>
        </div>
      </div>
    );
  }

  const fixCount = snapshot?.remediation
    ? snapshot.remediation.changes.length + snapshot.code_fixes.reduce((n, f) => n + f.changes.length, 0) : 0;

  return (
    <main className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-6 sm:px-6">
      {audit.error && (
        <Alert variant="destructive">
          <CircleAlert />
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{audit.error}</AlertDescription>
          <AlertAction><Button variant="ghost" size="sm" onClick={() => audit.setError(null)}>Dismiss</Button></AlertAction>
        </Alert>
      )}

      <RunBanner runId={runId} status={status} snapshot={snapshot} onNew={() => navigate("/dashboard")} />
      <PipelineStrip events={events} />

      {!hasResults ? (
        <Card>
          <CardHeader>
            <CardTitle>{status === "running" ? "Working on it" : "No results"}</CardTitle>
            <CardDescription>
              {status === "running" ? "Results appear here as each agent finishes." : "This audit stopped before it produced any results."}
            </CardDescription>
          </CardHeader>
          {status === "running" && (
            <CardContent className="flex flex-col gap-3">
              <Skeleton className="h-20 w-full" />
              <div className="grid gap-3 md:grid-cols-2"><Skeleton className="h-40" /><Skeleton className="h-40" /></div>
            </CardContent>
          )}
        </Card>
      ) : (
        <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
          <TabsList variant="line" className="w-full justify-start overflow-x-auto border-b">
            <TabsTrigger value="overview" className="flex-none px-3">Overview</TabsTrigger>
            <TabsTrigger value="findings" className="flex-none px-3">Findings <Count n={snapshot!.scored.length} /></TabsTrigger>
            <TabsTrigger value="fix" className="flex-none px-3" disabled={!snapshot!.remediation}>
              Fix <Count n={fixCount} />
              {status === "awaiting_approval" && <span className="size-1.5 rounded-full bg-amber-400" title="Waiting for your approval" />}
            </TabsTrigger>
            <TabsTrigger value="sbom" className="flex-none px-3">SBOM <Count n={snapshot!.components.length} /></TabsTrigger>
            <TabsTrigger value="activity" className="flex-none px-3">Activity</TabsTrigger>
            <TabsTrigger value="history" className="flex-none px-3">History {repoAudits && <Count n={repoAudits.length} />}</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="pt-2">
            <Overview snapshot={snapshot!} onOpen={setTab} />
          </TabsContent>
          <TabsContent value="findings" className="pt-2">
            {snapshot!.scored.length
              ? <RiskTable scored={snapshot!.scored} repoUrl={snapshot!.repo_url} />
              : <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">No known vulnerabilities were found.</CardContent></Card>}
          </TabsContent>
          <TabsContent value="fix" className="pt-2">
            {snapshot!.remediation && (
              <ApprovalPanel snapshot={snapshot!} auth={auth}
                             deciding={audit.deciding || (streaming && status === "running")}
                             onDecision={audit.decide} />
            )}
          </TabsContent>
          <TabsContent value="sbom" className="pt-2">
            <ComponentsPanel components={snapshot!.components} scored={snapshot!.scored} />
          </TabsContent>
          <TabsContent value="activity" className="pt-2">
            <div className="grid items-start gap-4 lg:grid-cols-[360px_minmax(0,1fr)]">
              <AgentTimeline events={events} scored={snapshot!.scored} />
              <LogsPanel runId={runId} refreshKey={events.filter((e) => !e.worker_id).length} traceUrl={snapshot!.trace_url} />
            </div>
          </TabsContent>
          <TabsContent value="history" className="pt-2">
            <RepoHistory repoUrl={snapshot!.repo_url} currentRunId={runId} audits={repoAudits} />
          </TabsContent>
        </Tabs>
      )}
    </main>
  );
}
