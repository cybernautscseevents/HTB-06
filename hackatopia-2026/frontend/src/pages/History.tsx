import { useMemo, useState } from "react";
import { GitPullRequest, Search } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useAudits } from "../hooks/useAudits";
import type { AuditSummary, RunStatus } from "../types";
import { STATUS_LABEL } from "./Dashboard";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { repoName, timeAgo } from "@/lib/format";
import { LEVEL_CLASS, STATUS_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

type Filter = "all" | RunStatus;
const FILTERS: Filter[] = ["all", "awaiting_approval", "completed", "rejected", "failed"];

/** Every audit that has been run, newest first. Kept on the backend, so it survives restarts. */
export default function History() {
  const navigate = useNavigate();
  const { audits, failed } = useAudits();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (audits ?? []).filter((a) => (filter === "all" || a.status === filter) && (!q || a.repo_url.toLowerCase().includes(q)));
  }, [audits, query, filter]);

  const count = (f: Filter) => (audits ?? []).filter((a) => f === "all" || a.status === f).length;

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-6 sm:px-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit history</h1>
        <p className="text-sm text-muted-foreground">Every audit that has been run, newest first.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Audits</CardTitle>
          <CardDescription>{audits ? `${rows.length} of ${audits.length} shown` : "Loading"}</CardDescription>
          <CardAction className="flex flex-wrap gap-2">
            <ToggleGroup variant="outline" size="sm" spacing={0} aria-label="Filter by status"
                         value={[filter]} onValueChange={(v) => v.length && setFilter(v[0] as Filter)}>
              {FILTERS.map((f) => (
                <ToggleGroupItem key={f} value={f} disabled={f !== "all" && !count(f)}>
                  {f === "all" ? "All" : STATUS_LABEL[f]} {count(f)}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input className="h-7 w-52 pl-8" placeholder="Filter by repository" value={query}
                     onChange={(e) => setQuery(e.target.value)} aria-label="Filter by repository" />
            </div>
          </CardAction>
        </CardHeader>
        <CardContent>
          {!audits ? (
            <div className="flex flex-col gap-2">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : rows.length === 0 ? (
            <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed py-10 text-center">
              <p className="text-sm text-muted-foreground">
                {failed ? "The backend could not be reached." : audits.length ? "No audit matches those filters." : "No audits yet."}
              </p>
              {!audits.length && !failed && <Link to="/dashboard" className={buttonVariants({ size: "sm" })}>Run your first audit</Link>}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repository</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>When</TableHead>
                  <TableHead>By</TableHead>
                  <TableHead className="text-right">Components</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead className="text-right">Upgrades</TableHead>
                  <TableHead className="text-right">Rewrites</TableHead>
                  <TableHead>Pull request</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((a) => (
                  <TableRow key={a.run_id} className="cursor-pointer" onClick={() => navigate(`/audit/${a.run_id}`)}>
                    <TableCell>
                      <Link to={`/audit/${a.run_id}`} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
                        {repoName(a.repo_url)}
                      </Link>
                      <div className="font-mono text-[11px] text-muted-foreground">{a.run_id}</div>
                    </TableCell>
                    <TableCell><Badge variant="outline" className={STATUS_CLASS[a.status]}>{STATUS_LABEL[a.status]}</Badge></TableCell>
                    <TableCell className="text-muted-foreground" title={new Date(a.created_at * 1000).toLocaleString()}>{timeAgo(a.created_at)}</TableCell>
                    <TableCell className="text-muted-foreground">{a.user ? `@${a.user}` : "anonymous"}</TableCell>
                    <TableCell className="text-right tabular-nums">{a.components}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <span className="mr-1 tabular-nums">{a.findings}</span>
                        {(["L2", "L1", "L0"] as const).map((l) => {
                          const n = { L2: a.l2, L1: a.l1, L0: a.l0 }[l];
                          return n ? <Badge key={l} variant="outline" className={cn("h-4 rounded-md px-1.5 text-[10px]", LEVEL_CLASS[l])}>{l} {n}</Badge> : null;
                        })}
                      </div>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{a.changes}</TableCell>
                    <TableCell className="text-right tabular-nums">{a.code_fixes}</TableCell>
                    <TableCell>
                      {a.pr_url ? (
                        <a href={a.pr_url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
                           className="inline-flex items-center gap-1 text-emerald-400 hover:underline">
                          <GitPullRequest className="size-3.5" /> #{a.pr_url.split("/").pop()}
                        </a>
                      ) : <span className="text-muted-foreground">–</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
