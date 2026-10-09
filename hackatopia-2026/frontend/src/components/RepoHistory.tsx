import { GitPullRequest } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useAudits } from "../hooks/useAudits";
import type { AuditSummary } from "../types";
import { STATUS_LABEL } from "../pages/Dashboard";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { repoName, timeAgo } from "@/lib/format";
import { LEVEL_CLASS, STATUS_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

/** Loads every audit of one repository, newest first. `refreshKey` changes when this run's status does. */
export function useRepoHistory(repoUrl: string | undefined, refreshKey: string) {
  return useAudits(repoUrl, refreshKey, !!repoUrl).audits;
}

interface Props { repoUrl: string; currentRunId: string; audits: AuditSummary[] | null; }

/** Every audit of this repository, so earlier runs are one click away from the current one. */
export default function RepoHistory({ repoUrl, currentRunId, audits }: Props) {
  const navigate = useNavigate();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Audits of {repoName(repoUrl)}</CardTitle>
        <CardDescription>
          {audits ? `${audits.length} audit${audits.length === 1 ? "" : "s"} of this repository, newest first.` : "Loading"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!audits ? (
          <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
        ) : audits.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">No audits found for this repository.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Audit</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>When</TableHead>
                <TableHead>By</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead className="text-right">Upgrades</TableHead>
                <TableHead className="text-right">Rewrites</TableHead>
                <TableHead>Pull request</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audits.map((a) => {
                const current = a.run_id === currentRunId;
                return (
                  <TableRow key={a.run_id} data-state={current ? "selected" : undefined}
                            className={cn(!current && "cursor-pointer")}
                            onClick={() => !current && navigate(`/audit/${a.run_id}`)}>
                    <TableCell>
                      {current ? (
                        <span className="flex items-center gap-2 font-mono text-xs">
                          {a.run_id} <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">viewing</Badge>
                        </span>
                      ) : (
                        <Link to={`/audit/${a.run_id}`} className="font-mono text-xs underline-offset-4 hover:underline"
                              onClick={(e) => e.stopPropagation()}>{a.run_id}</Link>
                      )}
                    </TableCell>
                    <TableCell><Badge variant="outline" className={STATUS_CLASS[a.status]}>{STATUS_LABEL[a.status]}</Badge></TableCell>
                    <TableCell className="text-muted-foreground" title={new Date(a.created_at * 1000).toLocaleString()}>{timeAgo(a.created_at)}</TableCell>
                    <TableCell className="text-muted-foreground">{a.user ? `@${a.user}` : "anonymous"}</TableCell>
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
                );
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
