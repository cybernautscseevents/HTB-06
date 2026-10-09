import { ArrowRight, GitPullRequest, History as HistoryIcon, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { Link } from "react-router-dom";
import type { AuditSnapshot } from "../types";
import { AlertFunnel, PackageRisk, ReachabilityBreakdown } from "./AuditCharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { timeAgo } from "@/lib/format";
import { LEVEL_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

interface Props { snapshot: AuditSnapshot; onOpen: (tab: "findings" | "fix" | "sbom") => void; }

/** The answer first: how many alerts matter, then three charts, then the top risks. */
export default function Overview({ snapshot, onOpen }: Props) {
  const { scored, components, remediation, code_fixes, since_last, status } = snapshot;
  const l2 = scored.filter((s) => s.reach.level === "L2").length;
  const l1 = scored.filter((s) => s.reach.level === "L1").length;
  const kev = scored.filter((s) => s.finding.kev).length;
  const upgrades = remediation?.changes.length ?? 0;
  const rewrites = code_fixes.reduce((n, f) => n + f.changes.length, 0);
  const direct = components.filter((c) => c.direct).length;
  const clean = scored.length === 0;
  const noSbom = components.length === 0;

  const kpis = [
    { label: "Components", value: components.length, sub: `${direct} direct, ${components.length - direct} transitive` },
    { label: "Known vulnerabilities", value: scored.length, sub: `in ${new Set(scored.map((s) => s.finding.package)).size} packages` },
    { label: "Actively exploited", value: kev, sub: "listed in CISA KEV" },
    { label: "Proposed changes", value: upgrades + rewrites, sub: `${upgrades} upgrades, ${rewrites} rewrites` },
  ];

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-wrap items-center gap-x-8 gap-y-4">
          <div className="flex items-center gap-4">
            <div className={cn("flex size-12 items-center justify-center rounded-xl",
                               l2 ? "bg-red-500/15 text-red-400" : noSbom ? "bg-amber-500/15 text-amber-400" : "bg-emerald-500/15 text-emerald-400")}>
              {l2 ? <ShieldAlert className="size-6" /> : noSbom ? <TriangleAlert className="size-6" /> : <ShieldCheck className="size-6" />}
            </div>
            <div>
              <div className="text-4xl font-semibold tabular-nums leading-none">
                {l2}<span className="text-xl font-normal text-muted-foreground"> of {scored.length}</span>
              </div>
              <div className="mt-1 text-sm text-muted-foreground">
                {noSbom ? "No packages could be identified, so nothing was checked for vulnerabilities."
                  : clean ? "No known vulnerabilities in this dependency tree."
                  : l2 ? "alerts are in code your application actually reaches"
                  : l1 ? `alerts are reachable; ${l1} are in packages your code imports`
                  : "alerts are reachable. None of the affected packages are imported."}
              </div>
            </div>
          </div>
          <dl className="grid flex-1 grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
            {kpis.map((k) => (
              <div key={k.label}>
                <dt className="text-xs text-muted-foreground">{k.label}</dt>
                <dd className="text-xl font-semibold tabular-nums">{k.value}</dd>
                <dd className="text-[11px] text-muted-foreground">{k.sub}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>

      {noSbom && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-400" />
          <div>
            <div className="font-medium">The dependency list is empty</div>
            <div className="text-xs text-muted-foreground">
              The requirements could not be installed and no pinned versions were found in the requirements file or the files it includes.
              The vulnerability results below are therefore not a clean bill of health. See the Activity tab for the install log.
            </div>
          </div>
        </div>
      )}

      {status === "awaiting_approval" && (
        <Card className="ring-2 ring-amber-500/50">
          <CardContent className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <GitPullRequest className="size-5 text-amber-400" />
              <div>
                <div className="text-sm font-medium">A fix is ready for your review</div>
                <div className="text-xs text-muted-foreground">
                  {upgrades} dependency upgrade{upgrades === 1 ? "" : "s"}{rewrites ? ` and ${rewrites} rewritten function${rewrites === 1 ? "" : "s"}` : ""}. Nothing is written to GitHub until you approve.
                </div>
              </div>
            </div>
            <Button onClick={() => onOpen("fix")}>Review the fix <ArrowRight /></Button>
          </CardContent>
        </Card>
      )}

      {since_last && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border px-4 py-2.5 text-xs">
          <HistoryIcon className="size-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">Since the last audit of this repository ({timeAgo(since_last.previous_at)}):</span>
          <span><span className="font-semibold">{since_last.new.length}</span> new</span>
          <span><span className="font-semibold">{since_last.resolved.length}</span> resolved</span>
          <span><span className="font-semibold">{since_last.unchanged}</span> unchanged</span>
          <Link to={`/audit/${since_last.previous_run_id}`} className="ml-auto underline-offset-4 hover:underline">Open previous audit</Link>
        </div>
      )}

      {!clean && (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <AlertFunnel snapshot={snapshot} />
            <ReachabilityBreakdown scored={scored} />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <PackageRisk scored={scored} />
            <Card>
              <CardHeader>
                <CardTitle>Top risks</CardTitle>
                <CardDescription>The findings to look at first.</CardDescription>
                <CardAction>
                  <Button variant="ghost" size="sm" onClick={() => onOpen("findings")}>All {scored.length} <ArrowRight /></Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                <ul className="flex flex-col divide-y">
                  {scored.slice(0, 4).map((s) => (
                    <li key={s.finding.id} className="flex items-start gap-3 py-2.5 first:pt-0 last:pb-0">
                      <span className="w-5 pt-0.5 text-sm font-semibold tabular-nums text-muted-foreground">{s.rank}</span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2 text-sm">
                          <span className="font-medium">{s.finding.package}</span>
                          <span className="font-mono text-xs text-muted-foreground">{s.finding.cve ?? s.finding.id}</span>
                          <Badge variant="outline" className={cn("h-4 rounded-md px-1.5 text-[10px]", LEVEL_CLASS[s.reach.level])}>{s.reach.level}</Badge>
                          {s.finding.kev && <Badge className="h-4 bg-red-500 px-1.5 text-[10px] text-white">KEV</Badge>}
                        </div>
                        <p className="truncate text-xs text-muted-foreground">
                          {s.reach.evidence[0] ? `${s.reach.evidence[0].file}:${s.reach.evidence[0].line}` : s.finding.summary}
                        </p>
                      </div>
                      <span className="text-sm font-semibold tabular-nums">{s.score.toFixed(1)}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
