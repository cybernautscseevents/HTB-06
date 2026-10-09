import { Fragment, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ChevronDown, ChevronRight } from "lucide-react";
import type { ReachLevel, ScoredFinding } from "../types";
import EvidenceRow from "./EvidenceRow";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { cvssClass, LEVEL_BAR, LEVEL_CLASS, REACH_LABEL } from "@/lib/reach";
import { cn } from "@/lib/utils";

type SortKey = "score" | "cvss";
type Filter = "all" | ReachLevel;

/** FR-29: CVSS vs risk-score ordering, KEV badge, reachability, expandable evidence. */
export default function RiskTable({ scored, repoUrl }: { scored: ScoredFinding[]; repoUrl: string }) {
  const [sort, setSort] = useState<SortKey>("score");
  const [filter, setFilter] = useState<Filter>("all");
  const [open, setOpen] = useState<string | null>(null);

  // Where each finding would sit if ranked by CVSS alone: shows what reachability changed.
  const cvssRank = useMemo(() => {
    const order = [...scored].sort((a, b) => b.finding.cvss - a.finding.cvss || a.rank - b.rank);
    return new Map(order.map((s, i) => [s.finding.id, i + 1]));
  }, [scored]);

  const rows = useMemo(() => {
    const list = scored.filter((s) => filter === "all" || s.reach.level === filter);
    return list.sort((a, b) => sort === "score" ? a.rank - b.rank
      : cvssRank.get(a.finding.id)! - cvssRank.get(b.finding.id)!);
  }, [scored, sort, filter, cvssRank]);

  const maxScore = Math.max(...scored.map((s) => s.score), 1);
  const counts = (l: ReachLevel) => scored.filter((s) => s.reach.level === l).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Findings</CardTitle>
        <CardDescription>
          {sort === "score"
            ? "Ranked by real risk. The arrow shows how far each finding moved from where CVSS alone would put it."
            : "Ranked the way a classic scanner would: by CVSS severity alone."}
        </CardDescription>
        <CardAction className="flex flex-wrap gap-2">
          <ToggleGroup variant="outline" size="sm" spacing={0} aria-label="Sort findings"
                       value={[sort]} onValueChange={(v) => v.length && setSort(v[0] as SortKey)}>
            <ToggleGroupItem value="score">Risk score</ToggleGroupItem>
            <ToggleGroupItem value="cvss">CVSS only</ToggleGroupItem>
          </ToggleGroup>
          <ToggleGroup variant="outline" size="sm" spacing={0} aria-label="Filter by reachability"
                       value={[filter]} onValueChange={(v) => v.length && setFilter(v[0] as Filter)}>
            <ToggleGroupItem value="all">All {scored.length}</ToggleGroupItem>
            {(["L2", "L1", "L0"] as ReachLevel[]).map((l) => (
              <ToggleGroupItem key={l} value={l} disabled={!counts(l)}>{l} {counts(l)}</ToggleGroupItem>
            ))}
          </ToggleGroup>
        </CardAction>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-16">{sort === "score" ? "Risk" : "CVSS"} #</TableHead>
              <TableHead>Package</TableHead>
              <TableHead>Vulnerability</TableHead>
              <TableHead className="text-right">CVSS</TableHead>
              <TableHead className="text-right">EPSS</TableHead>
              <TableHead>Reachability</TableHead>
              <TableHead className="w-32">Risk score</TableHead>
              <TableHead className="w-8"><span className="sr-only">Expand</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((s) => {
              const f = s.finding;
              const byCvss = cvssRank.get(f.id)!;
              const moved = byCvss - s.rank;   // positive: reachability pushed it up
              const expanded = open === f.id;
              return (
                <Fragment key={f.id}>
                  <TableRow className="cursor-pointer align-top" data-state={expanded ? "selected" : undefined}
                            onClick={() => setOpen(expanded ? null : f.id)}>
                    <TableCell>
                      <div className="text-base font-semibold tabular-nums">{sort === "score" ? s.rank : byCvss}</div>
                      {sort === "score" && moved !== 0 && (
                        <div className={cn("flex items-center text-[11px] font-medium", moved > 0 ? "text-emerald-400" : "text-muted-foreground")}
                             title={`#${byCvss} by CVSS alone`}>
                          {moved > 0 ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />}{Math.abs(moved)}
                        </div>
                      )}
                      {sort === "cvss" && <div className="text-[11px] text-muted-foreground">risk #{s.rank}</div>}
                    </TableCell>
                    <TableCell>
                      <div><span className="font-medium">{f.package}</span> <span className="text-muted-foreground">{f.version}</span></div>
                      <div className="text-xs text-muted-foreground">{f.direct ? "direct" : "transitive"}</div>
                    </TableCell>
                    <TableCell className="max-w-72 whitespace-normal">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs">{f.cve ?? f.id}</span>
                        {f.kev && <Badge className="h-4 bg-red-500 px-1.5 text-[10px] text-white" title="Listed in CISA Known Exploited Vulnerabilities">KEV</Badge>}
                      </div>
                      <div className="truncate text-xs text-muted-foreground">{f.summary}</div>
                    </TableCell>
                    <TableCell className={cn("text-right font-medium tabular-nums", cvssClass(f.cvss))}>{f.cvss.toFixed(1)}</TableCell>
                    <TableCell className="text-right tabular-nums">{(f.epss * 100).toFixed(f.epss < 0.1 ? 1 : 0)}%</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn("rounded-md", LEVEL_CLASS[s.reach.level])}>{s.reach.level}</Badge>
                      <div className="mt-0.5 text-xs text-muted-foreground">{REACH_LABEL[s.reach.level]}</div>
                    </TableCell>
                    <TableCell>
                      <div className="font-semibold tabular-nums">{s.score.toFixed(2)}</div>
                      <div className="mt-1 h-1 overflow-hidden rounded-full bg-muted">
                        <div className={cn("h-full rounded-full", LEVEL_BAR[s.reach.level])} style={{ width: `${(s.score / maxScore) * 100}%` }} />
                      </div>
                    </TableCell>
                    <TableCell>
                      <Button variant="ghost" size="icon-xs" aria-expanded={expanded}
                              aria-label={`${expanded ? "Hide" : "Show"} evidence for ${f.cve ?? f.id}`}
                              onClick={(e) => { e.stopPropagation(); setOpen(expanded ? null : f.id); }}>
                        {expanded ? <ChevronDown /> : <ChevronRight />}
                      </Button>
                    </TableCell>
                  </TableRow>
                  {expanded && (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={8} className="whitespace-normal bg-muted/30 p-4">
                        <EvidenceRow item={s} repoUrl={repoUrl} />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
