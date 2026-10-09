import type { ReactNode } from "react";
import type { AuditSnapshot, ReachLevel, ScoredFinding } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { CHART, REACH_LABEL } from "@/lib/reach";

const LEVELS: ReachLevel[] = ["L2", "L1", "L0"];
const LEVEL_NAME: Record<ReachLevel, string> = { L2: "Reachable", L1: "Imported", L0: "Not reachable" };

/** A bar or segment with a hover tooltip (the hit target is the whole mark). */
function Mark({ tip, className, style }: { tip: ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <Tooltip>
      <TooltipTrigger render={<div className={className} style={style} />} />
      <TooltipContent>{tip}</TooltipContent>
    </Tooltip>
  );
}

function Legend({ levels }: { levels: ReachLevel[] }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {levels.map((l) => (
        <span key={l} className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm" style={{ background: CHART[l] }} /> {l} · {LEVEL_NAME[l]}
        </span>
      ))}
    </div>
  );
}

/** Magnitude, one hue: how the scanner's alert count narrows to what needs action. */
export function AlertFunnel({ snapshot }: { snapshot: AuditSnapshot }) {
  const { scored, remediation } = snapshot;
  const closed = new Set((remediation?.changes ?? []).flatMap((c) => c.cves_closed));
  const stages = [
    { label: "Alerts a scanner reports", value: scored.length, note: "every known vulnerability in every package" },
    { label: "In packages your code imports", value: scored.filter((s) => s.reach.level !== "L0").length, note: "L1 and L2" },
    { label: "Vulnerable code is reached", value: scored.filter((s) => s.reach.level === "L2").length, note: "L2, with file and line" },
    { label: "Closed by this pull request", value: scored.filter((s) => closed.has(s.finding.cve ?? s.finding.id)).length, note: "after you approve" },
  ];
  const max = Math.max(...stages.map((s) => s.value), 1);
  return (
    <Card>
      <CardHeader>
        <CardTitle>From alerts to action</CardTitle>
        <CardDescription>How many findings survive each check.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {stages.map((s) => (
          <div key={s.label}>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
              <span>{s.label}</span>
              <span className="font-semibold tabular-nums">{s.value}</span>
            </div>
            <div className="h-2.5 rounded-r-sm bg-muted/60">
              <Mark tip={`${s.value} · ${s.note}`} className="h-full rounded-r-sm"
                    style={{ width: `${Math.max((s.value / max) * 100, s.value ? 1.5 : 0)}%`, background: CHART.magnitude }} />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

/** Part to whole: one stacked bar of findings by reachability level. */
export function ReachabilityBreakdown({ scored }: { scored: ScoredFinding[] }) {
  const counts = LEVELS.map((l) => ({ level: l, n: scored.filter((s) => s.reach.level === l).length }));
  const total = scored.length || 1;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Reachability</CardTitle>
        <CardDescription>Share of findings at each level.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex h-4 gap-0.5 overflow-hidden rounded-sm">
          {counts.filter((c) => c.n).map((c) => (
            <Mark key={c.level} tip={`${c.level} · ${REACH_LABEL[c.level]}: ${c.n} (${Math.round((c.n / total) * 100)}%)`}
                  className="h-full" style={{ width: `${(c.n / total) * 100}%`, minWidth: 4, background: CHART[c.level] }} />
          ))}
        </div>
        <dl className="grid grid-cols-3 gap-2">
          {counts.map((c) => (
            <div key={c.level}>
              <dt className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span className="size-2.5 rounded-sm" style={{ background: CHART[c.level] }} /> {c.level}
              </dt>
              <dd className="text-xl font-semibold tabular-nums">{c.n}</dd>
              <dd className="text-[11px] text-muted-foreground">{LEVEL_NAME[c.level]}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

/** Findings per package, stacked by level, ordered by the package's highest risk score. */
export function PackageRisk({ scored }: { scored: ScoredFinding[] }) {
  const byPkg = new Map<string, { L2: number; L1: number; L0: number; top: number }>();
  scored.forEach((s) => {
    const row = byPkg.get(s.finding.package) ?? { L2: 0, L1: 0, L0: 0, top: 0 };
    row[s.reach.level] += 1;
    row.top = Math.max(row.top, s.score);
    byPkg.set(s.finding.package, row);
  });
  const rows = [...byPkg.entries()].sort((a, b) => b[1].top - a[1].top).slice(0, 8);
  const max = Math.max(...rows.map(([, r]) => r.L2 + r.L1 + r.L0), 1);
  const hidden = byPkg.size - rows.length;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Where the findings are</CardTitle>
        <CardDescription>Findings per package, highest risk first{hidden > 0 ? ` (top 8 of ${byPkg.size})` : ""}.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="grid grid-cols-[minmax(72px,auto)_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2 text-xs">
          {rows.map(([name, r]) => (
            <div key={name} className="contents">
              <span className="truncate font-medium">{name}</span>
              <div className="flex h-3 gap-0.5">
                {LEVELS.filter((l) => r[l]).map((l) => (
                  <Mark key={l} tip={`${name}: ${r[l]} ${LEVEL_NAME[l].toLowerCase()} (${l})`}
                        className="h-full rounded-sm" style={{ width: `${(r[l] / max) * 100}%`, minWidth: 4, background: CHART[l] }} />
                ))}
              </div>
              <span className="text-right tabular-nums text-muted-foreground" title="Highest risk score in this package">
                {r.L2 + r.L1 + r.L0} · risk {r.top.toFixed(1)}
              </span>
            </div>
          ))}
        </div>
        <Legend levels={LEVELS} />
      </CardContent>
    </Card>
  );
}
