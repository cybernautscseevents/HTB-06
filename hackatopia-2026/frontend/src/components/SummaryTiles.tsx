import type { AuditSnapshot } from "../types";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export default function SummaryTiles({ snapshot }: { snapshot: AuditSnapshot }) {
  const { components, scored } = snapshot;
  const direct = components.filter((c) => c.direct).length;
  const count = (level: string) => scored.filter((s) => s.reach.level === level).length;
  const analysed = scored.length > 0;
  const dash = "–";

  const tiles: { label: string; value: number | string; sub: string; tone?: string }[] = [
    { label: "Components", value: components.length, sub: `${direct} direct · ${components.length - direct} transitive` },
    { label: "Vulnerabilities", value: analysed ? scored.length : snapshot.findings.length || dash,
      sub: analysed ? `in ${new Set(scored.map((s) => s.finding.package)).size} packages` : "what a scanner reports" },
    { label: "Reachable (L2)", value: analysed ? count("L2") : dash, sub: "vulnerable function called", tone: count("L2") ? "text-red-400" : "" },
    { label: "Imported (L1)", value: analysed ? count("L1") : dash, sub: "function not called", tone: count("L1") ? "text-amber-400" : "" },
    { label: "Not reachable (L0)", value: analysed ? count("L0") : dash, sub: "never imported", tone: "text-muted-foreground" },
    { label: "Actively exploited", value: analysed ? scored.filter((s) => s.finding.kev).length : dash, sub: "listed in CISA KEV" },
  ];

  return (
    <section aria-label="Summary" className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      {tiles.map((t) => (
        <Card key={t.label} size="sm">
          <CardContent>
            <div className={cn("text-2xl font-semibold tabular-nums leading-tight", t.tone)}>{t.value}</div>
            <div className="mt-1 text-xs font-medium">{t.label}</div>
            <div className="text-[11px] text-muted-foreground">{t.sub}</div>
          </CardContent>
        </Card>
      ))}
    </section>
  );
}
