import { ArrowDown, ExternalLink, FileCode } from "lucide-react";
import type { ReactNode } from "react";
import type { ScoredFinding } from "../types";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

function Label({ children }: { children: ReactNode }) {
  return <h4 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{children}</h4>;
}

/** US4 / FR-17: file:line evidence and a score anyone can recompute by hand. */
export default function EvidenceRow({ item, repoUrl }: { item: ScoredFinding; repoUrl: string }) {
  const { finding: f, reach, breakdown: b } = item;
  const factors = [
    { label: "CVSS", value: b.cvss.toFixed(1) },
    { label: `Reachability ${reach.level}`, value: b.reach_weight.toFixed(1) },
    { label: "1 + EPSS", value: b.epss_factor.toFixed(3) },
    { label: f.kev ? "In CISA KEV" : "Not in KEV", value: b.kev_boost.toFixed(1) },
    { label: f.direct ? "Direct" : "Transitive", value: b.direct_boost.toFixed(1) },
  ];

  return (
    <div className="flex flex-col gap-4 text-sm">
      {item.explanation && (
        <p className="rounded-md border-l-2 border-sky-500 bg-sky-500/10 px-3 py-2">{item.explanation}</p>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        <div className="min-w-0">
          <Label>Reachability evidence</Label>
          {reach.functions.length > 0 && (
            <div className="mb-2 flex flex-wrap items-center gap-1 text-xs">
              <span className="text-muted-foreground">Vulnerable functions</span>
              {reach.functions.map((fn) => <Badge key={fn} variant="secondary" className="rounded-md font-mono">{fn}</Badge>)}
            </div>
          )}
          {reach.evidence.length === 0 ? (
            <p className="text-muted-foreground">No usage found in the application source{reach.note ? ` (${reach.note})` : ""}.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {reach.evidence.map((e) => (
                <li key={`${e.file}:${e.line}`} className="overflow-hidden rounded-md border bg-background">
                  <a href={`${repoUrl}/blob/HEAD/${e.file}#L${e.line}`} target="_blank" rel="noreferrer"
                     className="flex items-center gap-1.5 border-b px-3 py-1.5 font-mono text-xs hover:underline">
                    <FileCode className="size-3.5 text-muted-foreground" />
                    {e.file}:{e.line}
                    <ExternalLink className="ml-auto size-3 text-muted-foreground" />
                  </a>
                  <pre className={cn("overflow-x-auto border-l-2 px-3 py-2 font-mono text-xs",
                                    reach.level === "L2" ? "border-red-500" : "border-amber-500")}>{e.snippet}</pre>
                </li>
              ))}
            </ul>
          )}
          {reach.path.length > 1 && (
            <div className="mt-3">
              <p className="mb-1.5 text-xs text-muted-foreground">
                Not called directly: your code calls <code className="font-mono text-foreground">{reach.path[0]}</code>, which reaches the
                vulnerable function through the library itself.
              </p>
              <ol className="flex flex-col items-start gap-0.5 rounded-md border bg-background p-2 font-mono text-xs">
                {reach.path.map((step, i) => (
                  <li key={i} className="flex flex-col items-start gap-0.5">
                    {i > 0 && <ArrowDown className="ml-2 size-3 text-muted-foreground" />}
                    <span className={cn("rounded px-1.5 py-0.5", i === 0 ? "bg-muted" : i === reach.path.length - 1 ? "bg-red-500/15 text-red-400" : "")}>{step}</span>
                  </li>
                ))}
              </ol>
              <p className="mt-1.5 text-[11px] text-muted-foreground">Static, name-based call graph of the installed package: evidence for review, not a proof.</p>
            </div>
          )}
          {reach.note && reach.evidence.length > 0 && reach.path.length <= 1 && <p className="mt-2 text-xs text-muted-foreground">Note: {reach.note}</p>}
        </div>

        <div className="min-w-0">
          <Label>Score breakdown</Label>
          <div className="flex flex-wrap items-center gap-1.5" aria-label="Risk score formula">
            {factors.map((x, i) => (
              <span key={x.label} className="flex items-center gap-1.5">
                {i > 0 && <span className="text-muted-foreground">×</span>}
                <span className="rounded-md border bg-background px-2 py-1 text-center">
                  <span className="block font-semibold tabular-nums">{x.value}</span>
                  <span className="block text-[10px] text-muted-foreground">{x.label}</span>
                </span>
              </span>
            ))}
            <span className="text-muted-foreground">=</span>
            <span className="rounded-md border border-foreground/30 bg-foreground/10 px-2 py-1 text-center">
              <span className="block font-semibold tabular-nums">{item.score.toFixed(2)}</span>
              <span className="block text-[10px] text-muted-foreground">Risk score</span>
            </span>
          </div>

          <div className="mt-4">
            <Label>Advisory</Label>
            <p>{f.summary}</p>
            <div className="mt-2 flex flex-wrap items-center gap-1 text-xs">
              <span className="text-muted-foreground">Fixed in</span>
              {f.fixed_in.length
                ? f.fixed_in.map((v) => <Badge key={v} variant="secondary" className="rounded-md font-mono">{v}</Badge>)
                : <span className="text-muted-foreground">no fixed release yet</span>}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span className="text-muted-foreground">Sources</span>
              {[f.id, ...f.aliases.filter((a) => a !== f.id)].map((id) => (
                <a key={id} href={`https://osv.dev/vulnerability/${id}`} target="_blank" rel="noreferrer"
                   className="whitespace-nowrap font-mono underline-offset-4 hover:underline">{id}</a>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
