import { useMemo, useState } from "react";
import { ChevronRight, CornerDownRight, GitBranch } from "lucide-react";
import type { Component, ScoredFinding } from "../types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";

/** FR-3: the SBOM as a dependency tree: direct packages, with what each one pulls in. */
export default function ComponentsPanel({ components, scored }: { components: Component[]; scored: ScoredFinding[] }) {
  const [query, setQuery] = useState("");

  const vulns = useMemo(() => {
    const m = new Map<string, number>();
    scored.forEach((s) => m.set(s.finding.package, (m.get(s.finding.package) ?? 0) + 1));
    return m;
  }, [scored]);

  const children = useMemo(() => {
    const m = new Map<string, Component[]>();
    components.forEach((c) => c.parents.forEach((p) => m.set(p, [...(m.get(p) ?? []), c])));
    return m;
  }, [components]);

  const q = query.trim().toLowerCase();
  const matches = (c: Component) => !q || c.name.includes(q);
  const roots = components.filter((c) => c.direct);
  // transitive packages whose parent is unknown still need to be listed somewhere
  const known = new Set(components.map((c) => c.name));
  const orphans = components.filter((c) => !c.direct && !c.parents.some((p) => known.has(p)));

  const external = components.filter((c) => c.source !== "pypi").length;

  const renderNode = (c: Component, depth: number, trail: string[]) => {
    const kids = (children.get(c.name) ?? []).filter((k) => !trail.includes(k.name));
    if (!matches(c) && !kids.some(matches)) return null;
    const n = vulns.get(c.name);
    return (
      <li key={`${trail.join("/")}/${c.name}`}>
        <div className="flex flex-wrap items-center gap-2 border-b py-1.5 text-sm" style={{ paddingLeft: depth * 20 }}>
          {depth > 0 && <CornerDownRight className="size-3.5 text-muted-foreground" />}
          <span className="font-medium">{c.name}</span>
          <span className="font-mono text-xs text-muted-foreground">{c.version}</span>
          {depth === 0 && c.direct && <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">direct</Badge>}
          {c.source !== "pypi" && (
            <Badge variant="outline" className="h-4 gap-1 border-sky-500/30 bg-sky-500/15 px-1.5 text-[10px] text-sky-400"
                   title={`Installed from ${c.source_url ?? "a repository"}. Not a PyPI release, so it is not checked against OSV.`}>
              <GitBranch /> {c.source === "vcs" ? "from repository" : "from URL"} · not checked
            </Badge>
          )}
          {n ? (
            <Badge variant="outline" className="h-4 border-red-500/30 bg-red-500/15 px-1.5 text-[10px] text-red-400">
              {n} {n === 1 ? "vulnerability" : "vulnerabilities"}
            </Badge>
          ) : null}
        </div>
        {kids.length > 0 && depth < 4 && <ul>{kids.map((k) => renderNode(k, depth + 1, [...trail, c.name]))}</ul>}
      </li>
    );
  };

  return (
    <Card>
      <Collapsible>
        <CardHeader>
          <CollapsibleTrigger className="group flex items-center gap-2 text-left">
            <ChevronRight className="size-4 text-muted-foreground transition-transform group-data-[panel-open]:rotate-90" />
            <CardTitle>Software bill of materials</CardTitle>
          </CollapsibleTrigger>
          <CardDescription className="pl-6">
            {components.length} components, {roots.length} direct{external ? `, ${external} from other repositories (not checked against OSV)` : ""}
          </CardDescription>
        </CardHeader>
        <CollapsibleContent>
          <CardContent className="pt-4">
            <Input className="mb-3 max-w-xs" placeholder="Filter packages" value={query}
                   onChange={(e) => setQuery(e.target.value)} aria-label="Filter packages" />
            <ul>
              {roots.map((c) => renderNode(c, 0, []))}
              {orphans.length > 0 && (
                <li className="mt-3">
                  <div className="text-xs text-muted-foreground">Other transitive packages</div>
                  <ul>{orphans.map((c) => renderNode(c, 1, ["other"]))}</ul>
                </li>
              )}
            </ul>
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}
