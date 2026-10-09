import { FileCode, Sparkles, Wrench } from "lucide-react";
import type { CodeFix } from "../types";
import DiffViewer from "./DiffViewer";
import { Badge } from "@/components/ui/badge";

/** Functions the Code Fix agent rewrote: what was wrong, what changed, and the diff per file. */
export default function CodeFixes({ fixes }: { fixes: CodeFix[] }) {
  return (
    <div>
      <p className="mb-3 text-xs text-muted-foreground">
        Each rewrite keeps the function's name and parameters and was checked to parse and to no longer make the flagged call.
        It was not run against your tests, so review the diff.
      </p>
      <div className="flex flex-col gap-4">
        {fixes.map((fix) => (
          <div key={fix.file} className="overflow-hidden rounded-md border">
            <div className="flex items-center gap-1.5 border-b bg-muted/40 px-3 py-1.5 font-mono text-xs">
              <FileCode className="size-3.5 text-muted-foreground" /> {fix.file}
            </div>
            <ul className="flex flex-col gap-3 px-3 py-3">
              {fix.changes.map((c) => (
                <li key={`${c.function}:${c.line}`} className="text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{c.function}()</code>
                    {c.issues.map((i) => (
                      <Badge key={`${i.api}:${i.line}`} variant="outline" title={i.detail}
                             className={i.kind === "vulnerable"
                               ? "rounded-md border-red-500/30 bg-red-500/15 text-red-400"
                               : "rounded-md border-amber-500/30 bg-amber-500/15 text-amber-400"}>
                        {i.kind} · {i.api}
                      </Badge>
                    ))}
                    <Badge variant="secondary" className="h-4 gap-1 px-1.5 text-[10px]">
                      {c.source === "llm" ? <><Sparkles /> LLM rewrite, checked in code</> : <><Wrench /> rule</>}
                    </Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{c.explanation}</p>
                </li>
              ))}
            </ul>
            <div className="border-t p-2"><DiffViewer diff={fix.diff} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}
