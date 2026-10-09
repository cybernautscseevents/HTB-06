import type { ReactNode } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

/** Inline `code` and _emphasis_ only; everything else is rendered as plain text (no HTML injection). */
function inline(text: string): ReactNode[] {
  return text.split(/(`[^`]+`|_[^_]+_)/g).filter(Boolean).map((part, i) =>
    part.startsWith("`") ? <code key={i} className="rounded bg-muted px-1 py-0.5 font-mono text-xs">{part.slice(1, -1)}</code>
      : part.startsWith("_") && part.endsWith("_") ? <em key={i} className="text-muted-foreground">{part.slice(1, -1)}</em>
      : part);
}

const cells = (row: string) => row.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());

/** Renders the small Markdown subset the Remediation agent writes: headings, tables, lists, paragraphs. */
export default function PrBody({ markdown }: { markdown: string }) {
  const lines = markdown.split("\n");
  const out: ReactNode[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    if (line.startsWith("### ")) out.push(<h5 key={i} className="mt-2 text-sm font-semibold">{inline(line.slice(4))}</h5>);
    else if (line.startsWith("## ")) out.push(<h4 key={i} className="text-base font-semibold">{inline(line.slice(3))}</h4>);
    else if (line.startsWith("|")) {
      const rows: string[] = [];
      while (i < lines.length && lines[i].startsWith("|")) rows.push(lines[i++]);
      i--;
      const [head, , ...body] = rows;
      out.push(
        <Table key={i}>
          <TableHeader><TableRow>{cells(head).map((c, j) => <TableHead key={j}>{inline(c)}</TableHead>)}</TableRow></TableHeader>
          <TableBody>
            {body.map((r, k) => <TableRow key={k}>{cells(r).map((c, j) => <TableCell key={j}>{inline(c)}</TableCell>)}</TableRow>)}
          </TableBody>
        </Table>,
      );
    } else if (line.startsWith("- ")) {
      const items: string[] = [];
      while (i < lines.length && lines[i].startsWith("- ")) items.push(lines[i++].slice(2));
      i--;
      out.push(<ul key={i} className="list-disc pl-5">{items.map((t, k) => <li key={k}>{inline(t)}</li>)}</ul>);
    } else out.push(<p key={i}>{inline(line)}</p>);
  }
  return <div className="flex flex-col gap-2 rounded-md border bg-background p-4 text-sm">{out}</div>;
}
