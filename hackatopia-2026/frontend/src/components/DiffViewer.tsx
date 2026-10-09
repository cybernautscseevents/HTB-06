import { cn } from "@/lib/utils";

const LINE: Record<string, string> = {
  file: "text-muted-foreground",
  hunk: "text-sky-400",
  add: "bg-emerald-500/15 text-emerald-300",
  del: "bg-red-500/15 text-red-300",
  ctx: "",
};

export default function DiffViewer({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, "").split("\n");
  return (
    <pre className="overflow-x-auto rounded-md border bg-background py-2 font-mono text-xs leading-relaxed" aria-label="Manifest diff">
      {lines.map((line, i) => {
        const kind = line.startsWith("+++") || line.startsWith("---") ? "file"
          : line.startsWith("@@") ? "hunk"
          : line.startsWith("+") ? "add"
          : line.startsWith("-") ? "del" : "ctx";
        return <div key={i} className={cn("whitespace-pre px-3", LINE[kind])}>{line || " "}</div>;
      })}
    </pre>
  );
}
