import type { ReactNode } from "react";
import { ArrowRight, Check, CircleAlert, CircleCheck, GitPullRequest, Info, LoaderCircle, TriangleAlert, X } from "lucide-react";
import { signIn } from "../api/client";
import type { AuditSnapshot, AuthState } from "../types";
import CodeFixes from "./CodeFixes";
import DiffViewer from "./DiffViewer";
import { GitHubMark } from "./Header";
import PrBody from "./PrBody";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { LEVEL_CLASS, STATUS_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

interface Props {
  snapshot: AuditSnapshot;
  auth: AuthState | null;
  deciding: boolean;
  onDecision: (approved: boolean) => void;
}

function Section({ value, title, count, tone, children }: { value: string; title: string; count?: number | string; tone?: string; children: ReactNode }) {
  return (
    <AccordionItem value={value}>
      <AccordionTrigger className="hover:no-underline">
        <span className="flex items-center gap-2">
          {title}
          {count !== undefined && (
            <span className={cn("rounded-full bg-muted px-1.5 text-[11px] font-normal tabular-nums text-muted-foreground", tone)}>{count}</span>
          )}
        </span>
      </AccordionTrigger>
      <AccordionContent className="[&_a]:no-underline">{children}</AccordionContent>
    </AccordionItem>
  );
}

function Note({ text }: { text: string }) {
  const kind = text.startsWith("FAIL:") ? "fail" : text.startsWith("warning:") ? "warn" : text.startsWith("note:") ? "info" : "ok";
  const Icon = { fail: CircleAlert, warn: TriangleAlert, info: Info, ok: CircleCheck }[kind];
  const tone = { fail: "text-red-400", warn: "text-amber-400", info: "text-sky-400", ok: "text-emerald-400" }[kind];
  return (
    <li className="flex gap-2 rounded-md border px-3 py-2 text-sm">
      <Icon className={cn("mt-0.5 size-4 shrink-0", tone)} />
      <span className="min-w-0 break-words">{text.replace(/^(FAIL|warning|note):\s*/, "")}</span>
    </li>
  );
}

/** FR-30 / FR-24: nothing is written to GitHub until the human approves what is shown here. */
export default function ApprovalPanel({ snapshot, auth, deciding, onDecision }: Props) {
  const { remediation, verification, status, pr_url, scored, code_fixes } = snapshot;
  if (!remediation) return null;

  const hasUpgrades = remediation.changes.length > 0;
  const hasChanges = hasUpgrades || code_fixes.length > 0;
  const awaiting = status === "awaiting_approval";
  const canOpenPr = !!auth && (auth.authenticated || auth.server_token);
  const byId = new Map(scored.map((s) => [s.finding.id, s]));
  const rewrites = code_fixes.reduce((n, f) => n + f.changes.length, 0);
  const notes = verification?.notes ?? [];
  const problems = notes.filter((n) => n.startsWith("FAIL:") || n.startsWith("warning:")).length;

  // Open what the reviewer has to read; keep reference material folded away.
  const open = [hasUpgrades && "upgrades", code_fixes.length > 0 && "code", problems > 0 && "checks",
                remediation.manual_review.length > 0 && "manual"].filter(Boolean) as string[];

  return (
    <Card className={cn(awaiting && "ring-2 ring-amber-500/50")}>
      <CardHeader>
        <CardTitle>{hasChanges ? "Proposed fix" : "No automatic fix"}</CardTitle>
        <CardDescription className={cn(hasChanges && "font-mono text-foreground")}>
          {hasChanges ? remediation.pr_title : "Nothing could be patched safely and automatically. See what needs manual review below."}
        </CardDescription>
        {verification && hasUpgrades && (
          <CardAction>
            <Badge variant="outline" className={cn("gap-1", STATUS_CLASS[verification.ok ? "completed" : "failed"])}>
              {verification.ok ? <Check /> : <X />}
              {verification.ok ? "Verified" : "Verification failed"} · attempt {verification.attempt}
            </Badge>
          </CardAction>
        )}
      </CardHeader>

      <CardContent className="flex flex-col gap-4">
        {status === "rejected" && (
          <Alert>
            <X />
            <AlertTitle>Rejected</AlertTitle>
            <AlertDescription>No changes were made to the repository.</AlertDescription>
          </Alert>
        )}
        {pr_url && (
          <Alert className="border-emerald-500/30">
            <GitPullRequest className="text-emerald-400" />
            <AlertTitle>Pull request opened</AlertTitle>
            <AlertDescription>
              <a href={pr_url} target="_blank" rel="noreferrer" className="break-all underline underline-offset-4">{pr_url}</a>
            </AlertDescription>
          </Alert>
        )}

        <Accordion multiple defaultValue={open} className="rounded-lg border px-4">
          {hasUpgrades && (
            <Section value="upgrades" title="Dependency upgrades" count={remediation.changes.length}>
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Package</TableHead><TableHead>Version</TableHead><TableHead>Closes</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {remediation.changes.map((c) => (
                    <TableRow key={c.package}>
                      <TableCell className="font-medium">{c.package}</TableCell>
                      <TableCell className="font-mono text-xs">
                        <span className="inline-flex items-center gap-1.5">
                          <span className="text-muted-foreground">{c.old}</span>
                          <ArrowRight className="size-3 text-muted-foreground" />
                          <span className="font-semibold">{c.new}</span>
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-normal font-mono text-xs">{c.cves_closed.join(", ") || "–"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="mt-3"><DiffViewer diff={remediation.diff} /></div>
            </Section>
          )}

          {code_fixes.length > 0 && (
            <Section value="code" title="Code changes" count={`${rewrites} function${rewrites === 1 ? "" : "s"}`}>
              <CodeFixes fixes={code_fixes} />
            </Section>
          )}

          {notes.length > 0 && (
            <Section value="checks" title="Verifier checks" count={problems ? `${problems} to review` : "passed"}
                     tone={problems ? "bg-amber-500/15 text-amber-400" : "bg-emerald-500/15 text-emerald-400"}>
              <ul className="flex flex-col gap-1.5">{notes.map((n, i) => <Note key={i} text={n} />)}</ul>
            </Section>
          )}

          {remediation.manual_review.length > 0 && (
            <Section value="manual" title="Needs manual review" count={remediation.manual_review.length} tone="bg-amber-500/15 text-amber-400">
              <ul className="flex flex-col gap-1.5">
                {remediation.manual_review.map((c) => (
                  <li key={c.package} className="flex flex-wrap items-center gap-x-2 rounded-md border px-3 py-2 text-sm">
                    <span className="font-medium">{c.package}</span>
                    <span className="font-mono text-xs">{c.old} → {c.new}</span>
                    <span className="text-xs text-muted-foreground">
                      not applied automatically{c.cves_closed.length ? ` · would close ${c.cves_closed.join(", ")}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {remediation.not_patched.length > 0 && (
            <Section value="skipped" title="Not patched" count={remediation.not_patched.length}>
              <ul className="flex max-h-72 flex-col gap-1.5 overflow-y-auto text-sm">
                {remediation.not_patched.map((id) => {
                  const s = byId.get(id);
                  return (
                    <li key={id} className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs">{s?.finding.cve ?? id}</span>
                      {s && <span className="font-medium">{s.finding.package}</span>}
                      {s && <Badge variant="outline" className={cn("h-4 rounded-md px-1.5 text-[10px]", LEVEL_CLASS[s.reach.level])}>{s.reach.level}</Badge>}
                      <span className="text-xs text-muted-foreground">
                        {s?.reach.level === "L0" ? "not reachable, reported only" : !s?.finding.fixed_in.length ? "no fixed release" : "not closed by the chosen version"}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </Section>
          )}

          {hasChanges && (
            <Section value="preview" title="Pull request preview">
              <PrBody markdown={remediation.pr_body} />
            </Section>
          )}
        </Accordion>
      </CardContent>

      {awaiting && (
        <CardFooter className="sticky bottom-4 z-10 flex-col items-start gap-3 bg-card">
          {canOpenPr ? (
            <div className="flex w-full flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-muted-foreground">
                {auth?.authenticated
                  ? <>The pull request will be opened as <span className="font-medium text-foreground">@{auth.user?.login}</span>.</>
                  : "The pull request will be opened with the server's GitHub token."}
                {" "}Nothing is written to GitHub until you approve.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button size="lg" variant="destructive" disabled={deciding} onClick={() => onDecision(false)}><X /> Reject</Button>
                <Button size="lg" disabled={deciding || !hasChanges} onClick={() => onDecision(true)}>
                  {deciding ? <LoaderCircle className="animate-spin" /> : <GitPullRequest />}
                  {deciding ? "Working" : "Approve and open PR"}
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex w-full flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-muted-foreground">
                {auth?.oauth_configured
                  ? "Sign in with GitHub to open this pull request as yourself. You will come straight back to this audit."
                  : "Opening a pull request needs GitHub credentials: configure the GitHub OAuth app or GITHUB_TOKEN on the backend."}
              </p>
              <div className="flex flex-wrap gap-2">
                <Button size="lg" variant="destructive" disabled={deciding} onClick={() => onDecision(false)}><X /> Reject</Button>
                {auth?.oauth_configured && (
                  <Button size="lg" onClick={signIn}><GitHubMark className="size-4" /> Sign in with GitHub to approve</Button>
                )}
              </div>
            </div>
          )}
        </CardFooter>
      )}
    </Card>
  );
}
