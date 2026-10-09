import { useMemo, useState } from "react";
import { ArrowRight, GitPullRequest, Lock, Play, Search, Star } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { signIn, startAudit } from "../api/client";
import { useAudits } from "../hooks/useAudits";
import type { AuditSummary, AuthState, RepoOption } from "../types";
import { GitHubMark } from "../components/Header";
import UrlForm from "../components/UrlForm";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { repoName, timeAgo } from "@/lib/format";
import { LEVEL_CLASS, STATUS_CLASS } from "@/lib/reach";
import { cn } from "@/lib/utils";

const STATUS_LABEL: Record<AuditSummary["status"], string> = {
  running: "Running", awaiting_approval: "Needs approval", completed: "Completed", rejected: "Rejected", failed: "Stopped",
};

interface Props { auth: AuthState | null; repos: RepoOption[]; reposLoading: boolean; }

/** Repositories of the signed-in user with their latest audit, plus import by URL. */
export default function Dashboard({ auth, repos, reposLoading }: Props) {
  const navigate = useNavigate();
  const { audits } = useAudits();
  const [query, setQuery] = useState("");
  const [starting, setStarting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // newest audit per repository (the list is already newest first)
  const latest = useMemo(() => {
    const m = new Map<string, AuditSummary>();
    (audits ?? []).forEach((a) => { if (!m.has(a.repo_url)) m.set(a.repo_url, a); });
    return m;
  }, [audits]);

  const audit = async (url: string) => {
    setError(null);
    setStarting(url);
    try {
      navigate(`/audit/${await startAudit(url)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStarting(null);
    }
  };

  const q = query.trim().toLowerCase();
  const shown = repos.filter((r) => !q || r.full_name.toLowerCase().includes(q) || (r.description ?? "").toLowerCase().includes(q));
  const done = audits ?? [];
  const auditsLoading = audits === null;     // only before the first response; later visits show cached rows at once
  const stats: { label: string; value: number; tone?: string; pending: boolean }[] = [
    { label: "Repositories", value: repos.length, pending: reposLoading },
    { label: "Audits run", value: done.length, pending: auditsLoading },
    { label: "Reachable findings", value: [...latest.values()].reduce((n, a) => n + a.l2, 0), tone: "text-red-400", pending: auditsLoading },
    { label: "Pull requests opened", value: done.filter((a) => a.pr_url).length, tone: "text-emerald-400", pending: auditsLoading },
  ];

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-6 sm:px-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">Pick a repository to audit, or paste any public GitHub URL.</p>
      </div>

      {error && (
        <Alert variant="destructive"><AlertTitle>Could not start the audit</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>
      )}

      <section aria-label="Summary" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map((s) => (
          <Card key={s.label} size="sm">
            <CardContent>
              {s.pending
                ? <Skeleton className="mb-1 h-7 w-10" />
                : <div className={cn("text-2xl font-semibold tabular-nums", s.value ? s.tone : "")}>{s.value}</div>}
              <div className="text-xs text-muted-foreground">{s.label}</div>
            </CardContent>
          </Card>
        ))}
      </section>

      <UrlForm onSubmit={audit} busy={!!starting} repos={repos} label="Import a repository by URL" />

      <Card>
        <CardHeader>
          <CardTitle>Your repositories</CardTitle>
          <CardDescription>
            {auth?.authenticated ? `Most recently pushed first. ${repos.length} found for @${auth.user?.login}.` : "Sign in to list your repositories here."}
          </CardDescription>
          {repos.length > 0 && (
            <CardAction>
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input className="w-56 pl-8" placeholder="Search repositories" value={query}
                       onChange={(e) => setQuery(e.target.value)} aria-label="Search repositories" />
              </div>
            </CardAction>
          )}
        </CardHeader>
        <CardContent>
          {!auth?.authenticated ? (
            <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed py-10 text-center">
              <p className="max-w-sm text-sm text-muted-foreground">
                {auth?.oauth_configured
                  ? "Connect GitHub to see your repositories, audit them in one click and open pull requests as yourself."
                  : "GitHub sign-in is not configured on the backend. You can still audit any public repository by URL above."}
              </p>
              {auth?.oauth_configured && <Button size="lg" onClick={signIn}><GitHubMark /> Sign in with GitHub</Button>}
            </div>
          ) : reposLoading ? (
            <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-16 w-full" />)}</div>
          ) : shown.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {repos.length ? "No repository matches that search." : "No repositories found for this account."}
            </p>
          ) : (
            <ul className="divide-y rounded-lg border">
              {shown.map((r) => {
                const last = latest.get(r.html_url);
                return (
                  <li key={r.full_name} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                    <div className="min-w-0 flex-1 basis-64">
                      <div className="flex flex-wrap items-center gap-2">
                        <a href={r.html_url} target="_blank" rel="noreferrer" className="truncate text-sm font-medium hover:underline">{r.full_name}</a>
                        {r.private && <Badge variant="outline" className="h-4 gap-1 px-1.5 text-[10px]"><Lock /> Private</Badge>}
                        {r.language && <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">{r.language}</Badge>}
                        {r.stars > 0 && <span className="flex items-center gap-0.5 text-xs text-muted-foreground"><Star className="size-3" />{r.stars}</span>}
                      </div>
                      <p className="truncate text-xs text-muted-foreground">
                        {r.description || "No description"}{r.pushed_at ? ` · pushed ${timeAgo(r.pushed_at)}` : ""}
                      </p>
                    </div>

                    <div className="flex basis-56 flex-wrap items-center gap-2 text-xs">
                      {last ? (
                        <>
                          <Badge variant="outline" className={STATUS_CLASS[last.status]}>{STATUS_LABEL[last.status]}</Badge>
                          {last.l2 > 0 && <Badge variant="outline" className={cn("rounded-md", LEVEL_CLASS.L2)}>{last.l2} reachable</Badge>}
                          {last.l2 === 0 && last.l1 > 0 && <Badge variant="outline" className={cn("rounded-md", LEVEL_CLASS.L1)}>{last.l1} imported</Badge>}
                          {last.pr_url && (
                            <a href={last.pr_url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-emerald-400 hover:underline">
                              <GitPullRequest className="size-3" /> PR
                            </a>
                          )}
                          <span className="text-muted-foreground">{timeAgo(last.created_at)}</span>
                        </>
                      ) : <span className="text-muted-foreground">Never audited</span>}
                    </div>

                    <div className="flex items-center gap-2">
                      {last && (
                        <Link to={`/audit/${last.run_id}`} className={buttonVariants({ variant: "ghost", size: "sm" })}>
                          Last audit <ArrowRight />
                        </Link>
                      )}
                      <Button size="sm" variant={last ? "outline" : "default"} disabled={!!starting} onClick={() => audit(r.html_url)}>
                        <Play /> {starting === r.html_url ? "Starting" : last ? "Audit again" : "Audit"}
                      </Button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {(auditsLoading || done.length > 0) && (
        <Card>
          <CardHeader>
            <CardTitle>Recent audits</CardTitle>
            <CardAction><Link to="/history" className={buttonVariants({ variant: "ghost", size: "sm" })}>View all <ArrowRight /></Link></CardAction>
          </CardHeader>
          <CardContent>
            {auditsLoading && <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>}
            <ul className={cn("divide-y rounded-lg border", auditsLoading && "hidden")}>
              {done.slice(0, 5).map((a) => (
                <li key={a.run_id}>
                  <Link to={`/audit/${a.run_id}`} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm hover:bg-muted/50">
                    <span className="min-w-0 flex-1 truncate font-medium">{repoName(a.repo_url)}</span>
                    <Badge variant="outline" className={STATUS_CLASS[a.status]}>{STATUS_LABEL[a.status]}</Badge>
                    <span className="w-40 text-xs text-muted-foreground">{a.findings} findings · {a.l2} reachable</span>
                    <span className="w-20 text-right text-xs text-muted-foreground">{timeAgo(a.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export { STATUS_LABEL };
