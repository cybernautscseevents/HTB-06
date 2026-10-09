import { useEffect, useState } from "react";
import { LoaderCircle, Play } from "lucide-react";
import type { RepoOption } from "../types";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Props {
  onSubmit: (repoUrl: string) => void;
  busy?: boolean;
  repos: RepoOption[];      // the signed-in user's repositories, offered as suggestions
  initial?: string;
  label?: string;
}

const REPO_URL = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+?(\.git)?\/?$/;

/** Accepts a full URL or the owner/repo shorthand. */
function normalise(value: string): string {
  const v = value.trim();
  return /^[\w.-]+\/[\w.-]+$/.test(v) ? `https://github.com/${v}` : v;
}

export default function UrlForm({ onSubmit, busy, repos, initial, label = "GitHub repository" }: Props) {
  const [url, setUrl] = useState(initial ?? "");
  const [touched, setTouched] = useState(false);

  useEffect(() => { if (initial) setUrl(initial); }, [initial]);

  const value = normalise(url);
  const valid = REPO_URL.test(value);
  const invalid = touched && !!url && !valid;

  return (
    <Card>
      <CardContent>
        <form
          className="flex flex-col gap-2"
          onSubmit={(e) => { e.preventDefault(); setTouched(true); if (valid && !busy) onSubmit(value); }}
        >
          <label htmlFor="repo-url" className="text-sm font-medium">{label}</label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              id="repo-url"
              list="repo-suggestions"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="https://github.com/owner/repo"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={invalid}
              className="h-9 flex-1 font-mono"
            />
            <datalist id="repo-suggestions">
              {repos.map((r) => <option key={r.full_name} value={r.html_url}>{r.full_name}</option>)}
            </datalist>
            <Button type="submit" size="lg" disabled={busy || !url.trim()}>
              {busy ? <LoaderCircle className="animate-spin" /> : <Play />}
              {busy ? "Starting" : "Run audit"}
            </Button>
          </div>
          {invalid && (
            <p className="text-xs text-destructive">Enter a public GitHub repository, e.g. https://github.com/owner/repo</p>
          )}
          {repos.length > 0 && !url && (
            <p className="text-xs text-muted-foreground">Start typing to pick one of your {repos.length} repositories.</p>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
