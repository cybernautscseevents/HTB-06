import { useEffect, useRef } from "react";
import { gsap } from "gsap";
import { ArrowRight, LayoutDashboard } from "lucide-react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { useReducedMotion, type Variants } from "motion/react";
import { signIn } from "../api/client";
import type { AuthState } from "../types";
import { GitHubMark } from "../components/Header";
import { AnimatedGroup } from "@/components/ui/animated-group";
import { buttonVariants } from "@/components/ui/button";
import { BRAND } from "@/lib/brand";
import { cn } from "@/lib/utils";

const item: Variants = {
  hidden: { opacity: 0, filter: "blur(12px)", y: 12 },
  visible: { opacity: 1, filter: "blur(0px)", y: 0, transition: { type: "spring", bounce: 0.3, duration: 1.5 } },
};
const variants = { container: { visible: { transition: { staggerChildren: 0.05, delayChildren: 0.5 } } } as Variants, item };

const SOURCES = ["OSV.dev", "FIRST EPSS", "CISA KEV", "Syft", "LangGraph", "GitHub"];

const STEPS = [
  ["Build the SBOM", "Every direct and transitive package, straight from an isolated install."],
  ["Prove reachability", "The file and line that calls the vulnerable code, directly or through the library."],
  ["Rank by real risk", "A reachable medium outranks an unreachable critical."],
  ["Fix the code too", "Deprecated and vulnerable calls are rewritten, function by function."],
  ["You approve", "A verified pull request, opened only when you say so."],
];

const cta = "h-11 rounded-xl px-5 text-base";

export default function Landing({ auth }: { auth: AuthState | null }) {
  const gradientRef = useRef<HTMLDivElement>(null);
  const [params] = useSearchParams();
  const reduce = useReducedMotion();

  useEffect(() => {
    if (!gradientRef.current || reduce) return;
    gsap.fromTo(gradientRef.current, { opacity: 0, y: -30 }, { opacity: 1, y: 0, duration: 1.6, ease: "power3.out" });
  }, [reduce]);

  // links from before the app had pages: /?run=abc
  const legacyRun = params.get("run");
  if (legacyRun) return <Navigate to={`/audit/${legacyRun}`} replace />;

  const signedIn = !!auth?.authenticated;

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
      <div className="relative isolate overflow-hidden rounded-2xl">
        <div
          ref={gradientRef}
          className="absolute inset-0 -z-10 rounded-2xl"
          style={{
            backgroundImage: `
              linear-gradient(180deg, #ffffff 0%, #FFEDD5 25%, #FFDAB9 50%, #FFB6C1 70%, #E0BBE4 85%, #F3E5F5 100%),
              radial-gradient(at 20% 30%, #ffffff33 0%, transparent 60%),
              radial-gradient(at 80% 70%, #f3e5f533 0%, transparent 70%)`,
            backgroundBlendMode: "overlay, screen",
          }}
        />

        <div className="px-4 pb-10 pt-12 text-center sm:pt-16">
          <div className="relative mx-auto max-w-3xl">
            <h1 className="text-3xl font-bold tracking-tight text-gray-900 sm:text-5xl md:text-6xl">
              {BRAND}: fix the vulnerabilities your code actually reaches
            </h1>
            <p className="mx-auto mt-4 max-w-2xl text-lg text-gray-600">
              Scanners flag every CVE in every package. {BRAND} proves which ones your application can reach,
              ranks them by real risk, and opens a verified pull request that upgrades the dependency and
              rewrites the affected code.
            </p>
            <AnimatedGroup variants={variants} className="mt-10 flex flex-col items-center justify-center gap-3 md:flex-row">
              <div className="rounded-[14px] border border-black/10 bg-black/10 p-0.5">
                {signedIn ? (
                  <Link to="/dashboard" className={cn(buttonVariants(), cta, "bg-gray-900 text-white hover:bg-gray-800")}>
                    <LayoutDashboard /> Open your dashboard
                  </Link>
                ) : auth?.oauth_configured ? (
                  <button onClick={signIn} className={cn(buttonVariants(), cta, "bg-gray-900 text-white hover:bg-gray-800")}>
                    <GitHubMark /> Sign in with GitHub
                  </button>
                ) : (
                  <Link to="/dashboard" className={cn(buttonVariants(), cta, "bg-gray-900 text-white hover:bg-gray-800")}>
                    Start an audit <ArrowRight />
                  </Link>
                )}
              </div>
              <div className="rounded-[14px] bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 p-0.5">
                <Link to="/dashboard" className={cn(buttonVariants(), cta, "bg-white text-black hover:bg-black hover:text-white")}>
                  Audit a public repository
                </Link>
              </div>
            </AnimatedGroup>
          </div>
        </div>

        <AnimatedGroup variants={variants}>
          <div className="relative px-2 sm:px-6">
            <div className="relative mx-auto max-h-[46vh] max-w-5xl overflow-hidden rounded-t-2xl border border-b-0 border-black/10 bg-neutral-950 p-2 shadow-lg shadow-zinc-950/25">
              <img
                src="/hero-app.png"
                alt={`${BRAND} showing an audit: agent timeline, ranked findings and the proposed fix`}
                width={2880} height={1600}
                className="w-full rounded-xl"
              />
            </div>
          </div>
        </AnimatedGroup>
      </div>

      <div className="py-8">
        <p className="text-center text-xs uppercase tracking-widest text-muted-foreground">Built on live data from</p>
        <div className="mx-auto mt-4 grid max-w-3xl grid-cols-2 gap-3 text-center text-sm font-medium text-muted-foreground sm:grid-cols-3 lg:grid-cols-6">
          {SOURCES.map((s) => <div key={s} className="rounded-lg border px-3 py-2">{s}</div>)}
        </div>
      </div>

      <ol className="grid gap-3 pb-10 sm:grid-cols-2 lg:grid-cols-5">
        {STEPS.map(([title, text], i) => (
          <li key={title} className="rounded-xl border bg-card p-4">
            <div className="mb-2 flex size-6 items-center justify-center rounded-full bg-muted text-xs font-semibold">{i + 1}</div>
            <div className="text-sm font-medium">{title}</div>
            <div className="mt-1 text-xs text-muted-foreground">{text}</div>
          </li>
        ))}
      </ol>
    </div>
  );
}
