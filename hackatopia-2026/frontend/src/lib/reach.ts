import type { ReachLevel, RunStatus } from "@/types";

export const REACH_LABEL: Record<ReachLevel, string> = {
  L2: "Vulnerable function called",
  L1: "Package imported",
  L0: "Not imported",
};

/** Flat tints only: one colour per meaning, used the same way everywhere. */
export const LEVEL_CLASS: Record<ReachLevel, string> = {
  L2: "border-red-500/30 bg-red-500/15 text-red-400",
  L1: "border-amber-500/30 bg-amber-500/15 text-amber-400",
  L0: "border-border bg-muted text-muted-foreground",
};

export const LEVEL_BAR: Record<ReachLevel, string> = {
  L2: "bg-red-500", L1: "bg-amber-500", L0: "bg-muted-foreground/50",
};

export const STATUS_CLASS: Record<RunStatus, string> = {
  running: "border-sky-500/30 bg-sky-500/15 text-sky-400",
  awaiting_approval: "border-amber-500/30 bg-amber-500/15 text-amber-400",
  completed: "border-emerald-500/30 bg-emerald-500/15 text-emerald-400",
  rejected: "border-red-500/30 bg-red-500/15 text-red-400",
  failed: "border-red-500/30 bg-red-500/15 text-red-400",
};

/** Chart fills. Validated together on the dark card surface (CVD and normal-vision separation). */
export const CHART = {
  L2: "#d03b3b",        // reachable
  L1: "#c98500",        // imported
  L0: "#52525b",        // not reachable: de-emphasised on purpose
  magnitude: "#3987e5", // single-hue bars
} as const;

export function cvssClass(score: number): string {
  return score >= 9 ? "text-red-400" : score >= 7 ? "text-orange-400" : score >= 4 ? "text-amber-400" : "text-muted-foreground";
}
