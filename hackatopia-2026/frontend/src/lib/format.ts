export const repoName = (url: string) => url.replace(/^https:\/\/github\.com\//, "").replace(/\/$/, "");

/** "just now", "5m ago", "3h ago", "2d ago", then a date. Accepts unix seconds or an ISO string. */
export function timeAgo(when: number | string | null | undefined): string {
  if (!when) return "";
  const ms = typeof when === "number" ? when * 1000 : Date.parse(when);
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago`;
  return new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
