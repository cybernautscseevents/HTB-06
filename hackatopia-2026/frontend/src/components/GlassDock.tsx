import { useState, type ComponentType } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { History, Home, LayoutDashboard, LogOut } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { signIn } from "../api/client";
import type { AuthState } from "../types";
import { GitHubMark } from "./Header";
import { cn } from "@/lib/utils";

interface DockItem {
  title: string;
  icon: ComponentType<{ className?: string }>;
  href?: string;
  onClick?: () => void;
  avatar?: string | null;
}

const SLOT = 52;   // 40px button + 12px gap: used to slide the tooltip under the hovered item

/** Glass dock in the header: the app's navigation and account. Icons lift on hover and one tooltip slides between them. */
export default function GlassDock({ auth, onSignOut }: { auth: AuthState | null; onSignOut: () => void }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const reduce = useReducedMotion();
  const [hovered, setHovered] = useState<number | null>(null);
  const [direction, setDirection] = useState(0);

  const items: DockItem[] = [
    { title: "Home", icon: Home, href: "/" },
    { title: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
    { title: "History", icon: History, href: "/history" },
  ];
  if (auth?.authenticated && auth.user) {
    items.push({ title: `@${auth.user.login}`, icon: GitHubMark, avatar: auth.user.avatar_url,
                 onClick: () => window.open(auth.user!.html_url ?? "https://github.com", "_blank", "noreferrer") });
    items.push({ title: "Sign out", icon: LogOut, onClick: onSignOut });
  } else if (auth?.oauth_configured) {
    items.push({ title: "Sign in with GitHub", icon: GitHubMark, onClick: signIn });
  }

  const isActive = (item: DockItem) =>
    !!item.href && (item.href === "/" ? pathname === "/" : pathname.startsWith(item.href));

  const enter = (index: number) => {
    if (hovered !== null && index !== hovered) setDirection(index > hovered ? 1 : -1);
    setHovered(index);
  };

  return (
    <nav aria-label="Main">
      <div
        className="relative flex items-center gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-1.5 shadow-lg shadow-black/40 backdrop-blur-xl"
        onMouseLeave={() => { setHovered(null); setDirection(0); }}
      >
        <AnimatePresence>
          {hovered !== null && (
            <motion.div
              initial={{ opacity: 0, scale: 0.92, y: 40 }}
              animate={{ opacity: 1, scale: 1, y: 60, x: hovered * SLOT + 36 }}
              exit={{ opacity: 0, scale: 0.92, y: 40 }}
              transition={reduce ? { duration: 0 } : { type: "spring", stiffness: 160, damping: 20 }}
              className="pointer-events-none absolute left-0 top-0 z-30 -translate-x-1/2"
            >
              <div className="flex min-w-[88px] items-center justify-center rounded-lg border border-neutral-300 bg-white px-4 py-1.5 text-black shadow-md">
                <div className="relative flex h-4 w-full items-center justify-center overflow-hidden">
                  <AnimatePresence mode="popLayout" custom={direction}>
                    <motion.span
                      key={items[hovered].title}
                      initial={{ x: direction > 0 ? 35 : -35, opacity: 0, filter: "blur(6px)" }}
                      animate={{ x: 0, opacity: 1, filter: "blur(0px)" }}
                      exit={{ x: direction > 0 ? -35 : 35, opacity: 0, filter: "blur(6px)" }}
                      transition={{ duration: reduce ? 0 : 0.25, ease: "easeOut" }}
                      className="whitespace-nowrap text-[13px] font-medium tracking-wide"
                    >
                      {items[hovered].title}
                    </motion.span>
                  </AnimatePresence>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {items.map((item, index) => {
          const Icon = item.icon;
          const active = isActive(item);
          const lifted = hovered === index && !reduce;
          return (
            <button
              key={item.title}
              type="button"
              aria-label={item.title}
              aria-current={active ? "page" : undefined}
              onMouseEnter={() => enter(index)}
              onFocus={() => enter(index)}
              onBlur={() => setHovered(null)}
              onClick={() => (item.onClick ? item.onClick() : item.href && navigate(item.href))}
              className={cn(
                "relative flex size-10 items-center justify-center rounded-xl outline-none transition-colors",
                "focus-visible:ring-2 focus-visible:ring-white/60",
                active ? "bg-white/15 text-white" : "text-neutral-400 hover:text-white",
              )}
            >
              <motion.span
                whileTap={{ scale: 0.92 }}
                animate={{ scale: lifted ? 1.15 : 1, y: lifted ? -3 : 0 }}
                transition={{ type: "spring", stiffness: 300, damping: 24 }}
                className="flex items-center justify-center"
              >
                {item.avatar
                  ? <img src={item.avatar} alt="" className="size-7 rounded-full" />
                  : <Icon className="size-5" />}
              </motion.span>
              {active && <span className="absolute -bottom-0.5 size-1 rounded-full bg-white" />}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
