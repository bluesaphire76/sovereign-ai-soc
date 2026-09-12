"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  BarChart3,
  Bot,
  Briefcase,
  Columns3,
  Cpu,
  Database,
  ExternalLink,
  Globe2,
  HeartPulse,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  getNavigationGroups,
  isNavigationItemActive,
  type NavigationIcon,
  type NavigationItem,
} from "@/lib/navigation";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";
import {
  clearAuthSession,
  fetchCurrentUser,
  getStoredUser,
  type AuthUser,
} from "@/lib/auth";
import { EnterpriseIconButton } from "./enterprise";

const GRAFANA_URL =
  process.env.NEXT_PUBLIC_GRAFANA_URL ||
  "https://grafana.varqon.net/grafana/d/ai-soc-platform-health/ai-soc-platform-health?orgId=1&refresh=30s";

const NAVIGATION_ICONS: Record<NavigationIcon, LucideIcon> = {
  activity: Activity,
  bot: Bot,
  briefcase: Briefcase,
  chart: BarChart3,
  columns: Columns3,
  cpu: Cpu,
  database: Database,
  dashboard: LayoutDashboard,
  globe: Globe2,
  health: HeartPulse,
  history: History,
  network: Network,
  shield: Shield,
  "shield-alert": ShieldAlert,
  "shield-check": ShieldCheck,
  users: Users,
};

function NavigationLink({
  item,
  pathname,
  onNavigate,
}: {
  item: NavigationItem;
  pathname: string;
  onNavigate: () => void;
}) {
  const active = isNavigationItemActive(pathname, item);
  const Icon = NAVIGATION_ICONS[item.icon];
  const href = item.external ? GRAFANA_URL : item.href;

  return (
    <Link
      href={href}
      target={item.external ? "_blank" : undefined}
      rel={item.external ? "noreferrer" : undefined}
      aria-current={active ? "page" : undefined}
      onClick={onNavigate}
      className={cx(
        "flex h-8 min-w-0 items-center gap-2 rounded-sm border px-2 text-xs font-medium transition",
        SOC_CONTROL_CLASSES.focus,
        active
          ? "border-cyan-700 bg-cyan-950/70 text-cyan-100"
          : "border-transparent text-slate-300 hover:border-slate-700 hover:bg-slate-900 hover:text-cyan-100"
      )}
    >
      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" strokeWidth={1.75} />
      <span className="min-w-0 flex-1 truncate">{item.label}</span>
      {item.external && (
        <ExternalLink
          aria-label="Opens in a new tab"
          className="h-3 w-3 shrink-0 text-slate-500"
          strokeWidth={1.75}
        />
      )}
    </Link>
  );
}

export default function AppNavigation() {
  const pathname = usePathname();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const groups = useMemo(() => getNavigationGroups(user?.role ?? null), [user?.role]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setUser(getStoredUser());

      fetchCurrentUser()
        .then((current) => setUser(current))
        .catch(() => {
          // authFetch handles expired or invalid sessions globally.
        });
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setMobileOpen(false), 0);
    return () => window.clearTimeout(timer);
  }, [pathname]);

  async function handleLogout() {
    await clearAuthSession();
    window.location.href = "/login";
  }

  return (
    <nav
      aria-label="Primary navigation"
      onKeyDown={(event) => {
        if (event.key === "Escape" && mobileOpen) {
          setMobileOpen(false);
          toggleRef.current?.focus();
        }
      }}
      className="ai-soc-sidebar mx-4 mt-4 overflow-hidden rounded-sm border border-slate-800 bg-slate-950/95 shadow-sm xl:fixed xl:bottom-4 xl:left-4 xl:top-4 xl:z-40 xl:m-0 xl:w-64"
    >
      <div className="flex min-w-0 flex-col xl:h-full">
        <div className="flex min-w-0 items-center gap-2 px-2.5 py-2.5 xl:border-b xl:border-slate-800 xl:py-3">
          <div className="shrink-0 rounded-sm border border-cyan-900/80 bg-slate-950 p-1.5 text-cyan-300">
            <Shield aria-hidden="true" className="h-4 w-4" strokeWidth={1.75} />
          </div>

          <div className="min-w-0 flex-1">
            <div className="truncate text-xs font-semibold uppercase tracking-wide text-slate-100">
              Sovereign AI SOC
            </div>
            <div className="truncate text-[11px] text-slate-500">Local-first operations</div>
          </div>

          <EnterpriseIconButton
            icon={mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
            label={mobileOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={mobileOpen}
            aria-controls="ai-soc-navigation-menu"
            onClick={(event) => {
              toggleRef.current = event.currentTarget;
              setMobileOpen((value) => !value);
            }}
            tone="ghost"
            size="sm"
            className="xl:hidden"
          />
        </div>

        <div
          id="ai-soc-navigation-menu"
          className={cx(
            "min-h-0 flex-col border-t border-slate-800 xl:flex xl:flex-1 xl:border-t-0",
            mobileOpen ? "flex" : "hidden"
          )}
        >
          <div className="min-h-0 space-y-3 overflow-y-auto px-2.5 py-3 xl:flex-1">
            {groups.map((group) => {
              const groupId = `nav-${group.label.replaceAll(/[^a-z]+/gi, "-").toLowerCase()}`;

              return (
                <div key={group.label} role="group" aria-labelledby={groupId}>
                  <h2
                    id={groupId}
                    className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-wide text-slate-600"
                  >
                    {group.label}
                  </h2>
                  <div className="grid gap-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-1">
                    {group.items.map((item) => (
                      <NavigationLink
                        key={item.href}
                        item={item}
                        pathname={pathname}
                        onNavigate={() => setMobileOpen(false)}
                      />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex min-w-0 items-center gap-2 border-t border-slate-800 px-2.5 py-2.5 xl:block">
            {user && (
              <div className="min-w-0 flex-1 px-2 xl:mb-1">
                <div className="truncate text-[11px] text-slate-400">
                  {user.display_name || user.username}
                </div>
                <div className="text-[10px] uppercase tracking-wide text-slate-600">{user.role}</div>
              </div>
            )}

            <button
              type="button"
              onClick={handleLogout}
              className={cx(
                "flex h-8 min-w-0 items-center gap-2 rounded-sm border border-transparent px-2 text-xs font-medium text-slate-300 transition hover:border-slate-700 hover:bg-slate-900 hover:text-slate-100 xl:w-full",
                SOC_CONTROL_CLASSES.focus
              )}
            >
              <LogOut aria-hidden="true" className="h-4 w-4 shrink-0" strokeWidth={1.75} />
              <span className="min-w-0 truncate">Logout</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
