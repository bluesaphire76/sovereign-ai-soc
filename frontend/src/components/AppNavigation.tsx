"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  BarChart3,
  Briefcase,
  ChevronDown,
  Columns3,
  Cpu,
  Globe2,
  HeartPulse,
  History,
  Info,
  LayoutDashboard,
  LogOut,
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Users,
} from "lucide-react";
import {
  clearAuthSession,
  fetchCurrentUser,
  getStoredUser,
  type AuthUser,
} from "../lib/auth";

const GRAFANA_URL =
  process.env.NEXT_PUBLIC_GRAFANA_URL ||
  "http://127.0.0.1:3002/grafana/d/ai-soc-platform-health/ai-soc-platform-health?orgId=1&refresh=30s";

type NavItem = {
  href: string;
  label: string;
  icon: React.ReactNode;
  match: "exact" | "prefix" | "cases";
  external?: boolean;
};

const NAV_ITEMS: NavItem[] = [
  {
    href: "/",
    label: "Dashboard",
    icon: <LayoutDashboard className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "exact",
  },
  {
    href: "/incidents",
    label: "Incidents",
    icon: <ShieldAlert className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
  {
    href: "/cases",
    label: "Case Queue",
    icon: <Briefcase className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "cases",
  },
  {
    href: "/cases/kanban",
    label: "Kanban",
    icon: <Columns3 className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
  {
    href: "/executive",
    label: "Executive",
    icon: <BarChart3 className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
  {
    href: "/detection-quality",
    label: "Detection Quality",
    icon: <Shield className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
  {
    href: "/network-events",
    label: "Network Activity",
    icon: <Network className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
  {
    href: "/dns-telemetry",
    label: "DNS Telemetry",
    icon: <Globe2 className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "exact",
  },
  {
    href: "/health",
    label: "Health",
    icon: <HeartPulse className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
];

const SETTINGS_ITEMS: NavItem[] = [
  {
    href: "/settings/detection-control",
    label: "Detection Control Plane",
    icon: <ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
  {
    href: "/settings/ai-providers",
    label: "AI Providers",
    icon: <Cpu className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
];

const SYSTEM_INFORMATION_ITEMS: NavItem[] = [
  {
    href: "/system-information/operation-history",
    label: "Operation History",
    icon: <History className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
];

const SYSTEM_INFORMATION_ADMIN_ITEMS: NavItem[] = [
  {
    href: "/system-information/security-audit",
    label: "Security Audit",
    icon: <ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.75} />,
    match: "prefix",
  },
];

function isActive(pathname: string, item: NavItem) {
  if (item.external) {
    return false;
  }

  if (item.match === "exact") {
    return pathname === item.href;
  }

  if (item.match === "cases") {
    return (
      pathname === "/cases" ||
      (pathname.startsWith("/cases/") && !pathname.startsWith("/cases/kanban"))
    );
  }

  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}

function NavLink({
  item,
  pathname,
  nested = false,
}: {
  item: NavItem;
  pathname: string;
  nested?: boolean;
}) {
  const active = isActive(pathname, item);

  return (
    <Link
      href={item.href}
      target={item.external ? "_blank" : undefined}
      rel={item.external ? "noreferrer" : undefined}
      className={`flex h-8 min-w-0 items-center gap-1.5 rounded-sm border text-xs font-medium transition ${
        nested ? "w-full px-2 py-1 pl-3 text-[11px]" : "w-full px-2.5"
      } ${
        active
          ? "border-cyan-500 bg-cyan-500 text-slate-950"
          : "border-transparent bg-transparent text-slate-300 hover:border-slate-700 hover:bg-slate-900 hover:text-cyan-200"
      }`}
    >
      <span className="shrink-0">{item.icon}</span>
      <span className="min-w-0 truncate">{item.label}</span>
    </Link>
  );
}

export default function AppNavigation() {
  const pathname = usePathname();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(pathname.startsWith("/settings"));
  const [systemInfoOpen, setSystemInfoOpen] = useState(
    pathname.startsWith("/system-information")
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setUser(getStoredUser());

      fetchCurrentUser()
        .then((current) => setUser(current))
        .catch(() => {
          // authFetch handles expired/invalid sessions globally.
        });
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (pathname.startsWith("/settings")) {
        setSettingsOpen(true);
      }

      if (pathname.startsWith("/system-information")) {
        setSystemInfoOpen(true);
      }
    }, 0);

    return () => window.clearTimeout(timer);
  }, [pathname]);

  async function handleLogout() {
    await clearAuthSession();
    window.location.href = "/login";
  }

  const canUseSettings =
    user?.role === "ADMIN" || user?.role === "ANALYST" || user?.role === "VIEWER";
  const settingsActive = pathname.startsWith("/settings");
  const canUseSystemInformation =
    user?.role === "ADMIN" || user?.role === "ANALYST" || user?.role === "VIEWER";
  const systemInfoActive = pathname.startsWith("/system-information");
  const systemInformationItems = [
    ...(user?.role === "ADMIN" ? SYSTEM_INFORMATION_ADMIN_ITEMS : []),
    ...SYSTEM_INFORMATION_ITEMS,
  ];

  const navItems: NavItem[] = user
    ? [
        ...NAV_ITEMS,
        ...(user.role === "ADMIN" || user.role === "ANALYST"
          ? [
              {
                href: GRAFANA_URL,
                label: "Observability",
                icon: <Activity className="h-3.5 w-3.5" strokeWidth={1.75} />,
                match: "exact" as const,
                external: true,
              },
            ]
          : []),
        {
          href: "/admin/users",
          label: "Users",
          icon: <Users className="h-3.5 w-3.5" strokeWidth={1.75} />,
          match: "prefix",
        },
      ]
    : NAV_ITEMS;

  return (
    <nav className="ai-soc-sidebar mb-5 overflow-hidden rounded-sm border border-slate-800 bg-slate-950/95 px-2.5 py-2 shadow-sm xl:fixed xl:bottom-4 xl:left-4 xl:top-4 xl:z-40 xl:mb-0 xl:w-64 xl:px-2.5 xl:py-3">
      <div className="flex min-w-0 flex-col gap-3 xl:h-full">
        <div className="flex min-w-0 items-center gap-2 border-slate-800 xl:border-b xl:pb-3">
          <div className="shrink-0 rounded-sm border border-cyan-900/80 bg-slate-950 p-1.5 text-cyan-300">
            <Shield className="h-3.5 w-3.5" strokeWidth={1.75} />
          </div>

          <div className="min-w-0">
            <div className="truncate text-xs font-semibold uppercase tracking-wide text-slate-100">
              Sovereign AI SOC
            </div>
            <div className="truncate text-[11px] text-slate-500">
              Local-first SOC case management
            </div>
          </div>
        </div>

        <div className="flex min-w-0 flex-wrap items-center gap-1.5 xl:flex-1 xl:flex-col xl:items-stretch xl:gap-1.5">
          {navItems.map((item) => (
            <NavLink key={item.href} item={item} pathname={pathname} />
          ))}

          {canUseSettings && (
            <div className="flex w-full min-w-0 flex-col gap-1">
              <button
                type="button"
                onClick={() => setSettingsOpen((value) => !value)}
                className={`flex h-8 w-full min-w-0 items-center gap-1.5 rounded-sm border px-2.5 text-xs font-medium transition ${
                  settingsActive
                    ? "border-slate-700 bg-slate-900 text-cyan-200"
                    : "border-transparent bg-transparent text-slate-300 hover:border-slate-700 hover:bg-slate-900 hover:text-cyan-200"
                }`}
              >
                <SlidersHorizontal className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} />
                <span className="min-w-0 truncate">Settings</span>
                <ChevronDown
                  className={`ml-auto h-3.5 w-3.5 shrink-0 transition ${
                    settingsOpen ? "rotate-180" : ""
                  }`}
                  strokeWidth={1.75}
                />
              </button>

              {settingsOpen && (
                <div className="w-full min-w-0 border-l border-slate-800 pl-2">
                  <div className="flex w-full min-w-0 flex-col gap-1">
                    {SETTINGS_ITEMS.map((item) => (
                      <NavLink
                        key={item.href}
                        item={item}
                        pathname={pathname}
                        nested
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {canUseSystemInformation && (
            <div className="flex w-full min-w-0 flex-col gap-1">
              <button
                type="button"
                onClick={() => setSystemInfoOpen((value) => !value)}
                className={`flex h-8 w-full min-w-0 items-center gap-1.5 rounded-sm border px-2.5 text-xs font-medium transition ${
                  systemInfoActive
                    ? "border-slate-700 bg-slate-900 text-cyan-200"
                    : "border-transparent bg-transparent text-slate-300 hover:border-slate-700 hover:bg-slate-900 hover:text-cyan-200"
                }`}
              >
                <Info className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} />
                <span className="min-w-0 truncate">System Information</span>
                <ChevronDown
                  className={`ml-auto h-3.5 w-3.5 shrink-0 transition ${
                    systemInfoOpen ? "rotate-180" : ""
                  }`}
                  strokeWidth={1.75}
                />
              </button>

              {systemInfoOpen && (
                <div className="w-full min-w-0 border-l border-slate-800 pl-2">
                  <div className="flex w-full min-w-0 flex-col gap-1">
                    {systemInformationItems.map((item) => (
                      <NavLink
                        key={item.href}
                        item={item}
                        pathname={pathname}
                        nested
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex min-w-0 flex-wrap items-center gap-1.5 border-slate-800 xl:flex-col xl:items-stretch xl:border-t xl:pt-3">
          {user && (
            <div className="max-w-full truncate px-2 text-[11px] text-slate-500">
              {user.display_name || user.username}
            </div>
          )}

          <button
            onClick={handleLogout}
            className="flex h-8 w-full min-w-0 items-center gap-1.5 rounded-sm border border-transparent bg-transparent px-2.5 text-xs font-medium text-slate-300 transition hover:border-slate-700 hover:bg-slate-900 hover:text-slate-100"
          >
            <LogOut className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} />
            <span className="min-w-0 truncate">Logout</span>
          </button>
        </div>
      </div>
    </nav>
  );
}
