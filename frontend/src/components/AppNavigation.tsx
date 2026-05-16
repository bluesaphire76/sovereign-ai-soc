"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3,
  Briefcase,
  Columns3,
  HeartPulse,
  LayoutDashboard,
  LogOut,
  Shield,
  Users,
} from "lucide-react";
import {
  clearAuthSession,
  getStoredUser,
  type AuthUser,
} from "../lib/auth";

type NavItem = {
  href: string;
  label: string;
  icon: React.ReactNode;
  match: "exact" | "prefix" | "cases";
};

const NAV_ITEMS: NavItem[] = [
  {
    href: "/",
    label: "Dashboard",
    icon: <LayoutDashboard className="h-3.5 w-3.5" />,
    match: "exact",
  },
  {
    href: "/cases",
    label: "Case Queue",
    icon: <Briefcase className="h-3.5 w-3.5" />,
    match: "cases",
  },
  {
    href: "/cases/kanban",
    label: "Kanban",
    icon: <Columns3 className="h-3.5 w-3.5" />,
    match: "prefix",
  },
  {
    href: "/executive",
    label: "Executive",
    icon: <BarChart3 className="h-3.5 w-3.5" />,
    match: "prefix",
  },
  {
    href: "/detection-quality",
    label: "Detection Quality",
    icon: <Shield className="h-3.5 w-3.5" />,
    match: "prefix",
  },
  {
    href: "/health",
    label: "Health",
    icon: <HeartPulse className="h-3.5 w-3.5" />,
    match: "prefix",
  },
];

function isActive(pathname: string, item: NavItem) {
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

export default function AppNavigation() {
  const pathname = usePathname();
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    setUser(getStoredUser());
  }, []);

  async function handleLogout() {
    await clearAuthSession();
    window.location.href = "/login";
  }

  const navItems: NavItem[] = user
    ? [
        ...NAV_ITEMS,
        {
          href: "/admin/users",
          label: "Users",
          icon: <Users className="h-3.5 w-3.5" />,
          match: "prefix",
        },
      ]
    : NAV_ITEMS;

  return (
    <nav className="mb-5 rounded-xl border border-slate-800 bg-slate-900/95 px-3 py-2 shadow-lg">
      <div className="flex flex-col gap-2 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-center gap-2">
          <div className="rounded-lg border border-cyan-900 bg-cyan-950 p-1.5 text-cyan-300">
            <Shield className="h-3.5 w-3.5" />
          </div>

          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-100">
              Sovereign AI SOC
            </div>
            <div className="text-[11px] text-slate-500">
              Local-first SOC case management
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {navItems.map((item) => {
            const active = isActive(pathname, item);

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-medium transition ${
                  active
                    ? "border-cyan-500 bg-cyan-500 text-slate-950"
                    : "border-slate-700 bg-slate-950 text-slate-300 hover:border-cyan-800 hover:bg-slate-800 hover:text-cyan-200"
                }`}
              >
                {item.icon}
                {item.label}
              </Link>
            );
          })}

          {user && (
            <div className="hidden max-w-[180px] truncate px-2 text-[11px] text-slate-500 xl:block">
              {user.display_name || user.username}
            </div>
          )}

          <button
            onClick={handleLogout}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-2.5 text-xs font-medium text-slate-300 transition hover:bg-slate-800 hover:text-slate-100"
          >
            <LogOut className="h-3.5 w-3.5" />
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
}
