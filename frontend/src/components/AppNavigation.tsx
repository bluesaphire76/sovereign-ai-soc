"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3,
  Briefcase,
  HeartPulse,
  LayoutDashboard,
  LogOut,
  Shield,
  Columns3,
} from "lucide-react";

type NavItem = {
  href: string;
  label: string;
  icon: React.ReactNode;
  match: "exact" | "prefix";
};

const NAV_ITEMS: NavItem[] = [
  {
    href: "/",
    label: "Dashboard",
    icon: <LayoutDashboard className="h-4 w-4" />,
    match: "exact",
  },
  {
    href: "/cases",
    label: "Case Queue",
    icon: <Briefcase className="h-4 w-4" />,
    match: "exact",
  },
  {
    href: "/cases/kanban",
    label: "Kanban",
    icon: <Columns3 className="h-4 w-4" />,
    match: "prefix",
  },
  {
    href: "/executive",
    label: "Executive",
    icon: <BarChart3 className="h-4 w-4" />,
    match: "prefix",
  },
  {
    href: "/detection-quality",
    label: "Detection Quality",
    icon: <Shield className="h-4 w-4" />,
    match: "prefix",
  },
  {
    href: "/health",
    label: "Health",
    icon: <HeartPulse className="h-4 w-4" />,
    match: "prefix",
  },
];

function isActive(pathname: string, item: NavItem) {
  if (item.match === "exact") {
    return pathname === item.href;
  }

  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}

export default function AppNavigation() {
  const pathname = usePathname();

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  }

  return (
    <nav className="mb-8 rounded-2xl border border-slate-800 bg-slate-900/90 p-3 shadow-lg">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-center gap-3 px-2">
          <div className="rounded-xl border border-cyan-800 bg-cyan-950 p-2 text-cyan-300">
            <Shield className="h-4 w-4" />
          </div>

          <div>
            <div className="text-sm font-semibold text-slate-100">
              Sovereign AI SOC
            </div>
            <div className="text-xs text-slate-500">
              Local-first SOC case management assistant
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {NAV_ITEMS.map((item) => {
            const active = isActive(pathname, item);

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm transition ${
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

          <button
            onClick={handleLogout}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-300 transition hover:bg-slate-800 hover:text-slate-100"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
}
