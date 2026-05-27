"use client";

import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  FileCog,
  Lock,
  RefreshCw,
  ServerCog,
  Shield,
  SlidersHorizontal,
  XCircle,
} from "lucide-react";

type InventoryItem = {
  id: string;
  name: string;
  type: string;
  source: string;
  scope: string;
  target: string;
  status: string;
  managed: boolean;
  requires_reload: boolean;
  last_seen: string | null;
  description: string;
  reason: string;
  metadata?: Record<string, unknown>;
};

type DetectionControlInventory = {
  summary: {
    total_items: number;
    total_rules: number;
    active_rules: number;
    disabled_rules: number;
    exceptions: number;
    telemetry_sources: number;
    policies: number;
    service_controls: number;
    managed_items: number;
    unmanaged_items: number;
    pending_review: number;
    read_only: boolean;
    generated_at: string;
  };
  rules: InventoryItem[];
  exceptions: InventoryItem[];
  telemetry_sources: InventoryItem[];
  policies: InventoryItem[];
  service_controls: InventoryItem[];
};

type TabKey = "rules" | "exceptions" | "sources" | "policies" | "services";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "rules", label: "Rules" },
  { key: "exceptions", label: "Exceptions" },
  { key: "sources", label: "Sources" },
  { key: "policies", label: "Policies" },
  { key: "services", label: "Service Control" },
];

async function fetchInventory(): Promise<DetectionControlInventory> {
  const response = await authFetch("/settings/detection-control", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }

  return (await response.json()) as DetectionControlInventory;
}

function statusTone(status: string) {
  const normalized = status.toUpperCase();

  if (normalized === "ACTIVE" || normalized === "OK") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if (normalized === "DISABLED" || normalized === "READ_ONLY" || normalized === "EMPTY") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }

  if (normalized === "ERROR") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  return "border-amber-800 bg-amber-950/60 text-amber-200";
}

function sourceTone(source: string) {
  const normalized = source.toLowerCase();

  if (normalized.includes("wazuh")) {
    return "border-cyan-900/80 bg-cyan-950/40 text-cyan-200";
  }

  if (normalized.includes("suricata")) {
    return "border-violet-900/80 bg-violet-950/40 text-violet-200";
  }

  if (normalized.includes("dns")) {
    return "border-sky-900/80 bg-sky-950/40 text-sky-200";
  }

  return "border-slate-700 bg-slate-900 text-slate-300";
}

function formatDate(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "Europe/Zurich",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function metadataPreview(metadata?: Record<string, unknown>) {
  if (!metadata) return "-";

  const entries = Object.entries(metadata)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 4);

  if (entries.length === 0) return "-";

  return entries
    .map(([key, value]) => {
      if (Array.isArray(value)) {
        return `${key}: ${value.length}`;
      }

      if (typeof value === "object") {
        return `${key}: object`;
      }

      return `${key}: ${String(value)}`;
    })
    .join(" · ");
}

export default function DetectionControlPlanePage() {
  const [inventory, setInventory] = useState<DetectionControlInventory | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("rules");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canView =
    currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";

  useEffect(() => {
    setCurrentUser(getStoredUser());

    fetchCurrentUser()
      .then((current) => setCurrentUser(current))
      .catch(() => {
        // authFetch handles expired/invalid sessions globally.
      });
  }, []);

  const loadInventory = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const data = await fetchInventory();
      setInventory(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load detection control inventory");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (currentUser && !canView) {
      setLoading(false);
      setError("Forbidden: Detection Control Plane is available only to ADMIN and ANALYST users.");
      return;
    }

    if (!currentUser) return;

    loadInventory();
  }, [currentUser, canView, loadInventory]);

  const activeItems = useMemo(() => {
    if (!inventory) return [];

    if (activeTab === "rules") return inventory.rules;
    if (activeTab === "exceptions") return inventory.exceptions;
    if (activeTab === "sources") return inventory.telemetry_sources;
    if (activeTab === "policies") return inventory.policies;

    return inventory.service_controls;
  }, [activeTab, inventory]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              ← Dashboard
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <SlidersHorizontal className="h-3.5 w-3.5" />
              Settings
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Detection Control Plane
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Read-only inventory for detection rules, exceptions, telemetry sources,
              internal policies and future service control actions. This foundation does
              not modify Wazuh, Suricata, DNS telemetry, Docker, systemd or runtime files.
            </p>
          </div>

          <button
            onClick={loadInventory}
            disabled={!canView || refreshing}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        <section className="mb-3 rounded-lg border border-cyan-900/70 bg-cyan-950/20 p-3 text-xs text-cyan-100">
          <div className="flex items-start gap-2">
            <Eye className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              <div className="font-semibold">Step 10A read-only foundation</div>
              <p className="mt-1 leading-5 text-cyan-100/80">
                Create, edit, delete, reload and restart actions are intentionally disabled.
                This page exists to restore operational visibility before enabling governed
                lifecycle management in a later step.
              </p>
            </div>
          </div>
        </section>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading detection control inventory...
          </section>
        ) : inventory && canView ? (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-6">
              <MetricCard
                title="Inventory"
                value={inventory.summary.total_items}
                subtitle="Total governed items"
                icon={<FileCog className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Rules"
                value={inventory.summary.total_rules}
                subtitle={`${inventory.summary.active_rules} active`}
                icon={<Shield className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Exceptions"
                value={inventory.summary.exceptions}
                subtitle="Noise / contextual logic"
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Sources"
                value={inventory.summary.telemetry_sources}
                subtitle="Telemetry paths"
                icon={<ServerCog className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Policies"
                value={inventory.summary.policies}
                subtitle="Internal decision policy"
                icon={<SlidersHorizontal className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Mode"
                value={inventory.summary.read_only ? "Read-only" : "Mutable"}
                subtitle={formatDate(inventory.summary.generated_at)}
                icon={<Lock className="h-3.5 w-3.5" />}
              />
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-2">
              <div className="mb-2 flex flex-wrap gap-1.5">
                {TABS.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition ${
                      activeTab === tab.key
                        ? "border-cyan-500 bg-cyan-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-600 hover:text-cyan-200"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {activeTab === "services" && (
                <div className="mb-2 rounded-lg border border-amber-900/70 bg-amber-950/30 p-3 text-xs text-amber-100">
                  <div className="flex items-start gap-2">
                    <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <p className="leading-5">
                      Service reload/restart actions are not enabled in Step 10A.
                      Future actions must use backend allowlists, validation, audit logging
                      and explicit confirmation.
                    </p>
                  </div>
                </div>
              )}

              <InventoryTable items={activeItems} />
            </section>
          </div>
        ) : null}
      </div>
    </main>
  );
}

function MetricCard({
  title,
  value,
  subtitle,
  icon,
}: {
  title: string;
  value: ReactNode;
  subtitle: string;
  icon: ReactNode;
}) {
  return (
    <article className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="text-slate-400">{icon}</div>
      </div>
      <div className="text-lg font-semibold text-slate-100">{value}</div>
      <div className="mt-1 text-[11px] text-slate-500">{subtitle}</div>
    </article>
  );
}

function InventoryTable({ items }: { items: InventoryItem[] }) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No inventory items found for this section.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Scope / Target</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Managed</th>
              <th className="px-3 py-2">Reload</th>
              <th className="px-3 py-2">Metadata</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {items.map((item) => (
              <tr key={item.id} className="align-top hover:bg-slate-800/40">
                <td className="max-w-sm px-3 py-2">
                  <div className="font-medium text-slate-100">{item.name}</div>
                  <div className="mt-1 leading-5 text-slate-500">{item.description}</div>
                  <div className="mt-1 leading-5 text-slate-600">{item.reason}</div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${sourceTone(item.source)}`}>
                    {item.source}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-300">{item.type}</td>
                <td className="px-3 py-2">
                  <div className="text-slate-300">{item.scope}</div>
                  <div className="mt-1 max-w-xs truncate text-slate-500" title={item.target}>
                    {item.target}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(item.status)}`}>
                    {item.status}
                  </span>
                </td>
                <td className="px-3 py-2">
                  {item.managed ? (
                    <span className="inline-flex items-center gap-1 text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      yes
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-slate-500">
                      <XCircle className="h-3.5 w-3.5" />
                      no
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-300">
                  {item.requires_reload ? "required" : "no"}
                </td>
                <td className="max-w-xs px-3 py-2 text-slate-500">
                  {metadataPreview(item.metadata)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
