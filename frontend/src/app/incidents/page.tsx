"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  RefreshCw,
  Search,
  ShieldAlert,
  SlidersHorizontal,
} from "lucide-react";
import AppNavigation from "../../components/AppNavigation";
import { authFetch } from "../../lib/auth";

type Incident = {
  id: number;
  timestamp: string | null;
  timestamp_local?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  status: string | null;
  risk_score: number | null;
  recommended_priority?: string | null;
  correlated?: boolean;
  correlation_score?: number | null;
  correlation_type?: string | null;
};

type IncidentsResponse = {
  items: Incident[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

const STATUS_OPTIONS = ["ALL", "NEW", "TRIAGED", "ESCALATED", "CLOSED", "FALSE_POSITIVE"];
const RISK_OPTIONS = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "short",
      timeStyle: "medium",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function riskBand(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "CRITICAL";
  if (value >= 61) return "HIGH";
  if (value >= 31) return "MEDIUM";
  return "LOW";
}

function badgeClass(tone: "neutral" | "success" | "warning" | "danger" | "cyan") {
  const classes = {
    neutral: "border-slate-700 bg-slate-950 text-slate-300",
    success: "border-emerald-700 bg-emerald-950 text-emerald-200",
    warning: "border-orange-700 bg-orange-950 text-orange-200",
    danger: "border-red-800 bg-red-950 text-red-200",
    cyan: "border-cyan-700 bg-cyan-950 text-cyan-200",
  };

  return classes[tone];
}

function riskTone(score: number | null | undefined): "neutral" | "success" | "warning" | "danger" {
  const band = riskBand(score);

  if (band === "CRITICAL") return "danger";
  if (band === "HIGH") return "warning";
  if (band === "MEDIUM") return "cyan" as any;
  return "success";
}

function statusTone(status: string | null | undefined): "neutral" | "success" | "warning" | "danger" | "cyan" {
  const value = (status ?? "NEW").toUpperCase();

  if (value === "ESCALATED") return "danger";
  if (value === "TRIAGED") return "cyan";
  if (value === "CLOSED" || value === "FALSE_POSITIVE") return "success";
  return "warning";
}

function EnterpriseBadge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "neutral" | "success" | "warning" | "danger" | "cyan";
}) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${badgeClass(tone)}`}>
      {children}
    </span>
  );
}

function MetricCard({
  title,
  value,
  description,
  tone = "neutral",
}: {
  title: string;
  value: string | number;
  description: string;
  tone?: "neutral" | "success" | "warning" | "danger" | "cyan";
}) {
  return (
    <div className={`rounded-xl border p-3 shadow-sm ${badgeClass(tone)}`}>
      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </div>
      <div className="mt-2 text-xl font-semibold text-slate-100">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{description}</div>
    </div>
  );
}

export default function IncidentsPage() {
  const [data, setData] = useState<IncidentsResponse | null>(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [searchFilter, setSearchFilter] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const incidents = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 1;

  const highRiskCount = useMemo(
    () => incidents.filter((incident) => (incident.risk_score ?? 0) >= 61).length,
    [incidents]
  );

  const escalatedCount = useMemo(
    () => incidents.filter((incident) => (incident.status ?? "").toUpperCase() === "ESCALATED").length,
    [incidents]
  );

  const correlatedCount = useMemo(
    () => incidents.filter((incident) => incident.correlated).length,
    [incidents]
  );

  const loadIncidents = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const params = new URLSearchParams({
        page: String(page),
        limit: "20",
      });

      if (statusFilter !== "ALL") params.set("status", statusFilter);
      if (riskFilter !== "ALL") params.set("risk", riskFilter.toLowerCase());
      if (searchFilter.trim()) params.set("search", searchFilter.trim());
      if (hostFilter.trim()) params.set("host", hostFilter.trim());

      const response = await authFetch(`/incidents?${params.toString()}`);

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      const payload = (await response.json()) as IncidentsResponse;
      setData(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [hostFilter, page, riskFilter, searchFilter, statusFilter]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  function resetFilters() {
    setStatusFilter("ALL");
    setRiskFilter("ALL");
    setSearchFilter("");
    setHostFilter("");
    setPage(1);
  }

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
              <ShieldAlert className="h-3.5 w-3.5" />
              Incident Operations
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Incidents
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Enterprise incident stream with Wazuh evidence, AI risk scoring,
              correlation context and analyst-ready investigation links.
            </p>
          </div>

          <button
            onClick={loadIncidents}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            {error}
          </div>
        )}

        <div className="space-y-3">
          <section className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              title="Visible incidents"
              value={total}
              description="Matching current filters."
              tone="cyan"
            />
            <MetricCard
              title="High attention"
              value={highRiskCount}
              description="Risk score 61+ on this page."
              tone={highRiskCount > 0 ? "warning" : "success"}
            />
            <MetricCard
              title="Escalated"
              value={escalatedCount}
              description="Escalated incidents on this page."
              tone={escalatedCount > 0 ? "danger" : "success"}
            />
            <MetricCard
              title="Correlated"
              value={correlatedCount}
              description="Incidents linked to patterns."
              tone="neutral"
            />
          </section>

          <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-3 shadow-lg">
            <div className="mb-3 flex flex-col gap-2 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-300">
                  <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-300" />
                  Queue controls
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Filter the active incident stream by status, risk, host and search terms.
                </p>
              </div>

              <button
                onClick={resetFilters}
                className="h-8 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-300 hover:bg-slate-800"
              >
                Reset filters
              </button>
            </div>

            <div className="grid gap-2 md:grid-cols-[160px_160px_1fr_1fr]">
              <label>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                  Status
                </span>
                <select
                  value={statusFilter}
                  onChange={(event) => {
                    setStatusFilter(event.target.value);
                    setPage(1);
                  }}
                  className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                >
                  {STATUS_OPTIONS.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </label>

              <label>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                  Risk
                </span>
                <select
                  value={riskFilter}
                  onChange={(event) => {
                    setRiskFilter(event.target.value);
                    setPage(1);
                  }}
                  className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                >
                  {RISK_OPTIONS.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </label>

              <label>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                  Host
                </span>
                <input
                  value={hostFilter}
                  onChange={(event) => {
                    setHostFilter(event.target.value);
                    setPage(1);
                  }}
                  placeholder="atomicstar, darkstar..."
                  className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                />
              </label>

              <label>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                  Search
                </span>
                <div className="flex h-8 items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-2 focus-within:border-cyan-500">
                  <Search className="h-3.5 w-3.5 text-slate-500" />
                  <input
                    value={searchFilter}
                    onChange={(event) => {
                      setSearchFilter(event.target.value);
                      setPage(1);
                    }}
                    placeholder="Rule, AI text, MITRE, raw alert..."
                    className="h-full w-full bg-transparent text-xs text-slate-100 outline-none"
                  />
                </div>
              </label>
            </div>
          </section>

          <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-3 shadow-lg">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">Incident stream</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Latest Wazuh incidents ordered by timestamp.
                </p>
              </div>

              <EnterpriseBadge tone="neutral">
                Page {data?.page ?? page} / {totalPages}
              </EnterpriseBadge>
            </div>

            {loading ? (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
                Loading incidents...
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="py-2 pr-3">ID</th>
                      <th className="py-2 pr-3">Status</th>
                      <th className="py-2 pr-3">Timestamp</th>
                      <th className="py-2 pr-3">Host</th>
                      <th className="py-2 pr-3">Rule</th>
                      <th className="py-2 pr-3">Level</th>
                      <th className="py-2 pr-3">Risk</th>
                      <th className="py-2 pr-3">Correlation</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/80">
                    {incidents.map((incident) => (
                      <tr key={incident.id} className="hover:bg-slate-800/40">
                        <td className="py-2 pr-3">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="font-medium text-cyan-300 hover:text-cyan-200"
                          >
                            #{incident.id}
                          </Link>
                        </td>
                        <td className="py-2 pr-3">
                          <EnterpriseBadge tone={statusTone(incident.status)}>
                            {incident.status ?? "NEW"}
                          </EnterpriseBadge>
                        </td>
                        <td className="py-2 pr-3 text-slate-400">
                          {incident.timestamp_local ?? formatTimestamp(incident.timestamp)}
                        </td>
                        <td className="py-2 pr-3 text-slate-300">
                          {incident.agent ?? "unknown"}
                        </td>
                        <td className="max-w-[420px] py-2 pr-3">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="line-clamp-2 text-slate-200 hover:text-cyan-200"
                          >
                            {incident.rule ?? "-"}
                          </Link>
                        </td>
                        <td className="py-2 pr-3 text-slate-300">
                          {incident.level ?? 0}
                        </td>
                        <td className="py-2 pr-3">
                          <EnterpriseBadge tone={riskTone(incident.risk_score) as any}>
                            {riskBand(incident.risk_score)} · {incident.risk_score ?? 0}
                          </EnterpriseBadge>
                        </td>
                        <td className="py-2 pr-3">
                          {incident.correlated ? (
                            <EnterpriseBadge tone="cyan">
                              {incident.correlation_score ?? 0} · {incident.correlation_type ?? "correlated"}
                            </EnterpriseBadge>
                          ) : (
                            <span className="text-slate-600">-</span>
                          )}
                        </td>
                      </tr>
                    ))}

                    {incidents.length === 0 && (
                      <tr>
                        <td colSpan={8} className="py-6 text-center text-xs text-slate-500">
                          No incidents found with current filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mt-3 flex items-center justify-between gap-3 border-t border-slate-800 pt-3 text-xs text-slate-500">
              <div>
                {total} incident(s)
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                  disabled={page <= 1}
                  className="h-8 rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Previous
                </button>

                <button
                  onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                  disabled={page >= totalPages}
                  className="h-8 rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
