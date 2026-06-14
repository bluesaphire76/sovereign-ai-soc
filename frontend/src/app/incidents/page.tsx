"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ChevronRight,
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

type Tone = "neutral" | "success" | "warning" | "danger" | "cyan";
type SeverityBand = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const STATUS_OPTIONS = [
  "ALL",
  "NEW",
  "TRIAGED",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "CLOSED",
  "FALSE_POSITIVE",
  "ESCALATED",
];

const RISK_OPTIONS = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const DEMO_SEARCH_TERM = "AI SOC demo scenario";

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "short",
      timeStyle: "short",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function riskBand(score: number | null | undefined): SeverityBand {
  const value = score ?? 0;

  if (value >= 80) return "CRITICAL";
  if (value >= 60) return "HIGH";
  if (value >= 40) return "MEDIUM";
  return "LOW";
}

function riskTone(score: number | null | undefined): Tone {
  const band = riskBand(score);

  if (band === "CRITICAL") return "danger";
  if (band === "HIGH") return "warning";
  if (band === "MEDIUM") return "cyan";
  return "success";
}

function statusTone(status: string | null | undefined): Tone {
  const value = (status ?? "NEW").toUpperCase();

  if (value === "ESCALATED") return "danger";
  if (value === "TRIAGED" || value === "INVESTIGATING") return "cyan";
  if (value === "CONTAINED") return "warning";
  if (value === "RESOLVED" || value === "CLOSED" || value === "FALSE_POSITIVE") return "success";
  return "warning";
}

function isDemoIncident(incident: Incident) {
  return (incident.rule ?? "").includes(DEMO_SEARCH_TERM);
}

function badgeClass(tone: Tone) {
  const classes: Record<Tone, string> = {
    neutral: "border-slate-700 bg-slate-950 text-slate-300",
    success: "border-emerald-800 bg-emerald-950/50 text-emerald-300",
    warning: "border-orange-800 bg-orange-950/50 text-orange-300",
    danger: "border-red-800 bg-red-950/50 text-red-300",
    cyan: "border-cyan-800 bg-cyan-950/50 text-cyan-300",
  };

  return classes[tone];
}

function severityDotClass(score: number | null | undefined) {
  const band = riskBand(score);

  if (band === "CRITICAL") return "bg-red-500";
  if (band === "HIGH") return "bg-orange-500";
  if (band === "MEDIUM") return "bg-cyan-500";
  return "bg-emerald-500";
}

function severityTextClass(score: number | null | undefined) {
  const band = riskBand(score);

  if (band === "CRITICAL") return "text-red-300";
  if (band === "HIGH") return "text-orange-300";
  if (band === "MEDIUM") return "text-cyan-300";
  return "text-emerald-300";
}

function TinyBadge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: Tone;
}) {
  return (
    <span
      className={`inline-flex h-[18px] min-w-[58px] max-w-[104px] items-center justify-center whitespace-nowrap border px-1.5 text-center text-[10px] font-semibold uppercase leading-none tracking-wide ${badgeClass(tone)}`}
    >
      {children}
    </span>
  );
}

function Counter({
  label,
  value,
  helper,
  tone = "neutral",
}: {
  label: string;
  value: number | string;
  helper: string;
  tone?: Tone;
}) {
  const cardClass: Record<Tone, string> = {
    neutral: "border-slate-800 bg-slate-900 text-slate-100",
    success: "border-emerald-900 bg-emerald-950/30 text-emerald-100",
    warning: "border-orange-900 bg-orange-950/30 text-orange-100",
    danger: "border-red-900 bg-red-950/30 text-red-100",
    cyan: "border-cyan-900 bg-cyan-950/30 text-cyan-100",
  };

  return (
    <div
      className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${cardClass[tone]}`}
    >
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {label}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
          <span className="text-xl font-semibold leading-6">{value}</span>
          <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500">
            {helper}
          </span>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-3 border-b border-slate-900 px-3 py-2 last:border-b-0">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
        {label}
      </dt>
      <dd className="min-w-0 text-xs text-slate-300">{value}</dd>
    </div>
  );
}

function decisionLabel(incident: Incident | null) {
  if (!incident) return "No incident selected";
  if ((incident.risk_score ?? 0) >= 80) return "Containment review";
  if ((incident.risk_score ?? 0) >= 60 || incident.correlated) return "Investigation required";
  if ((incident.level ?? 0) >= 8) return "Manual triage";
  return "Observation / classify";
}

function riskRationale(incident: Incident | null) {
  if (!incident) return "No incident selected.";

  const score = incident.risk_score ?? 0;
  const level = incident.level ?? 0;
  const correlated = incident.correlated;

  if (score >= 80) {
    return "Risk is in the critical band. Treat this as a candidate for immediate containment review, especially if the source host is production-relevant.";
  }

  if (score >= 60) {
    return correlated
      ? "Risk is high and the signal is correlated with a pattern. Prioritize investigation and check whether it belongs to an existing case."
      : "Risk is high even without correlation. Validate evidence before escalation, then decide whether to open or attach a case.";
  }

  if (correlated) {
    return "The individual risk score is not high, but correlation is present. Review the pattern before dismissing the alert as noise.";
  }

  if (level >= 8) {
    return "The Wazuh level is elevated. The event may still be benign, but it deserves manual triage before classification.";
  }

  return "Current indicators suggest a low-priority signal. Validate context and classify as observed, benign or false positive if appropriate.";
}

function investigationQuestions(incident: Incident | null) {
  if (!incident) return [];

  const questions = [
    "Is the source host expected to generate this type of event?",
    "Does the rule represent user activity, service activity, or suspicious behavior?",
  ];

  if (incident.correlated) {
    questions.push("Do related alerts indicate a repeated pattern or attack chain?");
  } else {
    questions.push("Is this a single isolated alert or the first signal of a repeated pattern?");
  }

  if ((incident.risk_score ?? 0) >= 60) {
    questions.push("Is there enough evidence to escalate this into an investigation case?");
  } else {
    questions.push("Can this be safely classified as observed, benign or false positive?");
  }

  return questions;
}

function paginationWindow(currentPage: number, totalPageCount: number) {
  const safeTotal = Math.max(1, totalPageCount);
  const safeCurrent = Math.min(Math.max(1, currentPage), safeTotal);
  const windowSize = Math.min(5, safeTotal);
  const start = Math.max(1, Math.min(safeCurrent - 2, safeTotal - windowSize + 1));

  return Array.from({ length: windowSize }, (_, index) => start + index);
}

export default function IncidentsPage() {
  const [data, setData] = useState<IncidentsResponse | null>(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [searchFilter, setSearchFilter] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [page, setPage] = useState(1);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const incidents = useMemo(() => data?.items ?? [], [data]);
  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 1;
  const demoMode = searchFilter.trim() === DEMO_SEARCH_TERM;

  const selectedIncident = useMemo(() => {
    if (incidents.length === 0) return null;
    return incidents.find((incident) => incident.id === selectedIncidentId) ?? incidents[0];
  }, [incidents, selectedIncidentId]);

  const highRiskCount = useMemo(
    () => incidents.filter((incident) => (incident.risk_score ?? 0) >= 60).length,
    [incidents]
  );

  const activeLifecycleCount = useMemo(
    () =>
      incidents.filter((incident) =>
        ["INVESTIGATING", "CONTAINED", "ESCALATED"].includes(
          (incident.status ?? "").toUpperCase()
        )
      ).length,
    [incidents]
  );

  const correlatedCount = useMemo(
    () => incidents.filter((incident) => incident.correlated).length,
    [incidents]
  );

  const demoIncidentCount = useMemo(
    () => incidents.filter(isDemoIncident).length,
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
    const timer = window.setTimeout(() => {
      void loadIncidents();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadIncidents]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!selectedIncidentId && incidents.length > 0) {
        setSelectedIncidentId(incidents[0].id);
      }
    }, 0);

    return () => window.clearTimeout(timer);
  }, [incidents, selectedIncidentId]);

  function resetFilters() {
    setStatusFilter("ALL");
    setRiskFilter("ALL");
    setSearchFilter("");
    setHostFilter("");
    setPage(1);
  }

  function enableDemoMode() {
    setStatusFilter("ALL");
    setRiskFilter("ALL");
    setSearchFilter(DEMO_SEARCH_TERM);
    setHostFilter("");
    setPage(1);
  }

  function exitDemoMode() {
    setSearchFilter("");
    setPage(1);
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1900px] px-4 py-4">
        <AppNavigation />

        <div className="border border-slate-800 bg-slate-950">
          <header className="border-b border-slate-800 bg-slate-950 px-4 py-3">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div className="min-w-0">
                <Link
                  href="/"
                  className="mb-1 inline-flex text-[11px] font-medium uppercase tracking-wide text-slate-500 hover:text-cyan-300"
                >
                  ← Dashboard
                </Link>

                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-cyan-300" strokeWidth={1.75} />
                  <h1 className="text-xl font-semibold tracking-tight text-slate-100">
                    Incidents
                  </h1>
                  <span className="text-xs text-slate-500">
                    Enterprise incident queue
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={demoMode ? exitDemoMode : enableDemoMode}
                  className={`h-8 border px-3 text-xs font-medium ${
                    demoMode
                      ? "border-cyan-500 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
                      : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-600 hover:bg-slate-900"
                  }`}
                >
                  {demoMode ? "Exit demo mode" : "Demo mode"}
                </button>

                <button
                  onClick={loadIncidents}
                  className="inline-flex h-8 items-center gap-1.5 border border-slate-700 bg-slate-950 px-3 text-xs font-medium text-slate-300 hover:bg-slate-900"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} strokeWidth={1.75} />
                  Refresh
                </button>
              </div>
            </div>
          </header>

          <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-5">
            <Counter label="Visible incidents" value={total} helper="Matching current filters" tone="cyan" />
            <Counter label="High attention" value={highRiskCount} helper="Risk score 60+ on this page" tone={highRiskCount > 0 ? "warning" : "success"} />
            <Counter label="Active lifecycle" value={activeLifecycleCount} helper="Investigating, contained or legacy escalated" tone={activeLifecycleCount > 0 ? "warning" : "success"} />
            <Counter label="Correlated" value={correlatedCount} helper="Incidents linked to patterns" tone="cyan" />
            <Counter label="Demo scenarios" value={demoIncidentCount} helper={demoMode ? "Demo filter active" : "Demo filter off"} tone={demoMode ? "cyan" : "neutral"} />
          </section>

          <section className="border-b border-slate-800 bg-slate-950 px-3 py-2">
            <div className="grid gap-2 xl:grid-cols-[auto_150px_150px_180px_minmax(320px,1fr)_auto_auto] xl:items-center">
              <div className="hidden items-center gap-2 pr-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500 xl:flex">
                <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-300" strokeWidth={1.75} />
                Filter
              </div>

              <select
                value={statusFilter}
                onChange={(event) => {
                  setStatusFilter(event.target.value);
                  setPage(1);
                }}
                className="h-8 border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                aria-label="Status filter"
              >
                {STATUS_OPTIONS.map((item) => (
                  <option key={item} value={item}>
                    Status: {item}
                  </option>
                ))}
              </select>

              <select
                value={riskFilter}
                onChange={(event) => {
                  setRiskFilter(event.target.value);
                  setPage(1);
                }}
                className="h-8 border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                aria-label="Risk filter"
              >
                {RISK_OPTIONS.map((item) => (
                  <option key={item} value={item}>
                    Risk: {item}
                  </option>
                ))}
              </select>

              <input
                value={hostFilter}
                onChange={(event) => {
                  setHostFilter(event.target.value);
                  setPage(1);
                }}
                placeholder="Host"
                className="h-8 border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
              />

              <div className="flex h-8 items-center gap-2 border border-slate-700 bg-slate-950 px-2 focus-within:border-cyan-500">
                <Search className="h-3.5 w-3.5 shrink-0 text-slate-500" strokeWidth={1.75} />
                <input
                  value={searchFilter}
                  onChange={(event) => {
                    setSearchFilter(event.target.value);
                    setPage(1);
                  }}
                  placeholder="Search rule, AI text, MITRE, raw alert..."
                  className="h-full w-full bg-transparent text-xs text-slate-100 outline-none"
                />
              </div>

              <button
                onClick={enableDemoMode}
                className="h-8 border border-cyan-800 bg-cyan-950 px-3 text-xs font-medium text-cyan-100 hover:bg-cyan-900"
              >
                Demo
              </button>

              <button
                onClick={resetFilters}
                className="h-8 border border-slate-700 bg-slate-950 px-3 text-xs font-medium text-slate-300 hover:bg-slate-900"
              >
                Reset
              </button>
            </div>
          </section>

          {error && (
            <div className="m-3 flex items-center gap-2 border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-200">
              <AlertTriangle className="h-3.5 w-3.5" strokeWidth={1.75} />
              {error}
            </div>
          )}

          <section className="grid min-h-[660px] xl:grid-cols-[minmax(0,1fr)_420px]">
            <div className="min-w-0 border-r border-slate-800">
              <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-3 py-2">
                <div>
                  <h2 className="text-[12px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                    Incident grid
                  </h2>
                  <p className="text-[11px] text-slate-500">
                    Select a row to inspect the summary pane. Open detail for the full workflow.
                  </p>
                </div>

                <span className="text-[11px] text-slate-500">
                  {data?.limit ?? 20} rows per page
                </span>
              </div>

              {loading ? (
                <div className="p-4 text-xs text-slate-500">Loading incidents...</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[1040px] table-fixed border-collapse text-left text-[12px]">
                    <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-[0.16em] text-slate-500">
                      <tr>
                        <th className="w-8 px-2 py-2"></th>
                        <th className="w-3 px-0 py-2"></th>
                        <th className="w-[76px] px-2 py-2 font-semibold">ID</th>
                        <th className="w-[116px] px-2 py-2 font-semibold">Severity</th>
                        <th className="w-[112px] px-2 py-2 font-semibold">Status</th>
                        <th className="w-[330px] px-2 py-2 font-semibold">Signal</th>
                        <th className="w-[130px] px-2 py-2 font-semibold">Host</th>
                        <th className="w-[92px] px-2 py-2 font-semibold">Pattern</th>
                        <th className="w-[130px] px-2 py-2 font-semibold">Created</th>
                        <th className="w-8 px-2 py-2"></th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-900">
                      {incidents.map((incident) => {
                        const selected = selectedIncident?.id === incident.id;
                        const band = riskBand(incident.risk_score);
                        const score = incident.risk_score ?? 0;

                        return (
                          <tr
                            key={incident.id}
                            onClick={() => setSelectedIncidentId(incident.id)}
                            className={`cursor-pointer ${
                              selected
                                ? "bg-cyan-950/20"
                                : isDemoIncident(incident)
                                  ? "bg-cyan-950/5 hover:bg-cyan-950/10"
                                  : "hover:bg-slate-900/70"
                            }`}
                          >
                            <td className="px-2 py-1.5 align-middle">
                              <input
                                type="checkbox"
                                checked={selected}
                                onChange={() => setSelectedIncidentId(incident.id)}
                                aria-label={`Select incident ${incident.id}`}
                                className="h-3.5 w-3.5 accent-cyan-500"
                              />
                            </td>

                            <td className="px-0 py-1.5 align-middle">
                              <span className={`block h-7 w-1 ${severityDotClass(incident.risk_score)}`} />
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <Link
                                href={`/incidents/${incident.id}`}
                                onClick={(event) => event.stopPropagation()}
                                className="font-mono text-[12px] font-semibold tabular-nums text-cyan-300 hover:text-cyan-200"
                              >
                                #{incident.id}
                              </Link>
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <div className="flex items-center gap-1.5">
                                <span className={`h-2 w-2 ${severityDotClass(incident.risk_score)}`} />
                                <span className={`text-[11px] font-semibold uppercase ${severityTextClass(incident.risk_score)}`}>
                                  {band}
                                </span>
                                <span className="border border-slate-600 bg-slate-800 px-1 font-mono text-[10px] font-semibold text-white">
                                  {score}
                                </span>
                              </div>
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <TinyBadge tone={statusTone(incident.status)}>
                                {incident.status ?? "NEW"}
                              </TinyBadge>
                            </td>

                            <td className="w-[330px] px-2 py-1.5 align-top">
                              <div className="flex min-w-0 items-start gap-2">
                                <div className="min-w-0">
                                  <div className="line-clamp-1 max-w-[310px] text-[12px] leading-5 text-slate-200">
                                    {incident.rule ?? "-"}
                                  </div>
                                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                                    <span className="font-mono text-[10px] uppercase tracking-wide text-slate-600">
                                      Level {incident.level ?? 0}
                                    </span>
                                    {isDemoIncident(incident) && <TinyBadge tone="cyan">Demo</TinyBadge>}
                                    {incident.correlated && (
                                      <span className="text-[10px] uppercase tracking-wide text-cyan-400">
                                        correlated
                                      </span>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </td>

                            <td className="px-2 py-1.5 align-top font-mono text-[11px] text-slate-300">
                              {incident.agent ?? "unknown"}
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <span className="font-mono text-[11px] text-slate-300">
                                {incident.correlated ? "multi" : "single"}
                              </span>
                            </td>

                            <td className="whitespace-nowrap px-2 py-1.5 align-top font-mono text-[10px] text-slate-500">
                              {incident.timestamp_local ?? formatTimestamp(incident.timestamp)}
                            </td>

                            <td className="px-2 py-1.5 align-middle text-right">
                              <ChevronRight className="h-3.5 w-3.5 text-slate-600" strokeWidth={1.75} />
                            </td>
                          </tr>
                        );
                      })}

                      {incidents.length === 0 && (
                        <tr>
                          <td colSpan={10} className="px-3 py-10 text-center text-xs text-slate-500">
                            No incidents found with current filters.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="flex flex-col gap-2 border-t border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-500 md:flex-row md:items-center md:justify-between">
                <div>
                  {total} incident(s) · Page {data?.page ?? page} of {totalPages}
                </div>

                <nav className="flex items-center gap-1" aria-label="Incident pagination">
                  <button
                    onClick={() => setPage((current) => Math.max(1, current - 1))}
                    disabled={page <= 1}
                    className="h-7 border border-slate-700 bg-slate-950 px-2.5 text-[11px] font-medium uppercase tracking-wide text-slate-300 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Previous
                  </button>

                  <div className="flex items-center gap-1 px-1">
                    {paginationWindow(data?.page ?? page, totalPages).map((pageNumber) => {
                      const active = pageNumber === (data?.page ?? page);

                      return (
                        <button
                          key={pageNumber}
                          onClick={() => setPage(pageNumber)}
                          aria-current={active ? "page" : undefined}
                          className={`h-7 min-w-7 border px-2 font-mono text-[11px] font-semibold tabular-nums ${
                            active
                              ? "border-cyan-600 bg-cyan-950 text-cyan-100"
                              : "border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700 hover:bg-slate-900 hover:text-slate-200"
                          }`}
                        >
                          {pageNumber}
                        </button>
                      );
                    })}
                  </div>

                  <button
                    onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                    disabled={page >= totalPages}
                    className="h-7 border border-slate-700 bg-slate-950 px-2.5 text-[11px] font-medium uppercase tracking-wide text-slate-300 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Next
                  </button>
                </nav>
              </div>
            </div>

            <aside className="min-w-0 bg-slate-950">
              <div className="border-b border-slate-800 px-3 py-2">
                <h2 className="text-[12px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                  Analyst decision support
                </h2>
                <p className="text-[11px] text-slate-500">
                  Triage guidance generated from the selected incident context.
                </p>
              </div>

              {selectedIncident ? (
                <div>
                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <TinyBadge tone={riskTone(selectedIncident.risk_score)}>
                            {riskBand(selectedIncident.risk_score)}
                          </TinyBadge>
                          <TinyBadge tone={statusTone(selectedIncident.status)}>
                            {selectedIncident.status ?? "NEW"}
                          </TinyBadge>
                        </div>

                        <div className="mt-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                          Recommended decision
                        </div>

                        <div className="mt-1 text-base font-semibold leading-6 text-slate-100">
                          {decisionLabel(selectedIncident)}
                        </div>
                      </div>

                      <Link
                        href={`/incidents/${selectedIncident.id}`}
                        className="shrink-0 border border-cyan-800 bg-cyan-950 px-2 py-1 text-[11px] font-medium text-cyan-100 hover:bg-cyan-900"
                      >
                        Open detail
                      </Link>
                    </div>
                  </div>

                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      Why this matters
                    </div>
                    <p className="mt-2 text-xs leading-5 text-slate-300">
                      {riskRationale(selectedIncident)}
                    </p>
                  </div>

                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      What to validate next
                    </div>
                    <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs leading-5 text-slate-400 marker:text-slate-500">
                      {investigationQuestions(selectedIncident).map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>

                  <dl className="border-b border-slate-800">
                    <Field
                      label="Case action"
                      value={
                        (selectedIncident.risk_score ?? 0) >= 60 || selectedIncident.correlated
                          ? "Review for case creation or case attachment"
                          : "Classify before opening a case"
                      }
                    />
                    <Field
                      label="Pattern"
                      value={selectedIncident.correlated ? selectedIncident.correlation_type ?? "correlated" : "No pattern detected"}
                    />
                    <Field
                      label="Evidence"
                      value={
                        <span>
                          Host <span className="font-mono text-slate-200">{selectedIncident.agent ?? "unknown"}</span>, Wazuh level{" "}
                          <span className="font-mono text-slate-200">{selectedIncident.level ?? 0}</span>
                        </span>
                      }
                    />
                    <Field
                      label="Created"
                      value={
                        <span className="font-mono">
                          {selectedIncident.timestamp_local ?? formatTimestamp(selectedIncident.timestamp)}
                        </span>
                      }
                    />
                  </dl>

                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      Signal summary
                    </div>
                    <p className="mt-2 line-clamp-4 text-xs leading-5 text-slate-300">
                      {selectedIncident.rule ?? "-"}
                    </p>
                  </div>

                  <div className="px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      Workflow reminder
                    </div>
                    <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs leading-5 text-slate-400 marker:text-slate-500">
                      <li>Validate the signal and host context.</li>
                      <li>Check whether correlation changes the priority.</li>
                      <li>Decide whether to escalate, classify or attach to a case.</li>
                      <li>Document the analyst decision in the full incident detail.</li>
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="p-4 text-xs text-slate-500">
                  Select an incident from the grid.
                </div>
              )}
            </aside>
          </section>
        </div>
      </div>
    </main>
  );
}
