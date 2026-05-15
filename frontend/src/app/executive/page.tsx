"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  ArrowLeft,
  AlertTriangle,
  BarChart3,
  Briefcase,
  CheckCircle2,
  RefreshCw,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";

type ExecutiveStatus = "OK" | "ATTENTION" | "CRITICAL" | string;

type ExecutiveSummary = {
  status: ExecutiveStatus;
  summary: {
    total_incidents: number;
    open_incidents: number;
    escalated_incidents: number;
    critical_incidents: number;
    high_or_critical_incidents: number;
    correlated_incidents: number;
    total_cases: number;
    open_cases: number;
    escalated_cases: number;
    critical_cases: number;
    average_risk_score: number;
    max_risk_score: number;
  };
  distributions: {
    incident_status: Record<string, number>;
    case_status: Record<string, number>;
    priority: Record<string, number>;
  };
  top_hosts: Array<{
    agent: string | null;
    count: number;
    max_risk: number;
    average_risk: number;
  }>;
  top_correlation_types: Array<{
    correlation_type: string | null;
    count: number;
  }>;
  latest_cases: Array<{
    id: number;
    title: string;
    status: string | null;
    severity: string | null;
    agent: string | null;
    correlation_type: string | null;
    risk_score: number | null;
    updated_at: string | null;
  }>;
  latest_high_risk_incidents: Array<{
    id: number;
    status: string | null;
    timestamp: string | null;
    timestamp_local?: string | null;
    agent: string | null;
    rule: string | null;
    risk_score: number | null;
    recommended_priority: string | null;
    correlation_type: string | null;
  }>;
  latest_case_analysis: {
    id: number;
    case_id: number;
    model: string | null;
    recommended_status: string | null;
    recommended_severity: string | null;
    created_at: string | null;
  } | null;
  recommendations: string[];
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("it-CH", {
    timeZone: "Europe/Zurich",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}

function statusClass(status: string | null | undefined) {
  const value = status ?? "OK";

  if (value === "CRITICAL" || value === "ESCALATED") {
    return "bg-red-100 text-red-800 border-red-200";
  }

  if (value === "ATTENTION" || value === "HIGH") {
    return "bg-orange-100 text-orange-800 border-orange-200";
  }

  if (value === "MEDIUM" || value === "TRIAGED") {
    return "bg-yellow-100 text-yellow-800 border-yellow-200";
  }

  if (value === "CLOSED") {
    return "bg-slate-200 text-slate-800 border-slate-300";
  }

  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function executiveIcon(status: ExecutiveStatus) {
  if (status === "CRITICAL") {
    return <AlertTriangle className="h-6 w-6 text-red-400" />;
  }

  if (status === "ATTENTION") {
    return <ShieldAlert className="h-6 w-6 text-orange-400" />;
  }

  return <CheckCircle2 className="h-6 w-6 text-emerald-400" />;
}

async function fetchExecutiveSummary(): Promise<ExecutiveSummary> {
  const response = await fetch(`${API_BASE}/executive/summary`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function ExecutivePage() {
  const [data, setData] = useState<ExecutiveSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadExecutiveSummary() {
    try {
      setRefreshing(true);
      setError(null);

      const response = await fetchExecutiveSummary();
      setData(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadExecutiveSummary();

    const interval = window.setInterval(() => {
      loadExecutiveSummary();
    }, 30000);

    return () => window.clearInterval(interval);
  }, []);

  const incidentStatusRows = useMemo(() => {
    return Object.entries(data?.distributions.incident_status ?? {});
  }, [data]);

  const caseStatusRows = useMemo(() => {
    return Object.entries(data?.distributions.case_status ?? {});
  }, [data]);

  const priorityRows = useMemo(() => {
    return Object.entries(data?.distributions.priority ?? {});
  }, [data]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <AppNavigation />
        <header className="mb-8 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to dashboard
            </Link>

            <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
              <BarChart3 className="h-4 w-4" />
              Executive summary
            </div>

            <h1 className="text-3xl font-semibold tracking-tight">
              Executive Dashboard
            </h1>

            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Management-oriented summary of SOC posture, open risk, case
              backlog and recommended operational focus.
            </p>
          </div>

          <button
            onClick={loadExecutiveSummary}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 shadow-sm hover:bg-slate-800"
          >
            <RefreshCw
              className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-6 rounded-2xl border border-red-800 bg-red-950/60 p-4 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-300">
            Loading executive summary...
          </div>
        ) : data ? (
          <div className="space-y-6">
            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div className="flex items-center gap-4">
                  <div className="rounded-2xl bg-slate-950 p-4">
                    {executiveIcon(data.status)}
                  </div>

                  <div>
                    <div className="text-sm text-slate-400">
                      Overall SOC posture
                    </div>
                    <div className="mt-1 text-3xl font-semibold">
                      {data.status}
                    </div>
                  </div>
                </div>

                <span
                  className={`inline-flex rounded-full border px-4 py-2 text-sm ${statusClass(
                    data.status
                  )}`}
                >
                  {data.status === "OK"
                    ? "No immediate executive escalation"
                    : data.status === "ATTENTION"
                    ? "Management attention recommended"
                    : "Immediate review required"}
                </span>
              </div>
            </section>

            <section className="grid gap-4 md:grid-cols-4">
              <MetricCard
                title="Open incidents"
                value={data.summary.open_incidents}
              />
              <MetricCard
                title="High / critical incidents"
                value={data.summary.high_or_critical_incidents}
              />
              <MetricCard
                title="Open cases"
                value={data.summary.open_cases}
              />
              <MetricCard
                title="Max risk score"
                value={data.summary.max_risk_score}
              />
            </section>

            <section className="grid gap-4 md:grid-cols-4">
              <MetricCard
                title="Total incidents"
                value={data.summary.total_incidents}
              />
              <MetricCard
                title="Correlated incidents"
                value={data.summary.correlated_incidents}
              />
              <MetricCard
                title="Total cases"
                value={data.summary.total_cases}
              />
              <MetricCard
                title="Average risk"
                value={data.summary.average_risk_score}
              />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">
                  Recommended operational focus
                </h2>
              </div>

              {data.recommendations.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No recommendations available.
                </div>
              ) : (
                <div className="space-y-3">
                  {data.recommendations.map((item) => (
                    <div
                      key={item}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300"
                    >
                      {item}
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="grid gap-6 lg:grid-cols-3">
              <DistributionCard
                title="Incident status"
                rows={incidentStatusRows}
              />
              <DistributionCard title="Case status" rows={caseStatusRows} />
              <DistributionCard title="Priority" rows={priorityRows} />
            </section>

            <section className="grid gap-6 lg:grid-cols-2">
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <h2 className="mb-4 text-lg font-medium">Top risk hosts</h2>

                <div className="space-y-3">
                  {data.top_hosts.length === 0 ? (
                    <div className="text-sm text-slate-400">
                      No host data available.
                    </div>
                  ) : (
                    data.top_hosts.map((host) => (
                      <div
                        key={host.agent ?? "unknown"}
                        className="rounded-xl border border-slate-800 bg-slate-950 p-4"
                      >
                        <div className="flex items-center justify-between gap-4">
                          <div>
                            <div className="font-medium">
                              {host.agent ?? "unknown"}
                            </div>
                            <div className="mt-1 text-xs text-slate-500">
                              {host.count} incidents · avg risk{" "}
                              {host.average_risk}
                            </div>
                          </div>

                          <span
                            className={`rounded-full border px-3 py-1 text-xs ${statusClass(
                              host.max_risk >= 81
                                ? "CRITICAL"
                                : host.max_risk >= 61
                                ? "HIGH"
                                : "OK"
                            )}`}
                          >
                            max {host.max_risk}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <h2 className="mb-4 text-lg font-medium">
                  Top correlation types
                </h2>

                <div className="space-y-3">
                  {data.top_correlation_types.length === 0 ? (
                    <div className="text-sm text-slate-400">
                      No correlation data available.
                    </div>
                  ) : (
                    data.top_correlation_types.map((item) => (
                      <div
                        key={item.correlation_type ?? "unknown"}
                        className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-4"
                      >
                        <div className="max-w-md truncate text-sm text-slate-300">
                          {item.correlation_type ?? "unknown"}
                        </div>

                        <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">
                          {item.count}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <Briefcase className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Latest cases</h2>
              </div>

              {data.latest_cases.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No cases available.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
                      <tr>
                        <th className="py-3 pr-4">Case</th>
                        <th className="py-3 pr-4">Status</th>
                        <th className="py-3 pr-4">Severity</th>
                        <th className="py-3 pr-4">Risk</th>
                        <th className="py-3 pr-4">Updated</th>
                      </tr>
                    </thead>

                    <tbody>
                      {data.latest_cases.map((item) => (
                        <tr
                          key={item.id}
                          className="border-b border-slate-800/70"
                        >
                          <td className="max-w-xl py-3 pr-4">
                            <Link
                              href={`/cases/${item.id}`}
                              className="text-cyan-300 hover:text-cyan-200"
                            >
                              #{item.id} {item.title}
                            </Link>
                          </td>

                          <td className="py-3 pr-4">
                            <span
                              className={`rounded-full border px-3 py-1 text-xs ${statusClass(
                                item.status
                              )}`}
                            >
                              {item.status ?? "OPEN"}
                            </span>
                          </td>

                          <td className="py-3 pr-4">
                            <span
                              className={`rounded-full border px-3 py-1 text-xs ${statusClass(
                                item.severity
                              )}`}
                            >
                              {item.severity ?? "LOW"}
                            </span>
                          </td>

                          <td className="py-3 pr-4">
                            {item.risk_score ?? 0}
                          </td>

                          <td className="py-3 pr-4 text-slate-400">
                            {formatTimestamp(item.updated_at)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <h2 className="mb-4 text-lg font-medium">
                Latest high-risk incidents
              </h2>

              {data.latest_high_risk_incidents.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No high-risk incidents available.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
                      <tr>
                        <th className="py-3 pr-4">ID</th>
                        <th className="py-3 pr-4">Time</th>
                        <th className="py-3 pr-4">Host</th>
                        <th className="py-3 pr-4">Rule</th>
                        <th className="py-3 pr-4">Risk</th>
                        <th className="py-3 pr-4">Priority</th>
                      </tr>
                    </thead>

                    <tbody>
                      {data.latest_high_risk_incidents.map((incident) => (
                        <tr
                          key={incident.id}
                          className="border-b border-slate-800/70"
                        >
                          <td className="py-3 pr-4">
                            <Link
                              href={`/incidents/${incident.id}`}
                              className="text-cyan-300 hover:text-cyan-200"
                            >
                              #{incident.id}
                            </Link>
                          </td>

                          <td className="py-3 pr-4 text-slate-400">
                            {incident.timestamp_local ??
                              formatTimestamp(incident.timestamp)}
                          </td>

                          <td className="py-3 pr-4">
                            {incident.agent ?? "unknown"}
                          </td>

                          <td className="max-w-xl py-3 pr-4 text-slate-300">
                            {incident.rule ?? "-"}
                          </td>

                          <td className="py-3 pr-4">
                            {incident.risk_score ?? 0}
                          </td>

                          <td className="py-3 pr-4 text-slate-400">
                            {incident.recommended_priority ?? "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
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
}: {
  title: string;
  value: string | number;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-3 text-sm text-slate-400">{title}</div>
      <div className="text-3xl font-semibold">{value}</div>
    </div>
  );
}

function DistributionCard({
  title,
  rows,
}: {
  title: string;
  rows: Array<[string, number]>;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <h2 className="mb-4 text-lg font-medium">{title}</h2>

      {rows.length === 0 ? (
        <div className="text-sm text-slate-400">No data available.</div>
      ) : (
        <div className="space-y-3">
          {rows.map(([label, value]) => (
            <div
              key={label}
              className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 px-4 py-3"
            >
              <span className="text-sm text-slate-300">{label}</span>
              <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">
                {value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
