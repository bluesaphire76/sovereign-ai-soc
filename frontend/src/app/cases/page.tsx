"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Briefcase, RefreshCw, ShieldAlert } from "lucide-react";

type IncidentCase = {
  id: number;
  group_key: string;
  title: string;
  status: string | null;
  severity: string | null;
  agent: string | null;
  correlation_type: string | null;
  risk_score: number | null;
  summary: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  incident_count: number;
  owner: string | null;
  sla_due_at: string | null;
  sla_status: string | null;
  severity_review: string | null;
  status_reason: string | null;
  last_reviewed_by: string | null;
  last_reviewed_at: string | null;
};

type CasesResponse = {
  items: IncidentCase[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

function severityClass(value: string | null | undefined) {
  const severity = value ?? "LOW";

  if (severity === "CRITICAL") return "bg-red-100 text-red-800 border-red-200";
  if (severity === "HIGH") return "bg-orange-100 text-orange-800 border-orange-200";
  if (severity === "MEDIUM") return "bg-yellow-100 text-yellow-800 border-yellow-200";

  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function statusClass(value: string | null | undefined) {
  const status = value ?? "OPEN";

  if (status === "ESCALATED") return "bg-red-100 text-red-800 border-red-200";
  if (status === "TRIAGED") return "bg-blue-100 text-blue-800 border-blue-200";
  if (status === "CLOSED") return "bg-slate-200 text-slate-800 border-slate-300";

  return "bg-cyan-100 text-cyan-800 border-cyan-200";
}

function slaClass(value: string | null | undefined) {
  const status = value ?? "NOT_SET";

  if (status === "BREACHED") return "bg-red-100 text-red-800 border-red-200";
  if (status === "WITHIN_SLA") return "bg-emerald-100 text-emerald-800 border-emerald-200";
  if (status === "COMPLETED") return "bg-slate-200 text-slate-800 border-slate-300";

  return "bg-slate-100 text-slate-700 border-slate-200";
}

function slaLabel(value: string | null | undefined) {
  if (!value) return "NOT SET";
  return value.replace("_", " ");
}

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

async function fetchCases(): Promise<CasesResponse> {
  const response = await fetch(`${API_BASE}/cases`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function CasesPage() {
  const [data, setData] = useState<CasesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cases = data?.items ?? [];

  const totalOpenCases = useMemo(() => {
    return cases.filter((item) => item.status !== "CLOSED").length;
  }, [cases]);

  const breachedCases = useMemo(() => {
    return cases.filter((item) => item.sla_status === "BREACHED").length;
  }, [cases]);

  async function loadCases() {
    try {
      setRefreshing(true);
      setError(null);
      const response = await fetchCases();
      setData(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadCases();
  }, []);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
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
              <Briefcase className="h-4 w-4" />
              Investigation cases
            </div>

            <h1 className="text-3xl font-semibold tracking-tight">
              Case Grouping
            </h1>

            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Group correlated incidents into investigation cases by host,
              correlation type and event day.
            </p>
          </div>

          <button
            onClick={loadCases}
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
            Loading cases...
          </div>
        ) : (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-4">
              <MetricCard title="Total cases" value={data?.total ?? 0} />
              <MetricCard title="Open cases" value={totalOpenCases} />
              <MetricCard title="SLA breached" value={breachedCases} />
              <MetricCard title="Page" value={data?.page ?? 1} />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-medium">Cases</h2>
                <span className="text-xs text-slate-500">
                  {data?.total ?? 0} total
                </span>
              </div>

              {cases.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No cases available yet. Run the case grouping script first.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
                      <tr>
                        <th className="py-3 pr-4">Case</th>
                        <th className="py-3 pr-4">Status</th>
                        <th className="py-3 pr-4">Severity</th>
                        <th className="py-3 pr-4">Owner</th>
                        <th className="py-3 pr-4">SLA</th>
                        <th className="py-3 pr-4">Host</th>
                        <th className="py-3 pr-4">Correlation type</th>
                        <th className="py-3 pr-4">Incidents</th>
                        <th className="py-3 pr-4">Updated</th>
                      </tr>
                    </thead>

                    <tbody>
                      {cases.map((item) => (
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
                              className={`rounded-full border px-3 py-1 text-xs ${severityClass(
                                item.severity
                              )}`}
                            >
                              {item.severity ?? "LOW"} · {item.risk_score ?? 0}
                            </span>
                          </td>

                          <td className="py-3 pr-4 text-slate-300">
                            {item.owner ?? "unassigned"}
                          </td>

                          <td className="py-3 pr-4">
                            <div className="flex flex-col gap-1">
                              <span
                                className={`w-fit rounded-full border px-3 py-1 text-xs ${slaClass(
                                  item.sla_status
                                )}`}
                              >
                                {slaLabel(item.sla_status)}
                              </span>
                              {item.sla_due_at && (
                                <span className="text-xs text-slate-500">
                                  Due {formatTimestamp(item.sla_due_at)}
                                </span>
                              )}
                            </div>
                          </td>

                          <td className="py-3 pr-4 text-slate-300">
                            {item.agent ?? "unknown"}
                          </td>

                          <td className="py-3 pr-4 text-slate-400">
                            {item.correlation_type ?? "-"}
                          </td>

                          <td className="py-3 pr-4">
                            <div className="inline-flex items-center gap-2 text-slate-300">
                              <ShieldAlert className="h-4 w-4 text-cyan-300" />
                              {item.incident_count}
                            </div>
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
          </div>
        )}
      </div>
    </main>
  );
}

function MetricCard({ title, value }: { title: string; value: number }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-3 text-sm text-slate-400">{title}</div>
      <div className="text-3xl font-semibold">{value}</div>
    </div>
  );
}
