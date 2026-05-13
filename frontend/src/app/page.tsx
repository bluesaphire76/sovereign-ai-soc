"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  Brain,
  Database,
  RefreshCw,
  Server,
  Shield,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Incident = {
  id: number;
  status: string | null;
  timestamp: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  risk_score: number | null;
  correlation_score: number | null;
  correlated: boolean | null;
  correlation_type: string | null;
  recommended_priority: string | null;
};

type Summary = {
  total_incidents: number;
  average_risk_score: number;
  max_risk_score: number;
  correlated_incidents: number;
};

type TopHost = {
  agent: string | null;
  count: number;
  max_risk: number | null;
};

type RiskDistribution = {
  low_0_30: number;
  medium_31_60: number;
  high_61_80: number;
  critical_81_100: number;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

function riskLabel(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "Critical";
  if (value >= 61) return "High";
  if (value >= 31) return "Medium";
  return "Low";
}

function riskClass(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "bg-red-100 text-red-800 border-red-200";
  if (value >= 61) return "bg-orange-100 text-orange-800 border-orange-200";
  if (value >= 31) return "bg-yellow-100 text-yellow-800 border-yellow-200";
  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function statusClass(status: string | null | undefined) {
  const value = status ?? "NEW";

  if (value === "ESCALATED") return "bg-red-100 text-red-800 border-red-200";
  if (value === "TRIAGED") return "bg-blue-100 text-blue-800 border-blue-200";
  if (value === "CLOSED") return "bg-slate-200 text-slate-800 border-slate-300";
  if (value === "FALSE_POSITIVE")
    return "bg-purple-100 text-purple-800 border-purple-200";

  return "bg-cyan-100 text-cyan-800 border-cyan-200";
}

function RiskBarShape(props: any) {
  const { x, y, width, height, payload } = props;

  return (
    <rect
      x={x}
      y={y}
      width={width}
      height={height}
      rx={8}
      ry={8}
      fill={payload.color}
    />
  );
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function Home() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [topHosts, setTopHosts] = useState<TopHost[]>([]);
  const [riskDistribution, setRiskDistribution] =
    useState<RiskDistribution | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadDashboard() {
    try {
      setRefreshing(true);
      setError(null);

      const [summaryData, incidentsData, topHostsData, riskData] =
        await Promise.all([
          fetchJson<Summary>("/metrics/summary"),
          fetchJson<Incident[]>("/incidents?limit=20"),
          fetchJson<TopHost[]>("/metrics/top-hosts?limit=10"),
          fetchJson<RiskDistribution>("/metrics/risk-distribution"),
        ]);

      setSummary(summaryData);
      setIncidents(incidentsData);
      setTopHosts(topHostsData);
      setRiskDistribution(riskData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadDashboard();

    const interval = window.setInterval(() => {
      loadDashboard();
    }, 30000);

    return () => window.clearInterval(interval);
  }, []);

  const riskChartData = useMemo(() => {
    if (!riskDistribution) return [];

    return [
      {
        name: "Low",
        value: riskDistribution.low_0_30,
        color: "#10b981",
      },
      {
        name: "Medium",
        value: riskDistribution.medium_31_60,
        color: "#f59e0b",
      },
      {
        name: "High",
        value: riskDistribution.high_61_80,
        color: "#f97316",
      },
      {
        name: "Critical",
        value: riskDistribution.critical_81_100,
        color: "#ef4444",
      },
    ];
  }, [riskDistribution]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
              <Shield className="h-4 w-4" />
              Sovereign AI SOC
            </div>

            <h1 className="text-3xl font-semibold tracking-tight">
              AI SOC Dashboard
            </h1>

            <p className="mt-2 max-w-2xl text-sm text-slate-400">
              Local-first SOC assistant with Wazuh, PostgreSQL, Qdrant RAG and
              Ollama-based triage.
            </p>
          </div>

          <button
            onClick={loadDashboard}
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
            Loading dashboard...
          </div>
        ) : (
          <>
            <section className="grid gap-4 md:grid-cols-4">
              <MetricCard
                title="Total incidents"
                value={summary?.total_incidents ?? 0}
                icon={<Database className="h-5 w-5" />}
              />

              <MetricCard
                title="Average risk"
                value={summary?.average_risk_score ?? 0}
                icon={<Activity className="h-5 w-5" />}
              />

              <MetricCard
                title="Max risk"
                value={summary?.max_risk_score ?? 0}
                icon={<AlertTriangle className="h-5 w-5" />}
              />

              <MetricCard
                title="Correlated"
                value={summary?.correlated_incidents ?? 0}
                icon={<Brain className="h-5 w-5" />}
              />
            </section>

            <section className="mt-6 grid gap-6 lg:grid-cols-2">
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <h2 className="mb-4 text-lg font-medium">
                  Risk distribution
                </h2>

                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={riskChartData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis allowDecimals={false} />
                      <Tooltip />
                      <Bar
                        dataKey="value"
                        shape={(props) => <RiskBarShape {...props} />}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <h2 className="mb-4 text-lg font-medium">Top noisy hosts</h2>

                <div className="space-y-3">
                  {topHosts.map((host) => (
                    <div
                      key={host.agent ?? "unknown"}
                      className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 px-4 py-3"
                    >
                      <div className="flex items-center gap-3">
                        <Server className="h-4 w-4 text-cyan-300" />

                        <div>
                          <div className="font-medium">
                            {host.agent ?? "unknown"}
                          </div>
                          <div className="text-xs text-slate-500">
                            {host.count} incidenti
                          </div>
                        </div>
                      </div>

                      <span
                        className={`rounded-full border px-3 py-1 text-xs ${riskClass(
                          host.max_risk
                        )}`}
                      >
                        max {host.max_risk ?? 0}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-medium">Recent incidents</h2>
                <span className="text-xs text-slate-500">
                  Auto refresh every 30s
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
                    <tr>
                      <th className="py-3 pr-4">ID</th>
                      <th className="py-3 pr-4">Status</th>
                      <th className="py-3 pr-4">Time</th>
                      <th className="py-3 pr-4">Host</th>
                      <th className="py-3 pr-4">Rule</th>
                      <th className="py-3 pr-4">Level</th>
                      <th className="py-3 pr-4">Risk</th>
                      <th className="py-3 pr-4">Priority</th>
                      <th className="py-3 pr-4">Correlation</th>
                    </tr>
                  </thead>

                  <tbody>
                    {incidents.map((incident) => (
                      <tr
                        key={incident.id}
                        className="border-b border-slate-800/70"
                      >
                        <td className="py-3 pr-4 text-slate-400">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="text-cyan-300 hover:text-cyan-200"
                          >
                            #{incident.id}
                          </Link>
                        </td>

                        <td className="py-3 pr-4">
                          <span
                            className={`rounded-full border px-3 py-1 text-xs ${statusClass(
                              incident.status
                            )}`}
                          >
                            {incident.status ?? "NEW"}
                          </span>
                        </td>


                        <td className="py-3 pr-4 text-slate-400">
                          {incident.timestamp ?? "-"}
                        </td>

                        <td className="py-3 pr-4">
                          {incident.agent ?? "unknown"}
                        </td>

                        <td className="max-w-xl py-3 pr-4 text-slate-300">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="hover:text-cyan-200"
                          >
                            {incident.rule ?? "-"}
                          </Link>
                        </td>

                        <td className="py-3 pr-4">{incident.level ?? 0}</td>

                        <td className="py-3 pr-4">
                          <span
                            className={`rounded-full border px-3 py-1 text-xs ${riskClass(
                              incident.risk_score
                            )}`}
                          >
                            {riskLabel(incident.risk_score)}{" "}
                            {incident.risk_score ?? 0}
                          </span>
                        </td>

                        <td className="py-3 pr-4">
                          <span
                            className={`rounded-full border px-3 py-1 text-xs ${riskClass(
                              incident.risk_score
                            )}`}
                          >
                            {incident.recommended_priority ?? riskLabel(incident.risk_score)}
                          </span>
                        </td>

                        <td className="py-3 pr-4">
                          {incident.correlated ? (
                            <div>
                              <div className="text-cyan-300">
                                {incident.correlation_score ?? 0}
                              </div>
                              <div className="max-w-xs truncate text-xs text-slate-500">
                                {incident.correlation_type ?? "correlated"}
                              </div>
                            </div>
                          ) : (
                            <span className="text-slate-500">No</span>
                          )}
                        </td>
                        
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </div>
    </main>
  );
}

function MetricCard({
  title,
  value,
  icon,
}: {
  title: string;
  value: number;
  icon: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-4 flex items-center justify-between">
        <div className="text-sm text-slate-400">{title}</div>
        <div className="rounded-xl bg-slate-800 p-2 text-cyan-300">
          {icon}
        </div>
      </div>

      <div className="text-3xl font-semibold">{value}</div>
    </div>
  );
}