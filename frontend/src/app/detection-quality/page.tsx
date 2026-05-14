"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  BarChart3,
  Brain,
  CheckCircle2,
  RefreshCw,
  ShieldCheck,
  Target,
  AlertTriangle,
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
  timestamp_local?: string | null;
  timezone?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  risk_score: number | null;
  correlation_score: number | null;
  correlated: boolean | null;
  correlation_type: string | null;
  recommended_priority: string | null;
  mitre_ids?: string[] | string | null;
  mitre_techniques?: string[] | string | null;
  raw_alert?: Record<string, unknown> | null;
};

type IncidentsResponse = {
  items: Incident[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

type ScenarioSummary = {
  scenario: string;
  incidents: number;
  correlated: number;
  high_or_critical: number;
  mitre_tagged: number;
  max_risk: number;
  avg_risk: number;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

const KNOWN_SCENARIOS = [
  "ssh_bruteforce",
  "privilege_escalation",
  "malware_indicator",
];

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
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

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value ?? {});
  } catch {
    return "";
  }
}

function incidentText(incident: Incident): string {
  return [
    incident.rule,
    incident.agent,
    incident.status,
    incident.correlation_type,
    incident.recommended_priority,
    safeStringify(incident.raw_alert),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function isSyntheticIncident(incident: Incident): boolean {
  const text = incidentText(incident);

  return (
    text.includes("synthetic") ||
    text.includes("sovereign-ai-soc-synthetic") ||
    KNOWN_SCENARIOS.some((scenario) => text.includes(scenario))
  );
}

function extractScenario(incident: Incident): string {
  const text = incidentText(incident);

  for (const scenario of KNOWN_SCENARIOS) {
    if (text.includes(scenario)) {
      return scenario;
    }
  }

  const rawText = safeStringify(incident.raw_alert);
  const match = rawText.match(/"scenario"\s*:\s*"([^"]+)"/i);

  if (match?.[1]) {
    return match[1];
  }

  return "unknown_synthetic";
}

function extractMitreIds(incident: Incident): string[] {
  const values: string[] = [];

  if (Array.isArray(incident.mitre_ids)) {
    values.push(...incident.mitre_ids);
  } else if (typeof incident.mitre_ids === "string") {
    values.push(incident.mitre_ids);
  }

  if (Array.isArray(incident.mitre_techniques)) {
    values.push(...incident.mitre_techniques);
  } else if (typeof incident.mitre_techniques === "string") {
    values.push(incident.mitre_techniques);
  }

  const text = incidentText(incident).toUpperCase();
  const matches = text.match(/T\d{4}(?:\.\d{3})?/g) ?? [];
  values.push(...matches);

  return Array.from(new Set(values.filter(Boolean)));
}

function priorityIsHighOrCritical(priority: string | null | undefined): boolean {
  const value = (priority ?? "").toUpperCase();
  return value === "HIGH" || value === "CRITICAL";
}

function riskClass(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "bg-red-100 text-red-800 border-red-200";
  if (value >= 61) return "bg-orange-100 text-orange-800 border-orange-200";
  if (value >= 31) return "bg-yellow-100 text-yellow-800 border-yellow-200";
  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function pct(value: number, total: number): number {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}

export default function DetectionQualityPage() {
  const [incidentsData, setIncidentsData] = useState<IncidentsResponse | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadDetectionQuality = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const params = new URLSearchParams({
        page: "1",
        limit: "20",
        search: "SYNTHETIC",
      });

      const response = await fetchJson<IncidentsResponse>(
        `/incidents?${params.toString()}`
      );

      setIncidentsData(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadDetectionQuality();

    const interval = window.setInterval(() => {
      loadDetectionQuality();
    }, 30000);

    return () => window.clearInterval(interval);
  }, [loadDetectionQuality]);

  const syntheticIncidents = useMemo(() => {
    const items = incidentsData?.items ?? [];
    return items.filter(isSyntheticIncident);
  }, [incidentsData]);

  const totalSynthetic = syntheticIncidents.length;

  const correlatedSynthetic = syntheticIncidents.filter(
    (incident) => incident.correlated
  ).length;

  const highOrCriticalSynthetic = syntheticIncidents.filter((incident) =>
    priorityIsHighOrCritical(incident.recommended_priority)
  ).length;

  const mitreTaggedSynthetic = syntheticIncidents.filter(
    (incident) => extractMitreIds(incident).length > 0
  ).length;

  const maxRisk = syntheticIncidents.reduce(
    (max, incident) => Math.max(max, incident.risk_score ?? 0),
    0
  );

  const averageRisk =
    totalSynthetic > 0
      ? Math.round(
          syntheticIncidents.reduce(
            (sum, incident) => sum + (incident.risk_score ?? 0),
            0
          ) / totalSynthetic
        )
      : 0;

  const detectionQualityScore = useMemo(() => {
    if (!totalSynthetic) return 0;

    const correlationScore = pct(correlatedSynthetic, totalSynthetic);
    const priorityScore = pct(highOrCriticalSynthetic, totalSynthetic);
    const mitreScore = pct(mitreTaggedSynthetic, totalSynthetic);

    return Math.round((correlationScore + priorityScore + mitreScore) / 3);
  }, [
    totalSynthetic,
    correlatedSynthetic,
    highOrCriticalSynthetic,
    mitreTaggedSynthetic,
  ]);

  const scenarioRows = useMemo<ScenarioSummary[]>(() => {
    const grouped = new Map<string, Incident[]>();

    for (const incident of syntheticIncidents) {
      const scenario = extractScenario(incident);
      const current = grouped.get(scenario) ?? [];
      current.push(incident);
      grouped.set(scenario, current);
    }

    return Array.from(grouped.entries())
      .map(([scenario, incidents]) => {
        const riskValues = incidents.map((incident) => incident.risk_score ?? 0);
        const riskSum = riskValues.reduce((sum, value) => sum + value, 0);

        return {
          scenario,
          incidents: incidents.length,
          correlated: incidents.filter((incident) => incident.correlated)
            .length,
          high_or_critical: incidents.filter((incident) =>
            priorityIsHighOrCritical(incident.recommended_priority)
          ).length,
          mitre_tagged: incidents.filter(
            (incident) => extractMitreIds(incident).length > 0
          ).length,
          max_risk: Math.max(...riskValues, 0),
          avg_risk: incidents.length ? Math.round(riskSum / incidents.length) : 0,
        };
      })
      .sort((a, b) => b.incidents - a.incidents);
  }, [syntheticIncidents]);

  const scenarioChartData = useMemo(() => {
    return scenarioRows.map((row) => ({
      name: row.scenario.replaceAll("_", " "),
      incidents: row.incidents,
      correlated: row.correlated,
    }));
  }, [scenarioRows]);

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
              <Target className="h-4 w-4" />
              Detection engineering
            </div>

            <h1 className="text-3xl font-semibold tracking-tight">
              Detection Quality Dashboard
            </h1>

            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Measures how synthetic defensive scenarios are observed by the AI
              SOC pipeline: visibility, correlation, priority assignment and
              MITRE signal coverage.
            </p>
          </div>

          <button
            onClick={loadDetectionQuality}
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
            Loading detection quality data...
          </div>
        ) : (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-5">
              <MetricCard
                title="Synthetic incidents"
                value={totalSynthetic}
                icon={<ShieldCheck className="h-5 w-5" />}
              />

              <MetricCard
                title="Correlated"
                value={`${pct(correlatedSynthetic, totalSynthetic)}%`}
                subtitle={`${correlatedSynthetic}/${totalSynthetic}`}
                icon={<Brain className="h-5 w-5" />}
              />

              <MetricCard
                title="High/Critical"
                value={`${pct(highOrCriticalSynthetic, totalSynthetic)}%`}
                subtitle={`${highOrCriticalSynthetic}/${totalSynthetic}`}
                icon={<AlertTriangle className="h-5 w-5" />}
              />

              <MetricCard
                title="MITRE signal"
                value={`${pct(mitreTaggedSynthetic, totalSynthetic)}%`}
                subtitle={`${mitreTaggedSynthetic}/${totalSynthetic}`}
                icon={<Target className="h-5 w-5" />}
              />

              <MetricCard
                title="Quality score"
                value={`${detectionQualityScore}%`}
                subtitle="Correlation + priority + MITRE"
                icon={<CheckCircle2 className="h-5 w-5" />}
              />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">
                    Synthetic scenario coverage
                  </h2>
                  <p className="mt-1 text-sm text-slate-400">
                    First version based on incidents already ingested into AI
                    SOC. It does not yet measure raw generated event count.
                  </p>
                </div>

                <span
                  className={`rounded-full border px-3 py-1 text-xs ${riskClass(
                    maxRisk
                  )}`}
                >
                  Max risk {maxRisk} · Avg risk {averageRisk}
                </span>
              </div>

              {totalSynthetic === 0 ? (
                <div className="rounded-2xl border border-yellow-800 bg-yellow-950/40 p-4 text-sm text-yellow-100">
                  No synthetic incidents found. Run a synthetic scenario, wait
                  for Wazuh and AI SOC ingestion, then refresh this page.
                </div>
              ) : (
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={scenarioChartData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis allowDecimals={false} />
                      <Tooltip />
                      <Bar dataKey="incidents" />
                      <Bar dataKey="correlated" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <h2 className="mb-4 text-lg font-medium">
                Scenario quality breakdown
              </h2>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-800 text-sm">
                  <thead>
                    <tr className="text-left text-xs uppercase tracking-wide text-slate-500">
                      <th className="px-3 py-3">Scenario</th>
                      <th className="px-3 py-3">Incidents</th>
                      <th className="px-3 py-3">Correlated</th>
                      <th className="px-3 py-3">High/Critical</th>
                      <th className="px-3 py-3">MITRE tagged</th>
                      <th className="px-3 py-3">Avg risk</th>
                      <th className="px-3 py-3">Max risk</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800">
                    {scenarioRows.map((row) => (
                      <tr key={row.scenario} className="hover:bg-slate-800/50">
                        <td className="px-3 py-3 font-medium text-slate-100">
                          {row.scenario}
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {row.incidents}
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {row.correlated} / {row.incidents} (
                          {pct(row.correlated, row.incidents)}%)
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {row.high_or_critical} / {row.incidents} (
                          {pct(row.high_or_critical, row.incidents)}%)
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {row.mitre_tagged} / {row.incidents} (
                          {pct(row.mitre_tagged, row.incidents)}%)
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {row.avg_risk}
                        </td>
                        <td className="px-3 py-3">
                          <span
                            className={`rounded-full border px-3 py-1 text-xs ${riskClass(
                              row.max_risk
                            )}`}
                          >
                            {row.max_risk}
                          </span>
                        </td>
                      </tr>
                    ))}

                    {scenarioRows.length === 0 && (
                      <tr>
                        <td
                          colSpan={7}
                          className="px-3 py-6 text-center text-slate-500"
                        >
                          No synthetic scenario data available yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <h2 className="mb-4 text-lg font-medium">
                Latest synthetic incidents
              </h2>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-800 text-sm">
                  <thead>
                    <tr className="text-left text-xs uppercase tracking-wide text-slate-500">
                      <th className="px-3 py-3">ID</th>
                      <th className="px-3 py-3">Time</th>
                      <th className="px-3 py-3">Host</th>
                      <th className="px-3 py-3">Rule</th>
                      <th className="px-3 py-3">Priority</th>
                      <th className="px-3 py-3">Risk</th>
                      <th className="px-3 py-3">Correlation</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800">
                    {syntheticIncidents.slice(0, 25).map((incident) => (
                      <tr key={incident.id} className="hover:bg-slate-800/50">
                        <td className="px-3 py-3">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="text-cyan-300 hover:text-cyan-200"
                          >
                            #{incident.id}
                          </Link>
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {formatTimestamp(
                            incident.timestamp_local ?? incident.timestamp
                          )}
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {incident.agent ?? "-"}
                        </td>
                        <td className="max-w-md truncate px-3 py-3 text-slate-300">
                          {incident.rule ?? "-"}
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {incident.recommended_priority ?? "-"}
                        </td>
                        <td className="px-3 py-3">
                          <span
                            className={`rounded-full border px-3 py-1 text-xs ${riskClass(
                              incident.risk_score
                            )}`}
                          >
                            {incident.risk_score ?? 0}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-slate-300">
                          {incident.correlated ? "Yes" : "No"}
                          {incident.correlation_score !== null &&
                          incident.correlation_score !== undefined
                            ? ` · ${incident.correlation_score}`
                            : ""}
                        </td>
                      </tr>
                    ))}

                    {syntheticIncidents.length === 0 && (
                      <tr>
                        <td
                          colSpan={7}
                          className="px-3 py-6 text-center text-slate-500"
                        >
                          No synthetic incidents found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}
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
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-3 flex items-center justify-between">
        <div className="rounded-xl bg-slate-950 p-2 text-cyan-300">{icon}</div>
      </div>

      <div className="text-sm text-slate-400">{title}</div>
      <div className="mt-1 text-3xl font-semibold">{value}</div>

      {subtitle && <div className="mt-1 text-xs text-slate-500">{subtitle}</div>}
    </div>
  );
}
