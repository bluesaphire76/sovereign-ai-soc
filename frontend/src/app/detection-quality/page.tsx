"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  RefreshCw,
  ShieldCheck,
  Target,
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

type Tone = "success" | "warning" | "danger" | "primary" | "neutral";

type SyntheticScenario = {
  id: string;
  title: string;
  rule: string;
  recommended_priority: string;
  risk_score: number;
  correlation_type: string;
  mitre: string[];
};

type SyntheticScenariosResponse = {
  items: SyntheticScenario[];
};

type SyntheticRunResponse = {
  status: string;
  scenario: string;
  host: string;
  count_per_scenario: number;
  created: number;
  incidents: Array<{
    id: number;
    scenario: string | null;
    rule: string | null;
    risk_score: number | null;
    recommended_priority: string | null;
    correlation_score: number | null;
  }>;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

const KNOWN_SCENARIOS = [
  "ssh_bruteforce",
  "privilege_escalation",
  "malware_indicator",
];

const CHART_GRID = "#334155";
const CHART_AXIS = "#64748b";
const CHART_TICK = "#cbd5e1";

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}


async function fetchSyntheticScenarios(): Promise<SyntheticScenariosResponse> {
  return fetchJson<SyntheticScenariosResponse>("/synthetic-tests/scenarios");
}

async function runSyntheticTest(payload: {
  scenario: string;
  count: number;
  host: string;
  created_by: string;
}): Promise<SyntheticRunResponse> {
  const response = await fetch(`${API_BASE}/synthetic-tests/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let detail = `API error ${response.status}`;

    try {
      const body = await response.json();
      detail = body?.detail?.message ?? body?.detail ?? detail;
    } catch {
      // keep default error
    }

    throw new Error(String(detail));
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

function pct(value: number, total: number): number {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}

function toneForScore(score: number): Tone {
  if (score >= 81) return "danger";
  if (score >= 61) return "warning";
  if (score >= 31) return "primary";
  return "success";
}

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { card: string; badge: string; text: string }> = {
    success: {
      card: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
    },
    warning: {
      card: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
    },
    danger: {
      card: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
    },
    primary: {
      card: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
    },
    neutral: {
      card: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
    },
  };

  return classes[tone];
}

function shortText(value: string | null | undefined, max = 96) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

function scenarioLabel(value: string) {
  return value.replaceAll("_", " ");
}

export default function DetectionQualityPage() {
  const [incidentsData, setIncidentsData] = useState<IncidentsResponse | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [syntheticScenarios, setSyntheticScenarios] = useState<SyntheticScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("all");
  const [syntheticCount, setSyntheticCount] = useState(1);
  const [syntheticHost, setSyntheticHost] = useState("synthetic-sensor-01");
  const [syntheticCreatedBy, setSyntheticCreatedBy] = useState("local_analyst");
  const [runningSynthetic, setRunningSynthetic] = useState(false);
  const [syntheticResult, setSyntheticResult] = useState<SyntheticRunResponse | null>(null);
  const [syntheticError, setSyntheticError] = useState<string | null>(null);

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


  useEffect(() => {
    fetchSyntheticScenarios()
      .then((response) => setSyntheticScenarios(response.items))
      .catch((err) =>
        setSyntheticError(
          err instanceof Error ? err.message : "Unable to load synthetic scenarios"
        )
      );
  }, []);

  async function handleRunSyntheticTest() {
    try {
      setRunningSynthetic(true);
      setSyntheticError(null);
      setSyntheticResult(null);

      const response = await runSyntheticTest({
        scenario: selectedScenario,
        count: syntheticCount,
        host: syntheticHost,
        created_by: syntheticCreatedBy,
      });

      setSyntheticResult(response);
      await loadDetectionQuality();
    } catch (err) {
      setSyntheticError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setRunningSynthetic(false);
    }
  }

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
      name: scenarioLabel(row.scenario),
      incidents: row.incidents,
      correlated: row.correlated,
    }));
  }, [scenarioRows]);

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
              <Target className="h-3.5 w-3.5" />
              Detection Engineering
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Detection Quality Dashboard
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Compact view of synthetic scenario visibility, AI correlation,
              priority assignment and MITRE coverage across the AI SOC pipeline.
            </p>
          </div>

          <button
            onClick={loadDetectionQuality}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading detection quality data...
          </section>
        ) : (
          <div className="space-y-3">
            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Synthetic test runner</h2>
                  <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
                    Generate controlled synthetic incidents to validate detection, correlation, priority and MITRE coverage from the GUI.
                  </p>
                </div>

                <button
                  onClick={handleRunSyntheticTest}
                  disabled={runningSynthetic}
                  className="h-8 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 shadow-sm hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {runningSynthetic ? "Running..." : "Run synthetic test"}
                </button>
              </div>

              <div className="grid gap-2 md:grid-cols-4">
                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Scenario
                  </span>
                  <select
                    value={selectedScenario}
                    onChange={(event) => setSelectedScenario(event.target.value)}
                    className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="all">All scenarios</option>
                    {syntheticScenarios.map((scenario) => (
                      <option key={scenario.id} value={scenario.id}>
                        {scenario.id.replaceAll("_", " ")}
                      </option>
                    ))}
                  </select>
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Count per scenario
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={10}
                    value={syntheticCount}
                    onChange={(event) =>
                      setSyntheticCount(
                        Math.max(1, Math.min(Number(event.target.value || 1), 10))
                      )
                    }
                    className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Host
                  </span>
                  <input
                    value={syntheticHost}
                    onChange={(event) => setSyntheticHost(event.target.value)}
                    className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Created by
                  </span>
                  <input
                    value={syntheticCreatedBy}
                    onChange={(event) => setSyntheticCreatedBy(event.target.value)}
                    className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>
              </div>

              {syntheticError && (
                <div className="mt-2 rounded-md border border-red-800 bg-red-950/60 p-2 text-xs text-red-200">
                  Synthetic test error: {syntheticError}
                </div>
              )}

              {syntheticResult && (
                <div className="mt-2 rounded-md border border-emerald-800 bg-emerald-950/30 p-2 text-xs text-emerald-200">
                  Created {syntheticResult.created} synthetic incident(s) on host{" "}
                  <strong>{syntheticResult.host}</strong>. Latest IDs:{" "}
                  {syntheticResult.incidents.slice(0, 6).map((item) => `#${item.id}`).join(", ")}
                  {syntheticResult.incidents.length > 6 ? "…" : ""}
                </div>
              )}
            </section>

            <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              <QualityMetric
                title="Synthetic incidents"
                value={totalSynthetic}
                subtitle={`${incidentsData?.total ?? 0} matching loaded`}
                icon={<ShieldCheck className="h-4 w-4" />}
                tone="primary"
              />

              <QualityMetric
                title="Correlated"
                value={`${pct(correlatedSynthetic, totalSynthetic)}%`}
                subtitle={`${correlatedSynthetic}/${totalSynthetic}`}
                icon={<Brain className="h-4 w-4" />}
                tone={
                  correlatedSynthetic === totalSynthetic && totalSynthetic > 0
                    ? "success"
                    : "warning"
                }
              />

              <QualityMetric
                title="High/Critical"
                value={`${pct(highOrCriticalSynthetic, totalSynthetic)}%`}
                subtitle={`${highOrCriticalSynthetic}/${totalSynthetic}`}
                icon={<AlertTriangle className="h-4 w-4" />}
                tone={highOrCriticalSynthetic > 0 ? "warning" : "neutral"}
              />

              <QualityMetric
                title="MITRE signal"
                value={`${pct(mitreTaggedSynthetic, totalSynthetic)}%`}
                subtitle={`${mitreTaggedSynthetic}/${totalSynthetic}`}
                icon={<Target className="h-4 w-4" />}
                tone={
                  mitreTaggedSynthetic === totalSynthetic && totalSynthetic > 0
                    ? "success"
                    : "warning"
                }
              />

              <QualityMetric
                title="Quality score"
                value={`${detectionQualityScore}%`}
                subtitle="Correlation + priority + MITRE"
                icon={<CheckCircle2 className="h-4 w-4" />}
                tone={toneForScore(detectionQualityScore)}
              />
            </section>

            <section className="grid gap-3 xl:grid-cols-[420px_1fr]">
              <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold">
                      Synthetic scenario coverage
                    </h2>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      Compact chart of scenario visibility and correlation.
                    </p>
                  </div>

                  <span
                    className={`shrink-0 rounded-md border px-2 py-1 text-[11px] ${
                      toneClasses(toneForScore(maxRisk)).badge
                    }`}
                  >
                    Max {maxRisk} · Avg {averageRisk}
                  </span>
                </div>

                {totalSynthetic === 0 ? (
                  <div className="rounded-md border border-orange-800 bg-orange-950/40 p-3 text-xs text-orange-100">
                    No synthetic incidents found. Run a synthetic scenario, wait
                    for ingestion, then refresh.
                  </div>
                ) : (
                  <div className="h-36">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={scenarioChartData}
                        layout="vertical"
                        margin={{ top: 4, right: 12, left: 8, bottom: 4 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
                        <XAxis
                          type="number"
                          allowDecimals={false}
                          tick={{ fill: CHART_TICK, fontSize: 10 }}
                          axisLine={{ stroke: CHART_AXIS }}
                          tickLine={{ stroke: CHART_AXIS }}
                        />
                        <YAxis
                          type="category"
                          dataKey="name"
                          width={115}
                          tick={{ fill: CHART_TICK, fontSize: 10 }}
                          axisLine={{ stroke: CHART_AXIS }}
                          tickLine={{ stroke: CHART_AXIS }}
                        />
                        <Tooltip
                          cursor={{ fill: "rgba(15, 23, 42, 0.6)" }}
                          contentStyle={{
                            backgroundColor: "#020617",
                            border: "1px solid #334155",
                            borderRadius: "10px",
                            color: "#e2e8f0",
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: "#67e8f9" }}
                          itemStyle={{ color: "#e2e8f0" }}
                        />
                        <Bar
                          dataKey="incidents"
                          name="Incidents"
                          fill="#22d3ee"
                          radius={[0, 6, 6, 0]}
                          barSize={12}
                        />
                        <Bar
                          dataKey="correlated"
                          name="Correlated"
                          fill="#34d399"
                          radius={[0, 6, 6, 0]}
                          barSize={12}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
                <div className="mb-2 flex items-center justify-between">
                  <h2 className="text-sm font-semibold">
                    Scenario quality breakdown
                  </h2>

                  <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                    {scenarioRows.length} scenario(s)
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="min-w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-2 py-1.5">Scenario</th>
                        <th className="px-2 py-1.5">Inc</th>
                        <th className="px-2 py-1.5">Corr</th>
                        <th className="px-2 py-1.5">High</th>
                        <th className="px-2 py-1.5">MITRE</th>
                        <th className="px-2 py-1.5">Avg</th>
                        <th className="px-2 py-1.5">Max</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/80">
                      {scenarioRows.map((row) => (
                        <tr key={row.scenario} className="hover:bg-slate-800/40">
                          <td className="max-w-[220px] truncate px-2 py-1.5 font-medium text-slate-100">
                            {scenarioLabel(row.scenario)}
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {row.incidents}
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {pct(row.correlated, row.incidents)}%
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {pct(row.high_or_critical, row.incidents)}%
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {pct(row.mitre_tagged, row.incidents)}%
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {row.avg_risk}
                          </td>
                          <td className="px-2 py-1.5">
                            <span
                              className={`rounded-md border px-1.5 py-0.5 text-[11px] ${
                                toneClasses(toneForScore(row.max_risk)).badge
                              }`}
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
                            className="px-2 py-4 text-center text-slate-500"
                          >
                            No synthetic scenario data available yet.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-2 flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">
                    Latest synthetic incidents
                  </h2>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Most recent synthetic detections loaded from the incident stream.
                  </p>
                </div>

                <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                  Showing {Math.min(syntheticIncidents.length, 25)}
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="px-2 py-1.5">ID</th>
                      <th className="px-2 py-1.5">Time</th>
                      <th className="px-2 py-1.5">Host</th>
                      <th className="px-2 py-1.5">Rule</th>
                      <th className="px-2 py-1.5">Priority</th>
                      <th className="px-2 py-1.5">Risk</th>
                      <th className="px-2 py-1.5">Correlation</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/80">
                    {syntheticIncidents.slice(0, 25).map((incident) => (
                      <tr key={incident.id} className="hover:bg-slate-800/40">
                        <td className="px-2 py-1.5">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="text-cyan-300 hover:text-cyan-200"
                          >
                            #{incident.id}
                          </Link>
                        </td>
                        <td className="whitespace-nowrap px-2 py-1.5 text-slate-300">
                          {formatTimestamp(
                            incident.timestamp_local ?? incident.timestamp
                          )}
                        </td>
                        <td className="max-w-[140px] truncate px-2 py-1.5 text-slate-300">
                          {incident.agent ?? "-"}
                        </td>
                        <td
                          className="max-w-xl truncate px-2 py-1.5 text-slate-300"
                          title={incident.rule ?? "-"}
                        >
                          {shortText(incident.rule, 120)}
                        </td>
                        <td className="px-2 py-1.5 text-slate-300">
                          {incident.recommended_priority ?? "-"}
                        </td>
                        <td className="px-2 py-1.5">
                          <span
                            className={`rounded-md border px-1.5 py-0.5 text-[11px] ${
                              toneClasses(
                                toneForScore(incident.risk_score ?? 0)
                              ).badge
                            }`}
                          >
                            {incident.risk_score ?? 0}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-slate-300">
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
                          className="px-2 py-4 text-center text-slate-500"
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

function QualityMetric({
  title,
  value,
  subtitle,
  icon,
  tone,
}: {
  title: string;
  value: string | number;
  subtitle: string;
  icon: ReactNode;
  tone: Tone;
}) {
  const classes = toneClasses(tone);

  return (
    <div className={`rounded-lg border px-3 py-2 shadow-sm ${classes.card}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
            {title}
          </div>
          <div className="mt-0.5 text-lg font-semibold leading-6 text-slate-100">
            {value}
          </div>
          <div className="truncate text-[11px] text-slate-500">{subtitle}</div>
        </div>

        <div className={`shrink-0 rounded-md bg-slate-950 p-1.5 ${classes.text}`}>
          {icon}
        </div>
      </div>
    </div>
  );
}
