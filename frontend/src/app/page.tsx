"use client";

import { authFetch } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  Brain,
  Briefcase,
  Clock,
  Database,
  RefreshCw,
  Server,
  Shield,
  Target,
  Zap,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import AppNavigation from "../components/AppNavigation";
import {
  EnterpriseBadge,
  EnterpriseButton,
  EnterpriseChartCard,
  EnterprisePageHeader,
  EnterpriseSection,
} from "../components/enterprise";

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
};

type IncidentsResponse = {
  items: Incident[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

type IncidentCase = {
  id: number;
  title: string;
  status: string | null;
  severity: string | null;
  severity_review?: string | null;
  owner: string | null;
  sla_status: string | null;
  agent?: string | null;
  incident_count: number;
  risk_score?: number | null;
  action_count: number | null;
  open_action_count: number | null;
  has_ai_analysis: boolean | null;
  has_closure_checklist: boolean | null;
  ready_to_close: boolean | null;
  queue_flags: string[] | null;
  updated_at: string | null;
};

type CasesResponse = {
  items: IncidentCase[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
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

type ChartRow = {
  name: string;
  value: number;
  color: string;
};

type EnterpriseTone =
  | "neutral"
  | "primary"
  | "success"
  | "warning"
  | "danger"
  | "executive";

const STATUS_OPTIONS = [
  "ALL",
  "NEW",
  "TRIAGED",
  "ESCALATED",
  "CLOSED",
  "FALSE_POSITIVE",
];

const RISK_OPTIONS = ["ALL", "low", "medium", "high", "critical"];
const PRIORITY_OPTIONS = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const CORRELATED_OPTIONS = [
  { label: "ALL", value: "ALL" },
  { label: "YES", value: "true" },
  { label: "NO", value: "false" },
];

const ACTIVE_CASE_STATUSES = new Set([
  "OPEN",
  "TRIAGED",
  "INVESTIGATING",
  "ESCALATED",
]);

const TERMINAL_CASE_STATUSES = new Set(["CLOSED", "FALSE_POSITIVE"]);

const CHART_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  primary: "#22d3ee",
  secondary: "#60a5fa",
  ai: "#a78bfa",
  muted: "#64748b",
  grid: "rgba(148, 163, 184, 0.14)",
  axis: "#94a3b8",
  panel: "#020617",
  tooltip: "#0f172a",
  border: "#334155",
  text: "#e2e8f0",
  cursor: "rgba(15, 23, 42, 0.42)",
};

const STATUS_CHART_COLORS: Record<string, string> = {
  NEW: CHART_COLORS.primary,
  OPEN: CHART_COLORS.primary,
  TRIAGED: CHART_COLORS.secondary,
  INVESTIGATING: CHART_COLORS.secondary,
  ESCALATED: CHART_COLORS.critical,
  CLOSED: CHART_COLORS.low,
  FALSE_POSITIVE: CHART_COLORS.muted,
};

function riskLabel(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 80) return "Critical";
  if (value >= 60) return "High";
  if (value >= 40) return "Medium";
  return "Low";
}

function riskTone(score: number | null | undefined): EnterpriseTone {
  const value = score ?? 0;

  if (value >= 80) return "danger";
  if (value >= 60) return "warning";
  if (value >= 40) return "warning";
  return "success";
}

function statusTone(status: string | null | undefined): EnterpriseTone {
  const value = status ?? "NEW";

  if (value === "ESCALATED") return "danger";
  if (value === "NEW" || value === "OPEN") return "primary";
  if (value === "TRIAGED" || value === "INVESTIGATING") return "primary";
  if (value === "CLOSED") return "success";
  if (value === "FALSE_POSITIVE") return "executive";

  return "neutral";
}

function severityTone(severity: string | null | undefined): EnterpriseTone {
  const value = (severity ?? "LOW").toUpperCase();

  if (value === "CRITICAL") return "danger";
  if (value === "HIGH") return "warning";
  if (value === "MEDIUM") return "warning";

  return "success";
}

function slaTone(slaStatus: string | null | undefined): EnterpriseTone {
  const value = (slaStatus ?? "UNKNOWN").toUpperCase();

  if (value === "BREACHED") return "danger";
  if (value === "AT_RISK") return "warning";
  if (value === "OK" || value === "WITHIN_SLA" || value === "COMPLETED") {
    return "success";
  }

  return "neutral";
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
    hour12: false,
  });
}

function shortTitle(value: string | null | undefined, maxLength = 88) {
  if (!value) return "-";
  if (value.length <= maxLength) return value;

  return `${value.slice(0, maxLength - 1)}…`;
}

function compactAxisLabel(value: string | number) {
  const label = String(value).replaceAll("_", " ");

  const labels: Record<string, string> = {
    "SLA breached": "SLA",
    "Open actions": "Actions",
    INVESTIGATING: "Investig.",
    "FALSE POSITIVE": "False pos.",
  };

  return labels[label] ?? label;
}

function compactYAxisNumber(value: string | number) {
  const numericValue = Number(value);

  if (!Number.isFinite(numericValue)) {
    return String(value);
  }

  if (Math.abs(numericValue) >= 1_000_000) {
    return `${Math.round(numericValue / 100_000) / 10}M`;
  }

  if (Math.abs(numericValue) >= 1_000) {
    return `${Math.round(numericValue / 100) / 10}k`;
  }

  return String(numericValue);
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await authFetch(path, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function Home() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [incidentsData, setIncidentsData] = useState<IncidentsResponse | null>(
    null
  );
  const [casesData, setCasesData] = useState<CasesResponse | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [topHosts, setTopHosts] = useState<TopHost[]>([]);
  const [riskDistribution, setRiskDistribution] =
    useState<RiskDistribution | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [priorityFilter, setPriorityFilter] = useState("ALL");
  const [correlatedFilter, setCorrelatedFilter] = useState("ALL");
  const [correlationTypeFilter, setCorrelationTypeFilter] = useState("");
  const [mitreFilter, setMitreFilter] = useState("");
  const [dateFromFilter, setDateFromFilter] = useState("");
  const [dateToFilter, setDateToFilter] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [searchFilter, setSearchFilter] = useState("");

  const incidents = useMemo(() => incidentsData?.items ?? [], [incidentsData?.items]);
  const cases = useMemo(() => casesData?.items ?? [], [casesData?.items]);
  const totalPages = incidentsData?.total_pages ?? 1;
  const totalIncidents = incidentsData?.total ?? 0;
  const totalCases = casesData?.total ?? 0;

  const loadDashboard = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const incidentParams = new URLSearchParams({
        page: String(currentPage),
        limit: "15",
      });

      if (statusFilter !== "ALL") {
        incidentParams.set("status", statusFilter);
      }

      if (riskFilter !== "ALL") {
        incidentParams.set("risk", riskFilter);
      }

      if (priorityFilter !== "ALL") {
        incidentParams.set("priority", priorityFilter);
      }

      if (correlatedFilter !== "ALL") {
        incidentParams.set("correlated", correlatedFilter);
      }

      if (correlationTypeFilter.trim()) {
        incidentParams.set("correlation_type", correlationTypeFilter.trim());
      }

      if (mitreFilter.trim()) {
        incidentParams.set("mitre", mitreFilter.trim());
      }

      if (dateFromFilter) {
        incidentParams.set("date_from", dateFromFilter);
      }

      if (dateToFilter) {
        incidentParams.set("date_to", dateToFilter);
      }

      if (hostFilter.trim()) {
        incidentParams.set("host", hostFilter.trim());
      }

      if (searchFilter.trim()) {
        incidentParams.set("search", searchFilter.trim());
      }

      const [
        summaryData,
        incidentsResponse,
        casesResponse,
        topHostsData,
        riskData,
      ] = await Promise.all([
        fetchJson<Summary>("/metrics/summary"),
        fetchJson<IncidentsResponse>(`/incidents?${incidentParams.toString()}`),
        fetchJson<CasesResponse>("/cases?limit=100"),
        fetchJson<TopHost[]>("/metrics/top-hosts?limit=8"),
        fetchJson<RiskDistribution>("/metrics/risk-distribution"),
      ]);

      setSummary(summaryData);
      setIncidentsData(incidentsResponse);
      setCasesData(casesResponse);
      setTopHosts(topHostsData);
      setRiskDistribution(riskData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [
    currentPage,
    statusFilter,
    riskFilter,
    priorityFilter,
    correlatedFilter,
    correlationTypeFilter,
    mitreFilter,
    dateFromFilter,
    dateToFilter,
    hostFilter,
    searchFilter,
  ]);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadDashboard();
    }, 0);

    const interval = window.setInterval(() => {
      void loadDashboard();
    }, 30000);

    return () => {
      window.clearTimeout(timeoutId);
      window.clearInterval(interval);
    };
  }, [loadDashboard]);

  const riskChartData = useMemo<ChartRow[]>(() => {
    if (!riskDistribution) return [];

    return [
      {
        name: "Low",
        value: riskDistribution.low_0_30,
        color: CHART_COLORS.low,
      },
      {
        name: "Medium",
        value: riskDistribution.medium_31_60,
        color: CHART_COLORS.medium,
      },
      {
        name: "High",
        value: riskDistribution.high_61_80,
        color: CHART_COLORS.high,
      },
      {
        name: "Critical",
        value: riskDistribution.critical_81_100,
        color: CHART_COLORS.critical,
      },
    ];
  }, [riskDistribution]);

  const caseMetrics = useMemo(() => {
    const activeCases = cases.filter((item) =>
      ACTIVE_CASE_STATUSES.has(item.status ?? "OPEN")
    );

    return {
      total: totalCases,
      active: activeCases.length,
      slaBreached: cases.filter((item) => item.sla_status === "BREACHED").length,
      readyToClose: cases.filter(
        (item) =>
          item.ready_to_close &&
          !TERMINAL_CASE_STATUSES.has(item.status ?? "OPEN")
      ).length,
      openActions: cases.filter((item) => (item.open_action_count ?? 0) > 0)
        .length,
      needsAi: cases.filter(
        (item) =>
          !item.has_ai_analysis &&
          !TERMINAL_CASE_STATUSES.has(item.status ?? "OPEN")
      ).length,
      needsClosure: cases.filter(
        (item) =>
          !item.has_closure_checklist &&
          !TERMINAL_CASE_STATUSES.has(item.status ?? "OPEN")
      ).length,
      unassigned: cases.filter(
        (item) =>
          !item.owner && !TERMINAL_CASE_STATUSES.has(item.status ?? "OPEN")
      ).length,
    };
  }, [cases, totalCases]);

  const caseStatusChartData = useMemo<ChartRow[]>(() => {
    const counts = new Map<string, number>();

    for (const item of cases) {
      const status = item.status ?? "OPEN";
      counts.set(status, (counts.get(status) ?? 0) + 1);
    }

    return Array.from(counts.entries())
      .map(([name, value]) => ({
        name,
        value,
        color: STATUS_CHART_COLORS[name] ?? CHART_COLORS.muted,
      }))
      .sort((a, b) => b.value - a.value);
  }, [cases]);

  const operationsChartData = useMemo<ChartRow[]>(() => {
    return [
      {
        name: "SLA breached",
        value: caseMetrics.slaBreached,
        color: CHART_COLORS.critical,
      },
      {
        name: "Open actions",
        value: caseMetrics.openActions,
        color: CHART_COLORS.high,
      },
      {
        name: "Needs AI",
        value: caseMetrics.needsAi,
        color: CHART_COLORS.ai,
      },
      {
        name: "Ready",
        value: caseMetrics.readyToClose,
        color: CHART_COLORS.low,
      },
    ];
  }, [caseMetrics]);

  const highPriorityCases = useMemo(() => {
    return [...cases]
      .filter((item) => !TERMINAL_CASE_STATUSES.has(item.status ?? "OPEN"))
      .sort((a, b) => {
        const scoreA =
          (a.sla_status === "BREACHED" ? 1000 : 0) +
          ((a.open_action_count ?? 0) > 0 ? 100 : 0) +
          (a.risk_score ?? 0);

        const scoreB =
          (b.sla_status === "BREACHED" ? 1000 : 0) +
          ((b.open_action_count ?? 0) > 0 ? 100 : 0) +
          (b.risk_score ?? 0);

        return scoreB - scoreA;
      })
      .slice(0, 8);
  }, [cases]);

  function resetFilters() {
    setStatusFilter("ALL");
    setRiskFilter("ALL");
    setPriorityFilter("ALL");
    setCorrelatedFilter("ALL");
    setCorrelationTypeFilter("");
    setMitreFilter("");
    setDateFromFilter("");
    setDateToFilter("");
    setHostFilter("");
    setSearchFilter("");
    setCurrentPage(1);
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <EnterprisePageHeader
          eyebrow="SOC Operations Console"
          title="AI SOC Dashboard"
          description="Compact operational view of incidents, case workflow, AI analysis coverage, SLA exposure and investigation backlog."
          icon={<Shield className="h-3.5 w-3.5" />}
          actions={
            <EnterpriseButton
              onClick={loadDashboard}
              tone="secondary"
              size="sm"
              icon={
                <RefreshCw
                  className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
                />
              }
            >
              Refresh
            </EnterpriseButton>
          }
        />

        {error && (
          <div className="mb-2 rounded-sm border border-red-800 bg-red-950/60 p-2.5 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <EnterpriseSection>
            <div className="text-xs text-slate-300">Loading dashboard...</div>
          </EnterpriseSection>
        ) : (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8">
              <DashboardKpi
                title="Incidents"
                value={summary?.total_incidents ?? 0}
                subtitle="Total observed"
                tone="primary"
                icon={<Database className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="Avg risk"
                value={summary?.average_risk_score ?? 0}
                subtitle="Current dataset"
                icon={<Activity className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="Max risk"
                value={summary?.max_risk_score ?? 0}
                subtitle={riskLabel(summary?.max_risk_score)}
                tone={riskTone(summary?.max_risk_score)}
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="Correlated"
                value={summary?.correlated_incidents ?? 0}
                subtitle="AI correlation"
                tone="executive"
                icon={<Brain className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="Cases"
                value={caseMetrics.total}
                subtitle={`${caseMetrics.active} active`}
                tone="primary"
                icon={<Briefcase className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="SLA breach"
                value={caseMetrics.slaBreached}
                subtitle="Immediate attention"
                tone={caseMetrics.slaBreached > 0 ? "danger" : "success"}
                icon={<Clock className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="Open actions"
                value={caseMetrics.openActions}
                subtitle="Cases with tasks"
                tone={caseMetrics.openActions > 0 ? "warning" : "success"}
                icon={<Zap className="h-3.5 w-3.5" />}
              />

              <DashboardKpi
                title="Needs AI"
                value={caseMetrics.needsAi}
                subtitle="Open cases"
                tone={caseMetrics.needsAi > 0 ? "warning" : "success"}
                icon={<Target className="h-3.5 w-3.5" />}
              />
            </section>

            <section className="grid gap-2 xl:grid-cols-3">
              <EnterpriseChartCard
                title="Incident Risk Distribution"
                description="Current incident distribution by calculated risk band."
                height="h-36"
              >
                <DashboardBarChart data={riskChartData} valueLabel="Incidents" />
              </EnterpriseChartCard>

              <EnterpriseChartCard
                title="Case Status Distribution"
                description="Investigation cases grouped by operational status."
                height="h-36"
              >
                <DashboardBarChart data={caseStatusChartData} valueLabel="Cases" />
              </EnterpriseChartCard>

              <EnterpriseChartCard
                title="Operational Backlog"
                description="SLA, actions, AI coverage and closure readiness."
                height="h-36"
              >
                <DashboardBarChart data={operationsChartData} valueLabel="Cases" />
              </EnterpriseChartCard>
            </section>

            <section className="grid gap-2 xl:grid-cols-[1.25fr_0.75fr]">
              <EnterpriseSection
                title="Priority Case Queue"
                description="Highest operational attention based on SLA breach, open actions and risk."
                actions={
                  <>
                    <EnterpriseButton href="/cases" tone="primary" size="xs">
                      Open Queue
                    </EnterpriseButton>
                    <EnterpriseButton href="/cases/kanban" tone="secondary" size="xs">
                      Kanban
                    </EnterpriseButton>
                  </>
                }
              >
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="py-1.5 pr-2">Case</th>
                        <th className="py-1.5 pr-2">Status</th>
                        <th className="py-1.5 pr-2">Severity</th>
                        <th className="py-1.5 pr-2">SLA</th>
                        <th className="py-1.5 pr-2">Owner</th>
                        <th className="py-1.5 pr-2">Actions</th>
                        <th className="py-1.5 pr-2">AI</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/80">
                      {highPriorityCases.map((item) => {
                        const effectiveSeverity =
                          item.severity_review ?? item.severity ?? "LOW";

                        return (
                          <tr key={item.id} className="hover:bg-slate-800/40">
                            <td className="max-w-md py-1.5 pr-2">
                              <Link
                                href={`/cases/${item.id}`}
                                className="font-medium text-cyan-300 hover:text-cyan-200"
                              >
                                #{item.id} {shortTitle(item.title, 72)}
                              </Link>
                              <div className="mt-0.5 text-[11px] text-slate-500">
                                {item.incident_count} incident(s) · updated{" "}
                                {formatTimestamp(item.updated_at)}
                              </div>
                            </td>

                            <td className="py-1.5 pr-2">
                              <EnterpriseBadge tone={statusTone(item.status)}>
                                {item.status ?? "OPEN"}
                              </EnterpriseBadge>
                            </td>

                            <td className="py-1.5 pr-2">
                              <EnterpriseBadge tone={severityTone(effectiveSeverity)}>
                                {effectiveSeverity}
                              </EnterpriseBadge>
                            </td>

                            <td className="py-1.5 pr-2">
                              <EnterpriseBadge tone={slaTone(item.sla_status)}>
                                {item.sla_status ?? "UNKNOWN"}
                              </EnterpriseBadge>
                            </td>

                            <td className="py-2 pr-3 text-slate-300">
                              {item.owner ?? "unassigned"}
                            </td>

                            <td className="py-2 pr-3 text-slate-300">
                              {item.open_action_count ?? 0}/{item.action_count ?? 0} open
                            </td>

                            <td className="py-1.5 pr-2">
                              <EnterpriseBadge
                                tone={item.has_ai_analysis ? "success" : "warning"}
                              >
                                {item.has_ai_analysis ? "ready" : "missing"}
                              </EnterpriseBadge>
                            </td>
                          </tr>
                        );
                      })}

                      {highPriorityCases.length === 0 && (
                        <tr>
                          <td colSpan={7} className="py-6 text-center text-slate-500">
                            No active priority cases found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </EnterpriseSection>

              <EnterpriseSection
                title="Top Noisy Hosts"
                description="Hosts generating the highest alert volume."
              >
                <div className="space-y-2">
                  {topHosts.map((host) => (
                    <div
                      key={host.agent ?? "unknown"}
                      className="flex items-center justify-between gap-3 rounded-sm border border-slate-800 bg-slate-950 px-2.5 py-2"
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <Server className="h-3.5 w-3.5 shrink-0 text-cyan-300" />

                        <div className="min-w-0">
                          <div className="truncate text-xs font-medium text-slate-200">
                            {host.agent ?? "unknown"}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {host.count} incident(s)
                          </div>
                        </div>
                      </div>

                      <EnterpriseBadge tone={riskTone(host.max_risk)}>
                        max {host.max_risk ?? 0}
                      </EnterpriseBadge>
                    </div>
                  ))}

                  {topHosts.length === 0 && (
                    <div className="rounded-md border border-slate-800 bg-slate-950 p-2 text-xs text-slate-500">
                      No host data available.
                    </div>
                  )}
                </div>
              </EnterpriseSection>
            </section>

            <EnterpriseSection
              title="Incident Stream"
              description="Recent Wazuh incidents with AI risk, priority and correlation metadata."
              actions={
                <EnterpriseBadge tone="muted">
                  Auto refresh 30s · page {currentPage}/{totalPages}
                </EnterpriseBadge>
              }
            >
              <div className="mb-2 grid gap-2 rounded-sm border border-slate-800 bg-slate-950 p-2 md:grid-cols-4 xl:grid-cols-6">
                <FilterSelect
                  label="Status"
                  value={statusFilter}
                  onChange={(value) => {
                    setStatusFilter(value);
                    setCurrentPage(1);
                  }}
                  options={STATUS_OPTIONS}
                />

                <FilterSelect
                  label="Risk"
                  value={riskFilter}
                  onChange={(value) => {
                    setRiskFilter(value);
                    setCurrentPage(1);
                  }}
                  options={RISK_OPTIONS.map((risk) => risk.toUpperCase())}
                  rawOptions={RISK_OPTIONS}
                />

                <FilterSelect
                  label="Priority"
                  value={priorityFilter}
                  onChange={(value) => {
                    setPriorityFilter(value);
                    setCurrentPage(1);
                  }}
                  options={PRIORITY_OPTIONS}
                />

                <FilterSelect
                  label="Correlated"
                  value={correlatedFilter}
                  onChange={(value) => {
                    setCorrelatedFilter(value);
                    setCurrentPage(1);
                  }}
                  options={CORRELATED_OPTIONS.map((item) => item.label)}
                  rawOptions={CORRELATED_OPTIONS.map((item) => item.value)}
                />

                <FilterInput
                  label="Host"
                  value={hostFilter}
                  onChange={(value) => {
                    setHostFilter(value);
                    setCurrentPage(1);
                  }}
                  placeholder="wazuh.manager"
                />

                <FilterInput
                  label="Rule"
                  value={searchFilter}
                  onChange={(value) => {
                    setSearchFilter(value);
                    setCurrentPage(1);
                  }}
                  placeholder="ssh, sudo, CIS"
                />

                <FilterInput
                  label="Correlation"
                  value={correlationTypeFilter}
                  onChange={(value) => {
                    setCorrelationTypeFilter(value);
                    setCurrentPage(1);
                  }}
                  placeholder="COMPROMISE"
                />

                <FilterInput
                  label="MITRE"
                  value={mitreFilter}
                  onChange={(value) => {
                    setMitreFilter(value);
                    setCurrentPage(1);
                  }}
                  placeholder="T1078"
                />

                <FilterInput
                  label="From"
                  value={dateFromFilter}
                  onChange={(value) => {
                    setDateFromFilter(value);
                    setCurrentPage(1);
                  }}
                  type="date"
                />

                <FilterInput
                  label="To"
                  value={dateToFilter}
                  onChange={(value) => {
                    setDateToFilter(value);
                    setCurrentPage(1);
                  }}
                  type="date"
                />

                <div className="flex items-end xl:col-span-2">
                  <EnterpriseButton
                    onClick={resetFilters}
                    tone="ghost"
                    size="sm"
                    className="w-full"
                  >
                    Reset filters
                  </EnterpriseButton>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="py-1.5 pr-2">ID</th>
                      <th className="py-1.5 pr-2">Status</th>
                      <th className="py-1.5 pr-2">Time</th>
                      <th className="py-1.5 pr-2">Host</th>
                      <th className="py-1.5 pr-2">Rule</th>
                      <th className="py-1.5 pr-2">Level</th>
                      <th className="py-1.5 pr-2">Risk</th>
                      <th className="py-1.5 pr-2">Priority</th>
                      <th className="py-1.5 pr-2">Correlation</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/80">
                    {incidents.map((incident) => (
                      <tr key={incident.id} className="hover:bg-slate-800/40">
                        <td className="py-1.5 pr-2">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="font-medium text-cyan-300 hover:text-cyan-200"
                          >
                            #{incident.id}
                          </Link>
                        </td>

                        <td className="py-1.5 pr-2">
                          <EnterpriseBadge tone={statusTone(incident.status)}>
                            {incident.status ?? "NEW"}
                          </EnterpriseBadge>
                        </td>

                        <td className="whitespace-nowrap py-2 pr-3 text-slate-400">
                          {incident.timestamp_local ??
                            formatTimestamp(incident.timestamp)}
                        </td>

                        <td className="max-w-[160px] truncate py-2 pr-3 text-slate-300">
                          {incident.agent ?? "unknown"}
                        </td>

                        <td className="max-w-xl py-2 pr-3 text-slate-300">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="line-clamp-1 hover:text-cyan-200"
                          >
                            {incident.rule ?? "-"}
                          </Link>
                        </td>

                        <td className="py-2 pr-3 text-slate-300">
                          {incident.level ?? 0}
                        </td>

                        <td className="py-1.5 pr-2">
                          <EnterpriseBadge tone={riskTone(incident.risk_score)}>
                            {riskLabel(incident.risk_score)} ·{" "}
                            {incident.risk_score ?? 0}
                          </EnterpriseBadge>
                        </td>

                        <td className="py-1.5 pr-2">
                          <EnterpriseBadge tone={riskTone(incident.risk_score)}>
                            {incident.recommended_priority ??
                              riskLabel(incident.risk_score)}
                          </EnterpriseBadge>
                        </td>

                        <td className="py-1.5 pr-2">
                          {incident.correlated ? (
                            <div>
                              <div className="text-cyan-300">
                                {incident.correlation_score ?? 0}
                              </div>
                              <div className="max-w-[180px] truncate text-[11px] text-slate-500">
                                {incident.correlation_type ?? "correlated"}
                              </div>
                            </div>
                          ) : (
                            <span className="text-slate-500">No</span>
                          )}
                        </td>
                      </tr>
                    ))}

                    {incidents.length === 0 && (
                      <tr>
                        <td colSpan={9} className="py-6 text-center text-slate-500">
                          No incidents found with current filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="mt-2 flex flex-col gap-3 border-t border-slate-800 pt-3 text-xs text-slate-400 md:flex-row md:items-center md:justify-between">
                <div>
                  Showing page{" "}
                  <span className="font-medium text-slate-200">{currentPage}</span>{" "}
                  of{" "}
                  <span className="font-medium text-slate-200">{totalPages}</span>{" "}
                  —{" "}
                  <span className="font-medium text-slate-200">
                    {totalIncidents}
                  </span>{" "}
                  incidents
                </div>

                <div className="flex items-center gap-2">
                  <EnterpriseButton
                    onClick={() => setCurrentPage((page) => Math.max(page - 1, 1))}
                    disabled={currentPage <= 1}
                    tone="secondary"
                    size="xs"
                  >
                    Previous
                  </EnterpriseButton>

                  <EnterpriseBadge tone="primary">{currentPage}</EnterpriseBadge>

                  <EnterpriseButton
                    onClick={() =>
                      setCurrentPage((page) => Math.min(page + 1, totalPages))
                    }
                    disabled={currentPage >= totalPages}
                    tone="secondary"
                    size="xs"
                  >
                    Next
                  </EnterpriseButton>
                </div>
              </div>
            </EnterpriseSection>
          </div>
        )}
      </div>
    </main>
  );
}

const dashboardKpiToneClasses: Record<EnterpriseTone, string> = {
  neutral: "border-slate-800 bg-slate-900 text-slate-100",
  primary: "border-cyan-900 bg-cyan-950/30 text-cyan-100",
  success: "border-emerald-900 bg-emerald-950/30 text-emerald-100",
  warning: "border-orange-900 bg-orange-950/30 text-orange-100",
  danger: "border-red-900 bg-red-950/30 text-red-100",
  executive: "border-violet-900 bg-violet-950/30 text-violet-100",
};

const dashboardKpiIconClasses: Record<EnterpriseTone, string> = {
  neutral: "bg-slate-950 text-slate-400",
  primary: "bg-cyan-950 text-cyan-300",
  success: "bg-emerald-950 text-emerald-300",
  warning: "bg-orange-950 text-orange-300",
  danger: "bg-red-950 text-red-300",
  executive: "bg-violet-950 text-violet-300",
};

function DashboardKpi({
  title,
  value,
  subtitle,
  tone = "neutral",
  icon,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  tone?: EnterpriseTone;
  icon: ReactNode;
}) {
  return (
    <div
      className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${dashboardKpiToneClasses[tone]}`}
    >
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
          <span className="text-xl font-semibold leading-6">{value}</span>
          {subtitle && (
            <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500">
              {subtitle}
            </span>
          )}
        </div>
      </div>
      <div className={`shrink-0 rounded-sm p-1.5 ${dashboardKpiIconClasses[tone]}`}>
        {icon}
      </div>
    </div>
  );
}

function DashboardBarChart({
  data,
  valueLabel,
}: {
  data: ChartRow[];
  valueLabel: string;
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart
        data={data}
        barCategoryGap="30%"
        margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
      >
        <CartesianGrid
          vertical={false}
          stroke={CHART_COLORS.grid}
          strokeDasharray="2 4"
        />
        <XAxis
          dataKey="name"
          tick={{ fill: CHART_COLORS.axis, fontSize: 10 }}
          axisLine={{ stroke: CHART_COLORS.grid }}
          tickLine={false}
          tickFormatter={compactAxisLabel}
          minTickGap={4}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fill: CHART_COLORS.axis, fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          tickFormatter={compactYAxisNumber}
          tickMargin={4}
          width={44}
        />
        <Tooltip
          cursor={{ fill: CHART_COLORS.cursor }}
          contentStyle={{
            backgroundColor: CHART_COLORS.tooltip,
            border: `1px solid ${CHART_COLORS.border}`,
            borderRadius: "3px",
            color: CHART_COLORS.text,
            fontSize: "12px",
          }}
          itemStyle={{ color: CHART_COLORS.text }}
          labelStyle={{ color: CHART_COLORS.primary }}
          formatter={(value) => [value, valueLabel]}
        />
        <Bar
          dataKey="value"
          name={valueLabel}
          radius={[2, 2, 0, 0]}
          maxBarSize={42}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
  rawOptions,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
  rawOptions?: string[];
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>

      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-200 outline-none focus:border-cyan-700"
      >
        {options.map((option, index) => (
          <option key={`${option}-${index}`} value={rawOptions?.[index] ?? option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function FilterInput({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>

      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-8 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-700"
      />
    </label>
  );
}
