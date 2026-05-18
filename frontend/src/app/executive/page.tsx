"use client";

import { authFetch } from "@/lib/auth";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  AlertTriangle,
  BarChart3,
  Briefcase,
  CheckCircle2,
  Clock,
  RefreshCw,
  Server,
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

type Tone = "success" | "warning" | "danger" | "primary" | "neutral" | "executive";

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

function shortTimestamp(value: string | null | undefined) {
  const formatted = formatTimestamp(value);
  if (formatted === "-") return "-";

  return formatted.replace(", ", " · ");
}

function shortText(value: string | null | undefined, max = 96) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

function toneForRisk(score: number | null | undefined): Tone {
  const value = score ?? 0;

  if (value >= 80) return "danger";
  if (value >= 60) return "warning";
  if (value >= 40) return "primary";
  return "success";
}

function toneForStatus(status: string | null | undefined): Tone {
  const value = status ?? "OK";

  if (value === "CRITICAL" || value === "ESCALATED") return "danger";
  if (value === "ATTENTION" || value === "HIGH") return "warning";
  if (value === "MEDIUM" || value === "TRIAGED") return "primary";
  if (value === "CLOSED") return "success";
  if (value === "FALSE_POSITIVE") return "executive";

  return "success";
}

function statusMessage(status: ExecutiveStatus) {
  if (status === "OK") return "No immediate executive escalation";
  if (status === "ATTENTION") return "Management attention recommended";
  if (status === "CRITICAL") return "Immediate executive review required";
  return "Executive posture requires review";
}

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { card: string; badge: string; text: string; bar: string }> = {
    success: {
      card: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
      bar: "bg-emerald-400",
    },
    warning: {
      card: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
      bar: "bg-orange-400",
    },
    danger: {
      card: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
      bar: "bg-red-400",
    },
    primary: {
      card: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
      bar: "bg-cyan-400",
    },
    neutral: {
      card: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
      bar: "bg-slate-400",
    },
    executive: {
      card: "border-violet-900/70 bg-violet-950/20",
      badge: "border-violet-700 bg-violet-950 text-violet-200",
      text: "text-violet-300",
      bar: "bg-violet-400",
    },
  };

  return classes[tone];
}

async function fetchExecutiveSummary(): Promise<ExecutiveSummary> {
  const response = await authFetch(`/executive/summary`, {
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
    return Object.entries(data?.distributions.incident_status ?? {}).sort(
      (a, b) => b[1] - a[1]
    );
  }, [data]);

  const caseStatusRows = useMemo(() => {
    return Object.entries(data?.distributions.case_status ?? {}).sort(
      (a, b) => b[1] - a[1]
    );
  }, [data]);

  const priorityRows = useMemo(() => {
    return Object.entries(data?.distributions.priority ?? {}).sort(
      (a, b) => b[1] - a[1]
    );
  }, [data]);

  const totalDistributionItems = useMemo(() => {
    const allRows = [...incidentStatusRows, ...caseStatusRows, ...priorityRows];
    return Math.max(...allRows.map(([, value]) => value), 1);
  }, [incidentStatusRows, caseStatusRows, priorityRows]);

  const postureTone: Tone =
    data?.status === "CRITICAL"
      ? "danger"
      : data?.status === "ATTENTION"
        ? "warning"
        : "success";

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
              <BarChart3 className="h-3.5 w-3.5" />
              Executive Summary
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Executive Dashboard
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Compact management view of SOC posture, open risk, case backlog,
              correlation coverage and recommended operational focus.
            </p>
          </div>

          <button
            onClick={loadExecutiveSummary}
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
            Loading executive summary...
          </section>
        ) : data ? (
          <div className="space-y-3">
            <section className="grid gap-2 lg:grid-cols-[360px_1fr]">
              <div className={`rounded-lg border p-3 shadow-sm ${toneClasses(postureTone).card}`}>
                <div className="mb-2 flex items-start justify-between gap-3">
                  <div>
                    <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
                      Overall SOC posture
                    </div>
                    <div className="mt-1 flex items-center gap-2">
                      <div className={toneClasses(postureTone).text}>
                        {data.status === "CRITICAL" ? (
                          <AlertTriangle className="h-4 w-4" />
                        ) : data.status === "ATTENTION" ? (
                          <ShieldAlert className="h-4 w-4" />
                        ) : (
                          <CheckCircle2 className="h-4 w-4" />
                        )}
                      </div>
                      <div className="text-xl font-semibold leading-7 text-slate-100">
                        {data.status}
                      </div>
                    </div>
                  </div>

                  <span className={`shrink-0 rounded-md border px-2 py-1 text-[11px] ${toneClasses(postureTone).badge}`}>
                    {statusMessage(data.status)}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-2 text-[11px] text-slate-500">
                  <MiniStat label="Open cases" value={data.summary.open_cases} />
                  <MiniStat label="Critical cases" value={data.summary.critical_cases} />
                  <MiniStat label="Max risk" value={data.summary.max_risk_score} />
                </div>
              </div>

              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <ExecutiveMetric
                  title="Open incidents"
                  value={data.summary.open_incidents}
                  subtitle={`${data.summary.total_incidents} total`}
                  tone={data.summary.open_incidents > 0 ? "primary" : "success"}
                  icon={<AlertTriangle className="h-4 w-4" />}
                />
                <ExecutiveMetric
                  title="High / Critical"
                  value={data.summary.high_or_critical_incidents}
                  subtitle="Incident exposure"
                  tone={data.summary.high_or_critical_incidents > 0 ? "warning" : "success"}
                  icon={<ShieldAlert className="h-4 w-4" />}
                />
                <ExecutiveMetric
                  title="Open cases"
                  value={data.summary.open_cases}
                  subtitle={`${data.summary.total_cases} total`}
                  tone={data.summary.open_cases > 0 ? "primary" : "success"}
                  icon={<Briefcase className="h-4 w-4" />}
                />
                <ExecutiveMetric
                  title="Max risk"
                  value={data.summary.max_risk_score}
                  subtitle={`Avg ${data.summary.average_risk_score}`}
                  tone={toneForRisk(data.summary.max_risk_score)}
                  icon={<TrendingUp className="h-4 w-4" />}
                />
              </div>
            </section>

            <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <ExecutiveMetric
                title="Total incidents"
                value={data.summary.total_incidents}
                subtitle="All observed"
                tone="neutral"
                icon={<BarChart3 className="h-4 w-4" />}
              />
              <ExecutiveMetric
                title="Correlated"
                value={data.summary.correlated_incidents}
                subtitle="AI correlation"
                tone="executive"
                icon={<TrendingUp className="h-4 w-4" />}
              />
              <ExecutiveMetric
                title="Escalated incidents"
                value={data.summary.escalated_incidents}
                subtitle="Needs review"
                tone={data.summary.escalated_incidents > 0 ? "danger" : "success"}
                icon={<AlertTriangle className="h-4 w-4" />}
              />
              <ExecutiveMetric
                title="Escalated cases"
                value={data.summary.escalated_cases}
                subtitle="Management queue"
                tone={data.summary.escalated_cases > 0 ? "danger" : "success"}
                icon={<Briefcase className="h-4 w-4" />}
              />
            </section>

            <section className="grid items-stretch gap-3 xl:grid-cols-4">
              <DistributionCard
                title="Incident status"
                rows={incidentStatusRows}
                maxValue={totalDistributionItems}
              />

              <DistributionCard
                title="Case status"
                rows={caseStatusRows}
                maxValue={totalDistributionItems}
              />

              <DistributionCard
                title="Priority"
                rows={priorityRows}
                maxValue={totalDistributionItems}
              />

              <div className="flex h-full flex-col rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold">
                      Recommended operational focus
                    </h2>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      Executive-level focus points.
                    </p>
                  </div>

                  <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                    {data.recommendations.length}
                  </span>
                </div>

                {data.recommendations.length === 0 ? (
                  <div className="rounded-md border border-slate-800 bg-slate-950 p-2 text-xs text-slate-500">
                    No recommendations available.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {data.recommendations.slice(0, 4).map((item, index) => (
                      <div
                        key={`${item}-${index}`}
                        className="rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs leading-5 text-slate-300"
                        title={item}
                      >
                        <div className="mb-0.5 text-[10px] uppercase tracking-wide text-cyan-300">
                          Focus #{index + 1}
                        </div>
                        <div className="line-clamp-2">{item}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>

            <section className="grid gap-3 xl:grid-cols-2">
              <CompactListCard title="Top risk hosts">
                {data.top_hosts.length === 0 ? (
                  <EmptyState label="No host data available." />
                ) : (
                  data.top_hosts.slice(0, 8).map((host) => (
                    <div
                      key={host.agent ?? "unknown"}
                      className="flex items-center justify-between gap-3 rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5"
                    >
                      <div className="min-w-0">
                        <div className="truncate text-xs font-medium text-slate-200">
                          {host.agent ?? "unknown"}
                        </div>
                        <div className="text-[11px] text-slate-500">
                          {host.count} incident(s) · avg {host.average_risk}
                        </div>
                      </div>

                      <span className={`shrink-0 rounded-md border px-2 py-0.5 text-[11px] ${toneClasses(toneForRisk(host.max_risk)).badge}`}>
                        max {host.max_risk}
                      </span>
                    </div>
                  ))
                )}
              </CompactListCard>

              <CompactListCard title="Top correlation types">
                {data.top_correlation_types.length === 0 ? (
                  <EmptyState label="No correlation data available." />
                ) : (
                  data.top_correlation_types.slice(0, 8).map((item) => (
                    <div
                      key={item.correlation_type ?? "unknown"}
                      className="flex items-center justify-between gap-3 rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5"
                    >
                      <div
                        className="min-w-0 truncate text-xs text-slate-300"
                        title={item.correlation_type ?? "unknown"}
                      >
                        {item.correlation_type ?? "unknown"}
                      </div>

                      <span className="shrink-0 rounded-md border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-300">
                        {item.count}
                      </span>
                    </div>
                  ))
                )}
              </CompactListCard>
            </section>

            <section className="grid gap-3 xl:grid-cols-2">
              <CompactTableCard title="Latest cases" count={data.latest_cases.length}>
                {data.latest_cases.length === 0 ? (
                  <EmptyTable colSpan={5} label="No cases available." />
                ) : (
                  <table className="min-w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-2 py-1.5">Case</th>
                        <th className="px-2 py-1.5">Status</th>
                        <th className="px-2 py-1.5">Severity</th>
                        <th className="px-2 py-1.5">Risk</th>
                        <th className="px-2 py-1.5">Updated</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/80">
                      {data.latest_cases.slice(0, 10).map((item) => (
                        <tr key={item.id} className="hover:bg-slate-800/40">
                          <td className="max-w-md truncate px-2 py-1.5">
                            <Link
                              href={`/cases/${item.id}`}
                              className="text-cyan-300 hover:text-cyan-200"
                              title={item.title}
                            >
                              #{item.id} {shortText(item.title, 70)}
                            </Link>
                          </td>

                          <td className="px-2 py-1.5">
                            <Badge tone={toneForStatus(item.status)}>
                              {item.status ?? "OPEN"}
                            </Badge>
                          </td>

                          <td className="px-2 py-1.5">
                            <Badge tone={toneForStatus(item.severity)}>
                              {item.severity ?? "LOW"}
                            </Badge>
                          </td>

                          <td className="px-2 py-1.5 text-slate-300">
                            {item.risk_score ?? 0}
                          </td>

                          <td className="whitespace-nowrap px-2 py-1.5 text-slate-400">
                            {shortTimestamp(item.updated_at)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </CompactTableCard>

              <CompactTableCard
                title="Latest high-risk incidents"
                count={data.latest_high_risk_incidents.length}
              >
                {data.latest_high_risk_incidents.length === 0 ? (
                  <EmptyTable colSpan={6} label="No high-risk incidents available." />
                ) : (
                  <table className="min-w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-2 py-1.5">ID</th>
                        <th className="px-2 py-1.5">Time</th>
                        <th className="px-2 py-1.5">Host</th>
                        <th className="px-2 py-1.5">Rule</th>
                        <th className="px-2 py-1.5">Risk</th>
                        <th className="px-2 py-1.5">Priority</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/80">
                      {data.latest_high_risk_incidents.slice(0, 10).map((incident) => (
                        <tr key={incident.id} className="hover:bg-slate-800/40">
                          <td className="px-2 py-1.5">
                            <Link
                              href={`/incidents/${incident.id}`}
                              className="text-cyan-300 hover:text-cyan-200"
                            >
                              #{incident.id}
                            </Link>
                          </td>

                          <td className="whitespace-nowrap px-2 py-1.5 text-slate-400">
                            {shortTimestamp(
                              incident.timestamp_local ?? incident.timestamp
                            )}
                          </td>

                          <td className="max-w-[120px] truncate px-2 py-1.5 text-slate-300">
                            {incident.agent ?? "unknown"}
                          </td>

                          <td
                            className="max-w-md truncate px-2 py-1.5 text-slate-300"
                            title={incident.rule ?? "-"}
                          >
                            {shortText(incident.rule, 86)}
                          </td>

                          <td className="px-2 py-1.5">
                            <Badge tone={toneForRisk(incident.risk_score)}>
                              {incident.risk_score ?? 0}
                            </Badge>
                          </td>

                          <td className="px-2 py-1.5 text-slate-400">
                            {incident.recommended_priority ?? "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </CompactTableCard>
            </section>
          </div>
        ) : null}
      </div>
    </main>
  );
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="truncate text-xs font-semibold text-slate-200">
        {value}
      </div>
    </div>
  );
}

function ExecutiveMetric({
  title,
  value,
  subtitle,
  tone,
  icon,
}: {
  title: string;
  value: string | number;
  subtitle: string;
  tone: Tone;
  icon: ReactNode;
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

function DistributionCard({
  title,
  rows,
  maxValue,
}: {
  title: string;
  rows: Array<[string, number]>;
  maxValue: number;
}) {
  return (
    <div className="flex h-full flex-col rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
          {rows.length}
        </span>
      </div>

      {rows.length === 0 ? (
        <EmptyState label="No data available." />
      ) : (
        <div className="space-y-1.5">
          {rows.slice(0, 5).map(([label, value]) => {
            const width = Math.max(8, Math.round((value / maxValue) * 100));
            const tone = toneForStatus(label);
            const classes = toneClasses(tone);

            return (
              <div key={label} className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="truncate text-xs text-slate-300">{label}</span>
                  <span className="text-[11px] text-slate-500">{value}</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-800">
                  <div
                    className={`h-1.5 rounded-full ${classes.bar}`}
                    style={{ width: `${width}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function CompactListCard({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">{title}</h2>
      </div>

      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function CompactTableCard({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
          {count}
        </span>
      </div>

      <div className="overflow-x-auto">{children}</div>
    </div>
  );
}

function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`rounded-md border px-1.5 py-0.5 text-[11px] ${toneClasses(tone).badge}`}>
      {children}
    </span>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-2 text-xs text-slate-500">
      {label}
    </div>
  );
}

function EmptyTable({ colSpan, label }: { colSpan: number; label: string }) {
  return (
    <table className="min-w-full text-left text-xs">
      <tbody>
        <tr>
          <td colSpan={colSpan} className="px-2 py-4 text-center text-slate-500">
            {label}
          </td>
        </tr>
      </tbody>
    </table>
  );
}
