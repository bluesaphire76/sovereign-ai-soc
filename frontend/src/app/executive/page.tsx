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
  decision_brief?: {
    decision: string;
    reason: string;
    next_action: string;
  };
  sla_posture?: {
    status: string;
    open_cases: number;
    cases_with_sla: number;
    on_track: number;
    due_soon: number;
    overdue: number;
    missing_sla: number;
    coverage_percent: number;
  };
  ai_triage_contribution?: {
    incident_ai_analyzed: number;
    total_incidents: number;
    incident_coverage_percent: number;
    case_ai_analyzed: number;
    total_cases: number;
    case_coverage_percent: number;
    total_case_analyses: number;
    overall_coverage_percent: number;
    latest_analysis_at: string | null;
  };
  noise_reduction?: {
    raw_events: number;
    security_alerts: number;
    incidents_created: number;
    incident_created_alerts: number;
    observed_only_alerts: number;
    event_aggregates: number;
    duplicate_events_collapsed: number;
    incident_creation_rate_percent: number;
    reduction_percent: number;
  };
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

type ExposureCategory = "Incidents" | "Cases" | "Priority";

type ExposureRow = {
  category: ExposureCategory;
  label: string;
  value: number;
  total: number;
};

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

  return formatted.replace(", ", " - ");
}

function shortText(value: string | null | undefined, max = 96) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}...`;
}

function toneForRisk(score: number | null | undefined): Tone {
  const value = score ?? 0;

  if (value >= 80) return "danger";
  if (value >= 60) return "warning";
  if (value >= 40) return "primary";
  return "success";
}

function toneForStatus(status: string | null | undefined): Tone {
  const value = (status ?? "OK").toUpperCase();

  if (value === "BREACHED") return "danger";
  if (value === "CRITICAL" || value === "ESCALATED") return "danger";
  if (value === "ATTENTION" || value === "HIGH") return "warning";
  if (value === "MEDIUM" || value === "TRIAGED" || value === "INVESTIGATING") {
    return "primary";
  }
  if (value === "CLOSED" || value === "RESOLVED" || value === "OK") return "success";
  if (value === "FALSE_POSITIVE") return "executive";

  return "neutral";
}

function toneForDecision(decision: string | null | undefined): Tone {
  const value = (decision ?? "MONITOR").toUpperCase();

  if (value === "ESCALATE") return "danger";
  if (value === "REVIEW") return "warning";
  if (value === "MONITOR") return "success";

  return "neutral";
}

function statusMessage(status: ExecutiveStatus) {
  if (status === "OK") return "No immediate executive escalation";
  if (status === "ATTENTION") return "Management attention recommended";
  if (status === "CRITICAL") return "Immediate executive review required";
  return "Executive posture requires review";
}

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { panel: string; badge: string; text: string; bar: string }> = {
    success: {
      panel: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
      bar: "bg-emerald-400",
    },
    warning: {
      panel: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
      bar: "bg-orange-400",
    },
    danger: {
      panel: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
      bar: "bg-red-400",
    },
    primary: {
      panel: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
      bar: "bg-cyan-400",
    },
    neutral: {
      panel: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
      bar: "bg-slate-400",
    },
    executive: {
      panel: "border-violet-900/70 bg-violet-950/20",
      badge: "border-violet-700 bg-violet-950 text-violet-200",
      text: "text-violet-300",
      bar: "bg-violet-400",
    },
  };

  return classes[tone];
}

function formatPercent(value: number, total: number) {
  if (total <= 0) return "0%";
  return `${Math.round((value / total) * 100)}%`;
}

function progressWidth(value: number, total: number) {
  if (value <= 0 || total <= 0) return 0;
  return Math.max(6, Math.min(100, Math.round((value / total) * 100)));
}

function summarizeExposure(summary: ExecutiveSummary["summary"]) {
  if (summary.escalated_cases > 0 || summary.escalated_incidents > 0) {
    return "Executive review queue is active.";
  }

  if (summary.high_or_critical_incidents > 0 || summary.critical_cases > 0) {
    return "High-risk exposure requires management visibility.";
  }

  if (summary.open_cases > 0 || summary.open_incidents > 0) {
    return "Operational backlog is present but not currently escalated.";
  }

  return "No active executive risk pressure detected.";
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
    const timer = window.setTimeout(() => {
      void loadExecutiveSummary();
    }, 0);

    const interval = window.setInterval(() => {
      void loadExecutiveSummary();
    }, 30000);

    return () => {
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
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

  const exposureRows = useMemo<ExposureRow[]>(() => {
    const incidentTotal = incidentStatusRows.reduce((sum, [, value]) => sum + value, 0);
    const caseTotal = caseStatusRows.reduce((sum, [, value]) => sum + value, 0);
    const priorityTotal = priorityRows.reduce((sum, [, value]) => sum + value, 0);

    return [
      ...incidentStatusRows.map(([label, value]) => ({
        category: "Incidents" as const,
        label,
        value,
        total: incidentTotal,
      })),
      ...caseStatusRows.map(([label, value]) => ({
        category: "Cases" as const,
        label,
        value,
        total: caseTotal,
      })),
      ...priorityRows.map(([label, value]) => ({
        category: "Priority" as const,
        label,
        value,
        total: priorityTotal,
      })),
    ];
  }, [incidentStatusRows, caseStatusRows, priorityRows]);

  const postureTone: Tone =
    data?.status === "CRITICAL"
      ? "danger"
      : data?.status === "ATTENTION"
        ? "warning"
        : "success";

  const correlationCoverage = data
    ? Math.round(
        ((data.summary.correlated_incidents || 0) /
          Math.max(data.summary.total_incidents || 0, 1)) *
          100
      )
    : 0;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-3 flex flex-col gap-3 border-b border-slate-800 pb-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              Dashboard
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <BarChart3 className="h-3.5 w-3.5" />
              Executive Command Record
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              SOC Executive Dashboard
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Decision-first view of SOC posture, management pressure, exposure
              distribution, active work queues and AI case analysis.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-800 bg-slate-900 px-2.5 text-[11px] text-slate-400">
              <Clock className="h-3.5 w-3.5 text-slate-500" />
              Auto-refresh 30s
            </span>
            <button
              onClick={loadExecutiveSummary}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="mb-3 rounded-md border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading executive summary...
          </section>
        ) : data ? (
          <div className="space-y-3">
            <ExecutivePulseBar
              data={data}
              tone={postureTone}
              correlationCoverage={correlationCoverage}
            />

            <section className="grid gap-px xl:grid-cols-[1.35fr_repeat(5,minmax(0,1fr))]">
              <div className="xl:col-span-4">
                <ExecutiveDecisionBrief data={data} />
              </div>
              <div className="xl:col-span-2">
                <OperatingAssurance data={data} />
              </div>
            </section>

            <section className="grid gap-px xl:grid-cols-[1.35fr_repeat(5,minmax(0,1fr))]">
              <div className="xl:col-span-4">
                <ManagementActionQueue data={data} />
              </div>
              <div className="xl:col-span-2">
                <LatestAiAnalysis analysis={data.latest_case_analysis} />
              </div>
            </section>

            <section className="grid gap-px xl:grid-cols-[1.35fr_repeat(5,minmax(0,1fr))]">
              <div className="xl:col-span-4">
                <ExposureMatrix rows={exposureRows} />
              </div>
              <div className="xl:col-span-2">
                <OperationalHotspots
                  hosts={data.top_hosts}
                  correlationTypes={data.top_correlation_types}
                />
              </div>
            </section>

            <section className="grid gap-3 xl:grid-cols-2">
              <CasesQueue cases={data.latest_cases} />
              <HighRiskIncidentQueue incidents={data.latest_high_risk_incidents} />
            </section>
          </div>
        ) : null}
      </div>
    </main>
  );
}

function ExecutivePulseBar({
  data,
  tone,
  correlationCoverage,
}: {
  data: ExecutiveSummary;
  tone: Tone;
  correlationCoverage: number;
}) {
  const classes = toneClasses(tone);
  const summary = data.summary;
  const signals = [
    {
      title: "Open exposure",
      value: summary.open_incidents + summary.open_cases,
      meta: `${summary.open_incidents} inc / ${summary.open_cases} cases`,
      tone: summary.open_incidents + summary.open_cases > 0 ? "primary" : "success",
      icon: <AlertTriangle className="h-3.5 w-3.5" />,
    },
    {
      title: "Critical pressure",
      value: summary.critical_incidents + summary.critical_cases,
      meta: `${summary.high_or_critical_incidents} high+`,
      tone:
        summary.critical_incidents + summary.critical_cases > 0
          ? "danger"
          : summary.high_or_critical_incidents > 0
            ? "warning"
            : "success",
      icon: <ShieldAlert className="h-3.5 w-3.5" />,
    },
    {
      title: "Escalation load",
      value: summary.escalated_incidents + summary.escalated_cases,
      meta: `${summary.escalated_incidents} inc / ${summary.escalated_cases} cases`,
      tone:
        summary.escalated_incidents + summary.escalated_cases > 0
          ? "danger"
          : "success",
      icon: <Briefcase className="h-3.5 w-3.5" />,
    },
    {
      title: "Correlation",
      value: `${correlationCoverage}%`,
      meta: `${summary.correlated_incidents} linked`,
      tone: correlationCoverage >= 60 ? "executive" : "neutral",
      icon: <TrendingUp className="h-3.5 w-3.5" />,
    },
    {
      title: "Risk ceiling",
      value: summary.max_risk_score,
      meta: `avg ${summary.average_risk_score}`,
      tone: toneForRisk(summary.max_risk_score),
      icon: <BarChart3 className="h-3.5 w-3.5" />,
    },
  ] satisfies Array<{
    title: string;
    value: string | number;
    meta: string;
    tone: Tone;
    icon: ReactNode;
  }>;

  return (
    <section className="rounded-sm border border-slate-800 bg-slate-900 p-2 shadow-sm">
      <div className="grid gap-1.5 md:grid-cols-2 xl:grid-cols-[1.35fr_repeat(5,minmax(0,1fr))]">
        <div className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${classes.panel}`}>
          <div className="min-w-0">
            <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
              SOC posture
            </div>
            <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
              <span className="truncate text-xl font-semibold leading-6 text-slate-100">
                {data.status}
              </span>
              <span className="min-w-0 truncate text-[11px] leading-4 text-slate-400" title={statusMessage(data.status)}>
                {statusMessage(data.status)}
              </span>
            </div>
          </div>
          <div className={`shrink-0 rounded-sm bg-slate-950 p-1.5 ${classes.text}`}>
              {data.status === "CRITICAL" ? (
                <AlertTriangle className="h-3.5 w-3.5" />
              ) : data.status === "ATTENTION" ? (
                <ShieldAlert className="h-3.5 w-3.5" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5" />
              )}
          </div>
        </div>

        {signals.map((signal) => (
          <PulseMetric key={signal.title} {...signal} />
        ))}
      </div>
    </section>
  );
}

function ExecutiveDecisionBrief({ data }: { data: ExecutiveSummary }) {
  const fallbackDecision =
    data.status === "CRITICAL"
      ? "Escalate"
      : data.status === "ATTENTION"
        ? "Review"
        : "Monitor";
  const brief = data.decision_brief ?? {
    decision: fallbackDecision,
    reason: summarizeExposure(data.summary),
    next_action: data.recommendations[0] ?? "Continue monitoring SOC posture.",
  };
  const tone = toneForDecision(brief.decision);

  return (
    <Panel
      title="Executive decision brief"
      description="Management-ready decision, reason and next action."
      icon={<CheckCircle2 className="h-3.5 w-3.5" />}
    >
      <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 xl:grid-cols-[160px_minmax(0,1fr)_minmax(0,1fr)]">
        <BriefCell label="Decision">
          <Badge tone={tone}>{brief.decision}</Badge>
        </BriefCell>
        <BriefCell label="Reason">{brief.reason}</BriefCell>
        <BriefCell label="Next action">{brief.next_action}</BriefCell>
      </div>
    </Panel>
  );
}

function OperatingAssurance({ data }: { data: ExecutiveSummary }) {
  const summary = data.summary;
  const sla = data.sla_posture ?? {
    status: summary.open_cases > 0 ? "UNKNOWN" : "OK",
    open_cases: summary.open_cases,
    cases_with_sla: 0,
    on_track: 0,
    due_soon: 0,
    overdue: 0,
    missing_sla: summary.open_cases,
    coverage_percent: 0,
  };
  const ai = data.ai_triage_contribution ?? {
    incident_ai_analyzed: 0,
    total_incidents: summary.total_incidents,
    incident_coverage_percent: 0,
    case_ai_analyzed: data.latest_case_analysis ? 1 : 0,
    total_cases: summary.total_cases,
    case_coverage_percent: 0,
    total_case_analyses: data.latest_case_analysis ? 1 : 0,
    overall_coverage_percent: 0,
    latest_analysis_at: data.latest_case_analysis?.created_at ?? null,
  };
  const noise = data.noise_reduction ?? {
    raw_events: 0,
    security_alerts: 0,
    incidents_created: summary.total_incidents,
    incident_created_alerts: 0,
    observed_only_alerts: 0,
    event_aggregates: 0,
    duplicate_events_collapsed: 0,
    incident_creation_rate_percent: 0,
    reduction_percent: 0,
  };
  const aiTone: Tone =
    ai.overall_coverage_percent >= 70
      ? "success"
      : ai.overall_coverage_percent >= 40
        ? "primary"
        : "neutral";
  const noiseTone: Tone =
    noise.reduction_percent >= 50 || noise.duplicate_events_collapsed > 0
      ? "executive"
      : "neutral";

  return (
    <Panel
      title="Operating assurance"
      description="SLA, AI assistance and noise reduction posture."
      icon={<Server className="h-3.5 w-3.5" />}
    >
      <div className="divide-y divide-slate-800 overflow-hidden rounded-md border border-slate-800 bg-slate-950">
        <AssuranceRow
          title="SLA posture"
          tone={toneForStatus(sla.status)}
          value={sla.status}
          detail={`${sla.overdue} overdue / ${sla.due_soon} due soon`}
          meta={`${sla.coverage_percent}% covered / ${sla.missing_sla} missing`}
        />
        <AssuranceRow
          title="AI triage contribution"
          tone={aiTone}
          value={`${ai.overall_coverage_percent}%`}
          detail={`${ai.incident_ai_analyzed}/${ai.total_incidents} incidents, ${ai.case_ai_analyzed}/${ai.total_cases} cases`}
          meta={`${ai.total_case_analyses} case analyses`}
        />
        <AssuranceRow
          title="Noise reduction / dedup"
          tone={noiseTone}
          value={`${noise.reduction_percent}%`}
          detail={`${noise.duplicate_events_collapsed} duplicate events collapsed`}
          meta={`${noise.observed_only_alerts} observed-only alerts`}
        />
      </div>
    </Panel>
  );
}

function ManagementActionQueue({ data }: { data: ExecutiveSummary }) {
  const recommendations = data.recommendations.slice(0, 5);

  return (
    <Panel
      title="Management action queue"
      description="Executive focus ordered by current exposure and operating pressure."
      count={data.recommendations.length}
      icon={<ShieldAlert className="h-3.5 w-3.5" />}
    >
      {recommendations.length === 0 ? (
        <EmptyState label="No recommendations available." />
      ) : (
        <div className="divide-y divide-slate-800 overflow-hidden rounded-md border border-slate-800">
          {recommendations.map((item, index) => {
            const action = classifyRecommendation(item, data.summary, index);

            return (
              <div
                key={`${item}-${index}`}
                className="grid gap-2 bg-slate-950 px-2.5 py-2 md:grid-cols-[130px_minmax(0,1fr)_120px]"
              >
                <div className="flex items-center gap-2">
                  <Badge tone={action.tone}>{action.label}</Badge>
                </div>
                <div className="min-w-0 text-xs leading-5 text-slate-300" title={item}>
                  <span className="line-clamp-2">{item}</span>
                </div>
                <div className="text-right text-[11px] text-slate-500">
                  {action.metric}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

function LatestAiAnalysis({
  analysis,
}: {
  analysis: ExecutiveSummary["latest_case_analysis"];
}) {
  return (
    <Panel
      title="Latest AI case analysis"
      description="Most recent model-assisted case recommendation."
      icon={<TrendingUp className="h-3.5 w-3.5" />}
    >
      {!analysis ? (
        <EmptyState label="No AI case analysis available." />
      ) : (
        <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800">
          <CompactField
            label="Case"
            value={
              <Link
                href={`/cases/${analysis.case_id}`}
                className="text-cyan-300 hover:text-cyan-200"
              >
                #{analysis.case_id}
              </Link>
            }
          />
          <CompactField label="Model" value={analysis.model ?? "-"} />
          <CompactField
            label="Recommended status"
            value={<Badge tone={toneForStatus(analysis.recommended_status)}>{analysis.recommended_status ?? "-"}</Badge>}
          />
          <CompactField
            label="Recommended severity"
            value={<Badge tone={toneForStatus(analysis.recommended_severity)}>{analysis.recommended_severity ?? "-"}</Badge>}
          />
          <CompactField label="Created" value={shortTimestamp(analysis.created_at)} />
        </div>
      )}
    </Panel>
  );
}

function ExposureMatrix({ rows }: { rows: ExposureRow[] }) {
  const visibleRows = rows.slice(0, 14);

  return (
    <Panel
      title="Exposure matrix"
      description="Unified distribution across incident state, case state and priority."
      count={rows.length}
      icon={<BarChart3 className="h-3.5 w-3.5" />}
    >
      {visibleRows.length === 0 ? (
        <EmptyState label="No distribution data available." />
      ) : (
        <div className="overflow-x-auto rounded-md border border-slate-800">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-2 py-1.5">Category</th>
                <th className="px-2 py-1.5">State</th>
                <th className="px-2 py-1.5 text-right">Count</th>
                <th className="px-2 py-1.5 text-right">Share</th>
                <th className="px-2 py-1.5">Distribution</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-950">
              {visibleRows.map((row) => {
                const tone = toneForStatus(row.label);
                const width = progressWidth(row.value, row.total);

                return (
                  <tr key={`${row.category}-${row.label}`} className="hover:bg-slate-900">
                    <td className="whitespace-nowrap px-2 py-2 text-slate-500">
                      {row.category}
                    </td>
                    <td className="px-2 py-2">
                      <Badge tone={tone}>{row.label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-right tabular-nums text-slate-200">
                      {row.value}
                    </td>
                    <td className="px-2 py-2 text-right tabular-nums text-slate-400">
                      {formatPercent(row.value, row.total)}
                    </td>
                    <td className="min-w-36 px-2 py-2">
                      <div className="h-1.5 rounded-full bg-slate-800">
                        <div
                          className={`h-1.5 rounded-full ${toneClasses(tone).bar}`}
                          style={{ width: `${width}%` }}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function OperationalHotspots({
  hosts,
  correlationTypes,
}: {
  hosts: ExecutiveSummary["top_hosts"];
  correlationTypes: ExecutiveSummary["top_correlation_types"];
}) {
  return (
    <Panel
      title="Operational hotspots"
      description="Most concentrated risk sources and correlation patterns."
      icon={<Server className="h-3.5 w-3.5" />}
    >
      <div className="grid gap-3">
        <DenseList title="Top risk hosts" count={hosts.length}>
          {hosts.length === 0 ? (
            <EmptyState label="No host data available." />
          ) : (
            hosts.slice(0, 6).map((host) => (
              <ConsoleRow
                key={host.agent ?? "unknown"}
                title={host.agent ?? "unknown"}
                meta={`${host.count} incidents / avg ${host.average_risk}`}
                value={`max ${host.max_risk}`}
                tone={toneForRisk(host.max_risk)}
              />
            ))
          )}
        </DenseList>

        <DenseList title="Top correlation types" count={correlationTypes.length}>
          {correlationTypes.length === 0 ? (
            <EmptyState label="No correlation data available." />
          ) : (
            correlationTypes.slice(0, 6).map((item) => (
              <ConsoleRow
                key={item.correlation_type ?? "unknown"}
                title={item.correlation_type ?? "unknown"}
                meta="Correlation pattern"
                value={item.count}
                tone="executive"
              />
            ))
          )}
        </DenseList>
      </div>
    </Panel>
  );
}

function CasesQueue({ cases }: { cases: ExecutiveSummary["latest_cases"] }) {
  return (
    <Panel
      title="Cases requiring attention"
      description="Open cases that still require management attention."
      count={cases.length}
      icon={<Briefcase className="h-3.5 w-3.5" />}
    >
      {cases.length === 0 ? (
        <EmptyTable colSpan={6} label="No open cases requiring attention." />
      ) : (
        <div className="overflow-x-auto rounded-md border border-slate-800">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-2 py-1.5">Case</th>
                <th className="px-2 py-1.5">Status</th>
                <th className="px-2 py-1.5">Severity</th>
                <th className="px-2 py-1.5">Host</th>
                <th className="px-2 py-1.5 text-right">Risk</th>
                <th className="px-2 py-1.5">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-950">
              {cases.slice(0, 10).map((item) => (
                <tr key={item.id} className="hover:bg-slate-900">
                  <td className="max-w-md truncate px-2 py-2">
                    <Link
                      href={`/cases/${item.id}`}
                      className="text-cyan-300 hover:text-cyan-200"
                      title={item.title}
                    >
                      #{item.id} {shortText(item.title, 64)}
                    </Link>
                  </td>
                  <td className="px-2 py-2">
                    <Badge tone={toneForStatus(item.status)}>{item.status ?? "OPEN"}</Badge>
                  </td>
                  <td className="px-2 py-2">
                    <Badge tone={toneForStatus(item.severity)}>{item.severity ?? "LOW"}</Badge>
                  </td>
                  <td className="max-w-[120px] truncate px-2 py-2 text-slate-400">
                    {item.agent ?? "unknown"}
                  </td>
                  <td className="px-2 py-2 text-right tabular-nums text-slate-300">
                    {item.risk_score ?? 0}
                  </td>
                  <td className="whitespace-nowrap px-2 py-2 text-slate-400">
                    {shortTimestamp(item.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function HighRiskIncidentQueue({
  incidents,
}: {
  incidents: ExecutiveSummary["latest_high_risk_incidents"];
}) {
  return (
    <Panel
      title="Open high-risk incident queue"
      description="Recent incident exposure sorted by executive relevance."
      count={incidents.length}
      icon={<AlertTriangle className="h-3.5 w-3.5" />}
    >
      {incidents.length === 0 ? (
        <EmptyTable colSpan={6} label="No high-risk incidents available." />
      ) : (
        <div className="overflow-x-auto rounded-md border border-slate-800">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-2 py-1.5">Incident</th>
                <th className="px-2 py-1.5">Time</th>
                <th className="px-2 py-1.5">Host</th>
                <th className="px-2 py-1.5">Rule</th>
                <th className="px-2 py-1.5 text-right">Risk</th>
                <th className="px-2 py-1.5">Priority</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-950">
              {incidents.slice(0, 10).map((incident) => (
                <tr key={incident.id} className="hover:bg-slate-900">
                  <td className="px-2 py-2">
                    <Link
                      href={`/incidents/${incident.id}`}
                      className="text-cyan-300 hover:text-cyan-200"
                    >
                      #{incident.id}
                    </Link>
                  </td>
                  <td className="whitespace-nowrap px-2 py-2 text-slate-400">
                    {shortTimestamp(incident.timestamp_local ?? incident.timestamp)}
                  </td>
                  <td className="max-w-[120px] truncate px-2 py-2 text-slate-400">
                    {incident.agent ?? "unknown"}
                  </td>
                  <td
                    className="max-w-md truncate px-2 py-2 text-slate-300"
                    title={incident.rule ?? "-"}
                  >
                    {shortText(incident.rule, 80)}
                  </td>
                  <td className="px-2 py-2 text-right">
                    <Badge tone={toneForRisk(incident.risk_score)}>
                      {incident.risk_score ?? 0}
                    </Badge>
                  </td>
                  <td className="px-2 py-2 text-slate-400">
                    {incident.recommended_priority ?? "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function classifyRecommendation(
  item: string,
  summary: ExecutiveSummary["summary"],
  index: number
): { label: string; metric: string; tone: Tone } {
  const text = item.toLowerCase();

  if (text.includes("escalat") || summary.escalated_cases + summary.escalated_incidents > 0) {
    return {
      label: "Escalation",
      metric: `${summary.escalated_cases + summary.escalated_incidents} active`,
      tone: "danger",
    };
  }

  if (text.includes("critical") || text.includes("high")) {
    return {
      label: "Risk",
      metric: `${summary.high_or_critical_incidents} high/critical`,
      tone: "warning",
    };
  }

  if (text.includes("case")) {
    return {
      label: "Cases",
      metric: `${summary.open_cases} open`,
      tone: "primary",
    };
  }

  if (text.includes("correlat")) {
    return {
      label: "Correlation",
      metric: `${summary.correlated_incidents} linked`,
      tone: "executive",
    };
  }

  return {
    label: index === 0 ? "Primary" : "Focus",
    metric: `${summary.open_incidents} open incidents`,
    tone: index === 0 ? "primary" : "neutral",
  };
}

function PulseMetric({
  title,
  value,
  meta,
  tone,
  icon,
}: {
  title: string;
  value: string | number;
  meta: string;
  tone: Tone;
  icon: ReactNode;
}) {
  const classes = toneClasses(tone);

  return (
    <div
      className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${classes.panel}`}
    >
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
          <span className="text-xl font-semibold leading-6 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500" title={meta}>
            {meta}
          </span>
        </div>
      </div>
      <div className={`shrink-0 rounded-sm bg-slate-950 p-1.5 ${classes.text}`}>
        {icon}
      </div>
    </div>
  );
}

function BriefCell({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="min-w-0 bg-slate-950 px-2.5 py-2">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 line-clamp-2 text-xs leading-5 text-slate-200">
        {children}
      </div>
    </div>
  );
}

function AssuranceRow({
  title,
  value,
  detail,
  meta,
  tone,
}: {
  title: string;
  value: string;
  detail: string;
  meta: string;
  tone: Tone;
}) {
  return (
    <div className="grid gap-2 px-2.5 py-2 md:grid-cols-[150px_72px_minmax(0,1fr)]">
      <div className="truncate text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </div>
      <div className="flex md:justify-end">
        <Badge tone={tone}>{value}</Badge>
      </div>
      <div className="min-w-0 text-xs text-slate-300">
        <div className="truncate" title={detail}>
          {detail}
        </div>
        <div className="truncate text-[11px] text-slate-500" title={meta}>
          {meta}
        </div>
      </div>
    </div>
  );
}

function Panel({
  title,
  description,
  count,
  icon,
  children,
}: {
  title: string;
  description?: string;
  count?: number;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="h-full rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {icon && <div className="text-cyan-300">{icon}</div>}
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-200">
              {title}
            </h2>
          </div>
          {description && (
            <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
              {description}
            </p>
          )}
        </div>

        {typeof count === "number" && (
          <span className="inline-flex h-5 min-w-5 shrink-0 items-center justify-center rounded-md border border-slate-700 bg-slate-950 px-2 text-[10px] leading-none text-slate-400">
            {count}
          </span>
        )}
      </div>

      {children}
    </section>
  );
}

function CompactField({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="min-w-0 bg-slate-950 px-2.5 py-2">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-0.5 truncate text-xs font-semibold text-slate-200">
        {value}
      </div>
    </div>
  );
}

function DenseList({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: ReactNode;
}) {
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5">
        <h3 className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          {title}
        </h3>
        <span className="text-[10px] tabular-nums text-slate-500">{count}</span>
      </div>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function ConsoleRow({
  title,
  meta,
  value,
  tone,
}: {
  title: string;
  meta: string;
  value: string | number;
  tone: Tone;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5">
      <div className="min-w-0">
        <div className="truncate text-xs font-medium text-slate-200" title={title}>
          {title}
        </div>
        <div className="truncate text-[11px] text-slate-500">{meta}</div>
      </div>
      <Badge tone={tone}>{value}</Badge>
    </div>
  );
}

function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex h-5 items-center justify-center rounded-md border px-2 text-[10px] font-medium leading-none ${toneClasses(tone).badge}`}
    >
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
    <div className="overflow-hidden rounded-md border border-slate-800">
      <table className="min-w-full text-left text-xs">
        <tbody>
          <tr>
            <td colSpan={colSpan} className="bg-slate-950 px-2 py-4 text-center text-slate-500">
              {label}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
