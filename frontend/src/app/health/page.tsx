"use client";

import { authFetch } from "@/lib/auth";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cloud,
  Database,
  HeartPulse,
  RefreshCw,
  Server,
  XCircle,
  Cpu,
  Shield,
} from "lucide-react";

type HealthStatus = "OK" | "WARN" | "ERROR" | string;

type HealthComponent = {
  component: string;
  status: HealthStatus;
  message: string;
  latency_ms: number;
  checked_at: string;
  details: Record<string, unknown>;
};

type LatestIncident = {
  id: number;
  timestamp: string | null;
  agent: string | null;
  rule: string | null;
  status: string | null;
  risk_score: number | null;
  correlation_score: number | null;
};

type PlatformHealth = {
  status: HealthStatus;
  checked_at: string;
  components: HealthComponent[];
  latest_incident: LatestIncident | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

const COMPONENT_ORDER = [
  "api",
  "postgres",
  "ollama",
  "qdrant",
  "wazuh_indexer",
  "wazuh_ingest",
  "event_processing_queue",
  "active_event_sources",
  "latest_raw_event_freshness",
  "latest_security_alert_freshness",
  "latest_incident_freshness",
  "ai_soc_worker",
  "cloudflare_tunnel",
];

function statusClasses(status: HealthStatus) {
  if (status === "OK") {
    return {
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      card: "border-emerald-900/70 bg-emerald-950/20",
      text: "text-emerald-300",
      dot: "bg-emerald-400",
    };
  }

  if (status === "WARN") {
    return {
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      card: "border-orange-900/70 bg-orange-950/20",
      text: "text-orange-300",
      dot: "bg-orange-400",
    };
  }

  if (status === "ERROR") {
    return {
      badge: "border-red-800 bg-red-950 text-red-200",
      card: "border-red-900/70 bg-red-950/25",
      text: "text-red-300",
      dot: "bg-red-400",
    };
  }

  return {
    badge: "border-slate-700 bg-slate-900 text-slate-300",
    card: "border-slate-800 bg-slate-900",
    text: "text-slate-300",
    dot: "bg-slate-400",
  };
}

function statusIcon(status: HealthStatus) {
  if (status === "OK") return <CheckCircle2 className="h-3.5 w-3.5" />;
  if (status === "WARN") return <AlertTriangle className="h-3.5 w-3.5" />;
  if (status === "ERROR") return <XCircle className="h-3.5 w-3.5" />;
  return <Activity className="h-3.5 w-3.5" />;
}

function componentIcon(component: string) {
  if (component.includes("postgres")) return <Database className="h-3.5 w-3.5" />;
  if (component.includes("worker")) return <HeartPulse className="h-3.5 w-3.5" />;
  if (component.includes("cloudflare")) return <Cloud className="h-3.5 w-3.5" />;
  if (component.includes("source")) return <Shield className="h-3.5 w-3.5" />;
  if (component.includes("queue")) return <Clock className="h-3.5 w-3.5" />;
  if (component.includes("freshness")) return <Shield className="h-3.5 w-3.5" />;
  if (component.includes("wazuh")) return <Server className="h-3.5 w-3.5" />;
  if (component.includes("ollama")) return <Cpu className="h-3.5 w-3.5" />;
  if (component.includes("qdrant")) return <Database className="h-3.5 w-3.5" />;
  return <Activity className="h-3.5 w-3.5" />;
}

function componentLabel(component: string) {
  return component
    .replace("event_processing_queue", "Event processing queue")
    .replace("active_event_sources", "Active event sources")
    .replace("latest_raw_event_freshness", "Latest RAW event freshness")
    .replace("latest_security_alert_freshness", "Latest SEC event freshness")
    .replace("latest_incident_freshness", "Latest incident creation freshness")
    .replace("cloudflare_tunnel", "Cloudflare tunnel")
    .replace("ai_soc_worker", "AI SOC worker")
    .replace("wazuh_indexer", "Wazuh indexer")
    .replace("wazuh_ingest", "Wazuh ingest")
    .replace("postgres", "Postgres")
    .replace("ai_runtime", "AI Runtime")
    .replace("ollama", "Ollama")
    .replace("qdrant", "Qdrant")
    .replace("api", "API");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readUnknown(root: unknown, path: string[]): unknown {
  let current: unknown = root;

  for (const key of path) {
    if (!isRecord(current)) return undefined;
    current = current[key];
  }

  return current;
}

function readRecord(root: unknown, path: string[]): Record<string, unknown> {
  const value = readUnknown(root, path);
  return isRecord(value) ? value : {};
}

function readString(root: unknown, path: string[], fallback = "-") {
  const value = readUnknown(root, path);

  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  return String(value);
}

function readNumber(root: unknown, path: string[]): number | null {
  const value = readUnknown(root, path);

  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function formatNumber(value: number | null, suffix = "") {
  if (value === null || value === undefined) return "-";

  const formatted = Number.isInteger(value) ? String(value) : value.toFixed(2);

  return suffix ? `${formatted} ${suffix}` : formatted;
}

function ingestModeTone(mode: string): HealthStatus | "neutral" {
  const value = mode.toUpperCase();

  if (value === "REALTIME") return "OK";
  if (value === "CATCHING_UP" || value === "IDLE") return "WARN";
  if (value === "LAGGING") return "ERROR";

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
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}

function shortText(value: string | null | undefined, max = 96) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

async function fetchHealth(): Promise<PlatformHealth> {
  const response = await authFetch(`/platform/health`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function HealthPage() {
  const [health, setHealth] = useState<PlatformHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sortedComponents = useMemo(() => {
    return [...(health?.components ?? [])].sort((a, b) => {
      const orderA = COMPONENT_ORDER.indexOf(a.component);
      const orderB = COMPONENT_ORDER.indexOf(b.component);

      return (orderA === -1 ? 999 : orderA) - (orderB === -1 ? 999 : orderB);
    });
  }, [health]);

  const healthCounts = useMemo(() => {
    const components = health?.components ?? [];

    return {
      total: components.length,
      ok: components.filter((item) => item.status === "OK").length,
      warn: components.filter((item) => item.status === "WARN").length,
      error: components.filter((item) => item.status === "ERROR").length,
      avgLatency:
        components.length > 0
          ? Math.round(
              components.reduce((sum, item) => sum + item.latency_ms, 0) /
                components.length
            )
          : 0,
    };
  }, [health]);

  async function loadHealth() {
    try {
      setRefreshing(true);
      setError(null);
      const data = await fetchHealth();
      setHealth(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadHealth();

    const interval = window.setInterval(() => {
      loadHealth();
    }, 30000);

    return () => window.clearInterval(interval);
  }, []);

  const overallStatus = health?.status ?? "UNKNOWN";
  const status = statusClasses(overallStatus);

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
              <HeartPulse className="h-3.5 w-3.5" />
              Platform Health
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Health Dashboard
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Operational status for the local AI SOC stack: API, database,
              Wazuh, Ollama, Qdrant and worker heartbeat.
            </p>
          </div>

          <button
            onClick={loadHealth}
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
            Loading platform health...
          </section>
        ) : (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-6">
              <StatusTile
                title="Overall"
                value={overallStatus}
                subtitle="Platform posture"
                icon={statusIcon(overallStatus)}
                tone={overallStatus}
              />

              <StatusTile
                title="Components"
                value={healthCounts.total}
                subtitle={`${healthCounts.ok} OK · ${healthCounts.warn} WARN · ${healthCounts.error} ERR`}
                icon={<Server className="h-3.5 w-3.5" />}
                tone={healthCounts.error > 0 ? "ERROR" : healthCounts.warn > 0 ? "WARN" : "OK"}
              />

              <StatusTile
                title="Avg latency"
                value={`${healthCounts.avgLatency} ms`}
                subtitle="Component checks"
                icon={<Clock className="h-3.5 w-3.5" />}
                tone={healthCounts.avgLatency > 500 ? "WARN" : "OK"}
              />

              <StatusTile
                title="Checked"
                value={formatTimestamp(health?.checked_at).split(",")[1]?.trim() ?? "-"}
                subtitle={formatTimestamp(health?.checked_at).split(",")[0] ?? "-"}
                icon={<Activity className="h-3.5 w-3.5" />}
                tone="neutral"
              />

              <StatusTile
                title="Latest incident"
                value={health?.latest_incident ? `#${health.latest_incident.id}` : "-"}
                subtitle={health?.latest_incident?.agent ?? "No incident"}
                icon={<Shield className="h-3.5 w-3.5" />}
                tone={(health?.latest_incident?.risk_score ?? 0) >= 60 ? "WARN" : "neutral"}
              />

              <StatusTile
                title="Latest risk"
                value={health?.latest_incident?.risk_score ?? 0}
                subtitle="Last incident risk"
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
                tone={(health?.latest_incident?.risk_score ?? 0) >= 80 ? "ERROR" : (health?.latest_incident?.risk_score ?? 0) >= 60 ? "WARN" : "OK"}
              />
            </section>

            {health?.latest_incident && (
              <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <h2 className="text-sm font-semibold">Latest processed incident</h2>
                  <Link
                    href={`/incidents/${health.latest_incident.id}`}
                    className="rounded-md border border-cyan-800 bg-cyan-950 px-2 py-1 text-[11px] text-cyan-200 hover:bg-cyan-900"
                  >
                    Open incident
                  </Link>
                </div>

                <div className="grid gap-2 lg:grid-cols-[90px_170px_180px_90px_1fr]">
                  <CompactField label="ID" value={`#${health.latest_incident.id}`} />
                  <CompactField
                    label="Time"
                    value={formatTimestamp(health.latest_incident.timestamp)}
                  />
                  <CompactField
                    label="Host"
                    value={health.latest_incident.agent ?? "unknown"}
                  />
                  <CompactField
                    label="Risk"
                    value={`${health.latest_incident.risk_score ?? 0}`}
                  />

                  <div className="min-w-0 rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5">
                    <div className="text-[10px] uppercase tracking-wide text-slate-500">
                      Rule
                    </div>
                    <div
                      className="truncate text-xs text-slate-200"
                      title={health.latest_incident.rule ?? "-"}
                    >
                      {health.latest_incident.rule ?? "-"}
                    </div>
                  </div>
                </div>
              </section>
            )}

            <WorkerIngestMetricsPanel components={sortedComponents} />

            <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-2 flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">Components</h2>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Compact service status tiles. Details are collapsed by default.
                  </p>
                </div>

                <span className="rounded-sm border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                  Auto refresh 30s
                </span>
              </div>

              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-6">
                {sortedComponents.map((item) => (
                  <ComponentTile key={item.component} item={item} />
                ))}
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function WorkerIngestMetricsPanel({
  components,
}: {
  components: HealthComponent[];
}) {
  const worker = components.find((item) => item.component === "ai_soc_worker");
  const ingest = components.find((item) => item.component === "wazuh_ingest");
  const queue = components.find((item) => item.component === "event_processing_queue");

  if (!worker && !ingest && !queue) return null;

  const workerDetails = readRecord(worker?.details, ["details"]);
  const workerBatchMetrics = readRecord(workerDetails, ["batch_metrics"]);
  const workerResultCounts = readRecord(workerDetails, ["result_counts"]);

  const ingestDetails = readRecord(ingest?.details, ["details"]);
  const ingestLastRun = readRecord(ingestDetails, ["last_run"]);
  const ingestBatchMetrics = readRecord(ingestLastRun, ["batch_metrics"]);
  const ingestResultCounts = readRecord(ingestLastRun, ["result_counts"]);

  const batchMetrics =
    Object.keys(workerBatchMetrics).length > 0
      ? workerBatchMetrics
      : ingestBatchMetrics;

  const resultCounts =
    Object.keys(workerResultCounts).length > 0
      ? workerResultCounts
      : ingestResultCounts;

  const ingestMode =
    readString(batchMetrics, ["ingest_mode"], readString(workerDetails, ["ingest_mode"], "-"));

  const pendingEvents = readNumber(queue?.details, ["pending_events"]);
  const alertsSeen =
    readNumber(batchMetrics, ["alerts_seen"]) ??
    readNumber(workerDetails, ["alerts_seen"]) ??
    readNumber(ingest?.details, ["alerts_seen"]);

  const alertsProcessed =
    readNumber(batchMetrics, ["alerts_processed"]) ??
    readNumber(workerDetails, ["alerts_processed"]) ??
    readNumber(ingest?.details, ["alerts_processed"]);

  const alertsSkipped =
    readNumber(batchMetrics, ["alerts_skipped"]) ??
    readNumber(workerDetails, ["alerts_skipped"]) ??
    readNumber(ingest?.details, ["alerts_skipped"]);

  const latestEventLagMinutes =
    readNumber(batchMetrics, ["latest_event_lag_minutes"]) ??
    readNumber(workerDetails, ["latest_event_lag_minutes"]);

  const watermarkLagMinutes = readNumber(batchMetrics, ["watermark_lag_minutes"]);
  const batchSize = readNumber(batchMetrics, ["batch_size"]);
  const pollInterval = readNumber(workerDetails, ["poll_interval_seconds"]);
  const totalProcessed = readNumber(ingest?.details, ["total_processed"]);

  const suppressedNoise = readNumber(resultCounts, ["suppressed_noise"]);
  const observedOnly = readNumber(resultCounts, ["observed_no_incident"]);
  const aggregatedDuplicate = readNumber(resultCounts, ["aggregated_duplicate"]);
  const duplicateDocId = readNumber(resultCounts, ["duplicate_doc_id"]);
  const noDocId = readNumber(resultCounts, ["no_doc_id"]);
  const otherSkipped = readNumber(resultCounts, ["other_skipped"]);

  const aiTriageSuccess = readNumber(resultCounts, ["ai_triage_success"]);
  const aiTriageFallback = readNumber(resultCounts, ["ai_triage_fallback"]);
  const aiTriageSkipped = readNumber(resultCounts, ["ai_triage_skipped"]);

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-3 flex flex-col gap-2 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="mb-1 flex items-center gap-2 text-[10px] font-medium uppercase tracking-wide text-cyan-300">
            <HeartPulse className="h-3.5 w-3.5" />
            Runtime operations
          </div>

          <h2 className="text-sm font-semibold">Worker / ingest metrics</h2>

          <p className="mt-0.5 max-w-3xl text-[11px] leading-4 text-slate-500">
            Focused view of Wazuh ingest, worker backlog, batch outcome and AI triage behavior.
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <StatusPill label="Mode" value={ingestMode} tone={ingestModeTone(ingestMode)} />
          <StatusPill label="Worker" value={worker?.status ?? "-"} tone={worker?.status ?? "neutral"} />
          <StatusPill label="Ingest" value={ingest?.status ?? "-"} tone={ingest?.status ?? "neutral"} />
          <StatusPill label="Queue" value={queue?.status ?? "-"} tone={queue?.status ?? "neutral"} />
        </div>
      </div>

      <div className="mb-3 grid gap-1.5 lg:grid-cols-3">
        <ExecutiveMetric
          label="Ingest mode"
          value={ingestMode}
          subtitle="Current worker processing posture"
          tone={ingestModeTone(ingestMode)}
        />

        <ExecutiveMetric
          label="Pending events"
          value={formatNumber(pendingEvents)}
          subtitle="Wazuh events newer than watermark"
          tone={(pendingEvents ?? 0) > 50 ? "WARN" : "OK"}
        />

        <ExecutiveMetric
          label="Latest event lag"
          value={formatNumber(latestEventLagMinutes, "min")}
          subtitle="Delay of newest event in last batch"
          tone={(latestEventLagMinutes ?? 0) > 15 ? "ERROR" : (latestEventLagMinutes ?? 0) > 2 ? "WARN" : "OK"}
        />
      </div>

      <div className="grid gap-2 xl:grid-cols-3">
        <MetricGroup
          title="Ingest & backlog"
          description="Worker cadence, queue pressure and watermark delay."
        >
          <MetricRow label="Alerts seen" value={formatNumber(alertsSeen)} />
          <MetricRow label="Pending events" value={formatNumber(pendingEvents)} />
          <MetricRow label="Watermark lag" value={formatNumber(watermarkLagMinutes, "min")} />
          <MetricRow label="Batch size" value={formatNumber(batchSize)} />
          <MetricRow label="Poll interval" value={formatNumber(pollInterval, "sec")} />
          <MetricRow label="Total processed" value={formatNumber(totalProcessed)} />
        </MetricGroup>

        <MetricGroup
          title="Batch outcome"
          description="How the last worker batch was classified."
        >
          <MetricRow label="Processed" value={formatNumber(alertsProcessed)} tone={(alertsProcessed ?? 0) > 0 ? "OK" : "neutral"} />
          <MetricRow label="Skipped" value={formatNumber(alertsSkipped)} />
          <MetricRow label="Suppressed noise" value={formatNumber(suppressedNoise)} tone="OK" />
          <MetricRow label="Observed only" value={formatNumber(observedOnly)} />
          <MetricRow label="Aggregated duplicate" value={formatNumber(aggregatedDuplicate)} />
          <MetricRow label="Duplicate doc id" value={formatNumber(duplicateDocId)} />
          <MetricRow label="No doc id" value={formatNumber(noDocId)} tone={(noDocId ?? 0) > 0 ? "WARN" : "neutral"} />
          <MetricRow label="Other skipped" value={formatNumber(otherSkipped)} tone={(otherSkipped ?? 0) > 0 ? "WARN" : "neutral"} />
        </MetricGroup>

        <MetricGroup
          title="AI triage"
          description="LLM usage and deterministic fallback visibility."
        >
          <MetricRow label="AI triage success" value={formatNumber(aiTriageSuccess)} tone="OK" />
          <MetricRow label="AI fallback" value={formatNumber(aiTriageFallback)} tone={(aiTriageFallback ?? 0) > 0 ? "WARN" : "neutral"} />
          <MetricRow label="AI skipped" value={formatNumber(aiTriageSkipped)} />
          <MetricRow label="Configured model" value={readString(workerDetails, ["ollama_model"], "-")} />
        </MetricGroup>
      </div>

      <div className="mt-3 grid gap-2 lg:grid-cols-3">
        <CompactField
          label="Latest event timestamp"
          value={formatTimestamp(readString(batchMetrics, ["latest_event_timestamp"], readString(ingest?.details, ["last_timestamp"], "-")))}
        />
        <CompactField
          label="Watermark timestamp"
          value={formatTimestamp(readString(ingest?.details, ["last_timestamp"], "-"))}
        />
        <CompactField
          label="Worker last seen"
          value={formatTimestamp(readString(worker?.details, ["last_seen_at"], "-"))}
        />
      </div>
    </section>
  );
}

function ExecutiveMetric({
  label,
  value,
  subtitle,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  subtitle: string;
  tone?: HealthStatus | "neutral";
}) {
  const status = statusClasses(tone);

  return (
    <div
      className={`flex min-h-[46px] items-center justify-between gap-2 rounded-sm border px-2 py-1.5 shadow-sm ${status.card}`}
    >
      <div className="min-w-0">
        <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
          {label}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-1.5">
          <span className="text-base font-semibold leading-5 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[10px] leading-3 text-slate-500">
            {subtitle}
          </span>
        </div>
      </div>
      <div className={`h-1.5 w-1.5 shrink-0 rounded-full ${status.dot}`} />
    </div>
  );
}

function MetricGroup({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5">
      <div className="mb-2 border-b border-slate-800 pb-2">
        <div className="text-xs font-semibold text-slate-100">{title}</div>
        <div className="mt-0.5 text-[11px] leading-4 text-slate-500">
          {description}
        </div>
      </div>

      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function MetricRow({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  tone?: HealthStatus | "neutral";
}) {
  const status = statusClasses(tone);

  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-slate-800 bg-slate-900/70 px-2 py-1.5">
      <div className="truncate text-[11px] text-slate-400">{label}</div>
      <div className={`shrink-0 rounded-md border px-2 py-0.5 text-[11px] font-medium ${status.badge}`}>
        {value}
      </div>
    </div>
  );
}

function StatusPill({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  tone?: HealthStatus | "neutral";
}) {
  const status = statusClasses(tone);

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium ${status.badge}`}>
      <span className="text-slate-400">{label}</span>
      <span>{value}</span>
    </span>
  );
}


function StatusTile({
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
  tone: HealthStatus | "neutral";
}) {
  const status = statusClasses(tone);

  return (
    <div
      className={`flex min-h-[46px] items-center justify-between gap-2 rounded-sm border px-2 py-1.5 shadow-sm ${status.card}`}
    >
      <div className="min-w-0">
        <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-1.5">
          <span className="text-base font-semibold leading-5 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[10px] leading-3 text-slate-500">
            {subtitle}
          </span>
        </div>
      </div>
      <div className={`shrink-0 rounded-sm bg-slate-950 p-1 ${status.text}`}>
        {icon}
      </div>
    </div>
  );
}

function ComponentTile({ item }: { item: HealthComponent }) {
  const status = statusClasses(item.status);

  return (
    <article className={`rounded-sm border p-2.5 shadow-sm ${status.card}`}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <div className={`shrink-0 rounded-sm bg-slate-950 p-1.5 ${status.text}`}>
            {componentIcon(item.component)}
          </div>

          <div className="min-w-0">
            <div className="truncate text-xs font-semibold text-slate-100">
              {componentLabel(item.component)}
            </div>
            <div className="text-[11px] text-slate-500">
              {item.latency_ms} ms
            </div>
          </div>
        </div>

        <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 text-[10px] font-medium ${status.badge}`}>
          {item.status}
        </span>
      </div>

      <div
        className="h-8 overflow-hidden text-[11px] leading-4 text-slate-400"
        title={item.message}
      >
        {item.message}
      </div>

      <details className="mt-2 rounded-sm border border-slate-800 bg-slate-950 px-2 py-1">
        <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
          Details
        </summary>

        <pre className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap text-[10px] leading-4 text-slate-400">
          {JSON.stringify(item.details ?? {}, null, 2)}
        </pre>
      </details>
    </article>
  );
}

function CompactField({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="truncate text-xs text-slate-200" title={value}>
        {value}
      </div>
    </div>
  );
}
