"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
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
  "ai_soc_worker",
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
  if (status === "OK") return <CheckCircle2 className="h-4 w-4" />;
  if (status === "WARN") return <AlertTriangle className="h-4 w-4" />;
  if (status === "ERROR") return <XCircle className="h-4 w-4" />;
  return <Activity className="h-4 w-4" />;
}

function componentIcon(component: string) {
  if (component.includes("postgres")) return <Database className="h-3.5 w-3.5" />;
  if (component.includes("worker")) return <HeartPulse className="h-3.5 w-3.5" />;
  if (component.includes("wazuh")) return <Server className="h-3.5 w-3.5" />;
  if (component.includes("ollama")) return <Cpu className="h-3.5 w-3.5" />;
  if (component.includes("qdrant")) return <Database className="h-3.5 w-3.5" />;
  return <Activity className="h-3.5 w-3.5" />;
}

function componentLabel(component: string) {
  return component
    .replace("ai_soc_worker", "AI SOC worker")
    .replace("wazuh_indexer", "Wazuh indexer")
    .replace("wazuh_ingest", "Wazuh ingest")
    .replace("postgres", "Postgres")
    .replace("ollama", "Ollama")
    .replace("qdrant", "Qdrant")
    .replace("api", "API");
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
  const response = await fetch(`${API_BASE}/platform/health`, {
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
            <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
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
                icon={<Server className="h-4 w-4" />}
                tone={healthCounts.error > 0 ? "ERROR" : healthCounts.warn > 0 ? "WARN" : "OK"}
              />

              <StatusTile
                title="Avg latency"
                value={`${healthCounts.avgLatency} ms`}
                subtitle="Component checks"
                icon={<Clock className="h-4 w-4" />}
                tone={healthCounts.avgLatency > 500 ? "WARN" : "OK"}
              />

              <StatusTile
                title="Checked"
                value={formatTimestamp(health?.checked_at).split(",")[1]?.trim() ?? "-"}
                subtitle={formatTimestamp(health?.checked_at).split(",")[0] ?? "-"}
                icon={<Activity className="h-4 w-4" />}
                tone="neutral"
              />

              <StatusTile
                title="Latest incident"
                value={health?.latest_incident ? `#${health.latest_incident.id}` : "-"}
                subtitle={health?.latest_incident?.agent ?? "No incident"}
                icon={<Shield className="h-4 w-4" />}
                tone={(health?.latest_incident?.risk_score ?? 0) >= 61 ? "WARN" : "neutral"}
              />

              <StatusTile
                title="Latest risk"
                value={health?.latest_incident?.risk_score ?? 0}
                subtitle="Last processed event"
                icon={<AlertTriangle className="h-4 w-4" />}
                tone={(health?.latest_incident?.risk_score ?? 0) >= 81 ? "ERROR" : (health?.latest_incident?.risk_score ?? 0) >= 61 ? "WARN" : "OK"}
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

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-2 flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">Components</h2>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Compact service status tiles. Details are collapsed by default.
                  </p>
                </div>

                <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
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
    <div className={`rounded-lg border px-3 py-2 shadow-sm ${status.card}`}>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className={status.text}>{icon}</div>
      </div>

      <div className="truncate text-lg font-semibold leading-6 text-slate-100">
        {value}
      </div>
      <div className="truncate text-[11px] text-slate-500">{subtitle}</div>
    </div>
  );
}

function ComponentTile({ item }: { item: HealthComponent }) {
  const status = statusClasses(item.status);

  return (
    <article className={`rounded-lg border p-2.5 shadow-sm ${status.card}`}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <div className={`shrink-0 rounded-md bg-slate-950 p-1.5 ${status.text}`}>
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

        <span className={`shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${status.badge}`}>
          {item.status}
        </span>
      </div>

      <div
        className="h-8 overflow-hidden text-[11px] leading-4 text-slate-400"
        title={item.message}
      >
        {item.message}
      </div>

      <details className="mt-2 rounded-md border border-slate-800 bg-slate-950 px-2 py-1">
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
