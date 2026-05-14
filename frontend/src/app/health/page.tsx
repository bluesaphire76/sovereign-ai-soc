"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  HeartPulse,
  RefreshCw,
  Server,
  XCircle,
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

function statusClass(status: HealthStatus) {
  if (status === "OK") return "bg-emerald-100 text-emerald-800 border-emerald-200";
  if (status === "WARN") return "bg-yellow-100 text-yellow-800 border-yellow-200";
  if (status === "ERROR") return "bg-red-100 text-red-800 border-red-200";

  return "bg-slate-200 text-slate-800 border-slate-300";
}

function statusIcon(status: HealthStatus) {
  if (status === "OK") return <CheckCircle2 className="h-5 w-5 text-emerald-400" />;
  if (status === "WARN") return <AlertTriangle className="h-5 w-5 text-yellow-400" />;
  if (status === "ERROR") return <XCircle className="h-5 w-5 text-red-400" />;

  return <Activity className="h-5 w-5 text-slate-400" />;
}

function componentIcon(component: string) {
  if (component.includes("postgres")) return <Database className="h-5 w-5" />;
  if (component.includes("worker")) return <HeartPulse className="h-5 w-5" />;
  if (component.includes("wazuh")) return <Server className="h-5 w-5" />;

  return <Activity className="h-5 w-5" />;
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
    const order = ["api", "postgres", "ollama", "wazuh_indexer", "wazuh_ingest", "qdrant", "ai_soc_worker"];

    return [...(health?.components ?? [])].sort((a, b) => {
      return order.indexOf(a.component) - order.indexOf(b.component);
    });
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
              <HeartPulse className="h-4 w-4" />
              Platform health
            </div>

            <h1 className="text-3xl font-semibold tracking-tight">
              Health Dashboard
            </h1>

            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Operational status for the local AI SOC stack: API, database,
              Wazuh, Ollama, Qdrant and worker heartbeat.
            </p>
          </div>

          <button
            onClick={loadHealth}
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
            Loading platform health...
          </div>
        ) : (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-3">
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <div className="mb-3 text-sm text-slate-400">Overall status</div>
                <div className="flex items-center gap-3">
                  {statusIcon(health?.status ?? "UNKNOWN")}
                  <span
                    className={`rounded-full border px-4 py-1.5 text-sm ${statusClass(
                      health?.status ?? "UNKNOWN"
                    )}`}
                  >
                    {health?.status ?? "UNKNOWN"}
                  </span>
                </div>
              </div>

              <MetricCard
                title="Components checked"
                value={health?.components.length ?? 0}
              />

              <MetricCard
                title="Checked at"
                value={formatTimestamp(health?.checked_at)}
              />
            </section>

            {health?.latest_incident && (
              <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <h2 className="mb-4 text-lg font-medium">Latest processed incident</h2>

                <div className="grid gap-4 md:grid-cols-4">
                  <DetailRow
                    label="Incident"
                    value={`#${health.latest_incident.id}`}
                  />
                  <DetailRow
                    label="Time"
                    value={formatTimestamp(health.latest_incident.timestamp)}
                  />
                  <DetailRow
                    label="Host"
                    value={health.latest_incident.agent ?? "unknown"}
                  />
                  <DetailRow
                    label="Risk"
                    value={`${health.latest_incident.risk_score ?? 0}`}
                  />
                </div>

                <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300">
                  {health.latest_incident.rule ?? "-"}
                </div>
              </section>
            )}

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-medium">Components</h2>
                <span className="text-xs text-slate-500">
                  Auto refresh every 30s
                </span>
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                {sortedComponents.map((item) => (
                  <div
                    key={item.component}
                    className="rounded-2xl border border-slate-800 bg-slate-950 p-5"
                  >
                    <div className="mb-4 flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <div className="rounded-xl bg-slate-900 p-2 text-cyan-300">
                          {componentIcon(item.component)}
                        </div>

                        <div>
                          <div className="font-medium">{item.component}</div>
                          <div className="text-xs text-slate-500">
                            {item.latency_ms} ms
                          </div>
                        </div>
                      </div>

                      <span
                        className={`rounded-full border px-3 py-1 text-xs ${statusClass(
                          item.status
                        )}`}
                      >
                        {item.status}
                      </span>
                    </div>

                    <div className="mb-4 text-sm text-slate-300">
                      {item.message}
                    </div>

                    <details className="rounded-xl border border-slate-800 bg-slate-900 p-3">
                      <summary className="cursor-pointer text-sm text-slate-400">
                        Details
                      </summary>

                      <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap text-xs leading-5 text-slate-300">
                        {JSON.stringify(item.details ?? {}, null, 2)}
                      </pre>
                    </details>
                  </div>
                ))}
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
}: {
  title: string;
  value: string | number;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-3 text-sm text-slate-400">{title}</div>
      <div className="break-words text-xl font-semibold">{value}</div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
      <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="break-words text-sm text-slate-200">{value}</div>
    </div>
  );
}
