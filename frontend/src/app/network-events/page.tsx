"use client";

import { authFetch } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  Activity,
  AlertTriangle,
  Database,
  Globe2,
  Network,
  RefreshCw,
  Search,
  Shield,
} from "lucide-react";

type NetworkEventItem = {
  id: number;
  source: string | null;
  event_type: string;
  event_timestamp: string | null;
  src_ip: string | null;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  hostname: string | null;
  url: string | null;
  http_method: string | null;
  http_user_agent: string | null;
  tls_sni: string | null;
  alert_signature: string | null;
  alert_category: string | null;
  alert_severity: number | null;
  created_at: string | null;
};

type NetworkEventsResponse = {
  total: number;
  limit: number;
  offset: number;
  items: NetworkEventItem[];
};

type NetworkEventsSummary = {
  total: number;
  by_event_type: Array<{ event_type: string; count: number }>;
  top_destinations: Array<{ dest_ip: string; count: number }>;
  top_hostnames: Array<{ hostname: string; count: number }>;
  latest_event_timestamp: string | null;
  latest_insert_timestamp: string | null;
};

const EVENT_TYPES = ["", "alert", "dns", "http", "tls", "flow"];

function formatDate(value: string | null) {
  if (!value) return "—";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "medium",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function compactValue(value: string | number | null | undefined) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function eventTypeClasses(type: string) {
  if (type === "alert") return "border-red-800 bg-red-950/40 text-red-200";
  if (type === "dns") return "border-cyan-800 bg-cyan-950/30 text-cyan-200";
  if (type === "http") return "border-blue-800 bg-blue-950/30 text-blue-200";
  if (type === "tls") return "border-violet-800 bg-violet-950/30 text-violet-200";
  if (type === "flow") return "border-slate-700 bg-slate-900 text-slate-300";

  return "border-slate-700 bg-slate-900 text-slate-300";
}

function alertSeverityClasses(severity: number | null) {
  if (severity === null || severity === undefined) {
    return "border-slate-700 bg-slate-900 text-slate-400";
  }

  if (severity <= 1) return "border-red-800 bg-red-950/40 text-red-200";
  if (severity === 2) return "border-orange-800 bg-orange-950/40 text-orange-200";
  if (severity === 3) return "border-amber-800 bg-amber-950/40 text-amber-200";

  return "border-slate-700 bg-slate-900 text-slate-300";
}

async function fetchSummary(): Promise<NetworkEventsSummary> {
  const response = await authFetch("/network-events/summary");

  if (!response.ok) {
    throw new Error(`Failed to load network summary: ${response.status}`);
  }

  return response.json();
}

async function fetchEvents(filters: {
  eventType: string;
  srcIp: string;
  destIp: string;
  hostname: string;
}): Promise<NetworkEventsResponse> {
  const params = new URLSearchParams();
  params.set("limit", "100");

  if (filters.eventType) params.set("event_type", filters.eventType);
  if (filters.srcIp) params.set("src_ip", filters.srcIp);
  if (filters.destIp) params.set("dest_ip", filters.destIp);
  if (filters.hostname) params.set("hostname", filters.hostname);

  const response = await authFetch(`/network-events?${params.toString()}`);

  if (!response.ok) {
    throw new Error(`Failed to load network events: ${response.status}`);
  }

  return response.json();
}

export default function NetworkEventsPage() {
  const [summary, setSummary] = useState<NetworkEventsSummary | null>(null);
  const [events, setEvents] = useState<NetworkEventsResponse | null>(null);
  const [eventType, setEventType] = useState("");
  const [srcIp, setSrcIp] = useState("");
  const [destIp, setDestIp] = useState("");
  const [hostname, setHostname] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const filters = useMemo(
    () => ({
      eventType,
      srcIp: srcIp.trim(),
      destIp: destIp.trim(),
      hostname: hostname.trim(),
    }),
    [eventType, srcIp, destIp, hostname]
  );

  const loadData = useCallback(async () => {
    setError(null);
    setRefreshing(true);

    try {
      const [summaryResponse, eventsResponse] = await Promise.all([
        fetchSummary(),
        fetchEvents(filters),
      ]);

      setSummary(summaryResponse);
      setEvents(eventsResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load network telemetry.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [filters]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const visibleEvents = events?.items ?? [];
  const byType = summary?.by_event_type ?? [];
  const topDestinations = summary?.top_destinations ?? [];
  const topHostnames = summary?.top_hostnames ?? [];

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <AppNavigation />

      <section className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-6 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-4 rounded-md border border-slate-800 bg-slate-950/80 p-5 shadow-sm">
          <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
            <div>
              <Link
                href="/"
                className="text-xs font-medium uppercase tracking-[0.24em] text-cyan-300 hover:text-cyan-200"
              >
                ← Dashboard
              </Link>

              <div className="mt-3 flex items-center gap-3">
                <div className="rounded-md border border-cyan-900/70 bg-cyan-950/30 p-2 text-cyan-200">
                  <Network className="h-5 w-5" />
                </div>

                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">
                    Network telemetry
                  </p>
                  <h1 className="text-2xl font-semibold tracking-tight text-slate-50">
                    Network Activity
                  </h1>
                </div>
              </div>

              <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
                Read-only Suricata telemetry for enterprise investigation context.
                Events are ingested as network evidence and are not converted into incidents automatically.
              </p>
            </div>

            <button
              onClick={loadData}
              disabled={refreshing}
              className="inline-flex items-center justify-center gap-2 rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>

        {error && (
          <div className="flex items-start gap-3 rounded-md border border-red-900/70 bg-red-950/30 p-4 text-sm text-red-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <p className="font-semibold">Unable to load network activity</p>
              <p className="mt-1 text-red-200/80">{error}</p>
            </div>
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            icon={<Database className="h-4 w-4" />}
            label="Network events"
            value={summary?.total ?? 0}
            helper="Persisted Suricata events"
          />
          <MetricCard
            icon={<Activity className="h-4 w-4" />}
            label="Event types"
            value={byType.length}
            helper="Alert / DNS / HTTP / TLS / Flow"
          />
          <MetricCard
            icon={<Globe2 className="h-4 w-4" />}
            label="Top destinations"
            value={topDestinations.length}
            helper="Destination IPs observed"
          />
          <MetricCard
            icon={<Shield className="h-4 w-4" />}
            label="Latest event"
            value={summary?.latest_event_timestamp ? "Active" : "No data"}
            helper={formatDate(summary?.latest_event_timestamp ?? null)}
          />
        </div>

        <section className="grid gap-4 xl:grid-cols-[1.4fr_0.8fr]">
          <Panel title="Network event filters" subtitle="Query network telemetry without changing incident state.">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <label className="flex flex-col gap-1.5 text-xs font-medium text-slate-400">
                Event type
                <select
                  value={eventType}
                  onChange={(event) => setEventType(event.target.value)}
                  className="rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-cyan-700"
                >
                  {EVENT_TYPES.map((type) => (
                    <option key={type || "all"} value={type}>
                      {type ? type.toUpperCase() : "All"}
                    </option>
                  ))}
                </select>
              </label>

              <TextFilter label="Source IP" value={srcIp} onChange={setSrcIp} placeholder="172.20.x.x" />
              <TextFilter label="Destination IP" value={destIp} onChange={setDestIp} placeholder="1.1.1.1" />
              <TextFilter label="Hostname" value={hostname} onChange={setHostname} placeholder="example.com" />
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2">
              <button
                onClick={loadData}
                disabled={refreshing}
                className="inline-flex items-center gap-2 rounded-md border border-cyan-800 bg-cyan-950/40 px-3 py-2 text-sm font-medium text-cyan-100 transition hover:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Search className="h-4 w-4" />
                Apply filters
              </button>

              <button
                onClick={() => {
                  setEventType("");
                  setSrcIp("");
                  setDestIp("");
                  setHostname("");
                }}
                className="rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-300 transition hover:border-slate-700"
              >
                Clear
              </button>
            </div>
          </Panel>

          <Panel title="Telemetry distribution" subtitle="Current event mix from Suricata EVE JSON.">
            <div className="space-y-2">
              {byType.length === 0 ? (
                <p className="text-sm text-slate-500">No event type summary available.</p>
              ) : (
                byType.map((item) => (
                  <div key={item.event_type} className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-950 px-3 py-2">
                    <span className={`rounded border px-2 py-0.5 text-xs font-semibold uppercase ${eventTypeClasses(item.event_type)}`}>
                      {item.event_type}
                    </span>
                    <span className="font-mono text-sm text-slate-300">{item.count}</span>
                  </div>
                ))
              )}
            </div>
          </Panel>
        </section>

        <section className="grid gap-4 xl:grid-cols-2">
          <RankedPanel title="Top destinations" emptyText="No destination IPs observed yet.">
            {topDestinations.map((item) => (
              <RankedRow key={item.dest_ip} label={item.dest_ip} value={item.count} />
            ))}
          </RankedPanel>

          <RankedPanel title="Top hostnames" emptyText="No hostnames observed yet.">
            {topHostnames.map((item) => (
              <RankedRow key={item.hostname} label={item.hostname} value={item.count} />
            ))}
          </RankedPanel>
        </section>

        <Panel
          title="Recent network events"
          subtitle={
            loading
              ? "Loading Suricata telemetry..."
              : `Showing ${visibleEvents.length} of ${events?.total ?? 0} matching events`
          }
        >
          {visibleEvents.length === 0 ? (
            <div className="rounded-md border border-dashed border-slate-800 bg-slate-950 p-8 text-center text-sm text-slate-500">
              No network events match the current filters.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="border-b border-slate-800 text-xs uppercase tracking-[0.18em] text-slate-500">
                  <tr>
                    <th className="py-3 pr-4">Time</th>
                    <th className="py-3 pr-4">Type</th>
                    <th className="py-3 pr-4">Source</th>
                    <th className="py-3 pr-4">Destination</th>
                    <th className="py-3 pr-4">Host / SNI</th>
                    <th className="py-3 pr-4">Protocol</th>
                    <th className="py-3 pr-4">Alert</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900">
                  {visibleEvents.map((item) => (
                    <tr key={item.id} className="align-top text-slate-300 hover:bg-slate-900/50">
                      <td className="max-w-[190px] py-3 pr-4 text-xs text-slate-400">
                        {formatDate(item.event_timestamp)}
                      </td>
                      <td className="py-3 pr-4">
                        <span className={`rounded border px-2 py-0.5 text-xs font-semibold uppercase ${eventTypeClasses(item.event_type)}`}>
                          {item.event_type}
                        </span>
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs">
                        {compactValue(item.src_ip)}
                        {item.src_port ? <span className="text-slate-500">:{item.src_port}</span> : null}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs">
                        {compactValue(item.dest_ip)}
                        {item.dest_port ? <span className="text-slate-500">:{item.dest_port}</span> : null}
                      </td>
                      <td className="max-w-[280px] py-3 pr-4">
                        <div className="truncate text-slate-200">
                          {compactValue(item.hostname ?? item.tls_sni)}
                        </div>
                        {item.url && (
                          <div className="mt-1 truncate font-mono text-xs text-slate-500">
                            {item.http_method ? `${item.http_method} ` : ""}
                            {item.url}
                          </div>
                        )}
                      </td>
                      <td className="py-3 pr-4">
                        <div className="font-mono text-xs text-slate-300">{compactValue(item.proto)}</div>
                        <div className="font-mono text-xs text-slate-500">{compactValue(item.app_proto)}</div>
                      </td>
                      <td className="max-w-[320px] py-3 pr-4">
                        {item.alert_signature ? (
                          <div className="space-y-1">
                            <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold ${alertSeverityClasses(item.alert_severity)}`}>
                              Severity {item.alert_severity ?? "—"}
                            </span>
                            <p className="text-xs text-slate-300">{item.alert_signature}</p>
                            {item.alert_category && (
                              <p className="text-xs text-slate-500">{item.alert_category}</p>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-600">No IDS alert</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </section>
    </main>
  );
}

function MetricCard({
  icon,
  label,
  value,
  helper,
}: {
  icon: ReactNode;
  label: string;
  value: string | number;
  helper: string;
}) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</p>
        <span className="rounded-md border border-slate-800 bg-slate-900 p-1.5 text-cyan-200">{icon}</span>
      </div>
      <p className="mt-3 text-2xl font-semibold text-slate-50">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{helper}</p>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-md border border-slate-800 bg-slate-950 p-4 shadow-sm">
      <div className="mb-4">
        <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">{title}</h2>
        {subtitle && <p className="mt-1 text-sm text-slate-500">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}

function TextFilter({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="flex flex-col gap-1.5 text-xs font-medium text-slate-400">
      {label}
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition placeholder:text-slate-700 focus:border-cyan-700"
      />
    </label>
  );
}

function RankedPanel({
  title,
  emptyText,
  children,
}: {
  title: string;
  emptyText: string;
  children: ReactNode;
}) {
  const hasChildren = Array.isArray(children) ? children.length > 0 : Boolean(children);

  return (
    <Panel title={title}>
      {hasChildren ? <div className="space-y-2">{children}</div> : <p className="text-sm text-slate-500">{emptyText}</p>}
    </Panel>
  );
}

function RankedRow({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-slate-800 bg-slate-950 px-3 py-2">
      <span className="truncate font-mono text-xs text-slate-300">{label}</span>
      <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-xs text-slate-300">
        {value}
      </span>
    </div>
  );
}
