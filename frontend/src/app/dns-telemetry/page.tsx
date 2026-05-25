"use client";

import { authFetch } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import { EnterpriseButton } from "../../components/enterprise";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Database,
  Globe2,
  RefreshCw,
  Search,
  Server,
  Shield,
} from "lucide-react";

type DnsEventItem = {
  id: number;
  source: string | null;
  raw_event_id?: number | null;
  source_event_id?: string | null;
  event_timestamp: string | null;
  agent_name: string | null;
  agent_ip: string | null;
  client_ip: string | null;
  client_port?: number | null;
  resolver_ip: string | null;
  resolver_port?: number | null;
  query_name: string | null;
  query_type: string | null;
  query_status: string | null;
  process_name?: string | null;
  process_path?: string | null;
  user_name?: string | null;
  collector: string | null;
  raw_line?: string | null;
  event_fingerprint?: string | null;
  created_at: string | null;
};

type DnsEventsResponse = {
  total: number;
  limit: number;
  offset: number;
  items: DnsEventItem[];
  filters?: Record<string, string | null>;
};

type DnsEventsSummary = {
  total: number;
  latest_event: DnsEventItem | null;
  latest_event_freshness_seconds: number | null;
  by_query_type: Array<{ query_type: string | null; count: number }>;
  top_domains: Array<{ query_name: string | null; count: number }>;
  top_clients: Array<{ client: string | null; count: number }>;
};

const QUERY_TYPES = ["", "A", "AAAA", "HTTPS", "CNAME", "MX", "TXT", "SRV", "PTR"];
const DNS_BADGE_BASE =
  "inline-flex h-5 w-fit items-center whitespace-nowrap rounded-sm border px-1.5 text-[10px] font-medium uppercase leading-none tracking-wide";
const COUNT_BADGE_BASE =
  "inline-flex h-5 min-w-8 items-center justify-center rounded-sm border border-slate-700 bg-slate-950 px-2 font-mono text-[10px] font-semibold text-slate-300";
const CONTROL_CLASS =
  "h-8 rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-500";

type DnsMetricTone = "neutral" | "primary" | "success" | "warning" | "danger";

const dnsMetricToneClasses: Record<DnsMetricTone, string> = {
  neutral: "border-slate-800 bg-slate-900 text-slate-100",
  primary: "border-cyan-900 bg-cyan-950/30 text-cyan-100",
  success: "border-emerald-900 bg-emerald-950/30 text-emerald-100",
  warning: "border-orange-900 bg-orange-950/30 text-orange-100",
  danger: "border-red-900 bg-red-950/30 text-red-100",
};

const dnsMetricIconClasses: Record<DnsMetricTone, string> = {
  neutral: "bg-slate-950 text-slate-400",
  primary: "bg-cyan-950 text-cyan-300",
  success: "bg-emerald-950 text-emerald-300",
  warning: "bg-orange-950 text-orange-300",
  danger: "bg-red-950 text-red-300",
};

function formatDate(value: string | null | undefined) {
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

function formatFreshness(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined) return "—";

  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;

  return `${Math.round(seconds / 86400)}d`;
}

function queryTypeClasses(type: string | null) {
  const value = (type ?? "").toUpperCase();

  if (value === "A") return "border-emerald-800 bg-emerald-950/30 text-emerald-200";
  if (value === "AAAA") return "border-cyan-800 bg-cyan-950/30 text-cyan-200";
  if (value === "HTTPS") return "border-violet-800 bg-violet-950/30 text-violet-200";
  if (value === "CNAME") return "border-blue-800 bg-blue-950/30 text-blue-200";
  if (value === "TXT") return "border-orange-800 bg-orange-950/30 text-orange-200";

  return "border-slate-700 bg-slate-900 text-slate-300";
}

async function fetchSummary(): Promise<DnsEventsSummary> {
  const response = await authFetch("/dns-events/summary");

  if (!response.ok) {
    throw new Error(`Failed to load DNS summary: ${response.status}`);
  }

  return response.json();
}

async function fetchDnsEvents(filters: {
  queryName: string;
  clientIp: string;
  queryType: string;
}): Promise<DnsEventsResponse> {
  const params = new URLSearchParams();
  params.set("limit", "100");

  if (filters.queryName) params.set("query_name", filters.queryName);
  if (filters.clientIp) params.set("client_ip", filters.clientIp);
  if (filters.queryType) params.set("query_type", filters.queryType);

  const response = await authFetch(`/dns-events?${params.toString()}`);

  if (!response.ok) {
    throw new Error(`Failed to load DNS events: ${response.status}`);
  }

  return response.json();
}

export default function DnsTelemetryPage() {
  const [summary, setSummary] = useState<DnsEventsSummary | null>(null);
  const [events, setEvents] = useState<DnsEventsResponse | null>(null);
  const [queryName, setQueryName] = useState("");
  const [clientIp, setClientIp] = useState("");
  const [queryType, setQueryType] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const filters = useMemo(
    () => ({
      queryName: queryName.trim(),
      clientIp: clientIp.trim(),
      queryType: queryType.trim(),
    }),
    [queryName, clientIp, queryType]
  );

  const loadData = useCallback(async () => {
    setError(null);
    setRefreshing(true);

    try {
      const [summaryResponse, eventsResponse] = await Promise.all([
        fetchSummary(),
        fetchDnsEvents(filters),
      ]);

      setSummary(summaryResponse);
      setEvents(eventsResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load DNS telemetry.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [filters]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const visibleEvents = events?.items ?? [];
  const byQueryType = summary?.by_query_type ?? [];
  const topDomains = summary?.top_domains ?? [];
  const topClients = summary?.top_clients ?? [];
  const latestEvent = summary?.latest_event ?? null;
  const topClient = topClients[0]?.client ?? latestEvent?.agent_name ?? "—";
  const topQueryType = byQueryType[0]?.query_type ?? "—";

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-2 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-3 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to dashboard
            </Link>

            <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
              <Globe2 className="h-4 w-4" />
              DNS telemetry
            </div>

            <h1 className="text-xl font-semibold tracking-tight text-slate-100">
              DNS Telemetry
            </h1>

            <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
              Read-only endpoint DNS evidence collected through Wazuh. DNS observations enrich
              investigations and are not converted into incidents, blocks or remediation actions automatically.
            </p>
          </div>

          <div className="flex flex-wrap gap-1.5">
            <EnterpriseButton
              onClick={loadData}
              disabled={refreshing}
              tone="secondary"
              size="xs"
              icon={<RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />}
            >
              Refresh
            </EnterpriseButton>
          </div>
        </header>

        {error && (
          <div className="mb-3 flex items-start gap-2 rounded-sm border border-red-800 bg-red-950/50 px-3 py-2 text-xs text-red-200">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              <p className="font-semibold">Unable to load DNS telemetry</p>
              <p className="mt-1 text-red-200/80">API error: {error}</p>
            </div>
          </div>
        )}

        {loading ? (
          <div className="rounded-sm border border-slate-800 bg-slate-900 px-3 py-8 text-center text-sm text-slate-400">
            Loading DNS telemetry...
          </div>
        ) : (
          <>
            <section className="mb-3 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
              <DnsMetric
                title="DNS events"
                value={summary?.total ?? 0}
                subtitle="Normalized endpoint DNS observations"
                icon={<Database className="h-4 w-4" />}
                tone="primary"
              />
              <DnsMetric
                title="Latest DNS event freshness"
                value={formatFreshness(summary?.latest_event_freshness_seconds)}
                subtitle={formatDate(latestEvent?.event_timestamp)}
                icon={<Activity className="h-4 w-4" />}
                tone={(summary?.latest_event_freshness_seconds ?? 999999) > 3600 ? "warning" : "success"}
              />
              <DnsMetric
                title="Top DNS client"
                value={compactValue(topClient)}
                subtitle={`${topClients[0]?.count ?? 0} observed queries`}
                icon={<Server className="h-4 w-4" />}
                tone="neutral"
              />
              <DnsMetric
                title="Top query type"
                value={compactValue(topQueryType)}
                subtitle={`${byQueryType[0]?.count ?? 0} observations`}
                icon={<Shield className="h-4 w-4" />}
                tone="neutral"
              />
            </section>

            <section className="grid gap-3 xl:grid-cols-[360px_minmax(0,1fr)]">
              <div className="space-y-3">
                <Panel title="DNS event filters" subtitle="Query DNS telemetry without changing incident state.">
                  <div className="grid gap-2">
                    <label className="grid gap-1 text-xs text-slate-400">
                      Domain contains
                      <div className="relative">
                        <Search className="pointer-events-none absolute left-2 top-2 h-3.5 w-3.5 text-slate-500" />
                        <input
                          value={queryName}
                          onChange={(event) => setQueryName(event.target.value)}
                          placeholder="github.com"
                          className={`${CONTROL_CLASS} w-full pl-7`}
                        />
                      </div>
                    </label>

                    <label className="grid gap-1 text-xs text-slate-400">
                      Client IP
                      <input
                        value={clientIp}
                        onChange={(event) => setClientIp(event.target.value)}
                        placeholder="192.168.1.148"
                        className={`${CONTROL_CLASS} w-full`}
                      />
                    </label>

                    <label className="grid gap-1 text-xs text-slate-400">
                      Query type
                      <select
                        value={queryType}
                        onChange={(event) => setQueryType(event.target.value)}
                        className={`${CONTROL_CLASS} w-full`}
                      >
                        {QUERY_TYPES.map((type) => (
                          <option key={type || "all"} value={type}>
                            {type || "All query types"}
                          </option>
                        ))}
                      </select>
                    </label>

                    <div className="flex gap-1.5 pt-1">
                      <EnterpriseButton onClick={loadData} tone="primary" size="xs">
                        Apply filters
                      </EnterpriseButton>
                      <EnterpriseButton
                        onClick={() => {
                          setQueryName("");
                          setClientIp("");
                          setQueryType("");
                        }}
                        tone="secondary"
                        size="xs"
                      >
                        Reset
                      </EnterpriseButton>
                    </div>
                  </div>
                </Panel>

                <Panel title="Query type distribution" subtitle="Normalized DNS record types.">
                  <div className="space-y-1.5">
                    {byQueryType.length === 0 ? (
                      <p className="text-xs text-slate-500">No DNS query types available.</p>
                    ) : (
                      byQueryType.map((item) => (
                        <div
                          key={item.query_type ?? "unknown"}
                          className="flex items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-950 px-2 py-1.5"
                        >
                          <span className={`${DNS_BADGE_BASE} ${queryTypeClasses(item.query_type)}`}>
                            {item.query_type ?? "UNKNOWN"}
                          </span>
                          <span className={COUNT_BADGE_BASE}>{item.count}</span>
                        </div>
                      ))
                    )}
                  </div>
                </Panel>

                <Panel title="Top DNS clients" subtitle="Most active observed clients.">
                  <div className="space-y-1.5">
                    {topClients.length === 0 ? (
                      <p className="text-xs text-slate-500">No DNS clients available.</p>
                    ) : (
                      topClients.slice(0, 10).map((item) => (
                        <div
                          key={item.client ?? "unknown"}
                          className="flex items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-950 px-2 py-1.5"
                        >
                          <span className="truncate text-xs text-slate-300">{item.client ?? "unknown"}</span>
                          <span className={COUNT_BADGE_BASE}>{item.count}</span>
                        </div>
                      ))
                    )}
                  </div>
                </Panel>
              </div>

              <div className="space-y-3">
                <Panel title="Recent DNS queries" subtitle="Endpoint DNS observations collected through Wazuh.">
                  {visibleEvents.length === 0 ? (
                    <div className="rounded-sm border border-slate-800 bg-slate-950 px-3 py-8 text-center text-xs text-slate-500">
                      No DNS events match the current filters.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-left text-xs">
                        <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                          <tr>
                            <th className="px-2 py-2 font-medium">Time</th>
                            <th className="px-2 py-2 font-medium">Client</th>
                            <th className="px-2 py-2 font-medium">Query</th>
                            <th className="px-2 py-2 font-medium">Type</th>
                            <th className="px-2 py-2 font-medium">Resolver</th>
                            <th className="px-2 py-2 font-medium">Source</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {visibleEvents.map((item) => (
                            <tr key={item.id} className="align-top hover:bg-slate-900/70">
                              <td className="whitespace-nowrap px-2 py-2 text-slate-400">
                                {formatDate(item.event_timestamp)}
                              </td>
                              <td className="px-2 py-2">
                                <div className="font-medium text-slate-200">
                                  {compactValue(item.agent_name)}
                                </div>
                                <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                                  {compactValue(item.client_ip)}
                                </div>
                              </td>
                              <td className="max-w-[360px] px-2 py-2">
                                <div className="truncate font-mono text-[11px] text-cyan-100" title={item.query_name ?? ""}>
                                  {compactValue(item.query_name)}
                                </div>
                                <div className="mt-0.5 truncate text-[10px] text-slate-500" title={item.raw_line ?? ""}>
                                  {compactValue(item.raw_line)}
                                </div>
                              </td>
                              <td className="px-2 py-2">
                                <span className={`${DNS_BADGE_BASE} ${queryTypeClasses(item.query_type)}`}>
                                  {item.query_type ?? "UNKNOWN"}
                                </span>
                              </td>
                              <td className="whitespace-nowrap px-2 py-2 font-mono text-[11px] text-slate-300">
                                {compactValue(item.resolver_ip)}
                              </td>
                              <td className="px-2 py-2">
                                <div className="text-slate-300">{compactValue(item.source)}</div>
                                <div className="mt-0.5 text-[10px] text-slate-500">
                                  {compactValue(item.collector)}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Panel>

                <Panel title="Top queried domains" subtitle="Most frequently observed domain names.">
                  <div className="grid gap-1.5 md:grid-cols-2">
                    {topDomains.length === 0 ? (
                      <p className="text-xs text-slate-500">No DNS domains available.</p>
                    ) : (
                      topDomains.slice(0, 20).map((item) => (
                        <div
                          key={item.query_name ?? "unknown"}
                          className="flex items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-950 px-2 py-1.5"
                        >
                          <span
                            className="truncate font-mono text-[11px] text-slate-300"
                            title={item.query_name ?? ""}
                          >
                            {item.query_name ?? "unknown"}
                          </span>
                          <span className={COUNT_BADGE_BASE}>{item.count}</span>
                        </div>
                      ))
                    )}
                  </div>
                </Panel>
              </div>
            </section>
          </>
        )}
      </div>
    </main>
  );
}

function DnsMetric({
  title,
  value,
  subtitle,
  icon,
  tone = "neutral",
}: {
  title: string;
  value: ReactNode;
  subtitle: string;
  icon: ReactNode;
  tone?: DnsMetricTone;
}) {
  return (
    <div
      className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${dnsMetricToneClasses[tone]}`}
    >
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-wide text-slate-500">{title}</p>
        <div className="mt-1 truncate text-base font-semibold text-slate-100">{value}</div>
        <p className="mt-0.5 truncate text-[10px] text-slate-500">{subtitle}</p>
      </div>
      <div className={`shrink-0 rounded-sm p-1.5 ${dnsMetricIconClasses[tone]}`}>{icon}</div>
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
    <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2">
        <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}
