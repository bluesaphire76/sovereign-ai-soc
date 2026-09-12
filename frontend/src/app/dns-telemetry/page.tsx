"use client";

import { authFetch } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import AppShell from "@/components/AppShell";
import {
  EnterpriseBadge, EnterpriseBreadcrumbs, EnterpriseButton, EnterpriseEmptyState,
  EnterpriseErrorState, EnterpriseMetricCard, EnterpriseMetricStrip, EnterprisePageHeader,
  EnterpriseSection, EnterpriseSearchInput, EnterpriseSelect, EnterpriseSkeleton,
} from "@/components/enterprise";
import { SOC_TONE_CLASSES } from "@/lib/semantic-styles";

import {
  Activity,
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

  if (value === "A") return SOC_TONE_CLASSES.low.badge;
  if (value === "AAAA") return SOC_TONE_CLASSES.primary.badge;
  if (value === "HTTPS") return SOC_TONE_CLASSES.executive.badge;
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
    const timer = window.setTimeout(() => {
      void loadData();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadData]);

  const visibleEvents = events?.items ?? [];
  const byQueryType = summary?.by_query_type ?? [];
  const topDomains = summary?.top_domains ?? [];
  const topClients = summary?.top_clients ?? [];
  const latestEvent = summary?.latest_event ?? null;
  const topClient = topClients[0]?.client ?? latestEvent?.agent_name ?? "—";
  const topQueryType = byQueryType[0]?.query_type ?? "—";

  return (
    <AppShell>

        <EnterprisePageHeader
          title="DNS Telemetry"
          eyebrow="Operations / Telemetry"
          density="compact"
          icon={<Globe2 aria-hidden="true" className="h-3.5 w-3.5" />}
          breadcrumbs={<EnterpriseBreadcrumbs items={[{ label: "Dashboard", href: "/" }, { label: "DNS Telemetry" }]} />}
          metadata={<EnterpriseBadge tone="muted">Read-only / Wazuh endpoint DNS evidence</EnterpriseBadge>}
          secondaryActions={<EnterpriseButton onClick={loadData} disabled={refreshing} size="xs"
            icon={<RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />}>Refresh</EnterpriseButton>}
        />

        {error && <EnterpriseErrorState className="mb-3" title="Unable to load DNS telemetry"
          message={`${error}${summary ? " Previous snapshot retained." : ""}`} onRetry={loadData} />}

        {loading ? (
          <EnterpriseSkeleton label="Loading DNS telemetry" rows={6} />
        ) : summary && events ? (
          <>
            <EnterpriseMetricStrip className="mb-3">
              <EnterpriseMetricCard stacked
                title="DNS events"
                value={summary?.total ?? 0}
                subtitle="Normalized endpoint DNS observations"
                icon={<Database className="h-4 w-4" />}
                tone="primary"
              />
              <EnterpriseMetricCard stacked
                title="Latest DNS event freshness"
                value={formatFreshness(summary?.latest_event_freshness_seconds)}
                subtitle={formatDate(latestEvent?.event_timestamp)}
                icon={<Activity className="h-4 w-4" />}
                tone={(summary?.latest_event_freshness_seconds ?? 999999) > 3600 ? "warning" : "success"}
              />
              <EnterpriseMetricCard stacked
                title="Top DNS client"
                value={compactValue(topClient)}
                subtitle={`${topClients[0]?.count ?? 0} observed queries`}
                icon={<Server className="h-4 w-4" />}
                tone="neutral"
              />
              <EnterpriseMetricCard stacked
                title="Top query type"
                value={compactValue(topQueryType)}
                subtitle={`${byQueryType[0]?.count ?? 0} observations`}
                icon={<Shield className="h-4 w-4" />}
                tone="neutral"
              />
            </EnterpriseMetricStrip>

            <section className="grid gap-3 xl:grid-cols-[320px_minmax(0,1fr)]">
              <div className="min-w-0 space-y-3">
                <Panel title="DNS event filters" subtitle="Query DNS telemetry without changing incident state.">
                  <div className="grid gap-2">
                    <EnterpriseSearchInput label="Domain contains" value={queryName} onChange={setQueryName} placeholder="github.com" />
                    <EnterpriseSearchInput label="Client IP" value={clientIp} onChange={setClientIp} placeholder="192.168.1.148" />
                    <EnterpriseSelect label="Query type" value={queryType} onChange={setQueryType}
                      options={QUERY_TYPES.map((type) => ({ value: type, label: type || "All query types" }))} />

                    <div className="flex gap-1.5 pt-1">
                      <EnterpriseButton onClick={loadData} disabled={refreshing} tone="primary" size="xs" icon={<Search className="h-3.5 w-3.5" />}>
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

              <div className="min-w-0 space-y-3">
                <Panel title="Recent DNS queries" subtitle="Endpoint DNS observations collected through Wazuh.">
                  {visibleEvents.length === 0 ? (
                    <EnterpriseEmptyState title="No DNS events match the current filters." />
                  ) : (
                    <div className="overflow-x-auto" role="region" aria-label="DNS events" tabIndex={0}>
                      <table className="w-full min-w-[850px] table-fixed text-left text-xs">
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
        ) : null}
    </AppShell>
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
    <EnterpriseSection title={title} description={subtitle} className="!border-0 !bg-transparent !p-0 !shadow-none">
      {children}
    </EnterpriseSection>
  );
}
