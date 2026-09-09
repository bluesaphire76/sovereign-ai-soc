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

type ResolverContext = {
  is_observed_resolver: boolean;
  label: string;
  resolver_ip: string | null;
  dns_event_count: number;
  latest_dns_event_timestamp: string | null;
};

type TopDestinationItem = {
  dest_ip: string;
  count: number;
  country?: string | null;
  country_code?: string | null;
  country_source?: string | null;
  ip_scope?: string | null;
  resolver_context?: ResolverContext | null;
};

type NetworkEventsSummary = {
  total: number;
  by_event_type: Array<{ event_type: string; count: number }>;
  top_destinations: TopDestinationItem[];
  top_hostnames: Array<{ hostname: string; count: number }>;
  latest_event_timestamp: string | null;
  latest_insert_timestamp: string | null;
};

const EVENT_TYPES = ["", "alert", "dns", "http", "tls", "flow"];
const NETWORK_BADGE_BASE =
  "inline-flex h-5 w-fit items-center whitespace-nowrap rounded-sm border px-1.5 text-[10px] font-medium uppercase leading-none tracking-wide";
const COUNT_BADGE_BASE =
  "inline-flex h-5 min-w-8 items-center justify-center rounded-sm border border-slate-700 bg-slate-950 px-2 font-mono text-[10px] font-semibold text-slate-300";
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
  if (type === "alert") return SOC_TONE_CLASSES.danger.badge;
  if (type === "dns") return SOC_TONE_CLASSES.primary.badge;
  if (type === "http") return SOC_TONE_CLASSES.low.badge;
  if (type === "tls") return SOC_TONE_CLASSES.executive.badge;
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
    const timer = window.setTimeout(() => {
      void loadData();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadData]);

  const visibleEvents = events?.items ?? [];
  const byType = summary?.by_event_type ?? [];
  const topDestinations = summary?.top_destinations ?? [];
  const topHostnames = summary?.top_hostnames ?? [];

  return (
    <AppShell>

        <EnterprisePageHeader
          title="Network Activity"
          eyebrow="Operations / Telemetry"
          density="compact"
          icon={<Network aria-hidden="true" className="h-3.5 w-3.5" />}
          breadcrumbs={<EnterpriseBreadcrumbs items={[{ label: "Dashboard", href: "/" }, { label: "Network Events" }]} />}
          metadata={<EnterpriseBadge tone="muted">Read-only / Suricata evidence</EnterpriseBadge>}
          secondaryActions={<EnterpriseButton onClick={loadData} disabled={refreshing} size="xs"
            icon={<RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />}>Refresh</EnterpriseButton>}
        />

        {error && <EnterpriseErrorState className="mb-3" title="Unable to load network telemetry"
          message={`${error}${summary ? " Previous snapshot retained." : ""}`} onRetry={loadData} />}

        {loading ? <EnterpriseSkeleton label="Loading network telemetry" rows={6} /> : summary && events ? (<>
        <EnterpriseMetricStrip>
          <EnterpriseMetricCard stacked
            icon={<Database className="h-4 w-4" />}
            title="Network events"
            value={summary?.total ?? 0}
            subtitle="Persisted Suricata events"
            tone="primary"
          />
          <EnterpriseMetricCard stacked
            icon={<Activity className="h-4 w-4" />}
            title="Event types"
            value={byType.length}
            subtitle="Alert / DNS / HTTP / TLS / Flow"
            tone="neutral"
          />
          <EnterpriseMetricCard stacked
            icon={<Globe2 className="h-4 w-4" />}
            title="Top destinations"
            value={topDestinations.length}
            subtitle="Destination IPs observed"
            tone="neutral"
          />
          <EnterpriseMetricCard stacked
            icon={<Shield className="h-4 w-4" />}
            title="Latest event"
            value={summary?.latest_event_timestamp ? "Active" : "No data"}
            subtitle={formatDate(summary?.latest_event_timestamp ?? null)}
            tone={summary?.latest_event_timestamp ? "success" : "neutral"}
          />
        </EnterpriseMetricStrip>

        <section className="mt-3 grid gap-3 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,0.8fr)]">
          <Panel title="Network event filters" subtitle="Query network telemetry without changing incident state.">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <EnterpriseSelect label="Event type" value={eventType} onChange={setEventType}
                options={EVENT_TYPES.map((type) => ({ value: type, label: type ? type.toUpperCase() : "All" }))} />

              <TextFilter label="Source IP" value={srcIp} onChange={setSrcIp} placeholder="172.20.x.x" />
              <TextFilter label="Destination IP" value={destIp} onChange={setDestIp} placeholder="1.1.1.1" />
              <TextFilter label="Hostname" value={hostname} onChange={setHostname} placeholder="example.com" />
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2">
              <EnterpriseButton
                onClick={loadData}
                disabled={refreshing}
                tone="primary"
                size="xs"
                icon={<Search className="h-3.5 w-3.5" />}
              >
                Apply filters
              </EnterpriseButton>

              <EnterpriseButton
                onClick={() => {
                  setEventType("");
                  setSrcIp("");
                  setDestIp("");
                  setHostname("");
                }}
                tone="ghost"
                size="xs"
              >
                Clear
              </EnterpriseButton>
            </div>
          </Panel>

          <Panel title="Telemetry distribution" subtitle="Current event mix from Suricata EVE JSON.">
            <div className="space-y-2">
              {byType.length === 0 ? (
                <p className="text-xs text-slate-500">No event type summary available.</p>
              ) : (
                byType.map((item) => (
                  <div key={item.event_type} className="flex items-center justify-between rounded-sm border border-slate-800 bg-slate-950/80 px-3 py-2">
                    <span className={`${NETWORK_BADGE_BASE} ${eventTypeClasses(item.event_type)}`}>
                      {item.event_type}
                    </span>
                    <span className={COUNT_BADGE_BASE}>{item.count}</span>
                  </div>
                ))
              )}
            </div>
          </Panel>
        </section>

        <section className="mt-3 grid gap-3 xl:grid-cols-2">
          <RankedPanel title="Top destinations" emptyText="No destination IPs observed yet.">
            {topDestinations.map((item) => (
              <DestinationRankedRow key={item.dest_ip} item={item} />
            ))}
          </RankedPanel>

          <RankedPanel title="Top hostnames" emptyText="No hostnames observed yet.">
            {topHostnames.map((item) => (
              <RankedRow key={item.hostname} label={item.hostname} value={item.count} />
            ))}
          </RankedPanel>
        </section>

        <div className="mt-3">
          <Panel
            title="Recent network events"
            subtitle={
              loading
                ? "Loading Suricata telemetry..."
                : `Showing ${visibleEvents.length} of ${events?.total ?? 0} matching events`
            }
          >
            {visibleEvents.length === 0 ? (
              <EnterpriseEmptyState title="No network events match the current filters." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1120px] table-fixed text-left text-[12px]">
                <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="w-[170px] px-2 py-2 font-semibold">Time</th>
                    <th className="w-[90px] px-2 py-2 font-semibold">Type</th>
                    <th className="w-[160px] px-2 py-2 font-semibold">Source</th>
                    <th className="w-[160px] px-2 py-2 font-semibold">Destination</th>
                    <th className="w-[260px] px-2 py-2 font-semibold">Host / SNI</th>
                    <th className="w-[120px] px-2 py-2 font-semibold">Protocol</th>
                    <th className="px-2 py-2 font-semibold">Alert</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900">
                  {visibleEvents.map((item) => (
                    <tr key={item.id} className="align-top text-slate-300 hover:bg-slate-900/50">
                      <td className="px-2 py-2 font-mono text-[10px] text-slate-500">
                        {formatDate(item.event_timestamp)}
                      </td>
                      <td className="px-2 py-2">
                        <span className={`${NETWORK_BADGE_BASE} ${eventTypeClasses(item.event_type)}`}>
                          {item.event_type}
                        </span>
                      </td>
                      <td className="px-2 py-2 font-mono text-[11px]">
                        {compactValue(item.src_ip)}
                        {item.src_port ? <span className="text-slate-500">:{item.src_port}</span> : null}
                      </td>
                      <td className="px-2 py-2 font-mono text-[11px]">
                        {compactValue(item.dest_ip)}
                        {item.dest_port ? <span className="text-slate-500">:{item.dest_port}</span> : null}
                      </td>
                      <td className="px-2 py-2">
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
                      <td className="px-2 py-2">
                        <div className="font-mono text-[11px] text-slate-300">{compactValue(item.proto)}</div>
                        <div className="font-mono text-xs text-slate-500">{compactValue(item.app_proto)}</div>
                      </td>
                      <td className="px-2 py-2">
                        {item.alert_signature ? (
                          <div className="space-y-1">
                            <span className={`${NETWORK_BADGE_BASE} ${alertSeverityClasses(item.alert_severity)}`}>
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
        </div>
        </>) : null}
    </AppShell>
  );
}


function DestinationRankedRow({ item }: { item: TopDestinationItem }) {
  const resolverContext = item.resolver_context;
  const resolverObserved = Boolean(resolverContext?.is_observed_resolver);
  const country = compactValue(item.country ?? "Unknown");
  const resolverLabel = resolverObserved ? "observed resolver" : "not observed";

  return (
    <div className="rounded-sm border border-slate-800 bg-slate-950/80 px-3 py-2">
      <div className="flex items-center justify-between gap-3">
        <span className="truncate font-mono text-[11px] text-slate-300">{compactValue(item.dest_ip)}</span>
        <span className={COUNT_BADGE_BASE}>{item.count}</span>
      </div>

      <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] leading-4 text-slate-500">
        <span>
          Country: <span className="text-slate-400">{country}</span>
        </span>
        <span className="text-slate-700">·</span>
        <span>
          Resolver context:{" "}
          <span className={resolverObserved ? "text-cyan-300" : "text-slate-400"}>
            {resolverLabel}
          </span>
        </span>
        {resolverObserved && resolverContext?.dns_event_count ? (
          <>
            <span className="text-slate-700">·</span>
            <span>
              DNS events: <span className="text-slate-400">{resolverContext.dns_event_count}</span>
            </span>
          </>
        ) : null}
      </div>
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
    <EnterpriseSection title={title} description={subtitle} className="!border-0 !bg-transparent !p-0 !shadow-none">
      {children}
    </EnterpriseSection>
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
  return <EnterpriseSearchInput label={label} value={value} onChange={onChange} placeholder={placeholder} />;
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
      {hasChildren ? <div className="space-y-2">{children}</div> : <EnterpriseEmptyState title={emptyText} />}
    </Panel>
  );
}

function RankedRow({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-sm border border-slate-800 bg-slate-950/80 px-3 py-2">
      <span className="truncate font-mono text-xs text-slate-300">{label}</span>
      <span className={COUNT_BADGE_BASE}>
        {value}
      </span>
    </div>
  );
}
