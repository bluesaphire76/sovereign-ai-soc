"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  FileJson,
  ListFilter,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";
import AppNavigation from "../../../components/AppNavigation";
import { authFetch, fetchCurrentUser, type AuthUser } from "../../../lib/auth";

type SecurityAuditEvent = {
  id: number;
  created_at: string | null;
  event_type: string;
  outcome: string;
  actor_user_id: number | null;
  actor_username: string | null;
  actor_role: string | null;
  target_type: string | null;
  target_id: string | null;
  target_username: string | null;
  method: string | null;
  path: string | null;
  client_ip: string | null;
  user_agent: string | null;
  details: Record<string, unknown> | null;
};

type SecurityAuditResponse = {
  items: SecurityAuditEvent[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

const EVENT_TYPES = [
  "ALL",
  "AUTH_LOGIN_SUCCESS",
  "AUTH_LOGIN_FAILURE",
  "RBAC_DENIED",
  "USER_CREATED",
  "USER_UPDATED",
  "USER_PASSWORD_RESET",
  "USER_DELETED",
  "SYNTHETIC_TEST_RUN",
  "INCIDENT_STATUS_UPDATED",
  "INCIDENT_NOTE_CREATED",
  "CASE_WORKFLOW_UPDATED",
  "CASE_CLOSURE_UPDATED",
  "CASE_ACTION_CREATED",
  "CASE_ACTION_UPDATED",
  "CASE_ACTION_SUGGESTIONS_GENERATED",
  "CASE_AI_ANALYSIS_GENERATED",
];

const OUTCOMES = ["ALL", "SUCCESS", "FAILURE", "DENIED"];

const TARGET_TYPES = [
  "ALL",
  "USER",
  "SYNTHETIC_TEST",
  "INCIDENT",
  "CASE",
  "CASE_ACTION",
];

function formatTimestamp(value: string | null) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "short",
      timeStyle: "medium",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function eventBadgeClass(eventType: string) {
  if (eventType.includes("FAILURE") || eventType.includes("DENIED")) {
    return "border-red-800 bg-red-950 text-red-200";
  }

  if (eventType.startsWith("AUTH_")) {
    return "border-cyan-800 bg-cyan-950 text-cyan-200";
  }

  if (eventType.startsWith("USER_")) {
    return "border-violet-800 bg-violet-950 text-violet-200";
  }

  return "border-slate-700 bg-slate-950 text-slate-300";
}

function outcomeBadgeClass(outcome: string) {
  if (outcome === "SUCCESS") {
    return "border-emerald-700 bg-emerald-950 text-emerald-200";
  }

  if (outcome === "DENIED") {
    return "border-amber-700 bg-amber-950 text-amber-200";
  }

  return "border-red-800 bg-red-950 text-red-200";
}

function detailsPreview(details: Record<string, unknown> | null) {
  if (!details) return "-";

  const keys = Object.keys(details);

  if (keys.length === 0) return "-";

  return keys.slice(0, 4).join(", ");
}

function detailsJson(details: Record<string, unknown> | null) {
  if (!details) return "{}";

  return JSON.stringify(details, null, 2);
}

export default function AdminSecurityAuditPage() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [data, setData] = useState<SecurityAuditResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const [page, setPage] = useState(1);
  const [eventType, setEventType] = useState("ALL");
  const [outcome, setOutcome] = useState("ALL");
  const [targetType, setTargetType] = useState("ALL");
  const [actorUsername, setActorUsername] = useState("");
  const [targetId, setTargetId] = useState("");
  const [search, setSearch] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  const isAdmin = currentUser?.role === "ADMIN";

  const queryString = useMemo(() => {
    const params = new URLSearchParams();

    params.set("page", String(page));
    params.set("limit", "25");

    if (eventType !== "ALL") params.set("event_type", eventType);
    if (outcome !== "ALL") params.set("outcome", outcome);
    if (targetType !== "ALL") params.set("target_type", targetType);
    if (actorUsername.trim()) params.set("actor_username", actorUsername.trim());
    if (targetId.trim()) params.set("target_id", targetId.trim());
    if (search.trim()) params.set("search", search.trim());
    if (dateFrom) params.set("date_from", dateFrom);
    if (dateTo) params.set("date_to", dateTo);

    return params.toString();
  }, [
    actorUsername,
    dateFrom,
    dateTo,
    eventType,
    outcome,
    page,
    search,
    targetId,
    targetType,
  ]);

  const loadEvents = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const current = await fetchCurrentUser();
      setCurrentUser(current);

      if (current.role !== "ADMIN") {
        setData(null);
        setError("Forbidden: Security Audit is available only to ADMIN users.");
        return;
      }

      const response = await authFetch(`/security-audit/events?${queryString}`);

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      const payload = (await response.json()) as SecurityAuditResponse;
      setData(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [queryString]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  function resetFilters() {
    setPage(1);
    setEventType("ALL");
    setOutcome("ALL");
    setTargetType("ALL");
    setActorUsername("");
    setTargetId("");
    setSearch("");
    setDateFrom("");
    setDateTo("");
  }

  const items = data?.items ?? [];
  const deniedOrFailed = items.filter((item) =>
    ["DENIED", "FAILURE"].includes(item.outcome)
  ).length;
  const rbacDenied = items.filter((item) => item.event_type === "RBAC_DENIED").length;

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
              <ShieldCheck className="h-3.5 w-3.5" />
              System Information
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Security Audit Trail
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Review authentication, authorization, user management and privileged SOC
              activity captured by the Sovereign AI SOC control plane.
            </p>
          </div>

          <button
            onClick={loadEvents}
            disabled={refreshing}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            {error}
          </div>
        )}

        {isAdmin && (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard
                label="Total matching events"
                value={data?.total ?? 0}
                description="Across all selected filters"
              />
              <MetricCard
                label="Events on page"
                value={items.length}
                description={`Page ${data?.page ?? page} of ${data?.total_pages ?? 1}`}
              />
              <MetricCard
                label="Denied / failed"
                value={deniedOrFailed}
                description="Current page only"
              />
              <MetricCard
                label="RBAC denied"
                value={rbacDenied}
                description="Current page only"
              />
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-3 flex items-center gap-2">
                <ListFilter className="h-3.5 w-3.5 text-cyan-300" />
                <h2 className="text-sm font-semibold">Filters</h2>
              </div>

              <div className="grid gap-2 md:grid-cols-4 xl:grid-cols-8">
                <Select
                  label="Event type"
                  value={eventType}
                  onChange={(value) => {
                    setPage(1);
                    setEventType(value);
                  }}
                  options={EVENT_TYPES}
                />

                <Select
                  label="Outcome"
                  value={outcome}
                  onChange={(value) => {
                    setPage(1);
                    setOutcome(value);
                  }}
                  options={OUTCOMES}
                />

                <Select
                  label="Target type"
                  value={targetType}
                  onChange={(value) => {
                    setPage(1);
                    setTargetType(value);
                  }}
                  options={TARGET_TYPES}
                />

                <Input
                  label="Actor"
                  value={actorUsername}
                  onChange={(value) => {
                    setPage(1);
                    setActorUsername(value);
                  }}
                  placeholder="username"
                />

                <Input
                  label="Target ID"
                  value={targetId}
                  onChange={(value) => {
                    setPage(1);
                    setTargetId(value);
                  }}
                  placeholder="id"
                />

                <Input
                  label="Date from"
                  type="date"
                  value={dateFrom}
                  onChange={(value) => {
                    setPage(1);
                    setDateFrom(value);
                  }}
                />

                <Input
                  label="Date to"
                  type="date"
                  value={dateTo}
                  onChange={(value) => {
                    setPage(1);
                    setDateTo(value);
                  }}
                />

                <div className="flex items-end">
                  <button
                    onClick={resetFilters}
                    className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Reset
                  </button>
                </div>
              </div>

              <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-2">
                <Search className="h-3.5 w-3.5 text-slate-500" />
                <input
                  value={search}
                  onChange={(event) => {
                    setPage(1);
                    setSearch(event.target.value);
                  }}
                  placeholder="Search event, actor, role, path, IP or details..."
                  className="h-9 w-full bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600"
                />
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileJson className="h-3.5 w-3.5 text-cyan-300" />
                  <h2 className="text-sm font-semibold">Audit events</h2>
                </div>

                <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                  {data?.total ?? 0}
                </span>
              </div>

              {loading ? (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">
                  Loading security audit events...
                </div>
              ) : items.length === 0 ? (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-6 text-center text-xs text-slate-500">
                  <AlertTriangle className="mx-auto mb-2 h-5 w-5 text-slate-600" />
                  No security audit events match the selected filters.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-2 py-1.5">Time</th>
                        <th className="px-2 py-1.5">Event</th>
                        <th className="px-2 py-1.5">Outcome</th>
                        <th className="px-2 py-1.5">Actor</th>
                        <th className="px-2 py-1.5">Target</th>
                        <th className="px-2 py-1.5">Request</th>
                        <th className="px-2 py-1.5">Client</th>
                        <th className="px-2 py-1.5">Details</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/80">
                      {items.map((item) => (
                        <tr key={item.id} className="align-top hover:bg-slate-800/40">
                          <td className="whitespace-nowrap px-2 py-2 text-slate-300">
                            {formatTimestamp(item.created_at)}
                          </td>

                          <td className="px-2 py-2">
                            <span
                              className={`inline-flex rounded-md border px-2 py-0.5 text-[11px] ${eventBadgeClass(
                                item.event_type
                              )}`}
                            >
                              {item.event_type}
                            </span>
                          </td>

                          <td className="px-2 py-2">
                            <span
                              className={`inline-flex rounded-md border px-2 py-0.5 text-[11px] ${outcomeBadgeClass(
                                item.outcome
                              )}`}
                            >
                              {item.outcome}
                            </span>
                          </td>

                          <td className="px-2 py-2 text-slate-300">
                            <div className="font-medium text-slate-100">
                              {item.actor_username ?? "system"}
                            </div>
                            <div className="text-[11px] text-slate-500">
                              {item.actor_role ?? "-"}
                            </div>
                          </td>

                          <td className="px-2 py-2 text-slate-300">
                            <div className="font-medium text-slate-100">
                              {item.target_type ?? "-"}
                            </div>
                            <div className="text-[11px] text-slate-500">
                              {item.target_username ?? item.target_id ?? "-"}
                            </div>
                          </td>

                          <td className="px-2 py-2 text-slate-300">
                            <div>{item.method ?? "-"}</div>
                            <div className="max-w-[260px] break-all text-[11px] text-slate-500">
                              {item.path ?? "-"}
                            </div>
                          </td>

                          <td className="px-2 py-2 text-slate-300">
                            <div>{item.client_ip ?? "-"}</div>
                            <div className="max-w-[240px] truncate text-[11px] text-slate-500">
                              {item.user_agent ?? "-"}
                            </div>
                          </td>

                          <td className="px-2 py-2">
                            <button
                              onClick={() =>
                                setExpandedId(expandedId === item.id ? null : item.id)
                              }
                              className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-800"
                            >
                              {expandedId === item.id
                                ? "Hide"
                                : detailsPreview(item.details)}
                            </button>

                            {expandedId === item.id && (
                              <pre className="mt-2 max-h-56 w-[420px] overflow-auto rounded-md border border-slate-800 bg-slate-950 p-2 text-[11px] leading-4 text-slate-300">
                                {detailsJson(item.details)}
                              </pre>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="mt-3 flex items-center justify-between border-t border-slate-800 pt-3 text-xs text-slate-400">
                <button
                  disabled={!data || data.page <= 1}
                  onClick={() => setPage((value) => Math.max(value - 1, 1))}
                  className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Previous
                </button>

                <span>
                  Page {data?.page ?? page} of {data?.total_pages ?? 1}
                </span>

                <button
                  disabled={!data || data.page >= data.total_pages}
                  onClick={() => setPage((value) => value + 1)}
                  className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function MetricCard({
  label,
  value,
  description,
}: {
  label: string;
  value: number;
  description: string;
}) {
  return (
    <div className="flex min-h-[58px] items-center justify-between gap-3 rounded-sm border border-slate-800 bg-slate-900 px-2.5 py-2 text-slate-100 shadow-sm">
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {label}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
          <span className="text-xl font-semibold leading-6">{value}</span>
          <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500">
            {description}
          </span>
        </div>
      </div>
    </div>
  );
}

function Input({
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
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500"
      />
    </label>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
}) {
  return (
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
      >
        {options.map((item) => (
          <option key={item} value={item}>
            {item}
          </option>
        ))}
      </select>
    </label>
  );
}
