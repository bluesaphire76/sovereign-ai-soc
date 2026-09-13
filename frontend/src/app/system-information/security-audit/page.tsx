"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, FileJson, RefreshCw, ShieldCheck } from "lucide-react";
import AppShell from "@/components/AppShell";
import {
  EnterpriseBadge,
  EnterpriseBreadcrumbs,
  EnterpriseButton,
  EnterpriseEmptyState,
  EnterpriseErrorState,
  EnterpriseMetricCard,
  EnterpriseMetricStrip,
  EnterprisePageHeader,
  EnterpriseSearchInput,
  EnterpriseSection,
  EnterpriseSelect,
  EnterpriseSkeleton,
} from "@/components/enterprise";
import { SOC_CONTROL_CLASSES, statusTone } from "@/lib/semantic-styles";
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

const TARGET_TYPES = ["ALL", "USER", "SYNTHETIC_TEST", "INCIDENT", "CASE", "CASE_ACTION"];

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

function eventTone(eventType: string) {
  if (!EVENT_TYPES.includes(eventType)) return "neutral";
  if (eventType.startsWith("AUTH_")) return "primary";
  if (eventType.startsWith("USER_")) return "executive";
  return "neutral";
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
  const [checkingAccess, setCheckingAccess] = useState(true);
  const loadSequence = useRef(0);

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
  }, [actorUsername, dateFrom, dateTo, eventType, outcome, page, search, targetId, targetType]);

  const loadEvents = useCallback(async () => {
    const sequence = ++loadSequence.current;
    let verifiedAdmin = false;
    setCheckingAccess(true);
    try {
      setRefreshing(true);
      setError(null);

      const current = await fetchCurrentUser();
      if (sequence !== loadSequence.current) return;
      setCurrentUser(current);

      if (current.role !== "ADMIN") {
        setData(null);
        setError("Forbidden: Security Audit is available only to ADMIN users.");
        return;
      }
      verifiedAdmin = true;

      const response = await authFetch(`/security-audit/events?${queryString}`);
      if (sequence !== loadSequence.current) return;

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          setData(null);
          setCurrentUser(null);
        }
        throw new Error(
          response.status === 403
            ? "Forbidden: Security Audit is available only to ADMIN users."
            : response.status === 401
              ? "Session expired. Please sign in again."
              : response.status === 400 || response.status === 422
                ? "Invalid audit filters. Check the selected dates and values."
                : "Security Audit service unavailable. Please try again.",
        );
      }

      const payload = (await response.json()) as SecurityAuditResponse;
      if (sequence === loadSequence.current) setData(payload);
    } catch (err) {
      if (sequence !== loadSequence.current) return;
      setData(null);
      if (!verifiedAdmin) setCurrentUser(null);
      setError(
        !verifiedAdmin
          ? "Unable to verify account access. Sign in again or retry when the authentication service is available."
          : err instanceof TypeError || err instanceof SyntaxError
            ? "Security Audit service unavailable. Please try again."
            : err instanceof Error
              ? err.message
              : "Unable to load Security Audit.",
      );
    } finally {
      if (sequence === loadSequence.current) {
        setLoading(false);
        setRefreshing(false);
        setCheckingAccess(false);
      }
    }
  }, [queryString]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadEvents();
    }, 0);

    return () => {
      window.clearTimeout(timer);
      loadSequence.current += 1;
    };
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

  const visibleData = checkingAccess ? null : data;
  const items = visibleData?.items ?? [];
  const deniedOrFailed = items.filter((item) => ["DENIED", "FAILURE"].includes(item.outcome)).length;
  const rbacDenied = items.filter((item) => item.event_type === "RBAC_DENIED").length;

  return (
    <AppShell>
      <EnterprisePageHeader
        title="Security Audit Trail"
        eyebrow="Governance"
        density="compact"
        icon={<ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />}
        breadcrumbs={
          <EnterpriseBreadcrumbs items={[{ label: "Dashboard", href: "/" }, { label: "Security Audit" }]} />
        }
        metadata={
          <>
            <EnterpriseBadge tone="neutral">ADMIN only</EnterpriseBadge>
            <EnterpriseBadge tone="muted">Read-only / browser-local time</EnterpriseBadge>
          </>
        }
        secondaryActions={
          <EnterpriseButton
            onClick={loadEvents}
            disabled={refreshing}
            size="xs"
            icon={<RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />}
          >
            Refresh
          </EnterpriseButton>
        }
      />

      {error && (
        <EnterpriseErrorState
          className="mb-3"
          title="Security Audit request failed"
          message={error}
          onRetry={!refreshing ? loadEvents : undefined}
        />
      )}

      {(checkingAccess || loading) && !isAdmin && (
        <EnterpriseSkeleton label="Loading Security Audit / checking access" rows={5} />
      )}
      {isAdmin && (
        <div className="space-y-3">
          <EnterpriseMetricStrip>
            <EnterpriseMetricCard
              title="Total matching events"
              value={visibleData?.total ?? "-"}
              subtitle="Across all selected filters"
            />
            <EnterpriseMetricCard
              title="Events on page"
              value={visibleData ? items.length : "-"}
              subtitle={`Page ${visibleData?.page ?? page} of ${visibleData?.total_pages ?? 1}`}
            />
            <EnterpriseMetricCard
              title="Denied / failed"
              value={visibleData ? deniedOrFailed : "-"}
              subtitle="Current page only"
            />
            <EnterpriseMetricCard
              title="RBAC denied"
              value={visibleData ? rbacDenied : "-"}
              subtitle="Current page only"
            />
          </EnterpriseMetricStrip>

          <EnterpriseSection title="Filters" className="!border-0 !bg-transparent !p-0 !shadow-none">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-8">
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
                <EnterpriseButton onClick={resetFilters} size="xs" tone="ghost" className="w-full">
                  Reset
                </EnterpriseButton>
              </div>
            </div>

            <EnterpriseSearchInput
              label="Search audit events"
              containerClassName="mt-2"
              value={search}
              onChange={(value) => {
                setPage(1);
                setSearch(value);
              }}
              onClear={() => {
                setPage(1);
                setSearch("");
              }}
              placeholder="Search event, actor, role, path, IP or details..."
            />
          </EnterpriseSection>

          <EnterpriseSection
            title="Audit events"
            actions={<EnterpriseBadge tone="neutral">{visibleData?.total ?? "-"}</EnterpriseBadge>}
            className="!border-0 !bg-transparent !p-0 !shadow-none"
          >
            {loading || checkingAccess ? (
              <EnterpriseSkeleton label="Loading security audit events" rows={5} />
            ) : !data && error ? null : items.length === 0 ? (
              <EnterpriseEmptyState title="No security audit events match the selected filters." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1160px] text-left text-xs">
                  <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                    <tr>
                      <th scope="col" className="px-2 py-1.5">
                        Time
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Event
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Outcome
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Actor
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Target
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Request
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Client
                      </th>
                      <th scope="col" className="px-2 py-1.5">
                        Details
                      </th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/80">
                    {items.map((item) => (
                      <tr key={item.id} className="align-top hover:bg-slate-800/40">
                        <td
                          className="whitespace-nowrap px-2 py-2 text-slate-300"
                          title={item.created_at ?? undefined}
                        >
                          {formatTimestamp(item.created_at)}
                          <div className="text-[11px] text-slate-500">Event #{item.id}</div>
                        </td>

                        <td className="px-2 py-2">
                          <EnterpriseBadge tone={eventTone(item.event_type)} size="compact">
                            {item.event_type}
                          </EnterpriseBadge>
                        </td>

                        <td className="px-2 py-2">
                          <EnterpriseBadge
                            tone={
                              OUTCOMES.slice(1).includes(item.outcome) ? statusTone(item.outcome) : "neutral"
                            }
                            size="compact"
                          >
                            {item.outcome}
                          </EnterpriseBadge>
                        </td>

                        <td className="px-2 py-2 text-slate-300">
                          <div className="font-medium text-slate-100">{item.actor_username ?? "system"}</div>
                          <div className="text-[11px] text-slate-500">{item.actor_role ?? "-"}</div>
                        </td>

                        <td className="px-2 py-2 text-slate-300">
                          <div className="font-medium text-slate-100">{item.target_type ?? "-"}</div>
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
                          <div
                            className="max-w-[240px] truncate text-[11px] text-slate-500"
                            title={item.user_agent ?? undefined}
                          >
                            {item.user_agent ?? "-"}
                          </div>
                        </td>

                        <td className="px-2 py-2">
                          <EnterpriseButton
                            onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}
                            size="xs"
                            ariaLabel={`${expandedId === item.id ? "Hide" : "Show"} details for event ${item.id}`}
                            aria-expanded={expandedId === item.id}
                            aria-controls={`audit-details-${item.id}`}
                            icon={<FileJson className="h-3.5 w-3.5" />}
                          >
                            {expandedId === item.id ? "Hide" : detailsPreview(item.details)}
                          </EnterpriseButton>

                          {expandedId === item.id && (
                            <div id={`audit-details-${item.id}`} className="mt-2 w-[420px] text-xs">
                              <pre
                                aria-label={`Details JSON for event ${item.id}`}
                                className="max-h-56 overflow-auto rounded-sm border border-slate-800 bg-slate-950 p-2 text-[11px] leading-4 text-slate-300"
                              >
                                {detailsJson(item.details)}
                              </pre>
                              <details className="mt-2">
                                <summary className={`cursor-pointer ${SOC_CONTROL_CLASSES.focus}`}>
                                  Full event / raw metadata
                                </summary>
                                <pre
                                  aria-label={`Full event JSON for event ${item.id}`}
                                  className="mt-2 max-h-72 overflow-auto text-[11px]"
                                >
                                  {JSON.stringify(item, null, 2)}
                                </pre>
                              </details>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 pt-3 text-xs text-slate-400">
              <EnterpriseButton
                size="xs"
                icon={<ChevronLeft className="h-3.5 w-3.5" />}
                disabled={!visibleData || visibleData.page <= 1}
                onClick={() => setPage((value) => Math.max(value - 1, 1))}
              >
                Previous
              </EnterpriseButton>

              <span>
                Page {visibleData?.page ?? page} of {visibleData?.total_pages ?? 1}
              </span>

              <EnterpriseButton
                size="xs"
                icon={<ChevronRight className="h-3.5 w-3.5" />}
                disabled={!visibleData || visibleData.page >= visibleData.total_pages}
                onClick={() => setPage((value) => value + 1)}
              >
                Next
              </EnterpriseButton>
            </div>
          </EnterpriseSection>
        </div>
      )}
    </AppShell>
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
    <label className="block min-w-0">
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className={`h-8 w-full px-2 text-xs ${SOC_CONTROL_CLASSES.input} ${SOC_CONTROL_CLASSES.focus}`}
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
    <EnterpriseSelect
      label={label}
      value={value}
      onChange={onChange}
      options={options.map((value) => ({ value, label: value }))}
    />
  );
}
