"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  RefreshCw,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import IncidentRiskScore from "@/components/incidents/IncidentRiskScore";
import {
  EnterpriseBadge,
  EnterpriseBreadcrumbs,
  EnterpriseButton,
  EnterpriseEmptyState,
  EnterpriseErrorState,
  EnterpriseIconButton,
  EnterpriseMetricCard,
  EnterpriseMetricStrip,
  EnterprisePageHeader,
  EnterprisePanel,
  EnterpriseSearchInput,
  EnterpriseSelect,
  EnterpriseSkeleton,
  EnterpriseStatusBadge,
} from "@/components/enterprise";
import {
  authFetch,
  fetchCurrentUser,
  getStoredUser,
  type AuthUser,
} from "../../lib/auth";

type Incident = {
  id: number;
  timestamp: string | null;
  timestamp_local?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  status: string | null;
  risk_score: number | null;
  recommended_priority?: string | null;
  correlated?: boolean;
  correlation_score?: number | null;
  correlation_type?: string | null;
  is_demo?: boolean;
  demo_origin?: "seed" | "synthetic_test" | null;
};

type IncidentsResponse = {
  items: Incident[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

const STATUS_OPTIONS = [
  "ALL",
  "NEW",
  "TRIAGED",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "CLOSED",
  "FALSE_POSITIVE",
  "ESCALATED",
];

const RISK_OPTIONS = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "short",
      timeStyle: "short",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function isDemoIncident(incident: Incident) {
  return Boolean(incident.is_demo);
}

function Field({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-3 border-b border-slate-900 px-3 py-2 last:border-b-0">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
        {label}
      </dt>
      <dd className="min-w-0 text-xs text-slate-300">{value}</dd>
    </div>
  );
}

function decisionLabel(incident: Incident | null) {
  if (!incident) return "No incident selected";
  if ((incident.risk_score ?? 0) >= 80) return "Containment review";
  if ((incident.risk_score ?? 0) >= 60 || incident.correlated) return "Investigation required";
  if ((incident.level ?? 0) >= 8) return "Manual triage";
  return "Observation / classify";
}

function riskRationale(incident: Incident | null) {
  if (!incident) return "No incident selected.";

  const score = incident.risk_score ?? 0;
  const level = incident.level ?? 0;
  const correlated = incident.correlated;

  if (score >= 80) {
    return "Risk is in the critical band. Treat this as a candidate for immediate containment review, especially if the source host is production-relevant.";
  }

  if (score >= 60) {
    return correlated
      ? "Risk is high and the signal is correlated with a pattern. Prioritize investigation and check whether it belongs to an existing case."
      : "Risk is high even without correlation. Validate evidence before escalation, then decide whether to open or attach a case.";
  }

  if (correlated) {
    return "The individual risk score is not high, but correlation is present. Review the pattern before dismissing the alert as noise.";
  }

  if (level >= 8) {
    return "The Wazuh level is elevated. The event may still be benign, but it deserves manual triage before classification.";
  }

  return "Current indicators suggest a low-priority signal. Validate context and classify as observed, benign or false positive if appropriate.";
}

function investigationQuestions(incident: Incident | null) {
  if (!incident) return [];

  const questions = [
    "Is the source host expected to generate this type of event?",
    "Does the rule represent user activity, service activity, or suspicious behavior?",
  ];

  if (incident.correlated) {
    questions.push("Do related alerts indicate a repeated pattern or attack chain?");
  } else {
    questions.push("Is this a single isolated alert or the first signal of a repeated pattern?");
  }

  if ((incident.risk_score ?? 0) >= 60) {
    questions.push("Is there enough evidence to escalate this into an investigation case?");
  } else {
    questions.push("Can this be safely classified as observed, benign or false positive?");
  }

  return questions;
}

function paginationWindow(currentPage: number, totalPageCount: number) {
  const safeTotal = Math.max(1, totalPageCount);
  const safeCurrent = Math.min(Math.max(1, currentPage), safeTotal);
  const windowSize = Math.min(5, safeTotal);
  const start = Math.max(1, Math.min(safeCurrent - 2, safeTotal - windowSize + 1));

  return Array.from({ length: windowSize }, (_, index) => start + index);
}

export default function IncidentsPage() {
  const [data, setData] = useState<IncidentsResponse | null>(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [searchFilter, setSearchFilter] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [demoMode, setDemoMode] = useState(false);
  const [page, setPage] = useState(1);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [deletingIncidentId, setDeletingIncidentId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const incidents = useMemo(() => data?.items ?? [], [data]);
  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 1;
  const canManageDemo =
    currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";

  const selectedIncident = useMemo(() => {
    if (incidents.length === 0) return null;
    return incidents.find((incident) => incident.id === selectedIncidentId) ?? incidents[0];
  }, [incidents, selectedIncidentId]);

  const highRiskCount = useMemo(
    () => incidents.filter((incident) => (incident.risk_score ?? 0) >= 60).length,
    [incidents]
  );

  const activeLifecycleCount = useMemo(
    () =>
      incidents.filter((incident) =>
        ["INVESTIGATING", "CONTAINED", "ESCALATED"].includes(
          (incident.status ?? "").toUpperCase()
        )
      ).length,
    [incidents]
  );

  const correlatedCount = useMemo(
    () => incidents.filter((incident) => incident.correlated).length,
    [incidents]
  );

  const demoIncidentCount = useMemo(
    () => incidents.filter(isDemoIncident).length,
    [incidents]
  );

  const loadIncidents = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const params = new URLSearchParams({
        page: String(page),
        limit: "20",
      });

      if (statusFilter !== "ALL") params.set("status", statusFilter);
      if (riskFilter !== "ALL") params.set("risk", riskFilter.toLowerCase());
      if (searchFilter.trim()) params.set("search", searchFilter.trim());
      if (hostFilter.trim()) params.set("host", hostFilter.trim());
      if (demoMode) params.set("demo_only", "true");

      const response = await authFetch(`/incidents?${params.toString()}`);

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      const payload = (await response.json()) as IncidentsResponse;
      setData(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [demoMode, hostFilter, page, riskFilter, searchFilter, statusFilter]);

  useEffect(() => {
    fetchCurrentUser()
      .then(setCurrentUser)
      .catch(() => setCurrentUser(getStoredUser()));
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadIncidents();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadIncidents]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!selectedIncidentId && incidents.length > 0) {
        setSelectedIncidentId(incidents[0].id);
      }
    }, 0);

    return () => window.clearTimeout(timer);
  }, [incidents, selectedIncidentId]);

  function resetFilters() {
    setStatusFilter("ALL");
    setRiskFilter("ALL");
    setSearchFilter("");
    setHostFilter("");
    setDemoMode(false);
    setPage(1);
    setSelectedIncidentId(null);
  }

  function enableDemoMode() {
    setStatusFilter("ALL");
    setRiskFilter("ALL");
    setSearchFilter("");
    setHostFilter("");
    setDemoMode(true);
    setPage(1);
    setSelectedIncidentId(null);
  }

  function exitDemoMode() {
    setDemoMode(false);
    setSearchFilter("");
    setPage(1);
    setSelectedIncidentId(null);
  }

  async function deleteDemoIncident(incident: Incident) {
    if (!canManageDemo || !incident.demo_origin) return;

    const confirmed = window.confirm(
      `Delete synthetic incident #${incident.id}? Its demo-only notes, audit entries, remediation proposals and case links will also be removed. Real incidents and telemetry are not deletion targets.`
    );
    if (!confirmed) return;

    try {
      setDeletingIncidentId(incident.id);
      setError(null);
      const response = await authFetch(
        `/demo-management/incidents/${incident.id}`,
        { method: "DELETE" }
      );
      if (!response.ok) {
        const body = await response.json().catch(() => null);
        const detail = body?.detail;
        const message =
          typeof detail === "string"
            ? detail
            : detail?.message ?? `API error ${response.status}`;
        throw new Error(message);
      }
      setSelectedIncidentId(null);
      await loadIncidents();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to delete demo incident"
      );
    } finally {
      setDeletingIncidentId(null);
    }
  }

  return (
    <AppShell width="dense">
      <EnterprisePageHeader
        breadcrumbs={
          <EnterpriseBreadcrumbs
            items={[
              { label: "Dashboard", href: "/" },
              { label: "Incidents" },
            ]}
          />
        }
        eyebrow="Investigation"
        title="Incidents"
        description="Dense incident queue for triage, correlation review and response handoff."
        icon={<ShieldAlert aria-hidden="true" className="h-3.5 w-3.5" />}
        status={demoMode ? <EnterpriseBadge tone="primary">Demo view</EnterpriseBadge> : null}
        density="compact"
        secondaryActions={
          <>
            <EnterpriseButton
              onClick={demoMode ? exitDemoMode : enableDemoMode}
              tone={demoMode ? "primary" : "secondary"}
              size="xs"
            >
              {demoMode ? "Exit current demo" : "Current demo"}
            </EnterpriseButton>
            <EnterpriseButton
              onClick={loadIncidents}
              disabled={refreshing}
              tone="secondary"
              size="xs"
              icon={
                <RefreshCw
                  aria-hidden="true"
                  className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
                />
              }
            >
              Refresh
            </EnterpriseButton>
          </>
        }
      />

      <div className="space-y-3">
        <EnterpriseMetricStrip className="lg:grid-cols-5">
          <EnterpriseMetricCard
            title="Visible incidents"
            value={total}
            subtitle="Matching current filters"
            tone="primary"
          />
          <EnterpriseMetricCard
            title="High attention"
            value={highRiskCount}
            subtitle="Risk score 60+ on this page"
            tone={highRiskCount > 0 ? "warning" : "success"}
          />
          <EnterpriseMetricCard
            title="Active lifecycle"
            value={activeLifecycleCount}
            subtitle="Investigating, contained or escalated"
            tone={activeLifecycleCount > 0 ? "warning" : "success"}
          />
          <EnterpriseMetricCard
            title="Correlated"
            value={correlatedCount}
            subtitle="Linked to patterns"
            tone="primary"
          />
          <EnterpriseMetricCard
            title="Demo scenarios"
            value={demoIncidentCount}
            subtitle={demoMode ? "Stable seed only" : "Visible on this page"}
            tone={demoMode ? "primary" : "neutral"}
          />
        </EnterpriseMetricStrip>

        <EnterprisePanel
          title="Filters"
          description="Narrow the queue without changing the underlying incident records."
          actions={
            <EnterpriseButton onClick={resetFilters} tone="ghost" size="xs">
              Reset
            </EnterpriseButton>
          }
        >
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-[150px_150px_180px_minmax(320px,1fr)] xl:items-end">
            <EnterpriseSelect
              label="Status"
              value={statusFilter}
              options={STATUS_OPTIONS.map((item) => ({ label: item, value: item }))}
              onChange={(value) => {
                setStatusFilter(value);
                setPage(1);
              }}
            />
            <EnterpriseSelect
              label="Risk"
              value={riskFilter}
              options={RISK_OPTIONS.map((item) => ({ label: item, value: item }))}
              onChange={(value) => {
                setRiskFilter(value);
                setPage(1);
              }}
            />
            <label className="block">
              <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                Host
              </span>
              <input
                value={hostFilter}
                onChange={(event) => {
                  setHostFilter(event.target.value);
                  setPage(1);
                }}
                placeholder="Filter by host"
                className="h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500 focus-visible:ring-2 focus-visible:ring-cyan-400/30"
              />
            </label>
            <EnterpriseSearchInput
              label="Search incidents"
              value={searchFilter}
              onChange={(value) => {
                setSearchFilter(value);
                setPage(1);
              }}
              onClear={() => {
                setSearchFilter("");
                setPage(1);
              }}
              placeholder="Search rule, AI text, MITRE, raw alert..."
            />
          </div>
        </EnterprisePanel>

        {error && (
          <EnterpriseErrorState
            title="Unable to load incidents"
            message={error}
            onRetry={loadIncidents}
          />
        )}

        <section className="grid min-h-[660px] overflow-hidden rounded-sm border border-slate-800 bg-slate-950 xl:grid-cols-[minmax(0,1fr)_420px]">
            <div className="min-w-0 border-r border-slate-800">
              <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-3 py-2">
                <div>
                  <h2 className="text-[12px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                    Incident grid
                  </h2>
                  <p className="text-[11px] text-slate-500">
                    Select a row to inspect the summary pane. Open detail for the full workflow.
                  </p>
                </div>

                <span className="text-[11px] text-slate-500">
                  {data?.limit ?? 20} rows per page
                </span>
              </div>

              {loading ? (
                <div className="p-4">
                  <EnterpriseSkeleton label="Loading incidents" rows={8} />
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[1080px] table-fixed border-collapse text-left text-[12px]">
                    <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-[0.16em] text-slate-500">
                      <tr>
                        <th className="w-[48px] px-2 py-2 text-center font-semibold">Select</th>
                        <th className="w-[150px] px-2 py-2 font-semibold">Severity / risk</th>
                        <th className="w-[330px] px-2 py-2 font-semibold">Signal</th>
                        <th className="w-[112px] px-2 py-2 font-semibold">Status</th>
                        <th className="w-[130px] px-2 py-2 font-semibold">Host</th>
                        <th className="w-[92px] px-2 py-2 font-semibold">Pattern</th>
                        <th className="w-[130px] px-2 py-2 font-semibold">Created</th>
                        <th className="w-[76px] px-2 py-2 font-semibold">ID</th>
                        <th className="w-[48px] px-2 py-2 text-right font-semibold">Actions</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-900">
                      {incidents.map((incident) => {
                        const selected = selectedIncident?.id === incident.id;

                        return (
                          <tr
                            key={incident.id}
                            onClick={() => setSelectedIncidentId(incident.id)}
                            className={`cursor-pointer ${
                              selected
                                ? "bg-cyan-950/20"
                                : isDemoIncident(incident)
                                  ? "bg-cyan-950/5 hover:bg-cyan-950/10"
                                  : "hover:bg-slate-900/70"
                            }`}
                          >
                            <td className="px-2 py-1.5 text-center align-middle">
                              <input
                                type="radio"
                                name="selected-incident"
                                checked={selected}
                                onChange={() => setSelectedIncidentId(incident.id)}
                                aria-label={`Select incident ${incident.id}`}
                                className="h-3.5 w-3.5 accent-cyan-500"
                              />
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <IncidentRiskScore score={incident.risk_score} />
                            </td>

                            <td className="w-[330px] px-2 py-1.5 align-top">
                              <div className="flex min-w-0 items-start gap-2">
                                <div className="min-w-0">
                                  <Link
                                    href={`/incidents/${incident.id}`}
                                    onClick={(event) => event.stopPropagation()}
                                    className="line-clamp-1 max-w-[310px] text-[12px] font-medium leading-5 text-cyan-200 hover:text-cyan-100"
                                  >
                                    {incident.rule ?? "-"}
                                  </Link>
                                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                                    <span className="font-mono text-[10px] uppercase tracking-wide text-slate-600">
                                      Level {incident.level ?? 0}
                                    </span>
                                    {isDemoIncident(incident) && (
                                      <EnterpriseBadge tone="primary" size="compact">
                                        Demo
                                      </EnterpriseBadge>
                                    )}
                                    {incident.correlated && (
                                      <EnterpriseBadge tone="executive" size="compact">
                                        Correlated
                                      </EnterpriseBadge>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <EnterpriseStatusBadge
                                value={incident.status ?? "NEW"}
                                size="compact"
                              />
                            </td>

                            <td className="px-2 py-1.5 align-top font-mono text-[11px] text-slate-300">
                              {incident.agent ?? "unknown"}
                            </td>

                            <td className="px-2 py-1.5 align-top">
                              <span className="font-mono text-[11px] text-slate-300">
                                {incident.correlated ? "multi" : "single"}
                              </span>
                            </td>

                            <td className="whitespace-nowrap px-2 py-1.5 align-top font-mono text-[10px] text-slate-500">
                              {incident.timestamp_local ?? formatTimestamp(incident.timestamp)}
                            </td>

                            <td className="px-2 py-1.5 align-top font-mono text-[11px] font-semibold tabular-nums text-slate-300">
                              #{incident.id}
                            </td>

                            <td className="px-2 py-1.5 align-middle text-right">
                              <div className="flex items-center justify-end gap-1">
                                {incident.demo_origin && canManageDemo && (
                                  <EnterpriseIconButton
                                    icon={<Trash2 aria-hidden="true" className="h-3 w-3" />}
                                    label={`Delete demo incident ${incident.id}`}
                                    tooltip="Delete this synthetic incident and its demo-owned workflow data"
                                    tone="danger"
                                    size="xs"
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      void deleteDemoIncident(incident);
                                    }}
                                    disabled={deletingIncidentId === incident.id}
                                  />
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}

                      {incidents.length === 0 && (
                        <tr>
                          <td colSpan={9} className="px-3 py-4">
                            <EnterpriseEmptyState
                              title="No incidents found"
                              description="No incidents match the current filters."
                              action={
                                <EnterpriseButton onClick={resetFilters} tone="ghost" size="xs">
                                  Reset filters
                                </EnterpriseButton>
                              }
                            />
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="flex flex-col gap-2 border-t border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-500 md:flex-row md:items-center md:justify-between">
                <div>
                  {total} incident(s) · Page {data?.page ?? page} of {totalPages}
                </div>

                <nav className="flex items-center gap-1" aria-label="Incident pagination">
                  <EnterpriseButton
                    onClick={() => setPage((current) => Math.max(1, current - 1))}
                    disabled={page <= 1}
                    tone="ghost"
                    size="xs"
                  >
                    Previous
                  </EnterpriseButton>

                  <div className="flex items-center gap-1 px-1">
                    {paginationWindow(data?.page ?? page, totalPages).map((pageNumber) => {
                      const active = pageNumber === (data?.page ?? page);

                      return (
                        <button
                          key={pageNumber}
                          onClick={() => setPage(pageNumber)}
                          aria-current={active ? "page" : undefined}
                          className={`h-7 min-w-7 border px-2 font-mono text-[11px] font-semibold tabular-nums ${
                            active
                              ? "border-cyan-600 bg-cyan-950 text-cyan-100"
                              : "border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700 hover:bg-slate-900 hover:text-slate-200"
                          }`}
                        >
                          {pageNumber}
                        </button>
                      );
                    })}
                  </div>

                  <EnterpriseButton
                    onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                    disabled={page >= totalPages}
                    tone="ghost"
                    size="xs"
                  >
                    Next
                  </EnterpriseButton>
                </nav>
              </div>
            </div>

            <section aria-label="Incident inspection" className="min-w-0 bg-slate-950">
              <div className="border-b border-slate-800 px-3 py-2">
                <h2 className="text-[12px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                  Analyst decision support
                </h2>
                <p className="text-[11px] text-slate-500">
                  Triage guidance generated from the selected incident context.
                </p>
              </div>

              {selectedIncident ? (
                <div>
                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <IncidentRiskScore score={selectedIncident.risk_score} />
                          <EnterpriseStatusBadge
                            value={selectedIncident.status ?? "NEW"}
                            size="compact"
                          />
                        </div>

                        <div className="mt-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                          Recommended decision
                        </div>

                        <div className="mt-1 text-base font-semibold leading-6 text-slate-100">
                          {decisionLabel(selectedIncident)}
                        </div>
                      </div>

                      <EnterpriseButton
                        href={`/incidents/${selectedIncident.id}`}
                        tone="primary"
                        size="xs"
                      >
                        Open detail
                      </EnterpriseButton>
                    </div>
                    {selectedIncident.demo_origin && canManageDemo && (
                      <EnterpriseButton
                        onClick={() => void deleteDemoIncident(selectedIncident)}
                        disabled={deletingIncidentId === selectedIncident.id}
                        tone="danger"
                        size="xs"
                        className="mt-3"
                        icon={<Trash2 aria-hidden="true" className="h-3.5 w-3.5" />}
                      >
                        {deletingIncidentId === selectedIncident.id
                          ? "Deleting..."
                          : "Delete demo incident"}
                      </EnterpriseButton>
                    )}
                  </div>

                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      Why this matters
                    </div>
                    <p className="mt-2 text-xs leading-5 text-slate-300">
                      {riskRationale(selectedIncident)}
                    </p>
                  </div>

                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      What to validate next
                    </div>
                    <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs leading-5 text-slate-400 marker:text-slate-500">
                      {investigationQuestions(selectedIncident).map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>

                  <dl className="border-b border-slate-800">
                    <Field
                      label="Case action"
                      value={
                        (selectedIncident.risk_score ?? 0) >= 60 || selectedIncident.correlated
                          ? "Review for case creation or case attachment"
                          : "Classify before opening a case"
                      }
                    />
                    <Field
                      label="Pattern"
                      value={selectedIncident.correlated ? selectedIncident.correlation_type ?? "correlated" : "No pattern detected"}
                    />
                    <Field
                      label="Evidence"
                      value={
                        <span>
                          Host <span className="font-mono text-slate-200">{selectedIncident.agent ?? "unknown"}</span>, Wazuh level{" "}
                          <span className="font-mono text-slate-200">{selectedIncident.level ?? 0}</span>
                        </span>
                      }
                    />
                    <Field
                      label="Created"
                      value={
                        <span className="font-mono">
                          {selectedIncident.timestamp_local ?? formatTimestamp(selectedIncident.timestamp)}
                        </span>
                      }
                    />
                  </dl>

                  <div className="border-b border-slate-800 px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      Signal summary
                    </div>
                    <p className="mt-2 line-clamp-4 text-xs leading-5 text-slate-300">
                      {selectedIncident.rule ?? "-"}
                    </p>
                  </div>

                  <div className="px-3 py-3">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                      Workflow reminder
                    </div>
                    <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs leading-5 text-slate-400 marker:text-slate-500">
                      <li>Validate the signal and host context.</li>
                      <li>Check whether correlation changes the priority.</li>
                      <li>Decide whether to escalate, classify or attach to a case.</li>
                      <li>Document the analyst decision in the full incident detail.</li>
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="p-4">
                  <EnterpriseEmptyState
                    title="No incident selected"
                    description="Select an incident from the grid to review its triage summary."
                  />
                </div>
              )}
            </section>
          </section>
        </div>
    </AppShell>
  );
}
