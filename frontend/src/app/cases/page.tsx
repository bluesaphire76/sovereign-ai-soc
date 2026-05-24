"use client";

import { authFetch } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  EnterpriseBadge,
  EnterpriseButton,
  EnterpriseSection,
} from "../../components/enterprise";
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  Briefcase,
  CheckCircle2,
  CircleDashed,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
} from "lucide-react";

type IncidentCase = {
  id: number;
  group_key: string;
  title: string;
  status: string | null;
  severity: string | null;
  agent: string | null;
  correlation_type: string | null;
  risk_score: number | null;
  summary: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  incident_count: number;
  owner: string | null;
  assignee: string | null;
  sla_due_at: string | null;
  sla_status: string | null;
  sla_breach_risk: string | null;
  severity_review: string | null;
  status_reason: string | null;
  last_reviewed_by: string | null;
  last_reviewed_at: string | null;

  action_count: number | null;
  open_action_count: number | null;
  completed_action_count: number | null;
  cancelled_action_count: number | null;
  latest_action_at: string | null;

  has_ai_analysis: boolean | null;
  latest_ai_analysis_at: string | null;
  latest_ai_model: string | null;
  latest_ai_recommended_status: string | null;
  latest_ai_recommended_severity: string | null;

  has_closure_checklist: boolean | null;
  ready_to_close: boolean | null;
  closure_missing_count: number | null;
  closure_missing_items: string[] | null;
  closure_decision: string | null;
  final_severity: string | null;
  closure_reviewed_at: string | null;

  queue_flags: string[] | null;
};

type CasesResponse = {
  items: IncidentCase[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

const TERMINAL_STATUSES = new Set(["CLOSED", "FALSE_POSITIVE"]);
const CASE_TABLE_BADGE_BASE =
  "inline-flex h-5 w-fit items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 text-[10px] font-medium leading-none";
const CASE_TABLE_PRIORITY_BADGE_BASE =
  `${CASE_TABLE_BADGE_BASE} min-w-[58px] justify-center uppercase tracking-wide`;

function shortText(value: string | null | undefined, maxLength = 96) {
  if (!value) return "-";
  if (value.length <= maxLength) return value;

  return `${value.slice(0, maxLength - 1)}…`;
}

function severityClass(value: string | null | undefined) {
  const severity = (value ?? "LOW").toUpperCase();

  if (severity === "CRITICAL") return "border-red-800 bg-red-950/70 text-red-200";
  if (severity === "HIGH") return "border-orange-800 bg-orange-950/70 text-orange-200";
  if (severity === "MEDIUM") return "border-amber-800 bg-amber-950/70 text-amber-200";

  return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
}

function statusClass(value: string | null | undefined) {
  const status = (value ?? "OPEN").toUpperCase();

  if (status === "ESCALATED") return "border-red-800 bg-red-950/70 text-red-200";
  if (status === "INVESTIGATING") return "border-cyan-800 bg-cyan-950/60 text-cyan-200";
  if (status === "TRIAGED") return "border-blue-800 bg-blue-950/60 text-blue-200";
  if (status === "CLOSED") return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  if (status === "FALSE_POSITIVE") return "border-violet-800 bg-violet-950/60 text-violet-200";

  return "border-cyan-800 bg-cyan-950/60 text-cyan-200";
}

function slaClass(value: string | null | undefined) {
  const status = (value ?? "NOT_SET").toUpperCase();

  if (status === "BREACHED") return "border-red-800 bg-red-950/70 text-red-200";
  if (status === "WITHIN_SLA") return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  if (status === "COMPLETED") return "border-emerald-800 bg-emerald-950/60 text-emerald-200";

  return "border-slate-700 bg-slate-950 text-slate-400";
}

function readinessClass(item: IncidentCase) {
  if (item.ready_to_close) {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if ((item.open_action_count ?? 0) > 0) {
    return "border-orange-800 bg-orange-950/70 text-orange-200";
  }

  if (!item.has_closure_checklist) {
    return "border-amber-800 bg-amber-950/70 text-amber-200";
  }

  return "border-cyan-800 bg-cyan-950/50 text-cyan-200";
}

function aiClass(item: IncidentCase) {
  if (item.has_ai_analysis) {
    return "border-violet-800 bg-violet-950/60 text-violet-200";
  }

  return "border-amber-800 bg-amber-950/70 text-amber-200";
}

function slaLabel(value: string | null | undefined) {
  if (!value) return "NOT SET";
  return value.replaceAll("_", " ");
}

function slaRiskLabel(value: string | null | undefined) {
  if (!value) return "UNKNOWN";
  return value.replaceAll("_", " ");
}

function slaRiskClass(value: string | null | undefined) {
  const risk = (value ?? "UNKNOWN").toUpperCase();

  if (risk === "BREACHED" || risk === "HIGH") {
    return "border-red-800 bg-red-950/70 text-red-200";
  }

  if (risk === "MEDIUM") {
    return "border-orange-800 bg-orange-950/70 text-orange-200";
  }

  if (risk === "LOW" || risk === "NONE") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  return "border-slate-700 bg-slate-950 text-slate-400";
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

function normalize(value: string | null | undefined) {
  return (value ?? "").trim().toLowerCase();
}

function isOpenCase(item: IncidentCase) {
  const status = item.status ?? "OPEN";
  return !TERMINAL_STATUSES.has(status);
}

function operationalPriority(item: IncidentCase) {
  let score = 0;

  const status = item.status ?? "OPEN";
  const severity = item.severity_review ?? item.final_severity ?? item.severity ?? "LOW";

  if (item.sla_status === "BREACHED") score += 1000;
  if (status === "ESCALATED") score += 800;
  if (severity === "CRITICAL") score += 600;
  if (severity === "HIGH") score += 400;
  if ((item.open_action_count ?? 0) > 0) score += 250;
  if (!item.has_ai_analysis && isOpenCase(item)) score += 180;
  if (!item.has_closure_checklist && isOpenCase(item)) score += 140;
  if (!item.owner && isOpenCase(item)) score += 100;
  if (item.ready_to_close && isOpenCase(item)) score += 90;

  score += item.risk_score ?? 0;
  score += Math.min(item.incident_count ?? 0, 100);

  return score;
}

async function fetchCases(): Promise<CasesResponse> {
  const response = await authFetch(`/cases?limit=100`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function CasesPage() {
  const [data, setData] = useState<CasesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [searchText, setSearchText] = useState("");
  const [statusFilter, setStatusFilter] = useState("ACTIVE");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [slaFilter, setSlaFilter] = useState("ALL");
  const [ownerFilter, setOwnerFilter] = useState("ALL");
  const [quickView, setQuickView] = useState("OPERATIONS");

  const cases = useMemo(() => data?.items ?? [], [data?.items]);

  const owners = useMemo(() => {
    const values = Array.from(
      new Set(
        cases
          .map((item) => item.owner?.trim())
          .filter((value): value is string => Boolean(value))
      )
    );

    return values.sort((a, b) => a.localeCompare(b));
  }, [cases]);

  const metrics = useMemo(() => {
    const activeCases = cases.filter(isOpenCase);
    const breachedCases = cases.filter((item) => item.sla_status === "BREACHED");
    const unassignedCases = cases.filter((item) => isOpenCase(item) && !item.owner);
    const criticalHighCases = cases.filter((item) =>
      ["CRITICAL", "HIGH"].includes(
        item.severity_review ?? item.final_severity ?? item.severity ?? "LOW"
      )
    );
    const readyToCloseCases = cases.filter(
      (item) => isOpenCase(item) && Boolean(item.ready_to_close)
    );
    const blockedByActionsCases = cases.filter(
      (item) => isOpenCase(item) && (item.open_action_count ?? 0) > 0
    );
    const needsAiCases = cases.filter(
      (item) => isOpenCase(item) && !item.has_ai_analysis
    );
    const needsClosureCases = cases.filter(
      (item) => isOpenCase(item) && !item.has_closure_checklist
    );
    const escalatedCases = cases.filter((item) => item.status === "ESCALATED");
    const closedCases = cases.filter((item) => item.status === "CLOSED");

    return {
      total: cases.length,
      active: activeCases.length,
      breached: breachedCases.length,
      unassigned: unassignedCases.length,
      criticalHigh: criticalHighCases.length,
      readyToClose: readyToCloseCases.length,
      blockedByActions: blockedByActionsCases.length,
      needsAi: needsAiCases.length,
      needsClosure: needsClosureCases.length,
      escalated: escalatedCases.length,
      closed: closedCases.length,
    };
  }, [cases]);

  const filteredCases = useMemo(() => {
    const query = normalize(searchText);

    return cases
      .filter((item) => {
        const status = item.status ?? "OPEN";
        const severity = item.severity_review ?? item.final_severity ?? item.severity ?? "LOW";
        const owner = item.owner ?? "unassigned";
        const sla = item.sla_status ?? "NOT_SET";

        if (quickView === "BREACHED" && sla !== "BREACHED") return false;
        if (quickView === "UNASSIGNED" && (owner !== "unassigned" || !isOpenCase(item))) return false;
        if (quickView === "HIGH_RISK" && !["CRITICAL", "HIGH"].includes(severity)) return false;
        if (quickView === "ESCALATED" && status !== "ESCALATED") return false;
        if (quickView === "READY_TO_CLOSE" && !(item.ready_to_close && isOpenCase(item))) return false;
        if (quickView === "BLOCKED_ACTIONS" && !((item.open_action_count ?? 0) > 0 && isOpenCase(item))) return false;
        if (quickView === "NEEDS_AI" && !(!item.has_ai_analysis && isOpenCase(item))) return false;
        if (quickView === "NEEDS_CLOSURE" && !(!item.has_closure_checklist && isOpenCase(item))) return false;
        if (quickView === "CLOSED" && status !== "CLOSED") return false;

        if (statusFilter === "ACTIVE" && !isOpenCase(item)) return false;
        if (statusFilter !== "ALL" && statusFilter !== "ACTIVE" && status !== statusFilter) {
          return false;
        }

        if (severityFilter !== "ALL" && severity !== severityFilter) return false;
        if (slaFilter !== "ALL" && sla !== slaFilter) return false;

        if (ownerFilter === "UNASSIGNED" && item.owner) return false;
        if (ownerFilter !== "ALL" && ownerFilter !== "UNASSIGNED" && item.owner !== ownerFilter) {
          return false;
        }

        if (!query) return true;

        const haystack = [
          item.id,
          item.title,
          item.group_key,
          item.agent,
          item.correlation_type,
          item.owner,
          item.status,
          item.severity,
          item.severity_review,
          item.status_reason,
          item.closure_decision,
          item.final_severity,
          item.queue_flags?.join(" "),
        ]
          .map((value) => normalize(String(value ?? "")))
          .join(" ");

        return haystack.includes(query);
      })
      .sort((a, b) => {
        const priorityDelta = operationalPriority(b) - operationalPriority(a);

        if (priorityDelta !== 0) {
          return priorityDelta;
        }

        const updatedA = new Date(a.updated_at ?? 0).getTime();
        const updatedB = new Date(b.updated_at ?? 0).getTime();

        return updatedB - updatedA;
      });
  }, [
    cases,
    ownerFilter,
    quickView,
    searchText,
    severityFilter,
    slaFilter,
    statusFilter,
  ]);

  function resetFilters() {
    setSearchText("");
    setStatusFilter("ACTIVE");
    setSeverityFilter("ALL");
    setSlaFilter("ALL");
    setOwnerFilter("ALL");
    setQuickView("OPERATIONS");
  }

  function applyQuickView(value: string) {
    setQuickView(value);

    if (value === "OPERATIONS") {
      setStatusFilter("ACTIVE");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "BREACHED") {
      setStatusFilter("ACTIVE");
      setSlaFilter("BREACHED");
      setSeverityFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "UNASSIGNED") {
      setStatusFilter("ACTIVE");
      setOwnerFilter("UNASSIGNED");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      return;
    }

    if (value === "HIGH_RISK") {
      setStatusFilter("ACTIVE");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "ESCALATED") {
      setStatusFilter("ESCALATED");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "READY_TO_CLOSE") {
      setStatusFilter("ACTIVE");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "BLOCKED_ACTIONS") {
      setStatusFilter("ACTIVE");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "NEEDS_AI") {
      setStatusFilter("ACTIVE");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "NEEDS_CLOSURE") {
      setStatusFilter("ACTIVE");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
      return;
    }

    if (value === "CLOSED") {
      setStatusFilter("CLOSED");
      setSeverityFilter("ALL");
      setSlaFilter("ALL");
      setOwnerFilter("ALL");
    }
  }

  const loadCases = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);
      const response = await fetchCases();
      setData(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadCases();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [loadCases]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />
        <header className="mb-2 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-3 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to dashboard
            </Link>

            <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
              <Briefcase className="h-4 w-4" />
              Investigation cases
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              SOC Case Queue
            </h1>

            <p className="mt-2 max-w-3xl text-xs text-slate-500">
              Prioritized operational queue for grouped investigations, SLA
              tracking, ownership, action progress, AI analysis and closure readiness.
            </p>
          </div>

          <div className="flex flex-wrap gap-1.5">
            <button
              onClick={loadCases}
              className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <RefreshCw
                className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="mb-3 rounded-2xl border border-red-800 bg-red-950/60 p-4 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <EnterpriseSection>
            <div className="text-xs text-slate-300">Loading cases...</div>
          </EnterpriseSection>
        ) : (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
              <CaseQueueMetric
                title="Active"
                value={metrics.active}
                subtitle={`${metrics.total} total`}
                tone="primary"
                icon={<Briefcase className="h-3.5 w-3.5" />}
              />
              <CaseQueueMetric
                title="SLA breached"
                value={metrics.breached}
                subtitle="Immediate review"
                tone={metrics.breached > 0 ? "danger" : "success"}
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
              />
              <CaseQueueMetric
                title="High / Critical"
                value={metrics.criticalHigh}
                subtitle="Priority queue"
                tone={metrics.criticalHigh > 0 ? "warning" : "success"}
                icon={<ShieldAlert className="h-3.5 w-3.5" />}
              />
              <CaseQueueMetric
                title="Ready to close"
                value={metrics.readyToClose}
                subtitle="Can be closed"
                tone={metrics.readyToClose > 0 ? "success" : "neutral"}
                icon={<CheckCircle2 className="h-3.5 w-3.5" />}
              />
              <CaseQueueMetric
                title="Open actions"
                value={metrics.blockedByActions}
                subtitle="Blocked cases"
                tone={metrics.blockedByActions > 0 ? "warning" : "success"}
                icon={<CircleDashed className="h-3.5 w-3.5" />}
              />
              <CaseQueueMetric
                title="Needs AI"
                value={metrics.needsAi}
                subtitle="No analysis yet"
                tone={metrics.needsAi > 0 ? "warning" : "success"}
                icon={<Bot className="h-3.5 w-3.5" />}
              />
            </section>

            <EnterpriseSection
              title="Queue Controls"
              description="Filter and prioritize cases by operational urgency."
              actions={
                <EnterpriseButton onClick={resetFilters} tone="ghost" size="xs">
                  Reset filters
                </EnterpriseButton>
              }
            >
              <div className="mb-2 flex flex-wrap gap-1.5">
                <QuickViewButton label="Operations" active={quickView === "OPERATIONS"} onClick={() => applyQuickView("OPERATIONS")} />
                <QuickViewButton label={`SLA breached (${metrics.breached})`} active={quickView === "BREACHED"} onClick={() => applyQuickView("BREACHED")} />
                <QuickViewButton label={`Unassigned (${metrics.unassigned})`} active={quickView === "UNASSIGNED"} onClick={() => applyQuickView("UNASSIGNED")} />
                <QuickViewButton label={`High risk (${metrics.criticalHigh})`} active={quickView === "HIGH_RISK"} onClick={() => applyQuickView("HIGH_RISK")} />
                <QuickViewButton label={`Ready to close (${metrics.readyToClose})`} active={quickView === "READY_TO_CLOSE"} onClick={() => applyQuickView("READY_TO_CLOSE")} />
                <QuickViewButton label={`Open actions (${metrics.blockedByActions})`} active={quickView === "BLOCKED_ACTIONS"} onClick={() => applyQuickView("BLOCKED_ACTIONS")} />
                <QuickViewButton label={`Needs AI (${metrics.needsAi})`} active={quickView === "NEEDS_AI"} onClick={() => applyQuickView("NEEDS_AI")} />
                <QuickViewButton label={`Needs closure (${metrics.needsClosure})`} active={quickView === "NEEDS_CLOSURE"} onClick={() => applyQuickView("NEEDS_CLOSURE")} />
                <QuickViewButton label={`Escalated (${metrics.escalated})`} active={quickView === "ESCALATED"} onClick={() => applyQuickView("ESCALATED")} />
                <QuickViewButton label={`Closed (${metrics.closed})`} active={quickView === "CLOSED"} onClick={() => applyQuickView("CLOSED")} />
              </div>

              <div className="grid gap-2 lg:grid-cols-5">
                <label className="lg:col-span-2">
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Search
                  </span>
                  <div className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-2">
                    <Search className="h-3.5 w-3.5 text-slate-500" />
                    <input
                      value={searchText}
                      onChange={(event) => setSearchText(event.target.value)}
                      placeholder="Case, host, owner, correlation type, flags..."
                      className="w-full bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600"
                    />
                  </div>
                </label>

                <FilterSelect
                  label="Status"
                  value={statusFilter}
                  onChange={setStatusFilter}
                  options={[
                    ["ALL", "All"],
                    ["ACTIVE", "Active"],
                    ["OPEN", "Open"],
                    ["TRIAGED", "Triaged"],
                    ["INVESTIGATING", "Investigating"],
                    ["ESCALATED", "Escalated"],
                    ["CLOSED", "Closed"],
                    ["FALSE_POSITIVE", "False positive"],
                  ]}
                />

                <FilterSelect
                  label="Severity"
                  value={severityFilter}
                  onChange={setSeverityFilter}
                  options={[
                    ["ALL", "All"],
                    ["CRITICAL", "Critical"],
                    ["HIGH", "High"],
                    ["MEDIUM", "Medium"],
                    ["LOW", "Low"],
                  ]}
                />

                <FilterSelect
                  label="SLA"
                  value={slaFilter}
                  onChange={setSlaFilter}
                  options={[
                    ["ALL", "All"],
                    ["BREACHED", "Breached"],
                    ["WITHIN_SLA", "Within SLA"],
                    ["COMPLETED", "Completed"],
                    ["NOT_SET", "Not set"],
                  ]}
                />
              </div>

              <div className="mt-2 grid gap-2 md:grid-cols-2 lg:grid-cols-5">
                <FilterSelect
                  label="Owner"
                  value={ownerFilter}
                  onChange={setOwnerFilter}
                  options={[
                    ["ALL", "All"],
                    ["UNASSIGNED", "Unassigned"],
                    ...owners.map((owner) => [owner, owner] as [string, string]),
                  ]}
                />

                <div className="self-end flex h-8 min-w-0 items-center rounded-lg border border-slate-800 bg-slate-950 px-2 lg:col-span-4">
                  <div className="flex min-w-0 items-center gap-2 overflow-hidden text-xs leading-none text-slate-300">
                    <Filter className="h-3.5 w-3.5 shrink-0 text-cyan-300" />
                    <span className="shrink-0">
                      Showing <strong>{filteredCases.length}</strong> of{" "}
                      <strong>{cases.length}</strong> loaded cases.
                    </span>
                    <span className="min-w-0 truncate whitespace-nowrap text-slate-500">
                      Sorted by SLA breach, escalation, severity, open actions, missing AI, closure readiness, ownership, assignment and risk score.
                    </span>
                  </div>
                </div>
              </div>
            </EnterpriseSection>

            <EnterpriseSection
              title="Cases"
              description="Operational queue ordered by urgency."
              actions={
                <EnterpriseBadge tone="muted">
                  {filteredCases.length} visible
                </EnterpriseBadge>
              }
            >

              {filteredCases.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
                  No cases match the current filters.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 z-10 border-b border-slate-800 bg-slate-900 text-[10px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="py-1.5 pr-2">Priority</th>
                        <th className="py-1.5 pr-2">Case</th>
                        <th className="py-1.5 pr-2">Status</th>
                        <th className="min-w-28 whitespace-nowrap py-2 pr-3">Severity</th>
                        <th className="py-1.5 pr-2">Owner</th>
                        <th className="py-1.5 pr-2">Assignee</th>
                        <th className="min-w-36 whitespace-nowrap py-2 pr-3">SLA</th>
                        <th className="min-w-36 whitespace-nowrap py-2 pr-3">Readiness</th>
                        <th className="min-w-28 whitespace-nowrap py-2 pr-3">Actions</th>
                        <th className="min-w-28 whitespace-nowrap py-2 pr-3">AI</th>
                        <th className="py-1.5 pr-2">Host</th>
                        <th className="py-1.5 pr-2">Correlation type</th>
                        <th className="py-1.5 pr-2">Incidents</th>
                        <th className="py-1.5 pr-2">Updated</th>
                      </tr>
                    </thead>

                    <tbody>
                      {filteredCases.map((item) => {
                        const priority = operationalPriority(item);
                        const severity = item.severity_review ?? item.final_severity ?? item.severity;

                        return (
                          <tr
                            key={item.id}
                            className="border-b border-slate-800/70 hover:bg-slate-800/35"
                          >
                            <td className="py-1.5 pr-2">
                              <OperationalPriorityBadge item={item} score={priority} />
                            </td>

                            <td className="max-w-[520px] py-1.5 pr-2">
                              <Link
                                href={`/cases/${item.id}`}
                                className="text-cyan-300 hover:text-cyan-200"
                              >
                                #{item.id} {shortText(item.title, 86)}
                              </Link>
                              {item.status_reason && (
                                <div className="mt-1 max-w-md truncate text-xs text-slate-500">
                                  {item.status_reason}
                                </div>
                              )}
                            </td>

                            <td className="py-1.5 pr-2">
                              <span className={`${CASE_TABLE_BADGE_BASE} ${statusClass(item.status)}`}>
                                {item.status ?? "OPEN"}
                              </span>
                            </td>

                            <td className="min-w-28 whitespace-nowrap py-2 pr-3">
                              <span className={`${CASE_TABLE_BADGE_BASE} ${severityClass(severity)}`}>
                                {severity ?? "LOW"} · {item.risk_score ?? 0}
                              </span>
                            </td>

                            <td className="py-2 pr-3 text-slate-300">
                              {item.owner ? (
                                item.owner
                              ) : (
                                <span className="inline-flex items-center gap-1 whitespace-nowrap text-orange-300">
                                  <AlertTriangle className="h-3 w-3" />
                                  unassigned
                                </span>
                              )}
                            </td>

                            <td className="py-2 pr-3 text-slate-300">
                              {item.assignee ? (
                                item.assignee
                              ) : (
                                <span className="inline-flex items-center gap-1 whitespace-nowrap text-orange-300">
                                  <AlertTriangle className="h-3 w-3" />
                                  unassigned
                                </span>
                              )}
                            </td>

                            <td className="min-w-36 whitespace-nowrap py-2 pr-3">
                              <div className="flex min-w-40 flex-col gap-1">
                                <span className={`${CASE_TABLE_BADGE_BASE} ${slaClass(item.sla_status)}`}>
                                  {slaLabel(item.sla_status)}
                                </span>
                                <span className={`${CASE_TABLE_BADGE_BASE} ${slaRiskClass(item.sla_breach_risk)}`}>
                                  Risk {slaRiskLabel(item.sla_breach_risk)}
                                </span>
                                {item.sla_due_at && (
                                  <span className="whitespace-nowrap text-xs text-slate-500">
                                    Due {formatTimestamp(item.sla_due_at)}
                                  </span>
                                )}
                              </div>
                            </td>

                            <td className="min-w-36 whitespace-nowrap py-2 pr-3">
                              <ClosureReadinessBadge item={item} />
                            </td>

                            <td className="min-w-28 whitespace-nowrap py-2 pr-3">
                              <ActionProgress item={item} />
                            </td>

                            <td className="min-w-28 whitespace-nowrap py-2 pr-3">
                              <AIStatusBadge item={item} />
                            </td>

                            <td className="py-2 pr-3 text-slate-300">
                              {item.agent ?? "unknown"}
                            </td>

                            <td className="py-2 pr-3 text-slate-400">
                              {item.correlation_type ?? "-"}
                            </td>

                            <td className="py-1.5 pr-2">
                              <div className="inline-flex items-center gap-2 text-slate-300">
                                <ShieldAlert className="h-4 w-4 text-cyan-300" />
                                {item.incident_count}
                              </div>
                            </td>

                            <td className="py-2 pr-3 text-slate-400">
                              {formatTimestamp(item.updated_at)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </EnterpriseSection>
          </div>
        )}
      </div>
    </main>
  );
}

type CaseMetricTone = "neutral" | "primary" | "success" | "warning" | "danger";

const caseMetricToneClasses: Record<CaseMetricTone, string> = {
  neutral: "border-slate-800 bg-slate-900 text-slate-100",
  primary: "border-cyan-900 bg-cyan-950/30 text-cyan-100",
  success: "border-emerald-900 bg-emerald-950/30 text-emerald-100",
  warning: "border-orange-900 bg-orange-950/30 text-orange-100",
  danger: "border-red-900 bg-red-950/30 text-red-100",
};

const caseMetricIconClasses: Record<CaseMetricTone, string> = {
  neutral: "bg-slate-950 text-slate-400",
  primary: "bg-cyan-950 text-cyan-300",
  success: "bg-emerald-950 text-emerald-300",
  warning: "bg-orange-950 text-orange-300",
  danger: "bg-red-950 text-red-300",
};

function CaseQueueMetric({
  title,
  value,
  subtitle,
  tone = "neutral",
  icon,
}: {
  title: string;
  value: number;
  subtitle?: string;
  tone?: CaseMetricTone;
  icon: ReactNode;
}) {
  return (
    <div
      className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${caseMetricToneClasses[tone]}`}
    >
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
          <span className="text-xl font-semibold leading-6">{value}</span>
          {subtitle && (
            <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500">
              {subtitle}
            </span>
          )}
        </div>
      </div>
      <div className={`shrink-0 rounded-sm p-1.5 ${caseMetricIconClasses[tone]}`}>
        {icon}
      </div>
    </div>
  );
}

function QuickViewButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`h-8 rounded-lg border px-2.5 text-xs font-medium transition ${
        active
          ? "border-cyan-500 bg-cyan-500 text-slate-950"
          : "border-slate-700 bg-slate-950 text-slate-300 hover:border-cyan-800 hover:bg-slate-800 hover:text-cyan-200"
      }`}
    >
      {label}
    </button>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: [string, string][];
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
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </label>
  );
}

function OperationalPriorityBadge({
  item,
  score,
}: {
  item: IncidentCase;
  score: number;
}) {
  const severity = item.severity_review ?? item.final_severity ?? item.severity ?? "LOW";

  if (item.sla_status === "BREACHED") {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} ${slaClass("BREACHED")}`}>
        SLA
      </span>
    );
  }

  if (item.status === "ESCALATED") {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} ${statusClass("ESCALATED")}`}>
        Escalated
      </span>
    );
  }

  if (["CRITICAL", "HIGH"].includes(severity)) {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} ${severityClass("HIGH")}`}>
        High risk
      </span>
    );
  }

  if ((item.open_action_count ?? 0) > 0) {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} ${readinessClass(item)}`}>
        Actions
      </span>
    );
  }

  if (!item.has_ai_analysis && isOpenCase(item)) {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} ${aiClass(item)}`}>
        Needs AI
      </span>
    );
  }

  if (item.ready_to_close && isOpenCase(item)) {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} ${readinessClass(item)}`}>
        Close
      </span>
    );
  }

  if (!item.owner && isOpenCase(item)) {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} border-amber-800 bg-amber-950/70 text-amber-200`}>
        No owner
      </span>
    );
  }

  if (score > 200) {
    return (
      <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} border-cyan-800 bg-cyan-950/60 text-cyan-200`}>
        Review
      </span>
    );
  }

  return (
    <span className={`${CASE_TABLE_PRIORITY_BADGE_BASE} border-slate-700 bg-slate-950 text-slate-400`}>
      Normal
    </span>
  );
}

function ClosureReadinessBadge({ item }: { item: IncidentCase }) {
  if (item.ready_to_close) {
    return (
      <div className="flex flex-col gap-1">
        <span className={`${CASE_TABLE_BADGE_BASE} ${readinessClass(item)}`}>
          <CheckCircle2 className="h-3 w-3" />
          Ready
        </span>
        {item.closure_decision && (
          <span className="text-xs text-slate-500">{item.closure_decision}</span>
        )}
      </div>
    );
  }

  if ((item.open_action_count ?? 0) > 0) {
    return (
      <div className="flex flex-col gap-1">
        <span className={`${CASE_TABLE_BADGE_BASE} ${readinessClass(item)}`}>
          <CircleDashed className="h-3 w-3" />
          Blocked
        </span>
        <span className="text-xs text-slate-500">
          {item.open_action_count} open action(s)
        </span>
      </div>
    );
  }

  if (!item.has_closure_checklist) {
    return (
      <span className={`${CASE_TABLE_BADGE_BASE} ${readinessClass(item)}`}>
        Needs checklist
      </span>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <span className={`${CASE_TABLE_BADGE_BASE} ${readinessClass(item)}`}>
        In progress
      </span>
      {(item.closure_missing_count ?? 0) > 0 && (
        <span className="text-xs text-slate-500">
          {item.closure_missing_count} missing
        </span>
      )}
    </div>
  );
}

function ActionProgress({ item }: { item: IncidentCase }) {
  const total = item.action_count ?? 0;
  const open = item.open_action_count ?? 0;
  const done = item.completed_action_count ?? 0;
  const cancelled = item.cancelled_action_count ?? 0;

  if (total === 0) {
    return <span className="text-xs text-slate-500">No actions</span>;
  }

  return (
    <div className="flex flex-col gap-1">
      <span className="whitespace-nowrap text-xs text-slate-300">
        {done}/{total} done
      </span>
      <span className="whitespace-nowrap text-xs text-slate-500">
        {open} open · {cancelled} cancelled
      </span>
    </div>
  );
}

function AIStatusBadge({ item }: { item: IncidentCase }) {
  if (item.has_ai_analysis) {
    return (
      <div className="flex flex-col gap-1">
        <span className={`${CASE_TABLE_BADGE_BASE} ${aiClass(item)}`}>
          <Bot className="h-3 w-3" />
          AI done
        </span>
        {item.latest_ai_analysis_at && (
          <span className="text-xs text-slate-500">
            {formatTimestamp(item.latest_ai_analysis_at)}
          </span>
        )}
      </div>
    );
  }

  return (
    <span className={`${CASE_TABLE_BADGE_BASE} ${aiClass(item)}`}>
      <Bot className="h-3 w-3" />
      Needs AI
    </span>
  );
}
