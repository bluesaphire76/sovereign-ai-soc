"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  Briefcase,
  CheckCircle2,
  CircleDashed,
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
  sla_due_at: string | null;
  sla_status: string | null;
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

type KanbanColumn = {
  id: string;
  title: string;
  description: string;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

const TERMINAL_STATUSES = new Set(["CLOSED", "FALSE_POSITIVE"]);

const COLUMNS: KanbanColumn[] = [
  {
    id: "OPEN",
    title: "Open",
    description: "New cases requiring first review.",
  },
  {
    id: "TRIAGED",
    title: "Triaged",
    description: "Reviewed and waiting for investigation.",
  },
  {
    id: "INVESTIGATING",
    title: "Investigating",
    description: "Active analyst work in progress.",
  },
  {
    id: "ESCALATED",
    title: "Escalated",
    description: "Requires management or senior analyst attention.",
  },
  {
    id: "READY_TO_CLOSE",
    title: "Ready to close",
    description: "Closure checklist complete and actions resolved.",
  },
  {
    id: "CLOSED",
    title: "Closed",
    description: "Resolved cases.",
  },
  {
    id: "FALSE_POSITIVE",
    title: "False positive",
    description: "Closed as non-incident.",
  },
];

function severityClass(value: string | null | undefined) {
  const severity = value ?? "LOW";

  if (severity === "CRITICAL") return "border-red-700 bg-red-950 text-red-200";
  if (severity === "HIGH") return "border-orange-700 bg-orange-950 text-orange-200";
  if (severity === "MEDIUM") return "border-yellow-700 bg-yellow-950 text-yellow-200";

  return "border-emerald-700 bg-emerald-950 text-emerald-200";
}

function statusClass(value: string | null | undefined) {
  const status = value ?? "OPEN";

  if (status === "ESCALATED") return "border-red-700 bg-red-950 text-red-200";
  if (status === "INVESTIGATING") return "border-violet-700 bg-violet-950 text-violet-200";
  if (status === "TRIAGED") return "border-blue-700 bg-blue-950 text-blue-200";
  if (status === "CLOSED") return "border-slate-700 bg-slate-800 text-slate-200";
  if (status === "FALSE_POSITIVE") return "border-purple-700 bg-purple-950 text-purple-200";

  return "border-cyan-700 bg-cyan-950 text-cyan-200";
}

function slaClass(value: string | null | undefined) {
  const status = value ?? "NOT_SET";

  if (status === "BREACHED") return "border-red-700 bg-red-950 text-red-200";
  if (status === "WITHIN_SLA") return "border-emerald-700 bg-emerald-950 text-emerald-200";
  if (status === "COMPLETED") return "border-slate-700 bg-slate-800 text-slate-200";

  return "border-slate-700 bg-slate-950 text-slate-300";
}

function columnClass(columnId: string) {
  if (columnId === "ESCALATED") return "border-red-800 bg-red-950/20";
  if (columnId === "READY_TO_CLOSE") return "border-emerald-800 bg-emerald-950/20";
  if (columnId === "CLOSED") return "border-slate-800 bg-slate-900/70";
  if (columnId === "FALSE_POSITIVE") return "border-purple-800 bg-purple-950/20";
  if (columnId === "INVESTIGATING") return "border-violet-800 bg-violet-950/20";
  if (columnId === "TRIAGED") return "border-blue-800 bg-blue-950/20";

  return "border-slate-800 bg-slate-900";
}

function slaLabel(value: string | null | undefined) {
  if (!value) return "NOT SET";
  return value.replaceAll("_", " ");
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

function columnForCase(item: IncidentCase) {
  if (item.ready_to_close && isOpenCase(item)) {
    return "READY_TO_CLOSE";
  }

  const status = item.status ?? "OPEN";

  if (COLUMNS.some((column) => column.id === status)) {
    return status;
  }

  return "OPEN";
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
  const response = await fetch(`${API_BASE}/cases?limit=100`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function CaseKanbanPage() {
  const [data, setData] = useState<CasesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchText, setSearchText] = useState("");
  const [hideClosed, setHideClosed] = useState(false);
  const [compactCards, setCompactCards] = useState(true);

  const cases = data?.items ?? [];

  const filteredCases = useMemo(() => {
    const query = normalize(searchText);

    return cases
      .filter((item) => {
        if (hideClosed && TERMINAL_STATUSES.has(item.status ?? "OPEN")) {
          return false;
        }

        if (!query) return true;

        const haystack = [
          item.id,
          item.title,
          item.group_key,
          item.agent,
          item.owner,
          item.status,
          item.severity,
          item.severity_review,
          item.final_severity,
          item.correlation_type,
          item.closure_decision,
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
  }, [cases, hideClosed, searchText]);

  const groupedCases = useMemo(() => {
    const groups: Record<string, IncidentCase[]> = {};

    for (const column of COLUMNS) {
      groups[column.id] = [];
    }

    for (const item of filteredCases) {
      groups[columnForCase(item)].push(item);
    }

    return groups;
  }, [filteredCases]);

  const metrics = useMemo(() => {
    return {
      total: filteredCases.length,
      slaBreached: filteredCases.filter((item) => item.sla_status === "BREACHED").length,
      readyToClose: filteredCases.filter((item) => item.ready_to_close && isOpenCase(item)).length,
      openActions: filteredCases.filter((item) => (item.open_action_count ?? 0) > 0).length,
      needsAi: filteredCases.filter((item) => isOpenCase(item) && !item.has_ai_analysis).length,
    };
  }, [filteredCases]);

  async function loadCases() {
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
  }

  useEffect(() => {
    loadCases();
  }, []);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1800px] px-6 py-8">
        <header className="mb-8 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/cases"
              className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to case queue
            </Link>

            <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
              <Briefcase className="h-4 w-4" />
              Investigation cases
            </div>

            <h1 className="text-3xl font-semibold tracking-tight">
              Case Kanban Board
            </h1>

            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Visual SOC backlog board grouped by investigation state and closure readiness.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <Link
              href="/cases"
              className="rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 shadow-sm hover:bg-slate-800"
            >
              Queue view
            </Link>

            <button
              onClick={loadCases}
              className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <RefreshCw
                className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="mb-6 rounded-2xl border border-red-800 bg-red-950/60 p-4 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-300">
            Loading case board...
          </div>
        ) : (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-5">
              <MetricCard title="Visible cases" value={metrics.total} />
              <MetricCard title="SLA breached" value={metrics.slaBreached} danger={metrics.slaBreached > 0} />
              <MetricCard title="Ready to close" value={metrics.readyToClose} success={metrics.readyToClose > 0} />
              <MetricCard title="Open actions" value={metrics.openActions} warning={metrics.openActions > 0} />
              <MetricCard title="Needs AI" value={metrics.needsAi} warning={metrics.needsAi > 0} />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="grid gap-4 md:grid-cols-4">
                <label className="md:col-span-2">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Search board
                  </span>
                  <div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2">
                    <Search className="h-4 w-4 text-slate-500" />
                    <input
                      value={searchText}
                      onChange={(event) => setSearchText(event.target.value)}
                      placeholder="Case, host, owner, status, severity, flags..."
                      className="w-full bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-600"
                    />
                  </div>
                </label>

                <label className="flex items-end">
                  <button
                    type="button"
                    onClick={() => setHideClosed((current) => !current)}
                    className={`w-full rounded-xl border px-4 py-2 text-sm ${
                      hideClosed
                        ? "border-cyan-500 bg-cyan-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    {hideClosed ? "Closed hidden" : "Show all statuses"}
                  </button>
                </label>

                <label className="flex items-end">
                  <button
                    type="button"
                    onClick={() => setCompactCards((current) => !current)}
                    className={`w-full rounded-xl border px-4 py-2 text-sm ${
                      compactCards
                        ? "border-emerald-500 bg-emerald-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    {compactCards ? "Compact cards" : "Detailed cards"}
                  </button>
                </label>
              </div>

              <p className="mt-3 text-xs text-slate-500">
                Compact mode keeps the board readable during backlog reviews. Detailed mode shows more operational context inside each card.
              </p>
            </section>

            <section className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-950/40 p-4 pb-5">
              <div className="flex min-w-max gap-5">
                {COLUMNS.map((column) => (
                  <KanbanColumn
                    key={column.id}
                    column={column}
                    items={groupedCases[column.id] ?? []}
                    compactCards={compactCards}
                  />
                ))}
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function KanbanColumn({
  column,
  items,
  compactCards,
}: {
  column: KanbanColumn;
  items: IncidentCase[];
  compactCards: boolean;
}) {
  return (
    <div className={`h-fit w-[360px] shrink-0 rounded-2xl border p-4 shadow-lg ${columnClass(column.id)}`}>
      <div className="mb-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-base font-semibold">{column.title}</h2>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              {column.description}
            </p>
          </div>

          <span className="shrink-0 rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-300">
            {items.length}
          </span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
          No cases.
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item) => (
            <CaseCard key={item.id} item={item} compact={compactCards} />
          ))}
        </div>
      )}
    </div>
  );
}

function CaseCard({
  item,
  compact,
}: {
  item: IncidentCase;
  compact: boolean;
}) {
  const severity = item.severity_review ?? item.final_severity ?? item.severity ?? "LOW";
  const openActions = item.open_action_count ?? 0;
  const totalActions = item.action_count ?? 0;

  if (compact) {
    return (
      <article className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-sm transition hover:border-slate-700">
        <div className="mb-3 flex items-start justify-between gap-3">
          <Link
            href={`/cases/${item.id}`}
            className="line-clamp-2 min-w-0 break-words text-sm font-medium leading-5 text-cyan-300 hover:text-cyan-200"
            title={item.title}
          >
            #{item.id} {item.title}
          </Link>

          <span className={`shrink-0 whitespace-nowrap rounded-full border px-2 py-1 text-[10px] ${severityClass(severity)}`}>
            {severity}
          </span>
        </div>

        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          {item.sla_status === "BREACHED" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-700 bg-red-950 px-2 py-1 text-[10px] text-red-200">
              <AlertTriangle className="h-3 w-3" />
              SLA
            </span>
          )}

          {item.ready_to_close && (
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-700 bg-emerald-950 px-2 py-1 text-[10px] text-emerald-200">
              <CheckCircle2 className="h-3 w-3" />
              Ready
            </span>
          )}

          {openActions > 0 && (
            <span className="inline-flex items-center gap-1 rounded-full border border-orange-700 bg-orange-950 px-2 py-1 text-[10px] text-orange-200">
              <CircleDashed className="h-3 w-3" />
              {openActions} open
            </span>
          )}

          {!item.has_ai_analysis && isOpenCase(item) && (
            <span className="inline-flex items-center gap-1 rounded-full border border-yellow-700 bg-yellow-950 px-2 py-1 text-[10px] text-yellow-200">
              <Bot className="h-3 w-3" />
              AI
            </span>
          )}

          {!item.owner && isOpenCase(item) && (
            <span className="inline-flex items-center gap-1 rounded-full border border-yellow-700 bg-yellow-950 px-2 py-1 text-[10px] text-yellow-200">
              <AlertTriangle className="h-3 w-3" />
              Owner
            </span>
          )}
        </div>

        <div className="grid grid-cols-2 gap-2 text-[11px]">
          <CompactMetric label="Owner" value={item.owner ?? "unassigned"} warning={!item.owner && isOpenCase(item)} />
          <CompactMetric label="Host" value={item.agent ?? "unknown"} />
          <CompactMetric label="Incidents" value={String(item.incident_count ?? 0)} />
          <CompactMetric label="Actions" value={`${totalActions - openActions}/${totalActions}`} />
        </div>

        <div className="mt-3 flex items-center justify-between gap-2 border-t border-slate-800 pt-3 text-[11px] text-slate-500">
          <span className="truncate">{item.correlation_type ?? "No correlation type"}</span>
          <span className="shrink-0">Risk {item.risk_score ?? 0}</span>
        </div>
      </article>
    );
  }

  return (
    <article className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950 p-4 shadow-sm transition hover:border-slate-700">
      <div className="mb-3 flex items-start justify-between gap-3">
        <Link
          href={`/cases/${item.id}`}
          className="block min-w-0 break-words text-sm font-medium leading-5 text-cyan-300 hover:text-cyan-200"
          title={item.title}
        >
          #{item.id} {item.title}
        </Link>

        <span className={`shrink-0 whitespace-nowrap rounded-full border px-2 py-1 text-[11px] ${severityClass(severity)}`}>
          {severity}
        </span>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className={`inline-flex max-w-full shrink-0 rounded-full border px-2 py-1 text-[11px] ${statusClass(item.status)}`}>
          {item.status ?? "OPEN"}
        </span>

        <span className={`inline-flex max-w-full shrink-0 rounded-full border px-2 py-1 text-[11px] ${slaClass(item.sla_status)}`}>
          {slaLabel(item.sla_status)}
        </span>

        {item.sla_status === "BREACHED" && (
          <span className="inline-flex items-center gap-1 rounded-full border border-red-700 bg-red-950 px-2 py-1 text-[11px] text-red-200">
            <AlertTriangle className="h-3 w-3" />
            SLA breach
          </span>
        )}
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
        <div className="grid grid-cols-[76px_minmax(0,1fr)] gap-x-3 gap-y-2">
          <span>Owner</span>
          <span className={`min-w-0 truncate text-right ${item.owner ? "text-slate-200" : "text-orange-300"}`}>
            {item.owner ?? "unassigned"}
          </span>

          <span>Host</span>
          <span className="min-w-0 truncate text-right text-slate-200">
            {item.agent ?? "unknown"}
          </span>

          <span>Incidents</span>
          <span className="inline-flex min-w-0 items-center justify-end gap-1 text-slate-200">
            <ShieldAlert className="h-3 w-3 shrink-0 text-cyan-300" />
            {item.incident_count}
          </span>

          <span>Actions</span>
          <span className="min-w-0 truncate text-right text-slate-200">
            {item.action_count ?? 0} total · {item.open_action_count ?? 0} open
          </span>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <AIStatusBadge item={item} />
        <ClosureBadge item={item} />
      </div>

      {item.queue_flags && item.queue_flags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {item.queue_flags.slice(0, 3).map((flag) => (
            <span
              key={flag}
              className="max-w-full truncate rounded-full border border-slate-800 bg-slate-900 px-2 py-1 text-[10px] text-slate-400"
            >
              {flag.replaceAll("_", " ")}
            </span>
          ))}

          {item.queue_flags.length > 3 && (
            <span className="rounded-full border border-slate-800 bg-slate-900 px-2 py-1 text-[10px] text-slate-500">
              +{item.queue_flags.length - 3}
            </span>
          )}
        </div>
      )}

      <div className="mt-3 truncate border-t border-slate-800 pt-3 text-[11px] text-slate-500">
        Updated {formatTimestamp(item.updated_at)}
      </div>
    </article>
  );
}

function CompactMetric({
  label,
  value,
  warning = false,
}: {
  label: string;
  value: string;
  warning?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`mt-0.5 truncate text-[11px] ${warning ? "text-orange-300" : "text-slate-200"}`}>
        {value}
      </div>
    </div>
  );
}

function AIStatusBadge({ item }: { item: IncidentCase }) {
  if (item.has_ai_analysis) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-violet-700 bg-violet-950 px-2 py-1 text-[11px] text-violet-200">
        <Bot className="h-3 w-3" />
        AI done
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-yellow-700 bg-yellow-950 px-2 py-1 text-[11px] text-yellow-200">
      <Bot className="h-3 w-3" />
      Needs AI
    </span>
  );
}

function ClosureBadge({ item }: { item: IncidentCase }) {
  if (item.ready_to_close) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-700 bg-emerald-950 px-2 py-1 text-[11px] text-emerald-200">
        <CheckCircle2 className="h-3 w-3" />
        Ready
      </span>
    );
  }

  if ((item.open_action_count ?? 0) > 0) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-orange-700 bg-orange-950 px-2 py-1 text-[11px] text-orange-200">
        <CircleDashed className="h-3 w-3" />
        Blocked
      </span>
    );
  }

  if (!item.has_closure_checklist) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-yellow-700 bg-yellow-950 px-2 py-1 text-[11px] text-yellow-200">
        <CircleDashed className="h-3 w-3" />
        Needs checklist
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] text-slate-300">
      <CircleDashed className="h-3 w-3" />
      In progress
    </span>
  );
}

function MetricCard({
  title,
  value,
  danger = false,
  warning = false,
  success = false,
}: {
  title: string;
  value: number;
  danger?: boolean;
  warning?: boolean;
  success?: boolean;
}) {
  const className = danger
    ? "border-red-800 bg-red-950/50"
    : warning
      ? "border-orange-800 bg-orange-950/40"
      : success
        ? "border-emerald-800 bg-emerald-950/40"
        : "border-slate-800 bg-slate-900";

  return (
    <div className={`rounded-2xl border p-5 shadow-lg ${className}`}>
      <div className="mb-3 text-sm text-slate-400">{title}</div>
      <div className="text-3xl font-semibold">{value}</div>
    </div>
  );
}
