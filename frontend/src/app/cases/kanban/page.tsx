"use client";

import { authFetch } from "@/lib/auth";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import {
  AlertTriangle,
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

type Tone = "success" | "warning" | "danger" | "primary" | "neutral" | "executive";

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
    description: "Requires senior attention.",
  },
  {
    id: "READY_TO_CLOSE",
    title: "Ready",
    description: "Checklist complete and actions resolved.",
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

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { card: string; badge: string; text: string }> = {
    success: {
      card: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
    },
    warning: {
      card: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
    },
    danger: {
      card: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
    },
    primary: {
      card: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
    },
    neutral: {
      card: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
    },
    executive: {
      card: "border-violet-900/70 bg-violet-950/20",
      badge: "border-violet-700 bg-violet-950 text-violet-200",
      text: "text-violet-300",
    },
  };

  return classes[tone];
}

function severityTone(value: string | null | undefined): Tone {
  const severity = value ?? "LOW";

  if (severity === "CRITICAL") return "danger";
  if (severity === "HIGH") return "warning";
  if (severity === "MEDIUM") return "primary";

  return "success";
}

function statusTone(value: string | null | undefined): Tone {
  const status = value ?? "OPEN";

  if (status === "ESCALATED") return "danger";
  if (status === "INVESTIGATING") return "executive";
  if (status === "TRIAGED") return "primary";
  if (status === "CLOSED") return "neutral";
  if (status === "FALSE_POSITIVE") return "executive";

  return "primary";
}

function slaTone(value: string | null | undefined): Tone {
  const status = value ?? "NOT_SET";

  if (status === "BREACHED") return "danger";
  if (status === "WITHIN_SLA") return "success";
  if (status === "COMPLETED") return "neutral";

  return "neutral";
}

function columnTone(columnId: string): Tone {
  if (columnId === "ESCALATED") return "danger";
  if (columnId === "READY_TO_CLOSE") return "success";
  if (columnId === "INVESTIGATING") return "executive";
  if (columnId === "TRIAGED") return "primary";
  if (columnId === "FALSE_POSITIVE") return "executive";
  if (columnId === "CLOSED") return "neutral";

  return "primary";
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
  });
}

function shortText(value: string | null | undefined, max = 86) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
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
  const response = await authFetch(`/cases?limit=100`, {
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
      <div className="mx-auto max-w-[1800px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/cases"
              className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              ← Case Queue
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <Briefcase className="h-3.5 w-3.5" />
              Investigation Cases
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Case Kanban Board
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Compact visual SOC backlog grouped by investigation state and closure readiness.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <Link
              href="/cases"
              className="flex h-8 items-center rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
            >
              Queue view
            </Link>

            <button
              onClick={loadCases}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading case board...
          </section>
        ) : (
          <div className="space-y-3">
            <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              <MetricTile title="Visible cases" value={metrics.total} tone="primary" />
              <MetricTile
                title="SLA breached"
                value={metrics.slaBreached}
                tone={metrics.slaBreached > 0 ? "danger" : "success"}
              />
              <MetricTile
                title="Ready to close"
                value={metrics.readyToClose}
                tone={metrics.readyToClose > 0 ? "success" : "neutral"}
              />
              <MetricTile
                title="Open actions"
                value={metrics.openActions}
                tone={metrics.openActions > 0 ? "warning" : "success"}
              />
              <MetricTile
                title="Needs AI"
                value={metrics.needsAi}
                tone={metrics.needsAi > 0 ? "warning" : "success"}
              />
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="grid gap-2 lg:grid-cols-[1fr_150px_150px]">
                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Search board
                  </span>
                  <div className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-2">
                    <Search className="h-3.5 w-3.5 text-slate-500" />
                    <input
                      value={searchText}
                      onChange={(event) => setSearchText(event.target.value)}
                      placeholder="Case, host, owner, status, severity, flags..."
                      className="w-full bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600"
                    />
                  </div>
                </label>

                <div className="flex items-end">
                  <button
                    type="button"
                    onClick={() => setHideClosed((current) => !current)}
                    className={`h-8 w-full rounded-lg border px-2 text-xs ${
                      hideClosed
                        ? "border-cyan-500 bg-cyan-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    {hideClosed ? "Closed hidden" : "All statuses"}
                  </button>
                </div>

                <div className="flex items-end">
                  <button
                    type="button"
                    onClick={() => setCompactCards((current) => !current)}
                    className={`h-8 w-full rounded-lg border px-2 text-xs ${
                      compactCards
                        ? "border-emerald-500 bg-emerald-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    {compactCards ? "Compact cards" : "Detailed cards"}
                  </button>
                </div>
              </div>
            </section>

            <section className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
              <div className="flex min-w-max gap-2.5">
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

function MetricTile({
  title,
  value,
  tone,
}: {
  title: string;
  value: number;
  tone: Tone;
}) {
  const classes = toneClasses(tone);

  return (
    <div className={`rounded-lg border px-3 py-2 shadow-sm ${classes.card}`}>
      <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {title}
      </div>
      <div className="mt-0.5 text-lg font-semibold leading-6 text-slate-100">
        {value}
      </div>
    </div>
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
  const tone = columnTone(column.id);
  const classes = toneClasses(tone);

  return (
    <div className={`h-fit w-[292px] shrink-0 rounded-lg border p-2 shadow-sm ${classes.card}`}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold text-slate-100">
            {column.title}
          </h2>
          <p className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-slate-500">
            {column.description}
          </p>
        </div>

        <span className={`shrink-0 rounded-md border px-2 py-0.5 text-[11px] ${classes.badge}`}>
          {items.length}
        </span>
      </div>

      {items.length === 0 ? (
        <div className="rounded-md border border-slate-800 bg-slate-950 p-2 text-[11px] text-slate-500">
          No cases.
        </div>
      ) : (
        <div className="space-y-2">
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
  const completedActions = Math.max(totalActions - openActions, 0);

  if (compact) {
    return (
      <article className="rounded-md border border-slate-800 bg-slate-950 p-2 shadow-sm transition hover:border-slate-700">
        <div className="mb-1.5 flex items-start justify-between gap-2">
          <Link
            href={`/cases/${item.id}`}
            className="line-clamp-2 min-w-0 text-xs font-medium leading-4 text-cyan-300 hover:text-cyan-200"
            title={item.title}
          >
            #{item.id} {item.title}
          </Link>

          <Badge tone={severityTone(severity)}>{severity}</Badge>
        </div>

        <div className="mb-2 flex flex-wrap items-center gap-1">
          {item.sla_status === "BREACHED" && (
            <MiniFlag tone="danger" icon={<AlertTriangle className="h-3 w-3" />}>
              SLA
            </MiniFlag>
          )}

          {item.ready_to_close && (
            <MiniFlag tone="success" icon={<CheckCircle2 className="h-3 w-3" />}>
              Ready
            </MiniFlag>
          )}

          {openActions > 0 && (
            <MiniFlag tone="warning" icon={<CircleDashed className="h-3 w-3" />}>
              {openActions} open
            </MiniFlag>
          )}

          {!item.has_ai_analysis && isOpenCase(item) && (
            <MiniFlag tone="warning" icon={<Bot className="h-3 w-3" />}>
              AI
            </MiniFlag>
          )}

          {!item.owner && isOpenCase(item) && (
            <MiniFlag tone="warning" icon={<AlertTriangle className="h-3 w-3" />}>
              Owner
            </MiniFlag>
          )}
        </div>

        <div className="grid grid-cols-2 gap-1.5">
          <CompactMetric
            label="Owner"
            value={item.owner ?? "unassigned"}
            warning={!item.owner && isOpenCase(item)}
          />
          <CompactMetric label="Host" value={item.agent ?? "unknown"} />
          <CompactMetric label="Incidents" value={String(item.incident_count ?? 0)} />
          <CompactMetric label="Actions" value={`${completedActions}/${totalActions}`} />
        </div>

        <div className="mt-2 flex items-center justify-between gap-2 border-t border-slate-800 pt-2 text-[10px] text-slate-500">
          <span className="truncate">{item.correlation_type ?? "No correlation"}</span>
          <span className="shrink-0">Risk {item.risk_score ?? 0}</span>
        </div>
      </article>
    );
  }

  return (
    <article className="rounded-md border border-slate-800 bg-slate-950 p-2.5 shadow-sm transition hover:border-slate-700">
      <div className="mb-2 flex items-start justify-between gap-2">
        <Link
          href={`/cases/${item.id}`}
          className="line-clamp-3 min-w-0 text-xs font-medium leading-4 text-cyan-300 hover:text-cyan-200"
          title={item.title}
        >
          #{item.id} {item.title}
        </Link>

        <Badge tone={severityTone(severity)}>{severity}</Badge>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-1">
        <Badge tone={statusTone(item.status)}>{item.status ?? "OPEN"}</Badge>
        <Badge tone={slaTone(item.sla_status)}>{slaLabel(item.sla_status)}</Badge>
      </div>

      <div className="grid grid-cols-2 gap-1.5">
        <CompactMetric
          label="Owner"
          value={item.owner ?? "unassigned"}
          warning={!item.owner && isOpenCase(item)}
        />
        <CompactMetric label="Host" value={item.agent ?? "unknown"} />
        <CompactMetric label="Incidents" value={String(item.incident_count ?? 0)} />
        <CompactMetric label="Actions" value={`${completedActions}/${totalActions}`} />
      </div>

      <div className="mt-2 flex flex-wrap gap-1">
        <AIStatusBadge item={item} />
        <ClosureBadge item={item} />
      </div>

      {item.queue_flags && item.queue_flags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {item.queue_flags.slice(0, 2).map((flag) => (
            <span
              key={flag}
              className="max-w-full truncate rounded-md border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-400"
            >
              {flag.replaceAll("_", " ")}
            </span>
          ))}
        </div>
      )}

      <div className="mt-2 truncate border-t border-slate-800 pt-2 text-[10px] text-slate-500">
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
    <div className="min-w-0 rounded-md border border-slate-800 bg-slate-900/70 px-1.5 py-1">
      <div className="text-[9px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div
        className={`truncate text-[11px] leading-4 ${
          warning ? "text-orange-300" : "text-slate-200"
        }`}
        title={value}
      >
        {value}
      </div>
    </div>
  );
}

function Badge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span className={`shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] ${toneClasses(tone).badge}`}>
      {children}
    </span>
  );
}

function MiniFlag({
  tone,
  icon,
  children,
}: {
  tone: Tone;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] ${toneClasses(tone).badge}`}>
      {icon}
      {children}
    </span>
  );
}

function AIStatusBadge({ item }: { item: IncidentCase }) {
  if (item.has_ai_analysis) {
    return (
      <MiniFlag tone="executive" icon={<Bot className="h-3 w-3" />}>
        AI done
      </MiniFlag>
    );
  }

  return (
    <MiniFlag tone="warning" icon={<Bot className="h-3 w-3" />}>
      Needs AI
    </MiniFlag>
  );
}

function ClosureBadge({ item }: { item: IncidentCase }) {
  if (item.ready_to_close) {
    return (
      <MiniFlag tone="success" icon={<CheckCircle2 className="h-3 w-3" />}>
        Ready
      </MiniFlag>
    );
  }

  if ((item.open_action_count ?? 0) > 0) {
    return (
      <MiniFlag tone="warning" icon={<CircleDashed className="h-3 w-3" />}>
        Blocked
      </MiniFlag>
    );
  }

  if (!item.has_closure_checklist) {
    return (
      <MiniFlag tone="warning" icon={<CircleDashed className="h-3 w-3" />}>
        Checklist
      </MiniFlag>
    );
  }

  return (
    <MiniFlag tone="neutral" icon={<CircleDashed className="h-3 w-3" />}>
      Progress
    </MiniFlag>
  );
}
