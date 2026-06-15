"use client";

import { authFetch } from "@/lib/auth";
import {
  Activity,
  AlertTriangle,
  Brain,
  Clock3,
  FileText,
  Filter,
  GitBranch,
  NotebookPen,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";

type TimelineEntityRef = {
  type: string;
  value: string;
};

type TimelineEvidenceRef = {
  type: string;
  id?: string | number | null;
};

type TimelineItem = {
  id: string;
  incident_id: number;
  case_id?: number | null;
  category: string;
  source_system: string | null;
  timestamp: string | null;
  title: string;
  summary?: string | null;
  severity?: string | null;
  status?: string | null;
  entity_refs: TimelineEntityRef[];
  evidence_refs: TimelineEvidenceRef[];
  mitre: string[];
  confidence?: number | null;
  actor?: string | null;
  is_key_event: boolean;
  is_suppressed: boolean;
  is_correlated: boolean;
  details?: Record<string, unknown>;
  raw_payload_available: boolean;
};

type TimelineSummary = {
  total: number;
  key_events: number;
  raw_events: number;
  alerts: number;
  ai_events: number;
  lifecycle_events: number;
  case_events: number;
  notes: number;
  detection_noise_events: number;
  counts_by_category: Record<string, number>;
  counts_by_source: Record<string, number>;
  first_seen?: string | null;
  last_seen?: string | null;
  duration_seconds?: number | null;
  top_entities: Array<{ entity: string; count: number }>;
};

type TimelineCapabilities = {
  available_categories: string[];
  unavailable_categories: Array<{ category: string; reason: string }>;
  sources: string[];
  raw_payload_default: string;
  raw_payload_roles: string[];
};

type TimelineResponse = {
  incident_id: number;
  generated_at: string;
  sort: string;
  limit: number;
  cursor: string;
  next_cursor?: string | null;
  total_items: number;
  filtered_count: number;
  returned_count: number;
  summary: TimelineSummary;
  capabilities: TimelineCapabilities;
  items: TimelineItem[];
};

type TimelineView = {
  id: string;
  label: string;
  categories?: string[];
  keyOnly?: boolean;
};

const TIMELINE_VIEWS: TimelineView[] = [
  { id: "ALL", label: "All" },
  { id: "KEY", label: "Key events", keyOnly: true },
  { id: "RAW", label: "Raw", categories: ["RAW_EVENT"] },
  { id: "ALERTS", label: "Alerts", categories: ["SECURITY_ALERT", "AGGREGATED_DUPLICATE"] },
  { id: "AI", label: "AI", categories: ["AI_ANALYSIS", "AI_COMMAND_BRIEF"] },
  {
    id: "LIFECYCLE",
    label: "Lifecycle",
    categories: ["INCIDENT_CREATED", "INCIDENT_STATUS_CHANGE", "INCIDENT_SEVERITY_CHANGE"],
  },
  {
    id: "CASE",
    label: "Case",
    categories: ["CASE_CREATED", "CASE_STATUS_CHANGE", "CASE_ACTION_CREATED", "CASE_ACTION_COMPLETED"],
  },
  { id: "NOTES", label: "Notes", categories: ["ANALYST_NOTE"] },
  {
    id: "DETECTION",
    label: "Detection/noise",
    categories: [
      "DETECTION_RULE_MATCH",
      "NOISE_SUPPRESSION_MATCH",
      "EXCEPTION_MATCH",
      "AGGREGATED_DUPLICATE",
    ],
  },
];

const SEVERITY_OPTIONS = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

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

function durationLabel(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined) return "-";

  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;

  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ${minutes % 60}m`;

  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

function categoryLabel(value: string) {
  return value.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
}

function itemTone(item: TimelineItem) {
  const severity = (item.severity ?? "").toUpperCase();
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (item.is_suppressed || item.category.includes("NOISE") || item.category.includes("AGGREGATED")) return "warning";
  if (item.category.startsWith("AI")) return "ai";
  if (item.category.startsWith("CASE")) return "case";
  if (item.is_key_event) return "key";
  return "neutral";
}

function toneClasses(tone: string) {
  if (tone === "danger") {
    return {
      dot: "border-red-500 bg-red-400",
      badge: "border-red-800 bg-red-950 text-red-200",
      line: "border-red-900/60",
    };
  }
  if (tone === "warning") {
    return {
      dot: "border-orange-500 bg-orange-400",
      badge: "border-orange-800 bg-orange-950 text-orange-200",
      line: "border-orange-900/60",
    };
  }
  if (tone === "ai") {
    return {
      dot: "border-violet-500 bg-violet-400",
      badge: "border-violet-800 bg-violet-950 text-violet-200",
      line: "border-violet-900/60",
    };
  }
  if (tone === "case") {
    return {
      dot: "border-emerald-500 bg-emerald-400",
      badge: "border-emerald-800 bg-emerald-950 text-emerald-200",
      line: "border-emerald-900/60",
    };
  }
  if (tone === "key") {
    return {
      dot: "border-cyan-500 bg-cyan-400",
      badge: "border-cyan-800 bg-cyan-950 text-cyan-200",
      line: "border-cyan-900/60",
    };
  }

  return {
    dot: "border-slate-600 bg-slate-400",
    badge: "border-slate-700 bg-slate-950 text-slate-300",
    line: "border-slate-800",
  };
}

function buildTimelineUrl(
  incidentId: number | string,
  view: TimelineView,
  sort: string,
  source: string,
  severity: string,
  entity: string,
) {
  const params = new URLSearchParams();

  view.categories?.forEach((category) => params.append("category", category));
  if (view.keyOnly) params.set("key_only", "true");
  if (sort) params.set("sort", sort);
  if (source) params.set("source", source);
  if (severity) params.set("severity", severity);
  if (entity.trim()) params.set("entity", entity.trim());
  params.set("limit", "200");

  return `/incidents/${incidentId}/timeline?${params.toString()}`;
}

function SummaryCell({
  label,
  value,
  icon,
}: {
  label: string;
  value: string | number;
  icon?: ReactNode;
}) {
  return (
    <div className="min-w-0 bg-slate-950 px-2.5 py-2">
      <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {icon}
        {label}
      </div>
      <div className="mt-0.5 truncate text-xs font-semibold leading-5 text-slate-200">{value}</div>
    </div>
  );
}

function Chip({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex h-5 max-w-full items-center overflow-hidden text-ellipsis whitespace-nowrap rounded-md border px-2 text-[10px] font-medium leading-none ${className}`}>
      {children}
    </span>
  );
}

function TimelineEvent({ item }: { item: TimelineItem }) {
  const tone = toneClasses(itemTone(item));
  const detailText = item.details && Object.keys(item.details).length > 0
    ? JSON.stringify(item.details, null, 2)
    : "";

  return (
    <li className={`relative min-w-0 border-l pl-4 ${tone.line}`}>
      <span className={`absolute -left-[7px] top-1.5 h-3 w-3 rounded-full border-2 ${tone.dot}`} />
      <div className="min-w-0 overflow-hidden rounded-md border border-slate-800 bg-slate-950 p-3">
        <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-1.5">
              <Chip className={tone.badge}>{categoryLabel(item.category)}</Chip>
              {item.is_key_event && <Chip className="border-cyan-800 bg-cyan-950 text-cyan-200">Key</Chip>}
              {item.is_correlated && <Chip className="border-indigo-800 bg-indigo-950 text-indigo-200">Correlated</Chip>}
              {item.is_suppressed && <Chip className="border-orange-800 bg-orange-950 text-orange-200">Suppressed</Chip>}
              {item.raw_payload_available && (
                <Chip className="border-slate-700 bg-slate-900 text-slate-400">Raw available</Chip>
              )}
            </div>
            <h3 className="mt-2 break-words text-sm font-semibold leading-5 text-slate-100">{item.title}</h3>
            {item.summary && (
              <p className="mt-1 break-words text-xs leading-5 text-slate-400">{item.summary}</p>
            )}
          </div>
          <div className="shrink-0 text-left text-[11px] leading-5 text-slate-500 md:text-right">
            <div>{formatTimestamp(item.timestamp)}</div>
            <div>{item.source_system ?? "unknown source"}</div>
          </div>
        </div>

        <div className="mt-2 flex flex-wrap gap-1.5">
          {item.severity && <Chip className="border-slate-700 bg-slate-900 text-slate-300">{item.severity}</Chip>}
          {item.status && <Chip className="border-slate-700 bg-slate-900 text-slate-300">{item.status}</Chip>}
          {item.actor && <Chip className="border-slate-700 bg-slate-900 text-slate-300">Actor {item.actor}</Chip>}
          {item.confidence !== null && item.confidence !== undefined && (
            <Chip className="border-slate-700 bg-slate-900 text-slate-300">Confidence {item.confidence}</Chip>
          )}
          {item.case_id && <Chip className="border-emerald-800 bg-emerald-950 text-emerald-200">Case #{item.case_id}</Chip>}
          {item.mitre.slice(0, 5).map((tag) => (
            <Chip key={`${item.id}-${tag}`} className="border-slate-700 bg-slate-900 text-slate-300">
              {tag}
            </Chip>
          ))}
        </div>

        {item.entity_refs.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {item.entity_refs.slice(0, 10).map((ref) => (
              <Chip
                key={`${item.id}-${ref.type}-${ref.value}`}
                className="border-slate-800 bg-slate-950 text-slate-400"
              >
                {ref.type}: {ref.value}
              </Chip>
            ))}
          </div>
        )}

        {detailText && (
          <details className="mt-2 rounded-md border border-slate-800 bg-slate-900/70">
            <summary className="cursor-pointer px-2 py-1.5 text-[11px] font-medium text-slate-400 hover:text-slate-200">
              Details
            </summary>
            <pre className="max-h-56 max-w-full overflow-auto whitespace-pre-wrap break-words border-t border-slate-800 p-2 text-[11px] leading-5 text-slate-300">
              {detailText}
            </pre>
          </details>
        )}
      </div>
    </li>
  );
}

export default function IncidentTimeline({ incidentId }: { incidentId: number | string }) {
  const [activeViewId, setActiveViewId] = useState("ALL");
  const [sort, setSort] = useState("asc");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");
  const [entity, setEntity] = useState("");
  const [data, setData] = useState<TimelineResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const activeView = useMemo(
    () => TIMELINE_VIEWS.find((item) => item.id === activeViewId) ?? TIMELINE_VIEWS[0],
    [activeViewId],
  );

  const loadTimeline = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await authFetch(
        buildTimelineUrl(incidentId, activeView, sort, source, severity, entity),
        { cache: "no-store" },
      );

      if (!response.ok) {
        throw new Error(`Timeline API error ${response.status}`);
      }

      setData(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Timeline unavailable");
    } finally {
      setLoading(false);
    }
  }, [activeView, entity, incidentId, severity, sort, source]);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      setLoading(true);
      setError(null);

      try {
        const response = await authFetch(
          buildTimelineUrl(incidentId, activeView, sort, source, severity, entity),
          { cache: "no-store" },
        );

        if (!response.ok) {
          throw new Error(`Timeline API error ${response.status}`);
        }

        const payload = await response.json();
        if (!cancelled) setData(payload);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Timeline unavailable");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void run();

    return () => {
      cancelled = true;
    };
  }, [activeView, entity, incidentId, severity, sort, source]);

  const summary = data?.summary;
  const sourceOptions = data?.capabilities.sources ?? [];
  const unavailableCount = data?.capabilities.unavailable_categories.length ?? 0;

  return (
    <details
      open={isOpen}
      onToggle={(event) => setIsOpen(event.currentTarget.open)}
      className="min-w-0 overflow-hidden rounded-md border border-slate-800 bg-slate-950"
    >
      <summary className="cursor-pointer list-none border-b border-slate-800 px-3 py-2 hover:bg-slate-900/60">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <GitBranch className="h-3.5 w-3.5 text-cyan-300" />
              <h2 className="text-xs font-semibold text-slate-100">
                Advanced Incident Timeline
              </h2>
            </div>
            <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
              Unified incident, telemetry, AI, case and analyst activity from linked records.
            </p>
          </div>
          <span className="shrink-0 text-[10px] uppercase tracking-wide text-cyan-300">
            {isOpen ? "Close" : "Open"}
          </span>
        </div>
      </summary>

      <div className="space-y-3 p-3">
        <div className="flex justify-end">
          <button
            type="button"
            onClick={loadTimeline}
            disabled={loading}
            className="inline-flex h-7 w-fit items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 text-xs font-medium text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>

        <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 md:grid-cols-4 xl:grid-cols-8">
          <SummaryCell label="Events" value={summary?.total ?? "-"} icon={<Activity className="h-3 w-3" />} />
          <SummaryCell label="Key" value={summary?.key_events ?? "-"} icon={<Sparkles className="h-3 w-3" />} />
          <SummaryCell label="Raw" value={summary?.raw_events ?? "-"} icon={<FileText className="h-3 w-3" />} />
          <SummaryCell label="Alerts" value={summary?.alerts ?? "-"} icon={<ShieldCheck className="h-3 w-3" />} />
          <SummaryCell label="AI" value={summary?.ai_events ?? "-"} icon={<Brain className="h-3 w-3" />} />
          <SummaryCell label="Case" value={summary?.case_events ?? "-"} icon={<NotebookPen className="h-3 w-3" />} />
          <SummaryCell label="Noise" value={summary?.detection_noise_events ?? "-"} icon={<AlertTriangle className="h-3 w-3" />} />
          <SummaryCell label="Duration" value={durationLabel(summary?.duration_seconds)} icon={<Clock3 className="h-3 w-3" />} />
        </div>

        <div className="space-y-2 rounded-md border border-slate-800 bg-slate-900/60 p-2">
          <div className="flex flex-wrap gap-1.5">
            {TIMELINE_VIEWS.map((view) => {
              const active = view.id === activeViewId;
              return (
                <button
                  key={view.id}
                  type="button"
                  onClick={() => setActiveViewId(view.id)}
                  className={`h-7 rounded-md border px-2.5 text-xs font-medium ${
                    active
                      ? "border-cyan-700 bg-cyan-500 text-slate-950"
                      : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-900"
                  }`}
                >
                  {view.label}
                </button>
              );
            })}
          </div>

          <div className="grid gap-2 md:grid-cols-[150px_150px_150px_minmax(0,1fr)]">
            <label className="flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950 px-2 text-xs text-slate-400">
              <Filter className="h-3.5 w-3.5 text-slate-500" />
              <select
                value={sort}
                onChange={(event) => setSort(event.target.value)}
                className="h-8 min-w-0 flex-1 bg-transparent text-xs text-slate-200 outline-none"
              >
                <option value="asc">Oldest first</option>
                <option value="desc">Newest first</option>
              </select>
            </label>

            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              className="h-8 rounded-md border border-slate-800 bg-slate-950 px-2 text-xs text-slate-200 outline-none focus:border-cyan-500"
            >
              {SEVERITY_OPTIONS.map((option) => (
                <option key={option || "all"} value={option}>
                  {option || "All severities"}
                </option>
              ))}
            </select>

            <select
              value={source}
              onChange={(event) => setSource(event.target.value)}
              className="h-8 rounded-md border border-slate-800 bg-slate-950 px-2 text-xs text-slate-200 outline-none focus:border-cyan-500"
            >
              <option value="">All sources</option>
              {sourceOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>

            <label className="flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950 px-2 text-xs text-slate-400">
              <Search className="h-3.5 w-3.5 text-slate-500" />
              <input
                value={entity}
                onChange={(event) => setEntity(event.target.value)}
                placeholder="Entity, rule, status..."
                className="h-8 min-w-0 flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder:text-slate-600"
              />
            </label>
          </div>
        </div>

        {error && (
          <div className="rounded-md border border-red-800 bg-red-950/40 p-2 text-xs text-red-200">
            {error}
          </div>
        )}

        {data && (
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
            <span>
              Showing {data.returned_count} of {data.filtered_count} matching events
            </span>
            <span>·</span>
            <span>{data.total_items} linked records in scope</span>
            <span>·</span>
            <span>{unavailableCount} category sources unavailable</span>
          </div>
        )}

        {data?.capabilities.unavailable_categories.length ? (
          <details className="rounded-md border border-slate-800 bg-slate-900/60">
            <summary className="cursor-pointer px-2 py-1.5 text-[11px] font-medium text-slate-400 hover:text-slate-200">
              Capability notes
            </summary>
            <div className="grid gap-1 border-t border-slate-800 p-2 text-[11px] leading-4 text-slate-500 md:grid-cols-2">
              {data.capabilities.unavailable_categories.slice(0, 8).map((item) => (
                <div key={item.category}>
                  <span className="font-medium text-slate-300">{categoryLabel(item.category)}:</span> {item.reason}
                </div>
              ))}
            </div>
          </details>
        ) : null}

        {loading && !data && (
          <div className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading timeline...
          </div>
        )}

        {data && data.items.length === 0 && !loading && (
          <div className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs text-slate-500">
            No timeline events match the selected filters.
          </div>
        )}

        {data && data.items.length > 0 && (
          <ol className="min-w-0 space-y-3">
            {data.items.map((item) => (
              <TimelineEvent key={item.id} item={item} />
            ))}
          </ol>
        )}
      </div>
    </details>
  );
}
