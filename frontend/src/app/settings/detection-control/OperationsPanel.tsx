"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  Clock,
  Eye,
  FileSearch,
  RefreshCw,
  Search,
  ShieldAlert,
  Target,
} from "lucide-react";
import { authFetch, type AuthUser } from "@/lib/auth";

type OperationCategory = "noise" | "exceptions" | "rules";

type OperationItem = {
  id: string;
  source: string;
  native_id: string | number;
  type: string;
  name: string;
  description: string | null;
  rule_key: string;
  version_number: number | null;
  state: string;
  status: string;
  enabled: boolean;
  active: boolean;
  scope: string;
  scope_classification: string;
  scope_reasons: string[];
  matcher_kind: string;
  matcher_value: string;
  matcher_sha256: string | null;
  matcher_length: number;
  owner: string | null;
  source_system: string | null;
  business_reason: string | null;
  risk_note: string | null;
  expires_at: string | null;
  validation_status: string | null;
  validation_errors: Array<Record<string, unknown> | string>;
  validation_warnings: Array<Record<string, unknown> | string>;
  hit_count: number | null;
  hit_count_source: string;
  last_match_at: string | null;
  config_domain: string;
  affected_services: string[];
  restart_recommended: boolean;
  review_status: string;
  review_due: boolean;
  expired: boolean;
  reviewed_at: string | null;
  reviewed_by: string | null;
  review_notes: string | null;
  created_at: string | null;
  updated_at: string | null;
  metadata: Record<string, unknown>;
};

type OperationsSummary = {
  total: number;
  active: number;
  inactive: number;
  review_due: number;
  expired: number;
  validation_failed: number;
  scope: Record<string, number>;
  types: Record<string, number>;
  statuses: Record<string, number>;
  stored_hit_count: number;
  last_match_at: string | null;
  affected_services: string[];
};

type OperationsOverview = {
  summary: OperationsSummary;
  active_summary: OperationsSummary;
  top_review_items: OperationItem[];
  rbac: {
    role: string | null;
    can_preview: boolean;
    can_review: boolean;
    can_admin: boolean;
  };
  generated_at: string;
};

type OperationsListResponse = {
  items: OperationItem[];
  summary: OperationsSummary;
  available_filters: {
    status: string[];
    scope_classification: string[];
    review_status: string[];
  };
  generated_at: string;
};

type OperationEventMatch = {
  source_table: string;
  id: number;
  source: string | null;
  timestamp: string | null;
  agent: string | null;
  rule_id: string | null;
  rule_description: string | null;
  level: number | null;
  severity_bucket?: string | null;
  risk_score?: number | null;
  event_count: number | null;
  payload_preview: string;
};

type MatchedEventsResponse = {
  item: OperationItem;
  matches: OperationEventMatch[];
  observed_count: number;
  scan_limit: number;
  count_source: string;
  generated_at: string;
};

type MatchPreviewResponse = {
  preview: {
    scope_classification: {
      classification: string;
      reasons: string[];
    };
    observed_count: number;
    scan_limit: number;
    count_source: string;
  };
  matches: OperationEventMatch[];
  generated_at: string;
};

const CATEGORY_OPTIONS: Array<{ key: OperationCategory; label: string; endpoint: string }> = [
  { key: "noise", label: "Noise Suppression", endpoint: "/detection-control/operations/noise-suppression" },
  { key: "exceptions", label: "Exceptions", endpoint: "/detection-control/operations/exceptions" },
  { key: "rules", label: "Rules", endpoint: "/detection-control/operations/rules" },
];

const STATUS_FILTERS = ["all", "active", "inactive", "failed_validation", "review_due", "expired"];
const SCOPE_FILTERS = ["all", "narrow", "moderate", "broad", "dangerously_broad", "unknown"];
const REVIEW_FILTERS = ["all", "not_reviewed", "review_due", "reviewed", "needs_follow_up", "expired"];

function endpointForCategory(category: OperationCategory) {
  return CATEGORY_OPTIONS.find((item) => item.key === category)?.endpoint || CATEGORY_OPTIONS[0].endpoint;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function formatDate(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "Europe/Zurich",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function toneForScope(scope: string) {
  if (scope === "narrow") return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  if (scope === "moderate") return "border-cyan-800 bg-cyan-950/60 text-cyan-200";
  if (scope === "broad") return "border-amber-800 bg-amber-950/60 text-amber-200";
  if (scope === "dangerously_broad") return "border-red-800 bg-red-950/60 text-red-200";
  return "border-slate-700 bg-slate-900 text-slate-300";
}

function toneForReview(status: string) {
  if (status === "reviewed" || status === "risk_accepted") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }
  if (status === "expired") return "border-red-800 bg-red-950/60 text-red-200";
  if (status === "review_due" || status === "needs_follow_up") {
    return "border-amber-800 bg-amber-950/60 text-amber-200";
  }
  return "border-slate-700 bg-slate-900 text-slate-300";
}

function toneForState(state: string) {
  const normalized = state.toUpperCase();

  if (normalized === "ACTIVE" || normalized === "APPROVED") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }
  if (normalized === "DISABLED" || normalized === "REJECTED") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }
  if (normalized === "FAILED_VALIDATION" || normalized === "ERROR") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }
  return "border-cyan-800 bg-cyan-950/60 text-cyan-200";
}

async function fetchOverview(): Promise<OperationsOverview> {
  const response = await authFetch("/detection-control/operations/overview", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Operations overview API returned ${response.status}`);
  }

  return (await response.json()) as OperationsOverview;
}

async function fetchItems(
  category: OperationCategory,
  queryString: string
): Promise<OperationsListResponse> {
  const response = await authFetch(`${endpointForCategory(category)}?${queryString}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Operations list API returned ${response.status}`);
  }

  return (await response.json()) as OperationsListResponse;
}

async function fetchMatches(itemId: string): Promise<MatchedEventsResponse> {
  const response = await authFetch(
    `/detection-control/operations/items/${encodeURIComponent(itemId)}/matched-events?limit=25&scan_limit=1000`,
    { cache: "no-store" }
  );

  if (!response.ok) {
    throw new Error(`Matched events API returned ${response.status}`);
  }

  return (await response.json()) as MatchedEventsResponse;
}

export default function OperationsPanel({ currentUser }: { currentUser: AuthUser | null }) {
  const [overview, setOverview] = useState<OperationsOverview | null>(null);
  const [data, setData] = useState<OperationsListResponse | null>(null);
  const [category, setCategory] = useState<OperationCategory>("noise");
  const [statusFilter, setStatusFilter] = useState("all");
  const [scopeFilter, setScopeFilter] = useState("all");
  const [reviewFilter, setReviewFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selectedItem, setSelectedItem] = useState<OperationItem | null>(null);
  const [matches, setMatches] = useState<MatchedEventsResponse | null>(null);
  const [preview, setPreview] = useState<MatchPreviewResponse | null>(null);
  const [reviewDate, setReviewDate] = useState("");
  const [reviewNotes, setReviewNotes] = useState("");
  const [reviewStatus, setReviewStatus] = useState("reviewed");
  const [loading, setLoading] = useState(true);
  const [actionRunning, setActionRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const canReview =
    overview?.rbac.can_review ||
    currentUser?.role === "ADMIN" ||
    currentUser?.role === "ANALYST";
  const canPreview =
    overview?.rbac.can_preview ||
    currentUser?.role === "ADMIN" ||
    currentUser?.role === "ANALYST";

  const queryString = useMemo(() => {
    const params = new URLSearchParams();
    params.set("limit", "200");
    if (statusFilter !== "all") params.set("status", statusFilter);
    if (scopeFilter !== "all") params.set("scope_classification", scopeFilter);
    if (reviewFilter !== "all") params.set("review_status", reviewFilter);
    if (search.trim()) params.set("search", search.trim());
    return params.toString();
  }, [reviewFilter, scopeFilter, search, statusFilter]);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [overviewResult, itemsResult] = await Promise.all([
        fetchOverview(),
        fetchItems(category, queryString),
      ]);
      setOverview(overviewResult);
      setData(itemsResult);
      setSelectedItem((current) => {
        if (!current) return current;
        return itemsResult.items.find((item) => item.id === current.id) || null;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load operations data");
    } finally {
      setLoading(false);
    }
  }, [category, queryString]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadData();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadData]);

  useEffect(() => {
    let cancelled = false;

    if (!selectedItem) {
      setMatches(null);
      setPreview(null);
      return;
    }

    fetchMatches(selectedItem.id)
      .then((result) => {
        if (!cancelled) setMatches(result);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to load matched events");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedItem]);

  async function runPreview(item: OperationItem) {
    if (!canPreview) return;

    const content = isRecord(item.metadata?.content_json) ? item.metadata.content_json : item.metadata;

    try {
      setActionRunning(true);
      setError(null);
      setPreview(null);
      const response = await authFetch("/detection-control/operations/match-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: item.name,
          type: item.type,
          scope: item.scope,
          matcher_kind: item.matcher_kind,
          matcher_value: item.matcher_value,
          content_json: content,
          limit: 25,
          scan_limit: 1000,
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail || `API returned ${response.status}`));
      }

      setPreview((await response.json()) as MatchPreviewResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to run match preview");
    } finally {
      setActionRunning(false);
    }
  }

  async function markReviewed() {
    if (!selectedItem || !canReview) return;

    try {
      setActionRunning(true);
      setError(null);
      setMessage(null);
      const response = await authFetch(
        `/detection-control/operations/items/${encodeURIComponent(selectedItem.id)}/mark-reviewed`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            review_status: reviewStatus,
            review_notes: reviewNotes,
          }),
        }
      );

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail || `API returned ${response.status}`));
      }

      const result = (await response.json()) as { item: OperationItem };
      setSelectedItem(result.item);
      setMessage("Review status updated.");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to mark item reviewed");
    } finally {
      setActionRunning(false);
    }
  }

  async function extendReview() {
    if (!selectedItem || !canReview || !reviewDate) return;

    try {
      setActionRunning(true);
      setError(null);
      setMessage(null);
      const response = await authFetch(
        `/detection-control/operations/items/${encodeURIComponent(selectedItem.id)}/extend-review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            expires_at: reviewDate,
            reason: reviewNotes,
          }),
        }
      );

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail || `API returned ${response.status}`));
      }

      const result = (await response.json()) as { item: OperationItem };
      setSelectedItem(result.item);
      setMessage("Review date extended.");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to extend review");
    } finally {
      setActionRunning(false);
    }
  }

  const items = data?.items ?? [];
  const currentSummary = data?.summary;
  const broadCount =
    (overview?.summary.scope.broad ?? 0) + (overview?.summary.scope.dangerously_broad ?? 0);

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Exceptions and Noise Operations
          </h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            Operational review for active detections, suppressions, exception scope and match evidence.
          </p>
        </div>

        <button
          type="button"
          onClick={loadData}
          disabled={loading || actionRunning}
          className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {message && (
        <div className="mb-3 rounded-lg border border-emerald-800 bg-emerald-950/60 p-3 text-xs text-emerald-200">
          {message}
        </div>
      )}

      <div className="mb-3 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-5">
        <OperationMetric
          label="Active Controls"
          value={overview?.summary.active ?? 0}
          detail={`${overview?.summary.inactive ?? 0} inactive`}
          icon={<Activity className="h-3.5 w-3.5" />}
        />
        <OperationMetric
          label="Review Due"
          value={overview?.summary.review_due ?? 0}
          detail={`${overview?.summary.expired ?? 0} expired`}
          icon={<CalendarClock className="h-3.5 w-3.5" />}
        />
        <OperationMetric
          label="Broad Scope"
          value={broadCount}
          detail={`${overview?.summary.scope.dangerously_broad ?? 0} dangerous`}
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
        />
        <OperationMetric
          label="Stored Hits"
          value={overview?.summary.stored_hit_count ?? 0}
          detail="Lifecycle counters"
          icon={<Target className="h-3.5 w-3.5" />}
        />
        <OperationMetric
          label="Last Match"
          value={overview?.summary.last_match_at ? formatDate(overview.summary.last_match_at) : "-"}
          detail={overview?.summary.affected_services.join(", ") || "No restart flag"}
          icon={<Clock className="h-3.5 w-3.5" />}
        />
      </div>

      <div className="mb-3 grid gap-2 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="flex flex-wrap gap-1.5">
          {CATEGORY_OPTIONS.map((item) => (
            <button
              key={item.key}
              type="button"
              onClick={() => {
                setCategory(item.key);
                setSelectedItem(null);
              }}
              className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition ${
                category === item.key
                  ? "border-cyan-500 bg-cyan-500 text-slate-950"
                  : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-600 hover:text-cyan-200"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-[repeat(3,minmax(120px,1fr))_minmax(200px,1.4fr)]">
          <FilterSelect label="Status" value={statusFilter} options={STATUS_FILTERS} onChange={setStatusFilter} />
          <FilterSelect label="Scope" value={scopeFilter} options={SCOPE_FILTERS} onChange={setScopeFilter} />
          <FilterSelect label="Review" value={reviewFilter} options={REVIEW_FILTERS} onChange={setReviewFilter} />
          <label className="flex h-8 items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-400">
            <Search className="h-3.5 w-3.5 shrink-0" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search operations..."
              className="min-w-0 flex-1 bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600"
            />
          </label>
        </div>
      </div>

      <div className="grid gap-3 2xl:grid-cols-[minmax(0,1.45fr)_minmax(380px,0.55fr)]">
        <div className="min-w-0">
          <div className="mb-2 flex items-center justify-between text-xs text-slate-500">
            <span>{loading ? "Loading operations..." : `${items.length} entries`}</span>
            <span>
              Active in view: {currentSummary?.active ?? 0} / Review due: {currentSummary?.review_due ?? 0}
            </span>
          </div>
          <OperationsTable
            items={items}
            selectedId={selectedItem?.id ?? null}
            onPreview={runPreview}
            onSelect={(item) => {
              setSelectedItem(item);
              setPreview(null);
              setReviewDate(item.expires_at ? item.expires_at.slice(0, 10) : "");
              setReviewNotes(item.review_notes || "");
              setReviewStatus(item.review_status === "needs_follow_up" ? "needs_follow_up" : "reviewed");
            }}
            canPreview={Boolean(canPreview)}
            running={actionRunning}
          />
        </div>

        <OperationDetail
          canReview={Boolean(canReview)}
          item={selectedItem}
          matches={matches}
          preview={preview}
          reviewDate={reviewDate}
          reviewNotes={reviewNotes}
          reviewStatus={reviewStatus}
          running={actionRunning}
          onExtendReview={extendReview}
          onMarkReviewed={markReviewed}
          onPreview={runPreview}
          onReviewDateChange={setReviewDate}
          onReviewNotesChange={setReviewNotes}
          onReviewStatusChange={setReviewStatus}
        />
      </div>
    </section>
  );
}

function OperationMetric({
  detail,
  icon,
  label,
  value,
}: {
  detail: string;
  icon: ReactNode;
  label: string;
  value: ReactNode;
}) {
  return (
    <article className="flex min-h-[48px] items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-950 px-2 py-1.5">
      <div className="min-w-0">
        <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
          {label}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-1.5">
          <span className="truncate text-base font-semibold leading-5 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[10px] leading-3 text-slate-500">
            {detail}
          </span>
        </div>
      </div>
      <div className="shrink-0 rounded-sm bg-slate-900 p-1 text-slate-400">
        {icon}
      </div>
    </article>
  );
}

function FilterSelect({
  label,
  onChange,
  options,
  value,
}: {
  label: string;
  onChange: (value: string) => void;
  options: string[];
  value: string;
}) {
  return (
    <label>
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
        title={label}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option.replaceAll("_", " ")}
          </option>
        ))}
      </select>
    </label>
  );
}

function OperationsTable({
  canPreview,
  items,
  onPreview,
  onSelect,
  running,
  selectedId,
}: {
  canPreview: boolean;
  items: OperationItem[];
  onPreview: (item: OperationItem) => void;
  onSelect: (item: OperationItem) => void;
  running: boolean;
  selectedId: string | null;
}) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 text-center text-xs text-slate-500">
        <AlertTriangle className="mx-auto mb-2 h-5 w-5 text-slate-600" />
        No operational entries match the selected filters.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Entry</th>
              <th className="px-3 py-2">State</th>
              <th className="px-3 py-2">Scope Risk</th>
              <th className="px-3 py-2">Review</th>
              <th className="px-3 py-2">Hits</th>
              <th className="px-3 py-2">Last Match</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {items.map((item) => (
              <tr
                key={item.id}
                className={`align-top hover:bg-slate-800/40 ${
                  selectedId === item.id ? "bg-cyan-950/20" : ""
                }`}
              >
                <td className="max-w-sm px-3 py-2">
                  <button
                    type="button"
                    onClick={() => onSelect(item)}
                    className="text-left font-medium text-slate-100 hover:text-cyan-200"
                  >
                    {item.name}
                  </button>
                  <div className="mt-1 truncate text-[11px] text-slate-500">
                    {item.type.replaceAll("_", " ")} / {item.rule_key}
                  </div>
                  <div className="mt-1 truncate text-[11px] text-slate-600">
                    {item.owner || "-"} / {item.source_system || item.source}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${toneForState(item.state)}`}>
                    {item.state.replaceAll("_", " ")}
                  </span>
                  {!item.enabled && (
                    <div className="mt-1 text-[11px] text-slate-500">disabled</div>
                  )}
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${toneForScope(item.scope_classification)}`}>
                    {item.scope_classification.replaceAll("_", " ")}
                  </span>
                  <div className="mt-1 max-w-[220px] truncate text-[11px] text-slate-500" title={item.scope}>
                    {item.scope || "-"}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${toneForReview(item.review_status)}`}>
                    {item.review_status.replaceAll("_", " ")}
                  </span>
                  <div className="mt-1 text-[11px] text-slate-500">
                    expires {formatDate(item.expires_at)}
                  </div>
                </td>
                <td className="px-3 py-2 text-slate-300">
                  {item.hit_count ?? "-"}
                  <div className="mt-1 text-[11px] text-slate-500">
                    {item.hit_count_source.replaceAll("_", " ")}
                  </div>
                </td>
                <td className="px-3 py-2 text-slate-300">
                  {formatDate(item.last_match_at)}
                </td>
                <td className="px-3 py-2">
                  <div className="flex min-w-[120px] flex-wrap gap-1.5">
                    <IconButton label="View details" disabled={false} onClick={() => onSelect(item)}>
                      <Eye className="h-3.5 w-3.5" />
                    </IconButton>
                    {canPreview && (
                      <IconButton label="Run match preview" disabled={running} onClick={() => onPreview(item)}>
                        <FileSearch className="h-3.5 w-3.5" />
                      </IconButton>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function IconButton({
  children,
  disabled,
  label,
  onClick,
}: {
  children: ReactNode;
  disabled: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className="flex h-7 w-7 items-center justify-center rounded-md border border-slate-700 bg-slate-950 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}

function OperationDetail({
  canReview,
  item,
  matches,
  onExtendReview,
  onMarkReviewed,
  onPreview,
  onReviewDateChange,
  onReviewNotesChange,
  onReviewStatusChange,
  preview,
  reviewDate,
  reviewNotes,
  reviewStatus,
  running,
}: {
  canReview: boolean;
  item: OperationItem | null;
  matches: MatchedEventsResponse | null;
  onExtendReview: () => void;
  onMarkReviewed: () => void;
  onPreview: (item: OperationItem) => void;
  onReviewDateChange: (value: string) => void;
  onReviewNotesChange: (value: string) => void;
  onReviewStatusChange: (value: string) => void;
  preview: MatchPreviewResponse | null;
  reviewDate: string;
  reviewNotes: string;
  reviewStatus: string;
  running: boolean;
}) {
  if (!item) {
    return (
      <aside className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        Select an operational entry to inspect scope, review state and recent event matches.
      </aside>
    );
  }

  const displayedMatches = preview?.matches || matches?.matches || [];
  const observedCount = preview?.preview.observed_count ?? matches?.observed_count;
  const countSource = preview?.preview.count_source ?? matches?.count_source;

  return (
    <aside className="min-w-0 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-slate-100">{item.name}</h3>
          <div className="mt-1 truncate text-xs text-slate-500">
            {item.type.replaceAll("_", " ")} / {item.source}
          </div>
        </div>
        <button
          type="button"
          onClick={() => onPreview(item)}
          disabled={running}
          className="flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-300 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <FileSearch className="h-3.5 w-3.5" />
          Preview
        </button>
      </div>

      <div className="grid gap-2 text-xs">
        <InfoRow label="State" value={item.state.replaceAll("_", " ")} />
        <InfoRow label="Scope" value={item.scope || "-"} />
        <InfoRow label="Scope risk" value={item.scope_classification.replaceAll("_", " ")} />
        <InfoRow label="Review" value={item.review_status.replaceAll("_", " ")} />
        <InfoRow label="Expires" value={formatDate(item.expires_at)} />
        <InfoRow label="Validation" value={item.validation_status || "-"} />
        <InfoRow label="Services" value={item.affected_services.join(", ") || "-"} />
      </div>

      {item.scope_reasons.length > 0 && (
        <div className="mt-3 rounded-md border border-slate-800 bg-slate-900 p-2 text-[11px] text-slate-500">
          {item.scope_reasons.join(" / ")}
        </div>
      )}

      <div className="mt-3 rounded-md border border-slate-800 bg-slate-900 p-2">
        <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
          Review Workflow
        </div>
        <div className="grid gap-2">
          <select
            value={reviewStatus}
            onChange={(event) => onReviewStatusChange(event.target.value)}
            disabled={!canReview || running}
            className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <option value="reviewed">reviewed</option>
            <option value="needs_follow_up">needs follow up</option>
            <option value="risk_accepted">risk accepted</option>
          </select>
          <input
            type="date"
            value={reviewDate}
            onChange={(event) => onReviewDateChange(event.target.value)}
            disabled={!canReview || running}
            className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
          />
          <textarea
            value={reviewNotes}
            onChange={(event) => onReviewNotesChange(event.target.value)}
            disabled={!canReview || running}
            rows={3}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-100 outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
            placeholder="Review notes"
          />
          <div className="flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={onMarkReviewed}
              disabled={!canReview || running}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-emerald-800 bg-emerald-950 px-3 text-xs text-emerald-100 hover:bg-emerald-900 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              Mark
            </button>
            <button
              type="button"
              onClick={onExtendReview}
              disabled={!canReview || running || !reviewDate}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-800 bg-cyan-950 px-3 text-xs text-cyan-100 hover:bg-cyan-900 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <CalendarClock className="h-3.5 w-3.5" />
              Extend
            </button>
          </div>
        </div>
      </div>

      <div className="mt-3 rounded-md border border-slate-800 bg-slate-900 p-2">
        <div className="mb-2 flex items-center justify-between gap-2">
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Match Evidence
          </div>
          <div className="text-[11px] text-slate-500">
            {observedCount ?? 0} observed / {countSource?.replaceAll("_", " ") || "not run"}
          </div>
        </div>

        {displayedMatches.length === 0 ? (
          <div className="text-xs text-slate-500">No recent matches in the current scan window.</div>
        ) : (
          <div className="max-h-72 overflow-auto rounded-md border border-slate-800 bg-slate-950">
            {displayedMatches.map((match) => (
              <div key={`${match.source_table}-${match.id}`} className="border-b border-slate-800 px-2 py-2 text-xs last:border-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-200">{match.source_table}</span>
                  <span className="text-slate-500">#{match.id}</span>
                  <span className="text-slate-600">{formatDate(match.timestamp)}</span>
                </div>
                <div className="mt-1 text-[11px] text-slate-500">
                  {match.agent || "-"} / {match.rule_id || "-"} / level {match.level ?? "-"}
                </div>
                {match.payload_preview && (
                  <div className="mt-1 line-clamp-2 text-[11px] leading-4 text-slate-600">
                    {match.payload_preview}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}

function InfoRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[96px_minmax(0,1fr)] gap-2">
      <span className="text-slate-500">{label}</span>
      <span className="min-w-0 truncate text-slate-200">{value}</span>
    </div>
  );
}
