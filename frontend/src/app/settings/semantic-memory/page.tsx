"use client";

import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  Database,
  FileText,
  History,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  Terminal,
  Trash2,
} from "lucide-react";
import AppNavigation from "../../../components/AppNavigation";

type SourceTypeCounts = Record<string, number>;

type IndexDocument = {
  source: string;
  source_type?: string;
  chunks: number;
  first_chunk_index: number | null;
  last_chunk_index: number | null;
  content_hashes_count: number;
};

type IndexStatusResponse = {
  enabled: boolean;
  status: string;
  provider: string;
  collection: string;
  points_count?: number | null;
  documents_count: number;
  points_scanned: number;
  max_points?: number;
  documents: IndexDocument[];
  source_type_counts?: SourceTypeCounts;
  indexing_mode: string;
  indexing_command: string;
  message: string;
  decision_boundary: string;
};

type CapabilitiesResponse = {
  enabled: boolean;
  mode: string;
  provider: string;
  collection: string;
  embedding_model: string;
  default_limit: number;
  allowed_uses: string[];
  forbidden_uses: string[];
  decision_boundary: string;
};

type SearchResult = {
  id: string;
  source_type?: string;
  source: string;
  text: string;
  chunk_index?: number | null;
  score?: number | null;
  collection: string;
};

type SearchResponse = {
  enabled: boolean;
  query: string;
  collection: string;
  source_type?: string | null;
  limit: number;
  result_count: number;
  results: SearchResult[];
  decision_boundary: string;
};

type SemanticOperationResult = {
  operation: string;
  mode: string;
  applied?: boolean;
  records_prepared?: number;
  indexed_points?: number;
  detection_control_records?: number;
  case_closure_records?: number;
  case_closure_skipped_non_final?: number;
  pruned_points?: number;
  redaction_applied_count?: number;
  scanned_points?: number;
  candidates?: number;
  deleted?: number;
  retention_days?: number;
  max_records?: number;
  skipped?: Record<string, number>;
  candidate_reasons?: Record<string, number>;
  collection?: string | null;
  decision_boundary?: string;
  requested_by?: string | null;
};

function formatNumber(value: number | null | undefined) {
  if (value === null || value === undefined) return "-";
  return new Intl.NumberFormat("en-US").format(value);
}

function formatScore(value: number | null | undefined) {
  if (value === null || value === undefined) return "-";
  return Number(value).toFixed(3);
}

function titleCase(value: string) {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function previewLines(value: string, maxLines = 4, lineLength = 170) {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (!normalized) return ["No preview text available."];

  const lines: string[] = [];
  let cursor = 0;

  while (cursor < normalized.length && lines.length < maxLines) {
    const next = normalized.slice(cursor, cursor + lineLength);
    const boundary = next.lastIndexOf(" ");
    const chunkLength = boundary > 80 ? boundary : next.length;
    const chunk = normalized.slice(cursor, cursor + chunkLength).trim();

    if (chunk) lines.push(chunk);
    cursor += chunkLength;
  }

  if (cursor < normalized.length && lines.length > 0) {
    lines[lines.length - 1] = `${lines[lines.length - 1].replace(/[. ]+$/, "")}...`;
  }

  return lines;
}

function statusTone(status: string | undefined) {
  const normalized = (status || "").toUpperCase();
  if (normalized === "OK") return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  if (normalized === "WARN" || normalized === "DISABLED") return "border-amber-800 bg-amber-950/60 text-amber-200";
  if (normalized === "ERROR") return "border-red-800 bg-red-950/60 text-red-200";
  return "border-slate-700 bg-slate-900 text-slate-200";
}

function MetricCard({
  title,
  value,
  subtitle,
  icon,
}: {
  title: string;
  value: ReactNode;
  subtitle: string;
  icon: ReactNode;
}) {
  return (
    <article className="flex min-h-[46px] items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-900 px-2 py-1.5 shadow-sm">
      <div className="min-w-0">
        <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-1.5">
          <span className="truncate text-base font-semibold leading-5 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[10px] leading-3 text-slate-500">
            {subtitle}
          </span>
        </div>
      </div>
      <div className="shrink-0 rounded-sm bg-slate-950 p-1 text-slate-400">
        {icon}
      </div>
    </article>
  );
}

function MiniStat({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="min-w-0 rounded-sm bg-slate-900 px-2 py-1.5">
      <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-0.5 truncate text-xs font-semibold leading-5 text-slate-200">{value}</div>
    </div>
  );
}

function KnowledgeDocumentCard({ document }: { document: IndexDocument }) {
  return (
    <article className="rounded-md border border-slate-800 bg-slate-950 p-2.5 text-xs">
      <div className="flex min-w-0 items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-slate-100">{document.source}</div>
          <div className="mt-1 inline-flex rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
            {titleCase(document.source_type ?? "unknown")}
          </div>
        </div>
        <FileText className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
      </div>
      <div className="mt-2 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 sm:grid-cols-4">
        <MiniStat label="Chunks" value={document.chunks} />
        <MiniStat label="First" value={document.first_chunk_index ?? "-"} />
        <MiniStat label="Last" value={document.last_chunk_index ?? "-"} />
        <MiniStat label="Hashes" value={document.content_hashes_count} />
      </div>
    </article>
  );
}

function SearchResultCard({ result }: { result: SearchResult }) {
  const lines = previewLines(result.text);

  return (
    <article className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs">
      <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_minmax(220px,0.35fr)]">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-slate-100">{result.source}</div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              {titleCase(result.source_type ?? "unknown")}
            </span>
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              Chunk {result.chunk_index ?? "-"}
            </span>
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              Score {formatScore(result.score)}
            </span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800">
          <MiniStat label="Collection" value={result.collection} />
          <MiniStat label="Score" value={formatScore(result.score)} />
        </div>
      </div>

      <div className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-2.5">
        <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">
          Preview
        </div>
        <ul className="space-y-1.5 text-slate-400">
          {lines.map((line, index) => (
            <li key={`${result.id}-${index}`} className="flex gap-2 leading-5">
              <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-slate-600" />
              <span className="min-w-0 break-words">{line}</span>
            </li>
          ))}
        </ul>
      </div>
    </article>
  );
}

function Section({
  title,
  icon,
  description,
  collapsible = false,
  defaultOpen = false,
  children,
}: {
  title: string;
  icon: ReactNode;
  description?: string;
  collapsible?: boolean;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  if (collapsible) {
    return (
      <details
        open={isOpen}
        onToggle={(event) => setIsOpen(event.currentTarget.open)}
        className="rounded-md border border-slate-800 bg-slate-950"
      >
        <summary className="cursor-pointer list-none px-3 py-2 hover:bg-slate-900/60">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-100">
                <span className="text-cyan-300">{icon}</span>
                <span className="truncate">{title}</span>
              </div>
              {description && (
                <p className="mt-0.5 max-w-5xl text-[11px] leading-4 text-slate-500">
                  {description}
                </p>
              )}
            </div>
            <span className="shrink-0 text-[10px] uppercase tracking-wide text-cyan-300">
              {isOpen ? "Close" : "Open"}
            </span>
          </div>
        </summary>
        <div className="border-t border-slate-800 p-3">{children}</div>
      </details>
    );
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex min-w-0 items-start gap-2">
        <div className="rounded-md border border-slate-800 bg-slate-950 p-1.5 text-cyan-300">
          {icon}
        </div>
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold text-slate-100">{title}</h2>
          {description && (
            <p className="mt-1 max-w-5xl text-xs leading-5 text-slate-500">
              {description}
            </p>
          )}
        </div>
      </div>
      {children}
    </section>
  );
}

function OperationControlCard({
  title,
  description,
  icon,
  stats,
  applyTone = "emerald",
  applyIcon = "play",
  applyRunning,
  onDryRun,
  onApply,
  disabled,
  result,
}: {
  title: string;
  description: string;
  icon: ReactNode;
  stats: Array<[string, ReactNode]>;
  applyTone?: "emerald" | "amber";
  applyIcon?: "play" | "trash";
  applyRunning: boolean;
  onDryRun: () => void;
  onApply: () => void;
  disabled: boolean;
  result: SemanticOperationResult | null;
}) {
  const applyClassName =
    applyTone === "amber"
      ? "border-amber-800 bg-amber-950 text-amber-100 hover:bg-amber-900"
      : "border-emerald-800 bg-emerald-950 text-emerald-100 hover:bg-emerald-900";

  return (
    <article className="flex h-full min-h-[188px] flex-col rounded-md border border-slate-800 bg-slate-950 p-2.5">
      <div className="mb-2 flex min-h-[62px] items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-semibold leading-5 text-slate-100">{title}</div>
          <p className="mt-1 text-xs leading-5 text-slate-500">{description}</p>
        </div>
        <div className="mt-0.5 shrink-0 text-slate-500">{icon}</div>
      </div>

      <div className="mb-2 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800">
        {stats.map(([label, value]) => (
          <MiniStat key={label} label={label} value={value} />
        ))}
      </div>

      <div className="mt-auto flex flex-wrap gap-2">
        <button
          type="button"
          disabled={disabled}
          onClick={onDryRun}
          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 text-xs text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Search className="h-3.5 w-3.5" />
          Dry-run
        </button>
        <button
          type="button"
          disabled={disabled}
          onClick={onApply}
          className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-50 ${applyClassName}`}
        >
          {applyIcon === "trash" ? (
            <Trash2 className={`h-3.5 w-3.5 ${applyRunning ? "animate-pulse" : ""}`} />
          ) : (
            <Play className={`h-3.5 w-3.5 ${applyRunning ? "animate-pulse" : ""}`} />
          )}
          Apply
        </button>
      </div>

      {result && (
        <div className="mt-2">
          <OperationResultCard result={result} />
        </div>
      )}
    </article>
  );
}

function Boundary({ text }: { text?: string }) {
  if (!text) return null;

  return (
    <div className="rounded-lg border border-cyan-900/70 bg-cyan-950/30 p-3 text-xs leading-5 text-cyan-100">
      {text}
    </div>
  );
}

function RunbookCommand({ command }: { command: string }) {
  return (
    <div className="overflow-x-auto rounded-md border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-[11px] text-slate-300">
      {command}
    </div>
  );
}

function OperationResultCard({ result }: { result: SemanticOperationResult }) {
  const isApply = result.applied || result.mode?.toUpperCase() === "APPLY" || result.mode === "apply";
  const title = titleCase(result.operation || "semantic_operation");
  const primaryMetrics =
    result.operation === "retention_cleanup"
      ? [
          ["Scanned", result.scanned_points],
          ["Candidates", result.candidates],
          ["Deleted", result.deleted],
        ]
      : [
          ["Prepared", result.records_prepared],
          ["Indexed", result.indexed_points],
          ["Redacted", result.redaction_applied_count],
        ];

  return (
    <div className={`rounded-md border p-2.5 text-xs ${
      isApply
        ? "border-emerald-900 bg-emerald-950/20"
        : "border-cyan-900/70 bg-cyan-950/20"
    }`}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <CheckCircle2 className={`h-3.5 w-3.5 ${isApply ? "text-emerald-300" : "text-cyan-300"}`} />
          <span className="truncate font-semibold text-slate-100">{title}</span>
        </div>
        <span className={`rounded-md border px-1.5 py-0.5 text-[10px] ${
          isApply
            ? "border-emerald-800 text-emerald-200"
            : "border-cyan-800 text-cyan-200"
        }`}>
          {result.mode}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800">
        {primaryMetrics.map(([label, value]) => (
          <MiniStat key={label} label={String(label)} value={formatNumber(value as number | undefined)} />
        ))}
      </div>

      {result.candidate_reasons && Object.keys(result.candidate_reasons).length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {Object.entries(result.candidate_reasons).map(([key, value]) => (
            <span key={key} className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              {titleCase(key)}: {formatNumber(value)}
            </span>
          ))}
        </div>
      )}
      {(result.detection_control_records !== undefined || result.case_closure_records !== undefined) && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {result.detection_control_records !== undefined && (
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              Detection Control: {formatNumber(result.detection_control_records)}
            </span>
          )}
          {result.case_closure_records !== undefined && (
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              Case Closure: {formatNumber(result.case_closure_records)}
            </span>
          )}
          {result.case_closure_skipped_non_final !== undefined && (
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              Non-final Skipped: {formatNumber(result.case_closure_skipped_non_final)}
            </span>
          )}
          {result.pruned_points !== undefined && (
            <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              Pruned: {formatNumber(result.pruned_points)}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export default function SemanticMemoryPage() {
  const [user, setUser] = useState<AuthUser | null>(() => getStoredUser());
  const [indexStatus, setIndexStatus] = useState<IndexStatusResponse | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [search, setSearch] = useState("");
  const [searchSourceType, setSearchSourceType] = useState("");
  const [searchResult, setSearchResult] = useState<SearchResponse | null>(null);
  const [backfillResult, setBackfillResult] = useState<SemanticOperationResult | null>(null);
  const [detectionCaseResult, setDetectionCaseResult] = useState<SemanticOperationResult | null>(null);
  const [retentionResult, setRetentionResult] = useState<SemanticOperationResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searching, setSearching] = useState(false);
  const [operationRunning, setOperationRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);

  const canView = user?.role === "ADMIN" || user?.role === "ANALYST";
  const canOperate = user?.role === "ADMIN";

  const load = useCallback(async () => {
    setRefreshing(true);
    setError(null);

    try {
      const current = await fetchCurrentUser();
      setUser(current);

      if (current.role !== "ADMIN" && current.role !== "ANALYST") {
        setIndexStatus(null);
        setCapabilities(null);
        setError("Forbidden: Semantic Memory is available only to ADMIN and ANALYST users.");
        return;
      }

      const [indexResponse, capabilitiesResponse] = await Promise.all([
        authFetch("/semantic-memory/index-status"),
        authFetch("/semantic-memory/capabilities"),
      ]);

      if (!indexResponse.ok) {
        throw new Error(`Index status API error ${indexResponse.status}`);
      }

      if (!capabilitiesResponse.ok) {
        throw new Error(`Capabilities API error ${capabilitiesResponse.status}`);
      }

      setIndexStatus(await indexResponse.json());
      setCapabilities(await capabilitiesResponse.json());
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to load semantic memory.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function runSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = search.trim();
    if (!query) return;

    setSearching(true);
    setSearchError(null);

    try {
      const response = await authFetch(
        `/semantic-memory/search?query=${encodeURIComponent(query)}&limit=5${
          searchSourceType ? `&source_type=${encodeURIComponent(searchSourceType)}` : ""
        }`
      );

      if (!response.ok) {
        throw new Error(`Search API error ${response.status}`);
      }

      setSearchResult(await response.json());
    } catch (exc) {
      setSearchError(exc instanceof Error ? exc.message : "Semantic search failed.");
    } finally {
      setSearching(false);
    }
  }

  async function runSemanticOperation(
    operation: "historical-backfill" | "detection-case-backfill" | "retention-cleanup",
    apply: boolean,
  ) {
    if (!canOperate) return;

    if (apply) {
      const accepted = window.confirm(
        operation === "historical-backfill"
          ? "Apply historical incident memory backfill now?"
          : operation === "detection-case-backfill"
            ? "Apply Detection Control and Case Closure semantic memory backfill now?"
          : "Apply historical incident memory retention cleanup now?"
      );
      if (!accepted) return;
    }

    const operationKey = `${operation}:${apply ? "apply" : "dry-run"}`;
    setOperationRunning(operationKey);
    setOperationError(null);

    const body =
      operation === "historical-backfill"
        ? {
            apply,
            confirm: apply,
            limit: 10000,
            since_days: null,
            include_open: false,
          }
        : operation === "detection-case-backfill"
          ? {
              apply,
              confirm: apply,
              limit: 1000,
              include_detection_control: true,
              include_case_closure: true,
            }
        : {
            apply,
            confirm: apply,
            retention_days: 180,
            max_records: 5000,
            include_open: false,
          };

    try {
      const response = await authFetch(`/semantic-memory/${operation}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });

      const payload = await response.json().catch(() => ({}));

      if (!response.ok) {
        const detail = payload?.detail;
        throw new Error(typeof detail === "string" ? detail : detail?.message || `Operation API error ${response.status}`);
      }

      if (operation === "historical-backfill") {
        setBackfillResult(payload);
      } else if (operation === "detection-case-backfill") {
        setDetectionCaseResult(payload);
      } else {
        setRetentionResult(payload);
      }

      if (apply) {
        await load();
      }
    } catch (exc) {
      setOperationError(exc instanceof Error ? exc.message : "Semantic memory operation failed.");
    } finally {
      setOperationRunning(null);
    }
  }

  const sourceTypeCounts = indexStatus?.source_type_counts ?? {};
  const historicalCount = sourceTypeCounts.historical_incident ?? 0;
  const knowledgeCount = sourceTypeCounts.knowledge_base ?? 0;
  const detectionControlCount = sourceTypeCounts.detection_control ?? 0;
  const caseClosureCount = sourceTypeCounts.case_closure ?? 0;

  const documentsByType = useMemo(() => {
    const grouped = new Map<string, IndexDocument[]>();
    for (const document of indexStatus?.documents ?? []) {
      const key = document.source_type || "unknown";
      grouped.set(key, [...(grouped.get(key) ?? []), document]);
    }
    return grouped;
  }, [indexStatus?.documents]);
  const knowledgeDocuments = documentsByType.get("knowledge_base") ?? [];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex w-full max-w-[1800px] flex-col gap-4 px-3 py-3 xl:flex-row xl:py-4">
        <aside className="xl:w-72 xl:shrink-0">
          <AppNavigation />
        </aside>

        <main className="min-w-0 flex-1 xl:ml-0">
          <header className="mb-4 flex flex-col gap-3 border-b border-slate-800 pb-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="min-w-0">
              <Link
                href="/"
                className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
              >
                Back to Dashboard
              </Link>

              <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
                <Database className="h-3.5 w-3.5" />
                Settings
              </div>

              <h1 className="text-xl font-semibold tracking-tight">Semantic Memory</h1>

              <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
                Qdrant governance, index visibility, semantic search and admin-controlled memory operations.
              </p>
            </div>

            <button
              type="button"
              onClick={() => void load()}
              disabled={refreshing}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </header>

          {error && (
            <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
              API error: {error}
            </div>
          )}

          {loading ? (
            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
              Loading semantic memory...
            </section>
          ) : canView && indexStatus && capabilities ? (
            <div className="space-y-3">
              <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-6">
                <MetricCard
                  title="Status"
                  value={<span className={`rounded-md border px-1.5 py-0.5 text-[10px] leading-none ${statusTone(indexStatus.status)}`}>{indexStatus.status}</span>}
                  subtitle={capabilities.provider}
                  icon={<ShieldCheck className="h-3.5 w-3.5" />}
                />
                <MetricCard
                  title="Collection"
                  value={indexStatus.collection}
                  subtitle={indexStatus.indexing_mode}
                  icon={<Database className="h-3.5 w-3.5" />}
                />
                <MetricCard
                  title="Points"
                  value={formatNumber(indexStatus.points_count)}
                  subtitle={`${formatNumber(indexStatus.points_scanned)} scanned`}
                  icon={<ActivityDot />}
                />
                <MetricCard
                  title="Documents"
                  value={formatNumber(indexStatus.documents_count)}
                  subtitle={`${formatNumber(indexStatus.documents.length)} sources`}
                  icon={<FileText className="h-3.5 w-3.5" />}
                />
                <MetricCard
                  title="Knowledge Base"
                  value={formatNumber(knowledgeCount)}
                  subtitle="Indexed chunks"
                  icon={<BookOpen className="h-3.5 w-3.5" />}
                />
                <MetricCard
                  title="Historical Memory"
                  value={formatNumber(historicalCount)}
                  subtitle="Incident memory"
                  icon={<History className="h-3.5 w-3.5" />}
                />
              </section>

              <Boundary text={indexStatus.decision_boundary || capabilities.decision_boundary} />

              <Section
                title="Knowledge Base Documents"
                icon={<FileText className="h-3.5 w-3.5" />}
                collapsible
              >
                {knowledgeDocuments.length > 0 ? (
                  <div className="grid gap-2 lg:grid-cols-2 2xl:grid-cols-3">
                    {knowledgeDocuments.map((document) => (
                      <KnowledgeDocumentCard key={document.source} document={document} />
                    ))}
                  </div>
                ) : (
                  <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                    No knowledge base documents indexed.
                  </div>
                )}
              </Section>

              <Section
                title="Capabilities / Guardrails"
                icon={<ShieldCheck className="h-3.5 w-3.5" />}
                description={capabilities.decision_boundary}
                collapsible
              >
                <div className="grid gap-2 text-xs lg:grid-cols-2">
                  <div className="rounded-md border border-slate-800 bg-slate-950 p-2.5">
                    <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">Allowed</div>
                    <div className="flex flex-wrap gap-1.5">
                      {capabilities.allowed_uses.map((item) => (
                        <span key={item} className="rounded-md border border-emerald-900 bg-emerald-950/40 px-2 py-1 text-[11px] text-emerald-200">
                          {titleCase(item)}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-md border border-slate-800 bg-slate-950 p-2.5">
                    <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">Forbidden</div>
                    <div className="flex flex-wrap gap-1.5">
                      {capabilities.forbidden_uses.map((item) => (
                        <span key={item} className="rounded-md border border-red-900 bg-red-950/40 px-2 py-1 text-[11px] text-red-200">
                          {titleCase(item)}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </Section>

              <Section
                title="Historical Incident Memory"
                icon={<History className="h-3.5 w-3.5" />}
                collapsible
              >
                <div className="grid gap-1.5 text-xs sm:grid-cols-2 xl:grid-cols-4">
                  <MetricCard
                    title="Indexed Points"
                    value={formatNumber(historicalCount)}
                    subtitle="Historical chunks"
                    icon={<History className="h-3.5 w-3.5" />}
                  />
                  <MetricCard
                    title="Source Type"
                    value="Historical Incident"
                    subtitle="Qdrant memory"
                    icon={<Database className="h-3.5 w-3.5" />}
                  />
                  <MetricCard
                    title="Mode"
                    value="Manual CLI"
                    subtitle="Indexing mode"
                    icon={<Terminal className="h-3.5 w-3.5" />}
                  />
                  <MetricCard
                    title="Governed Memory"
                    value={formatNumber(detectionControlCount + caseClosureCount)}
                    subtitle={`${formatNumber(detectionControlCount)} controls / ${formatNumber(caseClosureCount)} closures`}
                    icon={<ShieldCheck className="h-3.5 w-3.5" />}
                  />
                </div>
              </Section>

              <Section
                title="Operational Controls"
                icon={<Play className="h-3.5 w-3.5" />}
                description="Admin-only dry-run and apply actions for historical memory backfill and retention cleanup. Knowledge base points are never deleted by retention."
                collapsible
              >
                {operationError && (
                  <div className="mb-3 rounded-md border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
                    {operationError}
                  </div>
                )}

                <div className="grid items-stretch gap-2 xl:grid-cols-3">
                  <OperationControlCard
                    title="Historical backfill"
                    description="Index closed, resolved and false-positive incidents as advisory historical memory."
                    icon={<History className="h-3.5 w-3.5" />}
                    stats={[
                      ["Limit", "10,000"],
                      ["Open Incidents", "Excluded"],
                    ]}
                    applyRunning={operationRunning === "historical-backfill:apply"}
                    onDryRun={() => void runSemanticOperation("historical-backfill", false)}
                    onApply={() => void runSemanticOperation("historical-backfill", true)}
                    disabled={!canOperate || Boolean(operationRunning)}
                    result={backfillResult}
                  />

                  <OperationControlCard
                    title="Detection / Case memory"
                    description="Index governed detection controls and final case closure outcomes as advisory memory."
                    icon={<ShieldCheck className="h-3.5 w-3.5" />}
                    stats={[
                      ["Controls", formatNumber(detectionControlCount)],
                      ["Closures", formatNumber(caseClosureCount)],
                    ]}
                    applyRunning={operationRunning === "detection-case-backfill:apply"}
                    onDryRun={() => void runSemanticOperation("detection-case-backfill", false)}
                    onApply={() => void runSemanticOperation("detection-case-backfill", true)}
                    disabled={!canOperate || Boolean(operationRunning)}
                    result={detectionCaseResult}
                  />

                  <OperationControlCard
                    title="Retention cleanup"
                    description="Review stale, missing or duplicate historical memory points before deletion."
                    icon={<Trash2 className="h-3.5 w-3.5" />}
                    stats={[
                      ["Retention", "180 days"],
                      ["Scope", "Historical only"],
                    ]}
                    applyTone="amber"
                    applyIcon="trash"
                    applyRunning={operationRunning === "retention-cleanup:apply"}
                    onDryRun={() => void runSemanticOperation("retention-cleanup", false)}
                    onApply={() => void runSemanticOperation("retention-cleanup", true)}
                    disabled={!canOperate || Boolean(operationRunning)}
                    result={retentionResult}
                  />
                </div>

                {!canOperate && (
                  <div className="mt-2 rounded-md border border-amber-800 bg-amber-950/40 p-2.5 text-xs text-amber-100">
                    ADMIN role is required to run semantic memory backfill or retention cleanup.
                  </div>
                )}
              </Section>

              <Section title="Semantic Search Test" icon={<Search className="h-3.5 w-3.5" />}>
                <form onSubmit={runSearch} className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_220px_auto]">
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    maxLength={500}
                    placeholder="ssh brute force"
                    className="h-9 min-w-0 flex-1 rounded-md border border-slate-800 bg-slate-950 px-3 text-xs text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-700"
                  />
                  <select
                    value={searchSourceType}
                    onChange={(event) => setSearchSourceType(event.target.value)}
                    className="h-9 rounded-md border border-slate-800 bg-slate-950 px-3 text-xs text-slate-100 outline-none focus:border-cyan-700"
                    title="Semantic memory source type"
                  >
                    <option value="">All source types</option>
                    <option value="knowledge_base">Knowledge Base</option>
                    <option value="historical_incident">Historical Incidents</option>
                    <option value="detection_control">Detection Control</option>
                    <option value="case_closure">Case Closure</option>
                  </select>
                  <button
                    type="submit"
                    disabled={searching || !search.trim()}
                    className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-cyan-800 bg-cyan-950 px-3 text-xs font-medium text-cyan-100 hover:bg-cyan-900 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <Search className="h-3.5 w-3.5" />
                    Search
                  </button>
                </form>

                {searchError && (
                  <div className="mt-3 rounded-md border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
                    {searchError}
                  </div>
                )}

                {searchResult && (
                  <div className="mt-3 space-y-2">
                    <Boundary text={searchResult.decision_boundary} />
                    <div className="grid gap-2">
                      {searchResult.results.map((result) => (
                        <SearchResultCard key={result.id} result={result} />
                      ))}
                    </div>
                  </div>
                )}
              </Section>

              <Section
                title="Manual Runbook"
                icon={<Terminal className="h-3.5 w-3.5" />}
                collapsible
              >
                <div className="space-y-2">
                  <RunbookCommand command="PYTHONPATH=. .venv/bin/python rag_index.py" />
                  <RunbookCommand command="PYTHONPATH=. .venv/bin/python scripts/index_historical_incidents_to_qdrant.py --dry-run" />
                  <RunbookCommand command="PYTHONPATH=. .venv/bin/python scripts/index_historical_incidents_to_qdrant.py --apply" />
                  <RunbookCommand command="PYTHONPATH=. .venv/bin/python scripts/index_detection_case_memory_to_qdrant.py --dry-run" />
                  <RunbookCommand command="PYTHONPATH=. .venv/bin/python scripts/index_detection_case_memory_to_qdrant.py --apply" />
                  <RunbookCommand command="PYTHONPATH=. .venv/bin/python scripts/qdrant_memory_retention.py --dry-run" />
                </div>
              </Section>
            </div>
          ) : (
            <section className="rounded-lg border border-amber-800 bg-amber-950/50 p-3 text-xs text-amber-100">
              <div className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>Semantic Memory is available only to ADMIN and ANALYST users.</span>
              </div>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}

function ActivityDot() {
  return (
    <span className="relative flex h-3.5 w-3.5">
      <span className="absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-20" />
      <span className="relative inline-flex h-3.5 w-3.5 rounded-full border border-cyan-300 bg-cyan-500/40" />
    </span>
  );
}
