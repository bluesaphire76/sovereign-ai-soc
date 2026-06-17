"use client";

import { BookOpen, CheckCircle2, Loader2, MapPin, RefreshCw } from "lucide-react";

export type PlaybookRecommendationItem = {
  card_type?: string | null;
  title?: string | null;
  category?: string | null;
  relevance_score?: number | null;
  why_suggested?: string[];
  recommended_checks?: string[];
  gui_targets?: string[];
  operational_use?: string | null;
  source_type: string;
  source: string;
  score: number | null;
  excerpt: string;
  chunk_index?: number | null;
  content_hash?: string | null;
};

export type RecommendedPlaybooksResponse = {
  target_type: "incident" | "case" | string;
  target_id: number;
  enabled: boolean;
  status: string;
  source_type: string;
  recommendations: PlaybookRecommendationItem[];
  result_count: number;
  decision_boundary: string;
  message: string;
  error_type?: string | null;
};

function formatScore(value: number | null | undefined) {
  if (value === null || value === undefined) return "-";
  return Number(value).toFixed(3);
}

function sourceLabel(value: string | null | undefined) {
  if (!value) return "Knowledge base";
  const parts = value.split(/[\\/]/).filter(Boolean);
  return parts.slice(-2).join("/") || value;
}

function categoryLabel(value: string | null | undefined) {
  return (value || "general").replaceAll("_", " ");
}

function statusClass(status: string | null | undefined) {
  const value = (status || "").toUpperCase();
  if (value === "OK") return "border-emerald-800 bg-emerald-950 text-emerald-200";
  if (value === "DISABLED") return "border-slate-700 bg-slate-950 text-slate-300";
  return "border-amber-800 bg-amber-950 text-amber-200";
}

function compactList(items: string[] | undefined, fallback: string) {
  const values = (items || []).map((item) => item.trim()).filter(Boolean);
  return values.length > 0 ? values : [fallback];
}

export default function RecommendedPlaybooksPanel({
  response,
  loading,
  error,
  onRefresh,
}: {
  response: RecommendedPlaybooksResponse | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}) {
  const status = response?.status ?? (loading ? "LOADING" : "PENDING");
  const recommendations = response?.recommendations ?? [];

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-slate-800 bg-slate-950 p-3">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <BookOpen className="h-3.5 w-3.5 text-cyan-300" />
                Recommended Playbooks
              </div>
              <span className={`rounded-md border px-1.5 py-0.5 text-[10px] ${statusClass(status)}`}>
                {status}
              </span>
              <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                {recommendations.length} result{recommendations.length === 1 ? "" : "s"}
              </span>
            </div>
            <p className="mt-1 max-w-5xl text-xs leading-5 text-slate-500">
              {response?.message ??
                "Retrieves relevant SOC playbooks and procedures from Qdrant semantic memory."}
            </p>
          </div>

          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex h-8 w-fit items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 text-xs text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            Refresh
          </button>
        </div>

        {error && (
          <div className="mt-3 rounded-md border border-amber-800 bg-amber-950/50 p-2.5 text-xs text-amber-100">
            {error}
          </div>
        )}
      </div>

      {loading && !response ? (
        <div className="inline-flex items-center gap-2 rounded-md border border-cyan-900/60 bg-cyan-950/30 px-3 py-2 text-xs text-cyan-100">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Loading playbook recommendations.
        </div>
      ) : null}

      {!loading && response && recommendations.length === 0 ? (
        <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-500">
          No matching knowledge-base playbook was found for this context.
        </div>
      ) : null}

      {recommendations.length > 0 ? (
        <div className="grid gap-2 xl:grid-cols-2">
          {recommendations.slice(0, 4).map((item, index) => (
            <article
              key={`${item.source}-${item.chunk_index ?? index}-${index}`}
              className="rounded-md border border-slate-800 bg-slate-900/70 p-3"
            >
              <div className="flex min-w-0 items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm font-semibold leading-5 text-slate-100">
                    {item.title || sourceLabel(item.source)}
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                      {categoryLabel(item.category)}
                    </span>
                    <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                      Score {formatScore(item.score)}
                    </span>
                    {item.relevance_score !== undefined && item.relevance_score !== null ? (
                      <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                        Relevance {item.relevance_score}
                      </span>
                    ) : null}
                    {item.chunk_index !== undefined && item.chunk_index !== null ? (
                      <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                        Chunk {item.chunk_index}
                      </span>
                    ) : null}
                    <span className="rounded-md border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                      {sourceLabel(item.source)}
                    </span>
                  </div>
                </div>
              </div>

              {item.operational_use ? (
                <p className="mt-2 text-xs leading-5 text-cyan-100">
                  {item.operational_use}
                </p>
              ) : null}

              <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.25fr)_minmax(0,0.8fr)]">
                <div>
                  <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    <BookOpen className="h-3 w-3 text-cyan-300" />
                    Why suggested
                  </div>
                  <ul className="space-y-1 text-xs leading-5 text-slate-400">
                    {compactList(
                      item.why_suggested,
                      "Matched against the current investigation context.",
                    ).slice(0, 2).map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    <CheckCircle2 className="h-3 w-3 text-emerald-300" />
                    Recommended checks
                  </div>
                  <ol className="space-y-1 text-xs leading-5 text-slate-300">
                    {compactList(
                      item.recommended_checks,
                      "Review this playbook against deterministic evidence.",
                    ).slice(0, 4).map((check, checkIndex) => (
                      <li key={check} className="flex gap-2">
                        <span className="mt-0.5 text-[10px] text-slate-500">
                          {checkIndex + 1}.
                        </span>
                        <span>{check}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    <MapPin className="h-3 w-3 text-cyan-300" />
                    Where to verify
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {compactList(item.gui_targets, "Current detail page").slice(0, 5).map((target) => (
                      <span
                        key={target}
                        className="rounded-md border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[10px] text-slate-300"
                      >
                        {target}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-3 border-t border-slate-800 pt-2">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                  Supporting excerpt
                </div>
                <p className="mt-1 line-clamp-3 text-xs leading-5 text-slate-500">
                  {item.excerpt || "No excerpt available."}
                </p>
              </div>
            </article>
          ))}
        </div>
      ) : null}

      {response?.decision_boundary ? (
        <div className="rounded-md border border-cyan-900/70 bg-cyan-950/20 p-2.5 text-xs leading-5 text-cyan-100">
          {response.decision_boundary}
        </div>
      ) : null}
    </div>
  );
}
