"use client";

import { useMemo, useRef } from "react";
import { AlertTriangle, Database, Library } from "lucide-react";

import type {
  AssistantBlockKind,
  AssistantQueryResponse,
} from "@/lib/assistant";
import AssistantSources from "./AssistantSources";
import {
  formatAssistantLatency,
  humanizeAssistantLimitation,
  humanizeAssistantValue,
  sourceAnchorId,
} from "./assistantPresentation";

type AssistantAnswerProps = {
  response: AssistantQueryResponse;
  anchorPrefix: string;
};

const BLOCK_LABELS: Record<AssistantBlockKind, string> = {
  direct_answer: "Direct answer",
  analysis: "Analysis",
  next_check: "Next check",
  limitations: "Limitations",
};

export default function AssistantAnswer({
  response,
  anchorPrefix,
}: AssistantAnswerProps) {
  const sourcesDetailsRef = useRef<HTMLDetailsElement>(null);
  const sourceIndexes = useMemo(
    () =>
      new Map(
        response.sources.map((source, index) => [source.source_id, index]),
      ),
    [response.sources],
  );
  const sourcesById = useMemo(
    () =>
      new Map(response.sources.map((source) => [source.source_id, source])),
    [response.sources],
  );
  const limitations = response.limitations
    .map(humanizeAssistantLimitation)
    .filter(Boolean);
  const italian = response.metadata.response_language === "it";

  function revealSource(sourceId: string) {
    const sourceIndex = sourceIndexes.get(sourceId);
    if (sourceIndex === undefined) return;
    if (sourcesDetailsRef.current) {
      sourcesDetailsRef.current.open = true;
    }
    window.requestAnimationFrame(() => {
      document
        .getElementById(sourceAnchorId(anchorPrefix, sourceIndex))
        ?.focus();
    });
  }

  return (
    <div className="space-y-4">
      <div className="space-y-4">
        {response.blocks.map((block) => (
          <section
            key={`${block.kind}-${block.text}`}
            aria-labelledby={`${anchorPrefix}-${block.kind}`}
            className="border-l-2 border-slate-700 pl-3"
          >
            <h3
              id={`${anchorPrefix}-${block.kind}`}
              className="text-xs font-semibold text-slate-200"
            >
              {BLOCK_LABELS[block.kind]}
            </h3>
            <p className="mt-1 whitespace-pre-wrap break-words text-sm leading-6 text-slate-300">
              {block.text}
            </p>
            {block.source_ids.length > 0 ? (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {block.source_ids.map((sourceId) => {
                  const source = sourcesById.get(sourceId);
                  if (!source) return null;
                  const Icon =
                    source.authority === "authoritative" ? Database : Library;
                  return (
                    <button
                      key={sourceId}
                      type="button"
                      onClick={() => revealSource(sourceId)}
                      className="inline-flex min-h-7 items-center gap-1 border border-slate-700 bg-slate-950 px-2 text-[11px] text-cyan-300 hover:border-cyan-700 hover:text-cyan-200"
                      title={source.label}
                    >
                      <Icon aria-hidden="true" className="h-3 w-3" />
                      {source.label}
                    </button>
                  );
                })}
              </div>
            ) : null}
          </section>
        ))}
      </div>

      {response.metadata.semantic_degraded ? (
        <div
          role="status"
          className="flex items-start gap-2 border-l-2 border-amber-700 px-3 py-2 text-xs leading-5 text-amber-100/80"
        >
          <AlertTriangle
            aria-hidden="true"
            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300"
          />
          {italian
            ? "La memoria semantica non era disponibile entro il tempo previsto; la risposta utilizza i dati autorevoli della piattaforma."
            : "Semantic memory was unavailable within its time budget; the answer uses authoritative platform data."}
        </div>
      ) : null}

      {response.generation_kind === "deterministic_fallback" ? (
        <div
          role="status"
          className="flex items-start gap-2 border-l-2 border-amber-700 px-3 py-2 text-xs leading-5 text-amber-100/80"
        >
          <AlertTriangle
            aria-hidden="true"
            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300"
          />
          {italian
            ? "È mostrata una risposta deterministica fondata sui dati recuperati."
            : "A deterministic response grounded in retrieved data is shown."}
        </div>
      ) : null}

      {limitations.length > 0 ? (
        <ul className="space-y-1 border-t border-slate-800 pt-3 text-xs leading-5 text-slate-500">
          {limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      ) : null}

      {response.sources.length > 0 ? (
        <details
          ref={sourcesDetailsRef}
          className="border-t border-slate-800 pt-3"
        >
          <summary className="cursor-pointer text-xs font-semibold text-slate-200">
            Sources ({response.sources.length})
          </summary>
          <div className="mt-3">
            <AssistantSources
              sources={response.sources}
              anchorPrefix={anchorPrefix}
            />
          </div>
        </details>
      ) : null}

      <details className="border-t border-slate-800 pt-3">
        <summary className="cursor-pointer text-xs font-semibold text-slate-400">
          Technical details
        </summary>
        <dl className="mt-3 grid gap-x-5 gap-y-2 text-[11px] text-slate-500 sm:grid-cols-2">
          <TechnicalDetail
            label="Generation kind"
            value={humanizeAssistantValue(response.generation_kind)}
          />
          <TechnicalDetail
            label="Queue wait"
            value={formatAssistantLatency(response.metadata.queue_wait_ms)}
          />
          <TechnicalDetail
            label="Generation time"
            value={formatAssistantLatency(response.metadata.generation_ms)}
          />
          <TechnicalDetail
            label="Total latency"
            value={formatAssistantLatency(response.metadata.total_latency_ms)}
          />
          <TechnicalDetail
            label="Profile"
            value={response.metadata.effective_profile}
          />
          <TechnicalDetail
            label="Model"
            value={response.metadata.effective_model}
          />
          <TechnicalDetail
            label="Semantic status"
            value={humanizeAssistantValue(response.metadata.semantic_status)}
          />
          <TechnicalDetail
            label="Semantic elapsed"
            value={formatAssistantLatency(response.metadata.semantic_elapsed_ms)}
          />
          <TechnicalDetail
            label="Grounding validation"
            value={humanizeAssistantValue(
              response.metadata.grounding_validation,
            )}
          />
          <TechnicalDetail
            label="Focus validation"
            value={humanizeAssistantValue(response.metadata.focus_validation)}
          />
          <TechnicalDetail
            label="Fallback reason"
            value={
              response.metadata.fallback_reason
                ? humanizeAssistantValue(response.metadata.fallback_reason)
                : "none"
            }
          />
          <TechnicalDetail
            label="Source count"
            value={String(response.metadata.source_count)}
          />
          <TechnicalDetail
            label="Thinking disabled"
            value={response.metadata.thinking_disabled ? "Yes" : "No"}
          />
        </dl>
      </details>
    </div>
  );
}

function TechnicalDetail({
  label,
  value,
}: {
  label: string;
  value: string | null;
}) {
  if (!value) return null;
  return (
    <div>
      <dt>{label}</dt>
      <dd className="mt-0.5 break-words text-slate-300">{value}</dd>
    </div>
  );
}
