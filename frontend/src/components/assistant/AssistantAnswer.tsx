"use client";

import { AlertTriangle } from "lucide-react";

import type { AssistantQueryResponse } from "@/lib/assistant";
import AssistantSources from "./AssistantSources";
import {
  formatAssistantLatency,
  humanizeAssistantLimitation,
  humanizeAssistantValue,
} from "./assistantPresentation";

type AssistantAnswerProps = {
  response: AssistantQueryResponse;
  anchorPrefix: string;
};

export default function AssistantAnswer({
  response,
  anchorPrefix,
}: AssistantAnswerProps) {
  const limitations = response.limitations
    .map(humanizeAssistantLimitation)
    .filter(Boolean);
  const italian = response.metadata.response_language === "it";

  return (
    <div className="space-y-3">
      <div className="max-w-4xl space-y-3 text-sm leading-6 text-slate-200">
        {response.blocks.map((block) => (
          <div
            key={`${block.kind}-${block.text}`}
          >
            <p className="whitespace-pre-wrap break-words">
              {block.text}
            </p>
          </div>
        ))}
      </div>

      {response.generation_kind === "deterministic_fallback" ? (
        <div
          role="status"
          className="flex items-start gap-2 text-[11px] leading-5 text-amber-200/80"
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
        <ul className="space-y-1 text-xs leading-5 text-slate-500">
          {limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      ) : null}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-slate-800 pt-3">
        {response.sources.length > 0 ? (
          <details className="min-w-0">
            <summary className="cursor-pointer text-xs font-semibold text-slate-300">
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
        {response.metadata.semantic_degraded ? (
          <span
            role="status"
            className="inline-flex items-center gap-1.5 text-[11px] text-amber-300/80"
            title={
              italian
                ? "La risposta resta fondata sui dati autorevoli disponibili."
                : "The answer remains grounded in available authoritative data."
            }
          >
            <AlertTriangle aria-hidden="true" className="h-3 w-3" />
            Semantic: {humanizeAssistantValue(response.metadata.semantic_status)}
          </span>
        ) : null}
      </div>

      <details>
        <summary className="cursor-pointer text-xs font-semibold text-slate-400">
          Technical details
        </summary>
        <dl className="mt-3 grid gap-x-5 gap-y-2 text-[11px] text-slate-500 sm:grid-cols-2">
          <TechnicalDetail
            label="Architecture"
            value={response.metadata.response_architecture}
          />
          <TechnicalDetail
            label="Effective intent"
            value={
              response.metadata.assistant_intent
                ? humanizeAssistantValue(response.metadata.assistant_intent)
                : null
            }
          />
          <TechnicalDetail
            label="Analysis scope"
            value={
              response.metadata.analysis_scope
                ? humanizeAssistantValue(response.metadata.analysis_scope)
                : null
            }
          />
          <TechnicalDetail
            label="Cross-incident context"
            value={
              response.metadata.cross_incident_candidates > 0
                ? "Used"
                : "Not used"
            }
          />
          <TechnicalDetail
            label="Generation kind"
            value={humanizeAssistantValue(response.generation_kind)}
          />
          <TechnicalDetail
            label="Provider generations"
            value={String(response.metadata.provider_generation_count)}
          />
          <TechnicalDetail
            label="Automatic retries"
            value={String(response.metadata.automatic_retries)}
          />
          <TechnicalDetail
            label="Model switches"
            value={String(response.metadata.model_switches)}
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
            label="Semantic index"
            value={humanizeAssistantValue(
              response.metadata.semantic_index_status,
            )}
          />
          <TechnicalDetail
            label="Plan validation"
            value={humanizeAssistantValue(
              response.metadata.plan_validation_status,
            )}
          />
          <TechnicalDetail
            label="Context build"
            value={formatAssistantLatency(response.metadata.context_build_ms)}
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
