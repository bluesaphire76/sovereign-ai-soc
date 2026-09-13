"use client";

import {
  AlertTriangle,
  CheckCircle2,
  FileWarning,
  ShieldCheck,
  ShieldX,
  Sparkles,
} from "lucide-react";

import { EnterpriseBadge } from "@/components/enterprise";
import type {
  AssistantMode,
  AssistantQueryResponse,
  AssistantResponseBlock,
} from "@/lib/assistant";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";
import AssistantSources from "./AssistantSources";
import AssistantTechnicalDetails from "./AssistantTechnicalDetails";
import {
  ASSISTANT_BLOCK_LABELS,
  ASSISTANT_PROVENANCE,
  humanizeAssistantLimitation,
  humanizeAssistantValue,
  sourceAnchorId,
} from "./assistantPresentation";

type AssistantAnswerProps = {
  response: AssistantQueryResponse;
  anchorPrefix: string;
  requestedMode: AssistantMode;
  semanticMemoryRequested: boolean;
};

function ValidationBadge({
  label,
  value,
}: {
  label: string;
  value: "passed" | "failed" | "not_run" | "unavailable";
}) {
  const tone =
    value === "passed"
      ? "success"
      : value === "failed"
        ? "danger"
        : value === "unavailable"
          ? "warning"
          : "neutral";
  const icon =
    value === "passed" ? (
      <CheckCircle2 aria-hidden="true" className="h-3 w-3" />
    ) : value === "failed" ? (
      <ShieldX aria-hidden="true" className="h-3 w-3" />
    ) : value === "unavailable" ? (
      <AlertTriangle aria-hidden="true" className="h-3 w-3" />
    ) : null;

  return (
    <EnterpriseBadge tone={tone} size="compact" icon={icon}>
      {label}: {humanizeAssistantValue(value)}
    </EnterpriseBadge>
  );
}

function AssistantBlock({
  block,
  anchorPrefix,
  sourceIndexes,
  showHeading = true,
}: {
  block: AssistantResponseBlock;
  anchorPrefix: string;
  sourceIndexes: Map<string, number>;
  showHeading?: boolean;
}) {
  return (
    <section className="min-w-0">
      {showHeading ? (
        <div className="mb-1.5 flex flex-wrap items-center gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
            {ASSISTANT_BLOCK_LABELS[block.kind]}
          </h4>
          {block.provenance_classes.map((provenanceClass) => (
            <EnterpriseBadge
              key={provenanceClass}
              tone={ASSISTANT_PROVENANCE[provenanceClass].tone}
              size="compact"
            >
              {ASSISTANT_PROVENANCE[provenanceClass].label}
            </EnterpriseBadge>
          ))}
        </div>
      ) : null}
      <p className="whitespace-pre-wrap break-words text-sm leading-6 text-slate-200">
        {block.text}
      </p>
      {block.source_ids.length > 0 ? (
        <div
          className="mt-1.5 flex flex-wrap items-center gap-1.5"
          aria-label={`Sources for ${ASSISTANT_BLOCK_LABELS[block.kind]}`}
        >
          <span className="text-[10px] uppercase tracking-wide text-slate-500">
            Cites
          </span>
          {block.source_ids.map((sourceId) => {
            const sourceIndex = sourceIndexes.get(sourceId);
            if (sourceIndex === undefined) {
              return (
                <span key={sourceId} className="text-[11px] text-slate-400">
                  [{sourceId}]
                </span>
              );
            }
            const sourceTargetId = sourceAnchorId(anchorPrefix, sourceIndex);
            return (
              <a
                key={sourceId}
                href={`#${sourceTargetId}`}
                onClick={() => document.getElementById(sourceTargetId)?.focus()}
                className={cx(
                  "rounded-sm text-[11px] font-semibold text-cyan-300 hover:text-cyan-200",
                  SOC_CONTROL_CLASSES.focus,
                )}
                aria-label={`Jump to source ${sourceId}`}
              >
                [{sourceId}]
              </a>
            );
          })}
        </div>
      ) : null}
      {block.kind === "recommended_checks" || block.kind === "next_check" ? (
        <p className="mt-1.5 text-[11px] leading-5 text-amber-200/80">
          Generated guidance for analyst review. No action has been executed or approved.
        </p>
      ) : null}
    </section>
  );
}

export default function AssistantAnswer({
  response,
  anchorPrefix,
  requestedMode,
  semanticMemoryRequested,
}: AssistantAnswerProps) {
  const limitations = response.limitations
    .map(humanizeAssistantLimitation)
    .filter(Boolean);
  const answerBlocks = response.blocks.filter(
    (block) => block.kind !== "limitations",
  );
  const limitationBlocks = response.blocks.filter(
    (block) => block.kind === "limitations",
  );
  const sourceIndexes = new Map(
    response.sources.map((source, index) => [source.source_id, index] as const),
  );
  const italian = response.metadata.response_language === "it";

  return (
    <article className="space-y-4" aria-label="SOC Assistant response">
      <section aria-labelledby={`${anchorPrefix}-answer-heading`}>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <h3
            id={`${anchorPrefix}-answer-heading`}
            className="text-sm font-semibold text-slate-100"
          >
            Generated analysis
          </h3>
          <EnterpriseBadge
            tone={
              response.generation_kind === "deterministic_fallback"
                ? "warning"
                : "primary"
            }
            size="compact"
            icon={
              response.generation_kind === "deterministic_fallback" ? (
                <FileWarning aria-hidden="true" className="h-3 w-3" />
              ) : (
                <Sparkles aria-hidden="true" className="h-3 w-3" />
              )
            }
          >
            {response.generation_kind === "deterministic_fallback"
              ? "Deterministic fallback"
              : "AI generated"}
          </EnterpriseBadge>
          <ValidationBadge
            label="Grounding"
            value={response.metadata.grounding_validation}
          />
          <ValidationBadge
            label="Semantic proof"
            value={response.metadata.semantic_proof_status}
          />
          {response.metadata.semantic_degraded ? (
            <EnterpriseBadge
              tone="warning"
              size="compact"
              icon={<AlertTriangle aria-hidden="true" className="h-3 w-3" />}
            >
              Semantic retrieval degraded
            </EnterpriseBadge>
          ) : null}
        </div>

        <div className="max-w-4xl space-y-4">
          {answerBlocks.map((block, index) => (
            <AssistantBlock
              key={`${block.kind}-${index}`}
              block={block}
              anchorPrefix={anchorPrefix}
              sourceIndexes={sourceIndexes}
            />
          ))}
        </div>

        {response.generation_kind === "deterministic_fallback" ? (
          <div
            role="status"
            className="mt-3 flex items-start gap-2 border-l-2 border-amber-700 pl-3 text-[11px] leading-5 text-amber-200/90"
          >
            <AlertTriangle
              aria-hidden="true"
              className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300"
            />
            {italian
              ? "La generazione del modello non è stata pubblicata. È mostrata una risposta deterministica fondata sui dati recuperati."
              : "Model generation was not published. A deterministic response grounded in retrieved data is shown."}
          </div>
        ) : null}
      </section>

      <section
        aria-labelledby={`${anchorPrefix}-sources-heading`}
        className="border-t border-slate-800 pt-3"
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <h3
            id={`${anchorPrefix}-sources-heading`}
            className="text-xs font-semibold uppercase tracking-wide text-slate-300"
          >
            Evidence and sources
          </h3>
          <EnterpriseBadge tone="neutral" size="compact">
            {response.sources.length}
          </EnterpriseBadge>
        </div>
        <AssistantSources sources={response.sources} anchorPrefix={anchorPrefix} />
      </section>

      <section
        aria-labelledby={`${anchorPrefix}-limitations-heading`}
        className="border-t border-slate-800 pt-3"
      >
        <div className="mb-2 flex items-center gap-2">
          <ShieldCheck aria-hidden="true" className="h-3.5 w-3.5 text-amber-300" />
          <h3
            id={`${anchorPrefix}-limitations-heading`}
            className="text-xs font-semibold uppercase tracking-wide text-slate-300"
          >
            Limitations
          </h3>
        </div>
        {limitationBlocks.length > 0 ? (
          <div className="space-y-3">
            {limitationBlocks.map((block, index) => (
              <AssistantBlock
                key={`limitation-${index}`}
                block={block}
                anchorPrefix={anchorPrefix}
                sourceIndexes={sourceIndexes}
                showHeading={false}
              />
            ))}
          </div>
        ) : null}
        {limitations.length > 0 ? (
          <ul className="mt-2 space-y-1 text-xs leading-5 text-slate-500">
            {limitations.map((limitation, index) => (
              <li key={`${limitation}-${index}`} className="flex items-start gap-2">
                <span aria-hidden="true" className="mt-2 h-1 w-1 shrink-0 bg-slate-600" />
                <span>{limitation}</span>
              </li>
            ))}
          </ul>
        ) : limitationBlocks.length === 0 ? (
          <p className="text-xs leading-5 text-slate-500">
            No explicit limitations were returned with this response.
          </p>
        ) : null}
      </section>

      <AssistantTechnicalDetails
        response={response}
        requestedMode={requestedMode}
        semanticMemoryRequested={semanticMemoryRequested}
      />
    </article>
  );
}
