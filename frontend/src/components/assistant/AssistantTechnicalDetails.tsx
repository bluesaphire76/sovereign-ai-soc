"use client";

import type {
  AssistantMode,
  AssistantQueryResponse,
} from "@/lib/assistant";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";
import {
  formatAssistantLatency,
  humanizeAssistantValue,
} from "./assistantPresentation";

type AssistantTechnicalDetailsProps = {
  response: AssistantQueryResponse;
  requestedMode: AssistantMode;
  semanticMemoryRequested: boolean;
};

type Detail = {
  label: string;
  value: string | number | null | undefined;
};

function shown(value: Detail["value"]) {
  if (value === null || value === undefined || value === "") return "N/A";
  return String(value);
}

function booleanLabel(value: boolean) {
  return value ? "Yes" : "No";
}

function latency(value: number) {
  return formatAssistantLatency(value) ?? "N/A";
}

function TechnicalGroup({ title, items }: { title: string; items: Detail[] }) {
  return (
    <section aria-label={title}>
      <h4 className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
        {title}
      </h4>
      <dl className="grid gap-x-5 gap-y-2 text-[11px] text-slate-500 sm:grid-cols-2 xl:grid-cols-3">
        {items.map((item) => (
          <div key={item.label} className="min-w-0">
            <dt>{item.label}</dt>
            <dd className="mt-0.5 break-words text-slate-300">
              {shown(item.value)}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export default function AssistantTechnicalDetails({
  response,
  requestedMode,
  semanticMemoryRequested,
}: AssistantTechnicalDetailsProps) {
  const metadata = response.metadata;

  const requestAndResult: Detail[] = [
    { label: "Scope", value: humanizeAssistantValue(response.scope) },
    { label: "Incident ID", value: response.incident_id },
    { label: "Case ID", value: response.case_id },
    { label: "Requested mode", value: humanizeAssistantValue(requestedMode) },
    {
      label: "Semantic memory requested",
      value: booleanLabel(semanticMemoryRequested),
    },
    { label: "Response status", value: humanizeAssistantValue(response.status) },
    {
      label: "Response generation kind",
      value: humanizeAssistantValue(response.generation_kind),
    },
    {
      label: "Metadata generation kind",
      value: humanizeAssistantValue(metadata.generation_kind),
    },
    { label: "Architecture", value: metadata.response_architecture },
    { label: "Effective profile", value: metadata.effective_profile },
    { label: "Effective model", value: metadata.effective_model },
    { label: "Response language", value: metadata.response_language },
    { label: "Finish reason", value: metadata.finish_reason },
    { label: "Thinking disabled", value: booleanLabel(metadata.thinking_disabled) },
    {
      label: "Conversation follow-up",
      value: booleanLabel(metadata.conversation_followup),
    },
  ];

  const routingAndValidation: Detail[] = [
    {
      label: "Effective intent",
      value: metadata.assistant_intent
        ? humanizeAssistantValue(metadata.assistant_intent)
        : null,
    },
    {
      label: "Secondary intents",
      value:
        metadata.secondary_intents.length > 0
          ? metadata.secondary_intents.map(humanizeAssistantValue).join(", ")
          : null,
    },
    {
      label: "Analysis scope",
      value: metadata.analysis_scope
        ? humanizeAssistantValue(metadata.analysis_scope)
        : null,
    },
    {
      label: "Grounding validation",
      value: humanizeAssistantValue(metadata.grounding_validation),
    },
    {
      label: "Focus validation",
      value: humanizeAssistantValue(metadata.focus_validation),
    },
    {
      label: "Plan validation",
      value: humanizeAssistantValue(metadata.plan_validation_status),
    },
    {
      label: "Semantic proof",
      value: humanizeAssistantValue(metadata.semantic_proof_status),
    },
    {
      label: "Semantic proof model",
      value: metadata.semantic_proof_model,
    },
    {
      label: "Semantic proof revision",
      value: metadata.semantic_proof_revision,
    },
    {
      label: "Semantic index",
      value: humanizeAssistantValue(metadata.semantic_index_status),
    },
    {
      label: "Semantic retrieval",
      value: humanizeAssistantValue(metadata.semantic_status),
    },
    {
      label: "Semantic degraded",
      value: booleanLabel(metadata.semantic_degraded),
    },
    {
      label: "Fallback reason",
      value: metadata.fallback_reason
        ? humanizeAssistantValue(metadata.fallback_reason)
        : null,
    },
  ];

  const contextAndSources: Detail[] = [
    { label: "Source count", value: metadata.source_count },
    { label: "Context atoms", value: metadata.context_atoms },
    { label: "Operational atoms", value: metadata.operational_atoms },
    { label: "Reference atoms", value: metadata.reference_atoms },
    { label: "Advisory atoms", value: metadata.advisory_atoms },
    {
      label: "Cross-incident candidates",
      value: metadata.cross_incident_candidates,
    },
    {
      label: "Cross-incident candidates discovered",
      value: metadata.cross_incident_candidates_discovered,
    },
    { label: "Graph edges", value: metadata.graph_edges },
    {
      label: "Semantic raw candidates",
      value: metadata.semantic_raw_candidates,
    },
    {
      label: "Semantic threshold rejects",
      value: metadata.semantic_threshold_rejects,
    },
    {
      label: "Semantic invalid rejects",
      value: metadata.semantic_invalid_rejects,
    },
    {
      label: "Semantic duplicate rejects",
      value: metadata.semantic_duplicate_rejects,
    },
    {
      label: "Semantic excluded rejects",
      value: metadata.semantic_excluded_rejects,
    },
    {
      label: "Authoritative rehydration count",
      value: metadata.authoritative_rehydration_count,
    },
    {
      label: "Stale candidate rejects",
      value: metadata.stale_candidate_rejects,
    },
  ];

  const generationAndPlan: Detail[] = [
    {
      label: "Provider generations",
      value: metadata.provider_generation_count,
    },
    { label: "Automatic retries", value: metadata.automatic_retries },
    { label: "Model switches", value: metadata.model_switches },
    { label: "Plan sections", value: metadata.plan_sections },
    { label: "Plan units", value: metadata.plan_units },
    { label: "Cross-incident units", value: metadata.cross_incident_units },
    { label: "Reference units", value: metadata.reference_units },
    { label: "Advisory units", value: metadata.advisory_units },
    { label: "Schema characters", value: metadata.schema_chars },
    { label: "Prompt characters", value: metadata.prompt_chars },
    { label: "Prompt tokens", value: metadata.prompt_tokens },
    {
      label: "Structured output tokens",
      value: metadata.structured_output_tokens,
    },
    { label: "Semantic proof pairs", value: metadata.semantic_proof_pairs },
    { label: "Typed guard rejects", value: metadata.typed_guard_rejects },
    { label: "Deterministic proofs", value: metadata.deterministic_proofs },
    { label: "NLI proofs", value: metadata.nli_proofs },
  ];

  const timings: Detail[] = [
    { label: "Queue wait", value: latency(metadata.queue_wait_ms) },
    { label: "Generation time", value: latency(metadata.generation_ms) },
    { label: "Total latency", value: latency(metadata.total_latency_ms) },
    { label: "Context build", value: latency(metadata.context_build_ms) },
    { label: "Intent routing", value: latency(metadata.intent_routing_ms) },
    { label: "Focus routing", value: latency(metadata.focus_routing_ms) },
    { label: "Scope resolution", value: latency(metadata.scope_resolution_ms) },
    { label: "Context policy", value: latency(metadata.context_policy_ms) },
    {
      label: "Operational retrieval",
      value: latency(metadata.operational_retrieval_ms),
    },
    {
      label: "Atom normalization",
      value: latency(metadata.atom_normalization_ms),
    },
    {
      label: "Semantic candidates",
      value: latency(metadata.semantic_candidate_ms),
    },
    {
      label: "Semantic index query",
      value: latency(metadata.semantic_index_query_ms),
    },
    {
      label: "Authoritative rehydration",
      value: latency(metadata.authoritative_rehydration_ms),
    },
    { label: "Graph", value: latency(metadata.graph_ms) },
    {
      label: "Reference retrieval",
      value: latency(metadata.reference_retrieval_ms),
    },
    {
      label: "Advisory retrieval",
      value: latency(metadata.advisory_retrieval_ms),
    },
    {
      label: "Conversation state",
      value: latency(metadata.conversation_state_ms),
    },
    { label: "Schema build", value: latency(metadata.schema_build_ms) },
    {
      label: "Plan validation time",
      value: latency(metadata.plan_validation_ms),
    },
    { label: "Rendering", value: latency(metadata.rendering_ms) },
    { label: "Semantic proof time", value: latency(metadata.semantic_proof_ms) },
    { label: "Semantic elapsed", value: latency(metadata.semantic_elapsed_ms) },
  ];

  const analytics: Detail[] = [
    { label: "Analytics operation", value: metadata.analytics_operation },
    { label: "Analytics entity", value: metadata.analytics_entity },
    {
      label: "Analytics definition",
      value: metadata.analytics_definition_id,
    },
    {
      label: "Analytics plan fingerprint",
      value: metadata.analytics_query_plan_fingerprint,
    },
    { label: "Analytics result count", value: metadata.analytics_result_count },
    {
      label: "Analytics window start",
      value: metadata.analytics_window_start_utc,
    },
    {
      label: "Analytics window end",
      value: metadata.analytics_window_end_utc,
    },
  ];

  return (
    <details className="border-t border-slate-800 pt-3">
      <summary
        className={cx(
          "w-fit cursor-pointer rounded-sm text-xs font-semibold text-slate-400 hover:text-slate-200",
          SOC_CONTROL_CLASSES.focus,
        )}
      >
        Technical details
      </summary>
      <div className="mt-4 space-y-5">
        <TechnicalGroup title="Request and result" items={requestAndResult} />
        <TechnicalGroup title="Routing and validation" items={routingAndValidation} />
        <TechnicalGroup title="Context and sources" items={contextAndSources} />
        <TechnicalGroup title="Generation and plan" items={generationAndPlan} />
        <TechnicalGroup title="Timings" items={timings} />
        <TechnicalGroup title="Authoritative analytics" items={analytics} />
      </div>
    </details>
  );
}
