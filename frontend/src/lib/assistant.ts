import { authFetch } from "@/lib/auth";

export const ASSISTANT_MESSAGE_MAX_LENGTH = 2000;

export type AssistantScope = "global" | "incident" | "case";
export type ContextualAssistantScope = Exclude<AssistantScope, "global">;
export type AssistantMode = "auto" | "standard";
export type AssistantStatus = "ok" | "fallback";
export type AssistantAuthority = "authoritative" | "advisory";
export type AssistantProvenanceClass =
  | "operational_source"
  | "reference_knowledge"
  | "advisory_playbook"
  | "analytical_relationship"
  | "semantic_candidate";
export type AssistantGenerationKind = "model" | "deterministic_fallback";
export type AssistantResponseLanguage = "it" | "en";
export type AssistantRuntimeState =
  | "warming"
  | "ready"
  | "failed"
  | "stopped";
export type AssistantSemanticState =
  | "not_requested"
  | "disabled"
  | "warming"
  | "embedding_unavailable"
  | "qdrant_timeout"
  | "retrieval_timeout"
  | "retrieval_failed"
  | "available";
export type AssistantBlockKind =
  | "direct_answer"
  | "key_findings"
  | "related_incidents"
  | "evidence"
  | "technical_context"
  | "analysis"
  | "comparison"
  | "pattern"
  | "conclusion"
  | "next_check"
  | "recommended_checks"
  | "limitations";
export type AssistantValidationStatus = "passed" | "failed" | "not_run";
export type AssistantFallbackReason =
  | "gateway_unavailable"
  | "queue_deadline_exceeded"
  | "generation_timeout"
  | "invalid_structured_output"
  | "grounding_validation_failed"
  | "focus_validation_failed"
  | "v3_context_build_failed"
  | "v3_schema_build_failed"
  | "v3_invalid_structured_output"
  | "v3_plan_validation_failed"
  | "v3_renderer_failed"
  | "v3_semantic_index_degraded"
  | "v31_schema_build_failed"
  | "v31_invalid_structured_output"
  | "v31_grounding_validation_failed"
  | "v31_renderer_failed";

export type AssistantCapabilities = {
  enabled: boolean;
  feature_key: string;
  supported_scopes: AssistantScope[];
  supported_modes: AssistantMode[];
  persistent_conversations: boolean;
  streaming: boolean;
  project_documentation_indexed: boolean;
  semantic_memory_supported: boolean;
  write_actions_supported: boolean;
  decision_boundary: string;
  runtime_state?: AssistantRuntimeState | null;
  default_profile?: string | null;
  loaded_profile?: string | null;
  runtime_message?: string | null;
  semantic_runtime_state?:
    | "warming"
    | "available"
    | "embedding_unavailable"
    | null;
  embedding_backend?: string | null;
  embedding_cache_state?: string | null;
};

export type AssistantQueryRequest = {
  message: string;
  scope: AssistantScope;
  incident_id: number | null;
  case_id: number | null;
  requested_mode: AssistantMode;
  include_semantic_memory: boolean;
  conversation_id?: string | null;
  compare_incident_ids?: number[];
};

export type AssistantSource = {
  source_id: string;
  source_type: string;
  authority: AssistantAuthority;
  provenance_class: AssistantProvenanceClass;
  record_id: string | null;
  label: string;
  url: string | null;
  score: number | null;
  section: string | null;
};

export type AssistantMetadata = {
  generation_kind: AssistantGenerationKind;
  queue_wait_ms: number;
  generation_ms: number;
  total_latency_ms: number;
  effective_profile: "standard";
  effective_model: string;
  semantic_status: AssistantSemanticState;
  semantic_elapsed_ms: number;
  semantic_degraded: boolean;
  grounding_validation: AssistantValidationStatus;
  focus_validation: AssistantValidationStatus;
  fallback_reason: AssistantFallbackReason | null;
  response_language: AssistantResponseLanguage;
  thinking_disabled: boolean;
  source_count: number;
  assistant_intent:
    | "FACT_LOOKUP"
    | "EXPLAIN"
    | "SUMMARY"
    | "INVESTIGATE"
    | "COMPARE"
    | "CROSS_INCIDENT_ANALYSIS"
    | "PATTERN_ANALYSIS"
    | "NEXT_ACTION"
    | "HANDOVER"
    | "EXECUTIVE_SUMMARY"
    | null;
  secondary_intents: Array<
    | "FACT_LOOKUP"
    | "EXPLAIN"
    | "SUMMARY"
    | "INVESTIGATE"
    | "COMPARE"
    | "CROSS_INCIDENT_ANALYSIS"
    | "PATTERN_ANALYSIS"
    | "NEXT_ACTION"
    | "HANDOVER"
    | "EXECUTIVE_SUMMARY"
  >;
  analysis_scope:
    | "CURRENT_RECORD"
    | "CURRENT_CASE"
    | "EXPLICIT_RECORD_SET"
    | "RELATED_INCIDENTS"
    | "GLOBAL"
    | null;
  context_atoms: number;
  operational_atoms: number;
  reference_atoms: number;
  advisory_atoms: number;
  cross_incident_candidates: number;
  graph_edges: number;
  conversation_followup: boolean;
  context_build_ms: number;
  intent_routing_ms: number;
  focus_routing_ms: number;
  scope_resolution_ms: number;
  context_policy_ms: number;
  operational_retrieval_ms: number;
  atom_normalization_ms: number;
  semantic_candidate_ms: number;
  semantic_index_query_ms: number;
  authoritative_rehydration_ms: number;
  semantic_raw_candidates: number;
  semantic_threshold_rejects: number;
  semantic_invalid_rejects: number;
  semantic_duplicate_rejects: number;
  semantic_excluded_rejects: number;
  cross_incident_candidates_discovered: number;
  authoritative_rehydration_count: number;
  stale_candidate_rejects: number;
  graph_ms: number;
  reference_retrieval_ms: number;
  advisory_retrieval_ms: number;
  conversation_state_ms: number;
  response_architecture: "v2" | "v3" | "v3_1";
  plan_sections: number;
  plan_units: number;
  cross_incident_units: number;
  reference_units: number;
  advisory_units: number;
  plan_validation_status: AssistantValidationStatus;
  schema_build_ms: number;
  schema_chars: number;
  plan_validation_ms: number;
  rendering_ms: number;
  prompt_chars: number;
  prompt_tokens: number;
  structured_output_tokens: number;
  provider_generation_count: number;
  automatic_retries: number;
  model_switches: number;
  finish_reason: string | null;
  semantic_index_status:
    | "not_requested"
    | "ready"
    | "degraded"
    | "unavailable";
};

export type AssistantResponseBlock = {
  kind: AssistantBlockKind;
  text: string;
  source_ids: string[];
  provenance_classes: AssistantProvenanceClass[];
};

export type AssistantQueryResponse = {
  status: AssistantStatus;
  generation_kind: AssistantGenerationKind;
  answer: string;
  blocks: AssistantResponseBlock[];
  scope: AssistantScope;
  incident_id: number | null;
  case_id: number | null;
  sources: AssistantSource[];
  limitations: string[];
  metadata: AssistantMetadata;
};

export type AssistantErrorKind =
  | "aborted"
  | "validation"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "disabled"
  | "unavailable"
  | "unknown";

export type NormalizedAssistantError = {
  kind: AssistantErrorKind;
  message: string;
  retryable: boolean;
  locksInteraction: boolean;
};

type AssistantErrorEnvelope = {
  detail?: {
    error_category?: unknown;
  };
};

export class AssistantApiError extends Error {
  readonly status: number;
  readonly category: string | null;

  constructor(status: number, category: string | null) {
    super("The SOC Assistant request failed.");
    this.name = "AssistantApiError";
    this.status = status;
    this.category = category;
  }
}

export class AssistantContractError extends Error {
  constructor() {
    super("The SOC Assistant returned an incomplete response.");
    this.name = "AssistantContractError";
  }
}

function errorCategory(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") return null;

  const detail = (payload as AssistantErrorEnvelope).detail;
  const category = detail?.error_category;

  return typeof category === "string" && category.length <= 80 ? category : null;
}

async function requestAssistantJson<T>(
  path: "/assistant/capabilities" | "/assistant/query",
  init: RequestInit,
): Promise<T> {
  const response = await authFetch(path, init);

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new AssistantApiError(response.status, errorCategory(payload));
  }

  return response.json() as Promise<T>;
}

export function fetchAssistantCapabilities(
  signal?: AbortSignal,
): Promise<AssistantCapabilities> {
  return requestAssistantJson<AssistantCapabilities>("/assistant/capabilities", {
    method: "GET",
    signal,
  });
}

export async function submitAssistantQuery(
  payload: AssistantQueryRequest,
  signal?: AbortSignal,
): Promise<AssistantQueryResponse> {
  const response = await requestAssistantJson<AssistantQueryResponse>("/assistant/query", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal,
  });
  if (
    typeof response.answer !== "string" ||
    !response.answer.trim() ||
    !Array.isArray(response.blocks) ||
    response.blocks.length === 0
  ) {
    throw new AssistantContractError();
  }
  return response;
}

export function isSafeInternalAssistantUrl(value: string | null | undefined): value is string {
  if (!value || value !== value.trim()) return false;
  if (!value.startsWith("/") || value.startsWith("//")) return false;
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return false;

  try {
    const base = "https://assistant.internal";
    const parsed = new URL(value, base);
    return parsed.origin === base && parsed.pathname.startsWith("/");
  } catch {
    return false;
  }
}

export function normalizeAssistantApiError(
  error: unknown,
  scope: ContextualAssistantScope,
): NormalizedAssistantError {
  if (error instanceof DOMException && error.name === "AbortError") {
    return {
      kind: "aborted",
      message: "The assistant request was cancelled.",
      retryable: false,
      locksInteraction: false,
    };
  }

  if (error instanceof AssistantContractError) {
    return {
      kind: "unavailable",
      message:
        `The SOC Assistant returned an incomplete response. No ${scope} state was changed.`,
      retryable: true,
      locksInteraction: false,
    };
  }

  if (error instanceof AssistantApiError) {
    if (error.status === 400 || error.status === 422) {
      return {
        kind: "validation",
        message:
          "The question or context selection is not valid. Review the request and try again.",
        retryable: false,
        locksInteraction: false,
      };
    }

    if (error.status === 401) {
      return {
        kind: "unauthorized",
        message: "Your session is no longer available. Sign in again to continue.",
        retryable: false,
        locksInteraction: true,
      };
    }

    if (error.status === 403) {
      return {
        kind: "forbidden",
        message: "Your role is not permitted to use the SOC Assistant.",
        retryable: false,
        locksInteraction: true,
      };
    }

    if (error.status === 404) {
      return {
        kind: "not_found",
        message: `This ${scope} is no longer available.`,
        retryable: false,
        locksInteraction: true,
      };
    }

    if (error.category === "AssistantDisabled") {
      return {
        kind: "disabled",
        message:
          "SOC Assistant is currently disabled. An administrator can enable the governed backend capability when runtime validation is complete.",
        retryable: false,
        locksInteraction: true,
      };
    }

    if (
      error.status === 503 ||
      error.category === "ProviderUnavailable" ||
      error.category === "GenerationTimeout" ||
      error.category === "provider_unavailable" ||
      error.category === "timeout"
    ) {
      return {
        kind: "unavailable",
        message:
          `AI generation is currently unavailable. No ${scope} state was changed.`,
        retryable: true,
        locksInteraction: false,
      };
    }
  }

  return {
    kind: "unknown",
    message:
      `The SOC Assistant is temporarily unavailable. No ${scope} state was changed.`,
    retryable: true,
    locksInteraction: false,
  };
}
