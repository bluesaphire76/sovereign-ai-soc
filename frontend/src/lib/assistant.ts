import { authFetch } from "@/lib/auth";

export const ASSISTANT_MESSAGE_MAX_LENGTH = 2000;

export type AssistantScope = "global" | "incident" | "case";
export type ContextualAssistantScope = Exclude<AssistantScope, "global">;
export type AssistantMode = "auto" | "standard" | "quality";
export type AssistantStatus = "success" | "fallback" | "unavailable";
export type AssistantAuthority = "authoritative" | "advisory";

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
};

export type AssistantQueryRequest = {
  message: string;
  scope: AssistantScope;
  incident_id: number | null;
  case_id: number | null;
  requested_mode: AssistantMode;
  include_semantic_memory: boolean;
};

export type AssistantSource = {
  source_id: string;
  source_type: string;
  authority: AssistantAuthority;
  record_id: string | null;
  label: string;
  url: string | null;
  score: number | null;
  section: string | null;
};

export type AssistantMetadata = {
  provider_key: string | null;
  provider_type: string | null;
  profile: string | null;
  model: string | null;
  fallback_used: boolean;
  latency_ms: number | null;
  usage: Record<string, unknown>;
};

export type AssistantQueryResponse = {
  status: AssistantStatus;
  answer: string;
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

export function submitAssistantQuery(
  payload: AssistantQueryRequest,
  signal?: AbortSignal,
): Promise<AssistantQueryResponse> {
  return requestAssistantJson<AssistantQueryResponse>("/assistant/query", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal,
  });
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
      error.category === "GenerationTimeout"
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
