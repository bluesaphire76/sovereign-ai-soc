import type {
  AssistantMode,
  ContextualAssistantScope,
} from "@/lib/assistant";

export const ASSISTANT_SUGGESTIONS: Record<ContextualAssistantScope, string[]> = {
  incident: [
    "Summarize this incident using the recorded evidence.",
    "Which evidence is missing before escalation or containment review?",
    "Which similar historical incidents or playbooks are relevant?",
    "Explain the risk and correlation without changing the recorded severity.",
  ],
  case: [
    "Summarize this case and its linked incidents using recorded evidence.",
    "Which evidence gaps should be resolved before closure?",
    "Which historical cases, incidents, or playbooks are relevant?",
    "Which analyst questions should be answered next?",
  ],
};

export const ASSISTANT_MODE_OPTIONS: Array<{
  value: AssistantMode;
  label: string;
  description: string;
}> = [
  {
    value: "auto",
    label: "Auto",
    description: "Uses standard",
  },
  {
    value: "standard",
    label: "Standard",
    description: "Balanced",
  },
];

export function sourceAnchorId(prefix: string, sourceIndex: number) {
  return `${prefix}-source-${sourceIndex + 1}`;
}

export function humanizeAssistantValue(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ");
}

export function humanizeAssistantLimitation(value: string) {
  const normalized = value.trim();
  const replacements: Record<string, string> = {
    GenerationTimeout:
      "AI model generation timed out; a deterministic grounded response was used.",
    NoGroundingContext:
      "No grounded operational or advisory source was available for this request.",
    ProviderUnavailable:
      "AI model generation was unavailable; a deterministic grounded response was used.",
  };

  if (replacements[normalized]) return replacements[normalized];
  if (/^[A-Z][A-Za-z]+(?:Error|Exception)$/.test(normalized)) {
    return "A governed AI provider could not complete the request.";
  }
  return normalized;
}

export function formatAssistantScore(value: number | null) {
  return value === null || !Number.isFinite(value) ? null : value.toFixed(3);
}

export function formatAssistantLatency(value: number | null) {
  if (value === null || !Number.isFinite(value) || value < 0) return null;
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}
