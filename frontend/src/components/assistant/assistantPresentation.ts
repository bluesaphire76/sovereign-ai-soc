import type {
  AssistantBlockKind,
  AssistantMode,
  AssistantProvenanceClass,
  ContextualAssistantScope,
} from "@/lib/assistant";
import type { SocTone } from "@/lib/semantic-styles";

export const ASSISTANT_PROVENANCE: Record<
  AssistantProvenanceClass,
  {
    label: string;
    description: string;
    className: string;
    textClassName: string;
    tone: SocTone;
  }
> = {
  operational_source: {
    label: "Operational source",
    description: "Recorded platform data",
    className: "border-cyan-900 text-cyan-300",
    textClassName: "text-cyan-300",
    tone: "primary",
  },
  reference_knowledge: {
    label: "Reference knowledge",
    description: "Bounded technical definition",
    className: "border-sky-900 text-sky-300",
    textClassName: "text-sky-300",
    tone: "low",
  },
  advisory_playbook: {
    label: "Advisory / playbook",
    description: "Guidance for analyst review",
    className: "border-amber-900 text-amber-300",
    textClassName: "text-amber-300",
    tone: "warning",
  },
  analytical_relationship: {
    label: "Analytical relationship",
    description: "Derived from recorded evidence",
    className: "border-violet-900 text-violet-300",
    textClassName: "text-violet-300",
    tone: "executive",
  },
  semantic_candidate: {
    label: "Semantic candidate",
    description: "Similarity for comparison only",
    className: "border-slate-700 text-slate-300",
    textClassName: "text-slate-300",
    tone: "neutral",
  },
};

export const ASSISTANT_BLOCK_LABELS: Record<AssistantBlockKind, string> = {
  direct_answer: "Answer",
  key_findings: "Key findings",
  related_incidents: "Related incidents",
  evidence: "Evidence",
  technical_context: "Technical context",
  analysis: "Assessment",
  comparison: "Comparison",
  pattern: "Pattern",
  conclusion: "Conclusion",
  next_check: "Next check",
  recommended_checks: "Recommended checks",
  limitations: "Limitations",
};

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
