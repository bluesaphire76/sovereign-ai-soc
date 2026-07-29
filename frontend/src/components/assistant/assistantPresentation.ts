import type {
  AssistantMode,
  AssistantSource,
  ContextualAssistantScope,
} from "@/lib/assistant";

export const ASSISTANT_SUGGESTIONS: Record<ContextualAssistantScope, string[]> = {
  incident: [
    "Summarize this incident and cite the supporting evidence.",
    "Which evidence is missing before escalation or containment review?",
    "Which similar historical incidents or playbooks are relevant?",
    "Explain the risk and correlation without changing the recorded severity.",
  ],
  case: [
    "Summarize this case and its linked incidents with citations.",
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
    description: "Recommended",
  },
  {
    value: "standard",
    label: "Standard",
    description: "Balanced",
  },
  {
    value: "quality",
    label: "Quality",
    description: "Slower, deeper",
  },
];

export type AssistantAnswerToken =
  | {
      kind: "text";
      value: string;
    }
  | {
      kind: "citation";
      value: string;
      source: AssistantSource;
      sourceIndex: number;
    };

export function tokenizeAssistantAnswer(
  answer: string,
  sources: AssistantSource[],
): AssistantAnswerToken[] {
  const sourceIndexes = new Map(
    sources.map((source, index) => [source.source_id, index] as const),
  );
  const tokens: AssistantAnswerToken[] = [];
  const citationPattern = /\[(S\d+)\]/g;
  let cursor = 0;

  for (const match of answer.matchAll(citationPattern)) {
    const matchIndex = match.index;
    if (matchIndex > cursor) {
      tokens.push({
        kind: "text",
        value: answer.slice(cursor, matchIndex),
      });
    }

    const sourceId = match[1];
    const sourceIndex = sourceIndexes.get(sourceId);

    if (sourceIndex === undefined) {
      tokens.push({
        kind: "text",
        value: match[0],
      });
    } else {
      tokens.push({
        kind: "citation",
        value: match[0],
        source: sources[sourceIndex],
        sourceIndex,
      });
    }

    cursor = matchIndex + match[0].length;
  }

  if (cursor < answer.length) {
    tokens.push({
      kind: "text",
      value: answer.slice(cursor),
    });
  }

  return tokens;
}

export function sourceAnchorId(prefix: string, sourceIndex: number) {
  return `${prefix}-source-${sourceIndex + 1}`;
}

export function humanizeAssistantValue(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ");
}

export function formatAssistantScore(value: number | null) {
  return value === null || !Number.isFinite(value) ? null : value.toFixed(3);
}

export function formatAssistantLatency(value: number | null) {
  if (value === null || !Number.isFinite(value) || value < 0) return null;
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}
