"use client";

import { downloadBackendFile } from "@/lib/download";
import { authFetch } from "@/lib/auth";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import AppNavigation from "../../../components/AppNavigation";
import {
  AlertTriangle,
  Brain,
  Database,
  FileDown,
  FileText,
  RefreshCw,
  ShieldAlert,
  Target,
} from "lucide-react";

type IncidentDetail = {
  id: number;
  status: string | null;
  wazuh_doc_id: string | null;
  timestamp: string | null;
  timestamp_local?: string | null;
  timezone?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  mitre: string | null;
  risk_score: number | null;
  ai_analysis: string | null;
  correlated: boolean | null;
  correlation_score: number | null;
  correlation_summary: string | null;
  raw_alert: string | null;
  attack_chain: string | null;
  correlation_type: string | null;
  escalation_reason: string | null;
  recommended_priority: string | null;
};

type AuditEvent = {
  id: number;
  incident_id: number;
  event_type: string;
  old_value: string | null;
  new_value: string | null;
  comment: string | null;
  created_by: string | null;
  created_at: string | null;
};

type IncidentNote = {
  id: number;
  incident_id: number;
  note: string;
  created_by: string | null;
  created_at: string | null;
};

type CorrelationSummary = {
  agent?: string | null;
  window_minutes?: number | null;
  related_events?: number | null;
  current_incident_id?: number | null;
  base_score?: number | null;
  pattern_score?: number | null;
  volume_score?: number | null;
  chain_bonus?: number | null;
  final_correlation_score?: number | null;
  recommended_priority?: string | null;
  matched_patterns?: Record<
    string,
    {
      keywords?: string[];
      weight?: number;
    }
  >;
  matched_attack_chains?: Array<{
    name?: string;
    correlation_type?: string;
    priority?: string;
    reason?: string;
    score_bonus?: number;
  }>;
  related_event_details?: Array<{
    id?: number;
    timestamp?: string | null;
    agent?: string | null;
    rule?: string | null;
    level?: number | null;
    risk_score?: number | null;
    status?: string | null;
    correlation_score?: number | null;
  }>;
};

type Tone = "success" | "warning" | "danger" | "primary" | "neutral" | "executive";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

const INCIDENT_STATUSES = [
  "NEW",
  "TRIAGED",
  "ESCALATED",
  "CLOSED",
  "FALSE_POSITIVE",
];

function riskLabel(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "Critical";
  if (value >= 61) return "High";
  if (value >= 31) return "Medium";
  return "Low";
}

function toneForRisk(score: number | null | undefined): Tone {
  const value = score ?? 0;

  if (value >= 81) return "danger";
  if (value >= 61) return "warning";
  if (value >= 31) return "primary";
  return "success";
}

function toneForStatus(status: string | null | undefined): Tone {
  const value = status ?? "NEW";

  if (value === "ESCALATED") return "danger";
  if (value === "TRIAGED") return "primary";
  if (value === "CLOSED") return "success";
  if (value === "FALSE_POSITIVE") return "executive";

  return "neutral";
}

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { card: string; badge: string; text: string }> = {
    success: {
      card: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
    },
    warning: {
      card: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
    },
    danger: {
      card: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
    },
    primary: {
      card: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
    },
    neutral: {
      card: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
    },
    executive: {
      card: "border-violet-900/70 bg-violet-950/20",
      badge: "border-violet-700 bg-violet-950 text-violet-200",
      text: "text-violet-300",
    },
  };

  return classes[tone];
}

function prettyJson(value: string | null) {
  if (!value) return "";

  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function parseCorrelationSummary(
  value: string | null | undefined
): CorrelationSummary | null {
  if (!value) return null;

  try {
    const parsed = JSON.parse(value);

    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as CorrelationSummary;
    }

    return null;
  } catch {
    return null;
  }
}

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("it-CH", {
    timeZone: "Europe/Zurich",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}

function shortTimestamp(value: string | null | undefined) {
  return formatTimestamp(value).replace(", ", " · ");
}

function shortText(value: string | null | undefined, max = 120) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

async function fetchIncident(id: string): Promise<IncidentDetail> {
  const response = await authFetch(`/incidents/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchIncidentAudit(id: string): Promise<AuditEvent[]> {
  const response = await authFetch(`/incidents/${id}/audit`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchIncidentNotes(id: string): Promise<IncidentNote[]> {
  const response = await authFetch(`/incidents/${id}/notes`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}



type IncidentAiAssessmentInput = {
  ai_analysis: string | null;
  risk_score?: number | null;
  recommended_priority?: string | null;
  status?: string | null;
  correlation_score?: number | null;
  correlation_type?: string | null;
  attack_chain?: string | null;
  escalation_reason?: string | null;
  agent?: string | null;
  rule?: string | null;
};

type ParsedAiSection = {
  title: string;
  lines: string[];
};

function riskBand(score?: number | null): string {
  const value = score ?? 0;
  if (value >= 81) return "Critical";
  if (value >= 61) return "High";
  if (value >= 31) return "Medium";
  return "Low";
}

function riskTone(score?: number | null): string {
  const value = score ?? 0;
  if (value >= 81) return "border-red-800 bg-red-950/40 text-red-200";
  if (value >= 61) return "border-orange-800 bg-orange-950/40 text-orange-200";
  if (value >= 31) return "border-yellow-800 bg-yellow-950/30 text-yellow-200";
  return "border-emerald-800 bg-emerald-950/30 text-emerald-200";
}

function normalizeAiLine(line: string): string {
  return line
    .replace(/^[-*•]\s+/, "")
    .replace(/^\d+[.)]\s+/, "")
    .replace(/^#{1,4}\s*/, "")
    .replace(/^\*\*(.*)\*\*$/, "$1")
    .trim();
}

function splitAiSentences(value: string): string[] {
  const normalized = value.replace(/\r\n/g, "\n").trim();

  if (!normalized) return [];

  const withExplicitSections = normalized.replace(
    /\s*(?:\d+[.)]\s*)?(Short executive summary|Executive summary|Recommended checks|Recommended check|Suggested remediation|Suggested remediations|Recommended actions|Next actions):\s*/gi,
    "\n$1:\n",
  );

  const cleanLines = withExplicitSections
    .split("\n")
    .map((line) => normalizeAiLine(line))
    .map((line) => line.replace(/^\d+[.)]?$/, "").trim())
    .filter(Boolean);

  if (cleanLines.length > 1) return cleanLines;

  return normalized
    .split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
    .map((line) => normalizeAiLine(line))
    .map((line) => line.replace(/^\d+[.)]?$/, "").trim())
    .filter(Boolean);
}

function parseAiAnalysis(value: string): ParsedAiSection[] {
  const text = value.replace(/\r\n/g, "\n").trim();
  if (!text) return [];

  const blocks = text
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter(Boolean);

  if (blocks.length <= 1) {
    return [{ title: "Investigation narrative", lines: splitAiSentences(text) }];
  }

  return blocks.map((block, index) => {
    const lines = block
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    const first = lines[0] ?? "";
    const looksLikeHeading =
      /^#{1,4}\s+/.test(first) ||
      /^\*\*.*\*\*:?$/.test(first) ||
      /^[A-Z][A-Za-z0-9 /_-]{2,80}:$/.test(first);

    if (looksLikeHeading && lines.length > 1) {
      return {
        title: normalizeAiLine(first).replace(/:$/, ""),
        lines: lines.slice(1).map(normalizeAiLine).filter(Boolean),
      };
    }

    return {
      title: index === 0 ? "Executive assessment" : `Investigation detail ${index}`,
      lines: splitAiSentences(block),
    };
  });
}

function assessmentDecision(incident: IncidentAiAssessmentInput): string {
  const risk = incident.risk_score ?? 0;
  const priority = (incident.recommended_priority ?? "").toUpperCase();

  if (risk >= 81 || priority === "CRITICAL") return "Immediate escalation review";
  if (risk >= 61 || priority === "HIGH") return "Priority analyst investigation";
  if (risk >= 31 || priority === "MEDIUM") return "Standard triage review";
  return "Monitor and validate";
}

function CompactMetric({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  tone?: "neutral" | "risk";
}) {
  const toneClass =
    tone === "risk"
      ? riskTone(typeof value === "number" ? value : undefined)
      : "border-slate-800 bg-slate-950 text-slate-200";

  return (
    <div className={`rounded-lg border px-3 py-2 ${toneClass}`}>
      <div className="text-[10px] font-medium uppercase tracking-wide opacity-70">
        {label}
      </div>
      <div className="mt-1 truncate text-sm font-semibold" title={String(value)}>
        {value}
      </div>
    </div>
  );
}

function DecisionField({ label, value }: { label: string; value?: string | number | null }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 break-words text-sm leading-5 text-slate-200">
        {value || "-"}
      </div>
    </div>
  );
}

type HierarchicalAiItem = {
  title: string;
  children: string[];
};

const AI_SUBSECTION_HEADINGS = [
  "short executive summary",
  "executive summary",
  "recommended checks",
  "recommended check",
  "suggested remediation",
  "suggested remediations",
  "recommended actions",
  "next actions",
];

function canonicalAiHeading(line: string): string {
  return normalizeAiLine(line)
    .replace(/:$/, "")
    .trim()
    .toLowerCase();
}

function isAiSubsectionHeading(line: string): boolean {
  return AI_SUBSECTION_HEADINGS.includes(canonicalAiHeading(line));
}

function stripAiListMarker(line: string): string {
  return normalizeAiLine(line)
    .replace(/^\d+[.)]\s*/, "")
    .replace(/^[a-zA-Z][.)]\s*/, "")
    .replace(/^[-*•]\s*/, "")
    .trim();
}

function splitInlineAiHeading(line: string): { heading: string; rest: string } | null {
  const cleaned = stripAiListMarker(line);

  for (const heading of AI_SUBSECTION_HEADINGS) {
    const pattern = new RegExp(`^(${heading.replace(/ /g, "\\s+")}):\\s*(.*)$`, "i");
    const match = cleaned.match(pattern);

    if (match) {
      return {
        heading: match[1].replace(/\b\w/g, (char) => char.toUpperCase()),
        rest: stripAiListMarker(match[2] ?? ""),
      };
    }
  }

  return null;
}

function pushAiItem(items: HierarchicalAiItem[], item: HierarchicalAiItem | null) {
  if (!item) return;

  const title = stripAiListMarker(item.title);
  const children = item.children.map(stripAiListMarker).filter(Boolean);

  if (!title && children.length === 0) return;

  if (children.length === 0 && isAiSubsectionHeading(title)) {
    return;
  }

  items.push({ title, children });
}

function buildHierarchicalAiItems(lines: string[]): HierarchicalAiItem[] {
  const items: HierarchicalAiItem[] = [];
  let activeSection: HierarchicalAiItem | null = null;

  for (const rawLine of lines) {
    const line = stripAiListMarker(rawLine);

    if (!line) continue;

    const inlineHeading = splitInlineAiHeading(line);

    if (inlineHeading) {
      pushAiItem(items, activeSection);

      activeSection = {
        title: inlineHeading.heading,
        children: [],
      };

      if (inlineHeading.rest) {
        activeSection.children.push(inlineHeading.rest);
      }

      continue;
    }

    if (isAiSubsectionHeading(line)) {
      pushAiItem(items, activeSection);

      activeSection = {
        title: line.replace(/:$/, ""),
        children: [],
      };

      continue;
    }

    if (activeSection) {
      activeSection.children.push(line);
      continue;
    }

    pushAiItem(items, {
      title: line,
      children: [],
    });
  }

  pushAiItem(items, activeSection);

  return items.filter((item) => item.title || item.children.length > 0);
}

function StructuredAiNarrative({
  lines,
  variant = "primary",
}: {
  lines: string[];
  variant?: "primary" | "compact";
}) {
  const items = buildHierarchicalAiItems(lines);

  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
        No structured AI narrative available.
      </div>
    );
  }

  if (variant === "compact") {
    return (
      <div className="space-y-3">
        {items.map((item, index) => (
          <div key={`${item.title}-${index}`} className="space-y-2">
            <div className="flex gap-2 text-sm leading-6 text-slate-300">
              <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
              <span className={item.children.length > 0 ? "font-semibold text-slate-100" : ""}>
                {item.title}
              </span>
            </div>

            {item.children.length > 0 && (
              <div className="ml-5 space-y-2 border-l border-cyan-900/70 pl-4">
                {item.children.map((child, childIndex) => (
                  <div
                    key={`${item.title}-${childIndex}`}
                    className="flex gap-2 rounded-md border border-slate-800 bg-slate-900/70 px-3 py-2"
                  >
                    <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-500" />
                    <span className="text-sm leading-6 text-slate-300">{child}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((item, index) => (
        <div
          key={`${item.title}-${index}`}
          className="rounded-lg border border-slate-800 bg-slate-950 p-3"
        >
          <div className="flex gap-3">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-800 bg-cyan-950 text-xs font-semibold text-cyan-200">
              {index + 1}
            </div>

            <div className="min-w-0 flex-1">
              <p
                className={`text-sm leading-6 ${
                  item.children.length > 0
                    ? "font-semibold text-slate-100"
                    : "text-slate-300"
                }`}
              >
                {item.title}
              </p>

              {item.children.length > 0 && (
                <div className="mt-3 space-y-2 border-l border-cyan-900/70 pl-4">
                  {item.children.map((child, childIndex) => (
                    <div
                      key={`${item.title}-${childIndex}`}
                      className="flex gap-3 rounded-md border border-slate-800 bg-slate-900/80 p-3"
                    >
                      <div className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                      <p className="text-sm leading-6 text-slate-300">{child}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}


function AiSectionCard({ title, lines }: ParsedAiSection) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 shadow-sm">
      <div className="mb-3 flex items-center justify-between gap-3 border-b border-slate-800 pb-2">
        <h4 className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
          {title}
        </h4>
        <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-400">
          AI insight
        </span>
      </div>

      <StructuredAiNarrative lines={lines} variant="compact" />
    </div>
  );
}

function AnalystReviewChecklist() {
  const items = [
    "Validate the AI interpretation against raw Wazuh evidence.",
    "Confirm whether correlation context supports escalation.",
    "Check affected host, rule metadata and related events.",
    "Document analyst conclusion before closing or escalating.",
  ];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">
        Analyst review checklist
      </div>

      <div className="space-y-2">
        {items.map((item, index) => (
          <div key={item} className="flex gap-3 rounded-lg border border-slate-800 bg-slate-900/70 p-3">
            <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-950 text-[11px] font-semibold text-cyan-300">
              {index + 1}
            </div>
            <div className="text-sm leading-5 text-slate-300">{item}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EnterpriseIncidentAiAnalysis({ incident }: { incident: IncidentAiAssessmentInput }) {
  const analysis = (incident.ai_analysis ?? "").trim();

  if (!analysis) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No AI analysis available.
      </div>
    );
  }

  const sections = parseAiAnalysis(analysis);
  const primary = sections[0];
  const secondary = sections.slice(1);
  const decision = assessmentDecision(incident);

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-xl">
        <div className="border-b border-slate-800 bg-gradient-to-r from-slate-900 via-violet-950/40 to-slate-900 p-4">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-violet-300">
                Sovereign AI SOC Assessment
              </div>
              <h3 className="mt-2 text-lg font-semibold tracking-tight text-slate-100">
                {decision}
              </h3>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                AI-assisted triage summary structured for analyst review, escalation decisioning and audit-ready investigation handling.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <span className="rounded-full border border-violet-700 bg-violet-950 px-3 py-1 text-xs font-medium text-violet-200">
                AI-assisted
              </span>
              <span className="rounded-full border border-orange-700 bg-orange-950 px-3 py-1 text-xs font-medium text-orange-200">
                Human approval required
              </span>
            </div>
          </div>

          <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <CompactMetric label="Risk" value={`${riskBand(incident.risk_score)} · ${incident.risk_score ?? 0}`} />
            <CompactMetric label="Priority" value={incident.recommended_priority ?? "-"} />
            <CompactMetric label="Status" value={incident.status ?? "-"} />
            <CompactMetric label="Correlation" value={incident.correlation_score ?? 0} />
          </div>
        </div>

        <div className="grid gap-3 p-4 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="mb-3 border-b border-slate-800 pb-2">
              <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300">
                Executive assessment
              </div>
              <div className="mt-1 text-sm text-slate-500">
                Concise AI interpretation of the current incident.
              </div>
            </div>

            <StructuredAiNarrative
              lines={primary?.lines ?? splitAiSentences(analysis)}
              variant="primary"
            />
          </div>

          <div className="space-y-3">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="mb-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                Analyst decision support
              </div>

              <div className="grid gap-2">
                <DecisionField label="Correlation type" value={incident.correlation_type} />
                <DecisionField label="Attack chain" value={incident.attack_chain} />
                <DecisionField label="Escalation reason" value={incident.escalation_reason} />
                <DecisionField label="Affected host" value={incident.agent} />
                <DecisionField label="Detection rule" value={incident.rule} />
              </div>
            </div>

            <AnalystReviewChecklist />
          </div>
        </div>
      </div>

      {secondary.length > 0 && (
        <div className="grid gap-3 xl:grid-cols-2">
          {secondary.map((section, index) => (
            <AiSectionCard key={`${section.title}-${index}`} {...section} />
          ))}
        </div>
      )}

      <details className="rounded-xl border border-slate-800 bg-slate-950">
        <summary className="cursor-pointer px-4 py-3 text-xs font-medium text-slate-300 hover:text-cyan-200">
          Show original AI output
        </summary>
        <pre className="max-h-72 overflow-auto whitespace-pre-wrap border-t border-slate-800 p-4 text-xs leading-5 text-slate-400">
          {analysis}
        </pre>
      </details>
    </div>
  );
}


export default function IncidentDetailPage() {
  const params = useParams();
  const incidentId = String(params.id);

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [noteDraft, setNoteDraft] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadIncident() {
    try {
      setRefreshing(true);
      setError(null);
      const [data, auditData, notesData] = await Promise.all([
        fetchIncident(incidentId),
        fetchIncidentAudit(incidentId),
        fetchIncidentNotes(incidentId),
      ]);

      setIncident(data);
      setAuditEvents(auditData);
      setNotes(notesData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  async function updateStatus(status: string) {
    try {
      setError(null);

      const response = await authFetch(`/incidents/${incidentId}/status`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ status }),
      });

      if (!response.ok) {
        throw new Error(`API error ${response.status}`);
      }

      await loadIncident();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }

  async function addNote() {
    const note = noteDraft.trim();

    if (!note) return;

    try {
      setSavingNote(true);
      setError(null);

      const response = await authFetch(`/incidents/${incidentId}/notes`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          note,
          created_by: "local_analyst",
        }),
      });

      if (!response.ok) {
        throw new Error(`API error ${response.status}`);
      }

      setNoteDraft("");
      await loadIncident();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setSavingNote(false);
    }
  }

  useEffect(() => {
    loadIncident();
  }, [incidentId]);

  const rawAlert = useMemo(() => {
    return prettyJson(incident?.raw_alert ?? null);
  }, [incident]);

  const correlationSummary = useMemo(() => {
    return prettyJson(incident?.correlation_summary ?? null);
  }, [incident]);

  const parsedCorrelationSummary = useMemo(() => {
    return parseCorrelationSummary(incident?.correlation_summary);
  }, [incident]);

  const matchedPatterns = useMemo(() => {
    return Object.entries(parsedCorrelationSummary?.matched_patterns ?? {});
  }, [parsedCorrelationSummary]);

  const matchedAttackChains = parsedCorrelationSummary?.matched_attack_chains ?? [];
  const relatedCorrelationEvents =
    parsedCorrelationSummary?.related_event_details ?? [];

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              ← Dashboard
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              Incident Detail
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Incident #{incidentId}
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Compact AI triage view with lifecycle, correlation explanation,
              analyst notes and raw Wazuh evidence.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={loadIncident}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>

            <a
              href="#"
              onClick={(event) => {
                event.preventDefault();
                downloadBackendFile(`/reports/incidents/${incidentId}?format=markdown`, `incident-${incidentId}-report.md`).catch((error) => alert(error.message));
              }}
              download
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 shadow-sm hover:bg-cyan-400"
            >
              <FileDown className="h-3.5 w-3.5" />
              Markdown
            </a>

            <a
              href="#"
              onClick={(event) => {
                event.preventDefault();
                downloadBackendFile(`/reports/incidents/${incidentId}?format=json`, `incident-${incidentId}-report.json`).catch((error) => alert(error.message));
              }}
              download
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <FileDown className="h-3.5 w-3.5" />
              JSON
            </a>
          </div>
        </header>

        {loading && (
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading incident...
          </section>
        )}

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {incident && (
          <div className="space-y-3">
            <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
              <MetricTile
                title="Risk"
                value={`${riskLabel(incident.risk_score)} · ${incident.risk_score ?? 0}`}
                tone={toneForRisk(incident.risk_score)}
                icon={<AlertTriangle className="h-4 w-4" />}
              />
              <MetricTile
                title="Status"
                value={incident.status ?? "NEW"}
                tone={toneForStatus(incident.status)}
                icon={<ShieldAlert className="h-4 w-4" />}
              />
              <MetricTile
                title="Host"
                value={incident.agent ?? "unknown"}
                tone="primary"
                icon={<Database className="h-4 w-4" />}
              />
              <MetricTile
                title="Wazuh level"
                value={incident.level ?? 0}
                tone={toneForRisk((incident.level ?? 0) * 10)}
                icon={<Target className="h-4 w-4" />}
              />
              <MetricTile
                title="Correlation"
                value={incident.correlation_score ?? 0}
                tone={incident.correlated ? "executive" : "neutral"}
                icon={<Brain className="h-4 w-4" />}
              />
              <MetricTile
                title="Priority"
                value={incident.recommended_priority ?? "-"}
                tone={toneForStatus(incident.recommended_priority)}
                icon={<ShieldAlert className="h-4 w-4" />}
              />
            </section>

            <section className="grid gap-3 xl:grid-cols-[420px_1fr]">
              <Panel title="Incident lifecycle" description="Update operational SOC status.">
                <div className="mb-2 flex items-center justify-between">
                  <Badge tone={toneForStatus(incident.status)}>
                    {incident.status ?? "NEW"}
                  </Badge>
                  <span className="text-[11px] text-slate-500">
                    {shortTimestamp(incident.timestamp_local ?? incident.timestamp)}
                  </span>
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {INCIDENT_STATUSES.map((status) => (
                    <button
                      key={status}
                      onClick={() => updateStatus(status)}
                      className={`h-7 rounded-md border px-2 text-[11px] ${
                        incident.status === status
                          ? "border-cyan-400 bg-cyan-500 text-slate-950"
                          : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800"
                      }`}
                    >
                      {status}
                    </button>
                  ))}
                </div>
              </Panel>

              <Panel title="Detection rule" description="Primary Wazuh detection metadata.">
                <div className="grid gap-2 lg:grid-cols-4">
                  <CompactField
                    label="Timestamp"
                    value={incident.timestamp_local ?? formatTimestamp(incident.timestamp)}
                  />
                  <CompactField label="Agent" value={incident.agent ?? "-"} />
                  <CompactField label="Rule" value={shortText(incident.rule, 120)} />
                  <CompactField label="Wazuh doc ID" value={incident.wazuh_doc_id ?? "-"} />
                </div>
              </Panel>
            </section>

            <section className="grid gap-3 xl:grid-cols-[1fr_420px]">
              <Panel title="AI analysis" description="Generated triage explanation.">
                <EnterpriseIncidentAiAnalysis incident={incident} />
              </Panel>

              <Panel title="Analyst notes" description="Investigation notes and rationale.">
                <div className="space-y-2">
                  <textarea
                    value={noteDraft}
                    onChange={(event) => setNoteDraft(event.target.value)}
                    placeholder="Write an analyst note..."
                    className="min-h-20 w-full rounded-md border border-slate-800 bg-slate-950 p-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500"
                  />

                  <div className="flex justify-end">
                    <button
                      onClick={addNote}
                      disabled={savingNote || !noteDraft.trim()}
                      className="h-8 rounded-md border border-cyan-500 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {savingNote ? "Saving..." : "Add note"}
                    </button>
                  </div>

                  {notes.length === 0 ? (
                    <EmptyState label="No analyst notes available." />
                  ) : (
                    <div className="max-h-44 space-y-2 overflow-auto pr-1">
                      {notes.map((note) => (
                        <div
                          key={note.id}
                          className="rounded-md border border-slate-800 bg-slate-950 p-2"
                        >
                          <div className="mb-1 text-[10px] text-slate-500">
                            {formatTimestamp(note.created_at)} ·{" "}
                            {note.created_by ?? "local_analyst"}
                          </div>
                          <div className="whitespace-pre-wrap text-xs leading-5 text-slate-200">
                            {note.note}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </Panel>
            </section>

            <Panel
              title="Correlation explanation"
              description="Explainable correlation details derived from recent events, matched patterns and score components."
              icon={<Brain className="h-3.5 w-3.5" />}
            >
              {!parsedCorrelationSummary ? (
                <EmptyState label="No structured correlation explanation available yet." />
              ) : (
                <div className="space-y-3">
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                    <MetricTile title="Base score" value={parsedCorrelationSummary.base_score ?? 0} tone="neutral" />
                    <MetricTile title="Pattern score" value={parsedCorrelationSummary.pattern_score ?? 0} tone="primary" />
                    <MetricTile title="Volume score" value={parsedCorrelationSummary.volume_score ?? 0} tone="warning" />
                    <MetricTile title="Chain bonus" value={parsedCorrelationSummary.chain_bonus ?? 0} tone="executive" />
                  </div>

                  <div className="grid gap-3 xl:grid-cols-3">
                    <CompactList
                      title="Matched patterns"
                      emptyLabel="No security patterns matched."
                    >
                      {matchedPatterns.map(([name, pattern]) => (
                        <div key={name} className="rounded-md border border-slate-800 bg-slate-950 p-2">
                          <div className="flex items-center justify-between gap-2">
                            <div className="truncate text-xs font-medium text-cyan-300">
                              {name}
                            </div>
                            <span className="text-[11px] text-slate-500">
                              w {pattern.weight ?? 0}
                            </span>
                          </div>
                          <div className="mt-1 line-clamp-2 text-[11px] text-slate-400">
                            {(pattern.keywords ?? []).join(", ")}
                          </div>
                        </div>
                      ))}
                    </CompactList>

                    <CompactList
                      title="Matched attack chains"
                      emptyLabel="No multi-step attack chain matched."
                    >
                      {matchedAttackChains.map((chain, index) => (
                        <div key={`${chain.name ?? "chain"}-${index}`} className="rounded-md border border-slate-800 bg-slate-950 p-2">
                          <div className="flex items-center justify-between gap-2">
                            <div className="truncate text-xs font-medium text-cyan-300">
                              {chain.name ?? "Unnamed chain"}
                            </div>
                            <span className="text-[11px] text-slate-500">
                              +{chain.score_bonus ?? 0}
                            </span>
                          </div>
                          <div className="mt-1 line-clamp-2 text-[11px] text-slate-400">
                            {chain.reason ?? "No explanation available."}
                          </div>
                        </div>
                      ))}
                    </CompactList>

                    <CompactList
                      title="Related events"
                      emptyLabel="No related events available."
                    >
                      {relatedCorrelationEvents.slice(0, 8).map((event) => (
                        <div key={event.id} className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5">
                          <div className="flex items-center justify-between gap-2">
                            <Link
                              href={`/incidents/${event.id}`}
                              className="text-xs text-cyan-300 hover:text-cyan-200"
                            >
                              #{event.id}
                            </Link>
                            <span className="text-[11px] text-slate-500">
                              risk {event.risk_score ?? 0}
                            </span>
                          </div>
                          <div className="mt-0.5 truncate text-[11px] text-slate-400">
                            {event.rule ?? "-"}
                          </div>
                        </div>
                      ))}
                    </CompactList>
                  </div>
                </div>
              )}
            </Panel>

            <section className="grid gap-3 xl:grid-cols-2">
              <Panel title="Structured correlation" icon={<Brain className="h-3.5 w-3.5" />}>
                <div className="grid gap-2 lg:grid-cols-2">
                  <CompactField label="Correlation type" value={incident.correlation_type ?? "-"} />
                  <CompactField label="Recommended priority" value={incident.recommended_priority ?? "-"} />
                  <CompactField label="Attack chain" value={incident.attack_chain ?? "-"} />
                  <CompactField label="Escalation reason" value={incident.escalation_reason ?? "-"} />
                </div>
              </Panel>

              <Panel title="Audit trail" icon={<FileText className="h-3.5 w-3.5" />}>
                {auditEvents.length === 0 ? (
                  <EmptyState label="No audit events available." />
                ) : (
                  <div className="max-h-56 space-y-2 overflow-auto pr-1">
                    {auditEvents.map((event) => (
                      <div
                        key={event.id}
                        className="rounded-md border border-slate-800 bg-slate-950 p-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="text-xs font-medium text-slate-200">
                            {event.event_type}
                          </div>
                          <div className="text-[10px] text-slate-500">
                            {formatTimestamp(event.created_at)}
                          </div>
                        </div>
                        <div className="mt-1 text-[11px] text-slate-400">
                          {event.old_value ?? "-"} → {event.new_value ?? "-"}
                        </div>
                        {event.comment && (
                          <div className="mt-1 line-clamp-2 rounded-md border border-slate-800 bg-slate-900 px-2 py-1 text-[11px] text-slate-300">
                            {event.comment}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </section>

            <section className="grid gap-3 xl:grid-cols-2">
              <Panel title="MITRE / Metadata" icon={<Database className="h-3.5 w-3.5" />}>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-300">
                  {incident.mitre ?? "No MITRE data available."}
                </pre>
              </Panel>

              <Panel title="Correlation summary" icon={<FileText className="h-3.5 w-3.5" />}>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-300">
                  {correlationSummary || "No correlation summary available."}
                </pre>
              </Panel>
            </section>

            <Panel title="Raw Wazuh alert" icon={<FileText className="h-3.5 w-3.5" />}>
              <pre className="max-h-[420px] overflow-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-300">
                {rawAlert || "No raw alert available."}
              </pre>
            </Panel>
          </div>
        )}
      </div>
    </main>
  );
}

function MetricTile({
  title,
  value,
  tone,
  icon,
}: {
  title: string;
  value: string | number;
  tone: Tone;
  icon?: ReactNode;
}) {
  const classes = toneClasses(tone);

  return (
    <div className={`rounded-lg border px-3 py-2 shadow-sm ${classes.card}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
            {title}
          </div>
          <div className="mt-0.5 truncate text-lg font-semibold leading-6 text-slate-100">
            {value}
          </div>
        </div>
        {icon && (
          <div className={`shrink-0 rounded-md bg-slate-950 p-1.5 ${classes.text}`}>
            {icon}
          </div>
        )}
      </div>
    </div>
  );
}

function Panel({
  title,
  description,
  icon,
  children,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            {icon && <div className="text-cyan-300">{icon}</div>}
            <h2 className="text-sm font-semibold">{title}</h2>
          </div>
          {description && (
            <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
              {description}
            </p>
          )}
        </div>
      </div>
      {children}
    </section>
  );
}

function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`rounded-md border px-2 py-0.5 text-[11px] ${toneClasses(tone).badge}`}>
      {children}
    </span>
  );
}

function CompactField({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="truncate text-xs text-slate-200" title={value}>
        {value}
      </div>
    </div>
  );
}

function CompactList({
  title,
  emptyLabel,
  children,
}: {
  title: string;
  emptyLabel: string;
  children: ReactNode;
}) {
  const hasChildren = Array.isArray(children)
    ? children.length > 0
    : Boolean(children);

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2">
      <div className="mb-2 text-xs font-semibold text-slate-200">{title}</div>
      {!hasChildren ? (
        <EmptyState label={emptyLabel} />
      ) : (
        <div className="max-h-56 space-y-2 overflow-auto pr-1">{children}</div>
      )}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-2 text-xs text-slate-500">
      {label}
    </div>
  );
}
