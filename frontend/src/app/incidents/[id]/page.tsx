"use client";

import { downloadBackendFile } from "@/lib/download";
import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import AppNavigation from "../../../components/AppNavigation";
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  ClipboardList,
  Database,
  FileDown,
  FileText,
  Network,
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

type NetworkEvidenceItem = {
  id: number;
  source: string | null;
  event_type: string;
  event_timestamp: string | null;
  src_ip: string | null;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  hostname: string | null;
  url: string | null;
  http_method: string | null;
  http_user_agent: string | null;
  tls_sni: string | null;
  alert_signature: string | null;
  alert_category: string | null;
  alert_severity: number | null;
  created_at: string | null;
};

type IncidentNetworkEvidence = {
  incident_id: number;
  incident_timestamp: string | null;
  correlation_window_minutes: number;
  matched_ips: string[];
  matched_hostnames: string[];
  summary: {
    total: number;
    alert: number;
    dns: number;
    http: number;
    tls: number;
    flow: number;
  };
  items: NetworkEvidenceItem[];
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

type CorrelationTimelineEvent = {
  id?: number;
  timestamp?: string | null;
  agent?: string | null;
  rule?: string | null;
  level?: number | null;
  risk_score?: number | null;
  status?: string | null;
  correlation_score?: number | null;
  relationship: "current" | "related";
};

type Tone = "success" | "warning" | "danger" | "primary" | "neutral" | "executive";

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

type HierarchicalAiItem = {
  title: string;
  children: string[];
};

type RemediationPhase = "Validate" | "Contain" | "Remediate" | "Close";

const INCIDENT_STATUSES = [
  "NEW",
  "TRIAGED",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "CLOSED",
  "FALSE_POSITIVE",
  "ESCALATED",
];

const INCIDENT_EXCEPTION_STATUSES = ["FALSE_POSITIVE", "ESCALATED"];

const INCIDENT_WORKFLOW_STATUSES = INCIDENT_STATUSES.filter(
  (status) => !INCIDENT_EXCEPTION_STATUSES.includes(status)
);

const AI_REMEDIATION_HEADINGS = [
  "suggested remediation",
  "suggested remediations",
  "recommended actions",
  "next actions",
];

const AI_SUBSECTION_HEADINGS = [
  "short executive summary",
  "executive summary",
  "recommended checks",
  "recommended check",
  ...AI_REMEDIATION_HEADINGS,
];

const REVIEW_CHECKS = [
  "Validate the AI interpretation against raw Wazuh evidence.",
  "Confirm whether correlation context supports escalation.",
  "Check affected host, rule metadata and related events.",
  "Document analyst conclusion before closing or escalating.",
];

function riskLabel(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 80) return "Critical";
  if (value >= 60) return "High";
  if (value >= 40) return "Medium";
  return "Low";
}

function toneForRisk(score: number | null | undefined): Tone {
  const value = score ?? 0;

  if (value >= 80) return "danger";
  if (value >= 60) return "warning";
  if (value >= 40) return "primary";
  return "success";
}

function toneForStatus(status: string | null | undefined): Tone {
  const value = (status ?? "NEW").toUpperCase();

  if (value === "ESCALATED") return "danger";
  if (value === "TRIAGED" || value === "INVESTIGATING") return "primary";
  if (value === "CONTAINED") return "warning";
  if (value === "RESOLVED" || value === "CLOSED") return "success";
  if (value === "FALSE_POSITIVE") return "executive";

  return "neutral";
}

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { panel: string; badge: string; text: string }> = {
    success: {
      panel: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
    },
    warning: {
      panel: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
    },
    danger: {
      panel: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
    },
    primary: {
      panel: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
    },
    neutral: {
      panel: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
    },
    executive: {
      panel: "border-violet-900/70 bg-violet-950/20",
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

function parseMitreTags(value: string | null | undefined): string[] {
  if (!value) return [];

  const collect = (input: unknown): string[] => {
    if (!input) return [];

    if (Array.isArray(input)) {
      return input.flatMap(collect);
    }

    if (typeof input === "object") {
      return Object.values(input as Record<string, unknown>).flatMap(collect);
    }

    const text = String(input).trim();
    if (!text || text === "[]" || text === "{}") return [];

    try {
      return collect(JSON.parse(text));
    } catch {
      return text.toUpperCase().match(/T\d{4}(?:\.\d{3})?/g) ?? [];
    }
  };

  return Array.from(new Set(collect(value)));
}

function formatCorrelationLabel(value: string | null | undefined) {
  if (!value) return "-";

  return value
    .replaceAll("_", " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function correlationReason(
  incident: IncidentDetail,
  summary: CorrelationSummary | null,
  matchedAttackChains: NonNullable<CorrelationSummary["matched_attack_chains"]>,
  matchedPatterns: Array<[string, { keywords?: string[]; weight?: number }]>
) {
  if (incident.escalation_reason) return incident.escalation_reason;

  const chainReason = matchedAttackChains.find((chain) => chain.reason)?.reason;
  if (chainReason) return chainReason;

  const pattern = matchedPatterns[0];
  if (pattern) {
    const [name, details] = pattern;
    const keywords = details.keywords?.slice(0, 4).join(", ");

    return `Matched ${formatCorrelationLabel(name)} pattern${
      keywords ? ` using ${keywords}` : ""
    }.`;
  }

  if (summary?.related_events) {
    return `${summary.related_events} related event(s) were found in the correlation window.`;
  }

  if (incident.correlation_type || incident.attack_chain) {
    return "Incident was enriched with correlation metadata, but no structured explanation is available.";
  }

  return "No structured correlation decision data is available for this incident.";
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
  return `${value.slice(0, max - 1)}...`;
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


async function fetchIncidentNetworkEvidence(id: string): Promise<IncidentNetworkEvidence> {
  const response = await authFetch(`/incidents/${id}/network-evidence?window_minutes=120&limit=25`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to load network evidence: ${response.status}`);
  }

  return response.json();
}



function normalizeAiLine(line: string): string {
  return line
    .replace(/^[-*•]\s+/, "")
    .replace(/^\d+[.)]\s+/, "")
    .replace(/^#{1,4}\s*/, "")
    .replace(/^\*\*(.*)\*\*:?$/, "$1")
    .trim();
}

function splitAiSentences(value: string): string[] {
  const normalized = value.replace(/\r\n/g, "\n").trim();

  if (!normalized) return [];

  const withExplicitSections = normalized.replace(
    /\s*(?:\d+[.)]\s*)?(Short executive summary|Executive summary|Recommended checks|Recommended check|Suggested remediation|Suggested remediations|Recommended actions|Next actions):\s*/gi,
    "\n$1:\n"
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

  if (risk >= 80 || priority === "CRITICAL") return "Immediate escalation review";
  if (risk >= 60 || priority === "HIGH") return "Priority analyst investigation";
  if (risk >= 40 || priority === "MEDIUM") return "Standard triage review";
  return "Monitor and validate";
}

function canonicalAiHeading(line: string): string {
  return normalizeAiLine(line)
    .replace(/:$/, "")
    .trim()
    .toLowerCase();
}

function isAiSubsectionHeading(line: string): boolean {
  return AI_SUBSECTION_HEADINGS.includes(canonicalAiHeading(line));
}

function isAiRemediationHeading(line: string): boolean {
  return AI_REMEDIATION_HEADINGS.includes(canonicalAiHeading(line));
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

function flattenAiItems(items: HierarchicalAiItem[]): string[] {
  return items
    .flatMap((item) => [item.title, ...item.children])
    .map(stripAiListMarker)
    .filter((line) => line && !isAiSubsectionHeading(line));
}

function dedupeAiItems(items: HierarchicalAiItem[]): HierarchicalAiItem[] {
  const seen = new Set<string>();

  return items.filter((item) => {
    const key = `${item.title}|${item.children.join("|")}`.toLowerCase();

    if (seen.has(key)) return false;

    seen.add(key);
    return true;
  });
}

function remediationItemsFromAiSections(
  sections: ParsedAiSection[]
): HierarchicalAiItem[] {
  const items: HierarchicalAiItem[] = [];

  for (const section of sections) {
    const sectionIsRemediation = isAiRemediationHeading(section.title);
    const structuredItems = buildHierarchicalAiItems(section.lines);

    if (sectionIsRemediation) {
      for (const item of structuredItems) {
        items.push(item);
      }

      if (structuredItems.length === 0) {
        for (const line of section.lines) {
          items.push({ title: line, children: [] });
        }
      }

      continue;
    }

    for (const item of structuredItems) {
      if (!isAiRemediationHeading(item.title)) continue;

      if (item.children.length > 0) {
        for (const child of item.children) {
          items.push({ title: child, children: [] });
        }
      } else {
        items.push(item);
      }
    }
  }

  return dedupeAiItems(items).filter((item) => item.title || item.children.length > 0);
}

function contextRemediationItems(
  incident: IncidentAiAssessmentInput
): HierarchicalAiItem[] {
  const host = incident.agent ?? "affected host";
  const rule = incident.rule ?? "the triggering Wazuh rule";
  const risk = incident.risk_score ?? 0;
  const correlationScore = incident.correlation_score ?? 0;
  const actions: HierarchicalAiItem[] = [
    {
      title: "Validate and preserve evidence",
      children: [
        `Review raw Wazuh alert, ${rule}, affected host ${host}, timestamps and audit context before changing status.`,
      ],
    },
    {
      title: "Scope affected activity",
      children: [
        "Check recent alerts from the same host, user, source IP and detection family.",
      ],
    },
  ];

  if (risk >= 60 || (incident.recommended_priority ?? "").toUpperCase() === "HIGH") {
    actions.push({
      title: "Prepare containment decision",
      children: [
        `Prioritize host ${host} for containment review, credential checks and endpoint telemetry validation.`,
      ],
    });
  }

  if (correlationScore > 0 || incident.correlation_type || incident.attack_chain) {
    actions.push({
      title: "Remediate correlated chain",
      children: [
        `Use ${incident.correlation_type ?? "correlation context"} and ${incident.attack_chain ?? "attack chain context"} to identify upstream and downstream tasks.`,
      ],
    });
  }

  actions.push({
    title: "Document closure criteria",
    children: [
      "Record validation, remediation outcome and residual risk before moving to a terminal status.",
    ],
  });

  return actions;
}

function remediationPhase(item: HierarchicalAiItem): RemediationPhase {
  const text = `${item.title} ${item.children.join(" ")}`.toLowerCase();

  if (/\b(close|closure|document|residual|resolved|false_positive|false positive)\b/.test(text)) {
    return "Close";
  }

  if (/\b(contain|containment|isolate|block|disable|credential|quarantine|escalat)\b/.test(text)) {
    return "Contain";
  }

  if (/\b(remediate|remove|patch|recover|restore|reset|harden|eradicate)\b/.test(text)) {
    return "Remediate";
  }

  return "Validate";
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
    <div className={`rounded-md border px-2.5 py-2 shadow-sm ${classes.panel}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
            {title}
          </div>
          <div className="mt-0.5 truncate text-sm font-semibold leading-5 text-slate-100">
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
    <section className="rounded-md border border-slate-800 bg-slate-900/80 shadow-sm">
      <div className="flex items-start justify-between gap-3 border-b border-slate-800 px-3 py-2">
        <div>
          <div className="flex items-center gap-2">
            {icon && <div className="text-cyan-300">{icon}</div>}
            <h2 className="text-sm font-semibold uppercase tracking-wide">{title}</h2>
          </div>
          {description && (
            <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
              {description}
            </p>
          )}
        </div>
      </div>
      <div className="p-3">{children}</div>
    </section>
  );
}

function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex h-5 items-center justify-center rounded-md border px-2 text-[10px] font-medium leading-none ${toneClasses(tone).badge}`}>
      {children}
    </span>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5 text-xs text-slate-500">
      {label}
    </div>
  );
}

function DenseField({ label, value }: { label: string; value?: string | number | null }) {
  return (
    <div className="min-w-0 bg-slate-950 px-2.5 py-2">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-0.5 line-clamp-2 break-words text-xs leading-5 text-slate-200">
        {value || "-"}
      </div>
    </div>
  );
}

function CommandButton({
  children,
  tone = "neutral",
  disabled,
  onClick,
}: {
  children: ReactNode;
  tone?: "neutral" | "primary" | "success";
  disabled?: boolean;
  onClick?: () => void;
}) {
  const className =
    tone === "success"
      ? "border-emerald-700 bg-emerald-500 text-slate-950 hover:bg-emerald-400"
      : tone === "primary"
        ? "border-cyan-700 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
        : "border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium shadow-sm disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    >
      {children}
    </button>
  );
}

function LinkCommand({
  children,
  tone = "neutral",
  onClick,
}: {
  children: ReactNode;
  tone?: "neutral" | "primary";
  onClick: () => void;
}) {
  const className =
    tone === "primary"
      ? "border-cyan-700 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
      : "border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800";

  return (
    <a
      href="#"
      onClick={(event) => {
        event.preventDefault();
        onClick();
      }}
      download
      className={`inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium shadow-sm ${className}`}
    >
      {children}
    </a>
  );
}

function LifecycleConsole({
  status,
  timestamp,
  onStatusChange,
  readOnly = false,
}: {
  status: string | null | undefined;
  timestamp: string | null | undefined;
  onStatusChange?: (status: string) => void;
  readOnly?: boolean;
}) {
  const currentStatus = (status ?? "NEW").toUpperCase();
  const activeWorkflowIndex = INCIDENT_WORKFLOW_STATUSES.indexOf(currentStatus);
  const activeTone = toneForStatus(currentStatus);
  const activeClasses = toneClasses(activeTone);

  const handleChange = (nextStatus: string) => {
    if (readOnly || !onStatusChange) return;
    onStatusChange(nextStatus);
  };

  return (
    <div className="space-y-3">
      <div className={`rounded-md border px-2.5 py-2 ${activeClasses.panel}`}>
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              Current state
            </div>
            <div className="mt-1 flex items-center gap-2">
              <Badge tone={activeTone}>{currentStatus}</Badge>
              {activeWorkflowIndex >= 0 && (
                <span className="text-[10px] uppercase tracking-wide text-slate-500">
                  Workflow {activeWorkflowIndex + 1}/{INCIDENT_WORKFLOW_STATUSES.length}
                </span>
              )}
            </div>
          </div>

          <div className="text-right">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              Event time
            </div>
            <div className="mt-1 text-[11px] text-slate-300">
              {shortTimestamp(timestamp)}
            </div>
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950">
        <div className="border-b border-slate-800 bg-slate-900/70 px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          Primary workflow
        </div>
        <div className="divide-y divide-slate-800">
          {INCIDENT_WORKFLOW_STATUSES.map((candidate, index) => {
            const isActive = candidate === currentStatus;
            const isCompleted = activeWorkflowIndex >= 0 && index < activeWorkflowIndex;

            return (
              <button
                key={candidate}
                type="button"
                aria-pressed={isActive}
                disabled={readOnly}
                onClick={() => handleChange(candidate)}
                className={`grid h-8 w-full grid-cols-[1.25rem_1fr_auto] items-center gap-2 border-l-2 px-2 text-left text-xs transition disabled:cursor-default ${
                  isActive
                    ? "border-l-cyan-400 bg-cyan-950/40 text-cyan-100"
                    : isCompleted
                      ? "border-l-emerald-800 bg-emerald-950/15 text-slate-300"
                      : "border-l-transparent bg-slate-950 text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                }`}
              >
                <span
                  className={`flex h-4 w-4 items-center justify-center rounded-sm border text-[9px] font-semibold ${
                    isActive
                      ? "border-cyan-400 bg-cyan-500 text-slate-950"
                      : isCompleted
                        ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                        : "border-slate-700 bg-slate-900 text-slate-500"
                  }`}
                >
                  {index + 1}
                </span>
                <span className="truncate font-medium">{candidate}</span>
                <span className="text-[10px] uppercase tracking-wide text-slate-600">
                  {isActive ? "Now" : isCompleted ? "Done" : "Next"}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="rounded-md border border-slate-800 bg-slate-950 p-2">
        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          Exception disposition
        </div>
        <div className="grid grid-cols-2 gap-1.5">
          {INCIDENT_EXCEPTION_STATUSES.map((candidate) => {
            const isActive = candidate === currentStatus;
            return (
              <button
                key={candidate}
                type="button"
                aria-pressed={isActive}
                disabled={readOnly}
                onClick={() => handleChange(candidate)}
                className={`inline-flex h-7 items-center justify-center rounded-md border px-2 text-[10px] font-semibold leading-none transition disabled:cursor-default ${
                  isActive
                    ? "border-cyan-400 bg-cyan-500 text-slate-950"
                    : "border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700 hover:bg-slate-900 hover:text-slate-200"
                }`}
              >
                {candidate}
              </button>
            );
          })}
        </div>
      </div>

      {readOnly && (
        <div className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5 text-[11px] leading-4 text-slate-500">
          Read-only access: your role can review lifecycle state but cannot modify it.
        </div>
      )}
    </div>
  );
}

function ExecutiveBrief({
  lines,
  decision,
}: {
  lines: string[];
  decision: string;
}) {
  const items = buildHierarchicalAiItems(lines);
  const flattenedLines = flattenAiItems(items);
  const summary = flattenedLines[0] ?? "No executive assessment available.";
  const keyFindings = flattenedLines.slice(1, 4);

  return (
    <div className="space-y-2">
      <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 xl:grid-cols-[minmax(0,1fr)_220px]">
        <DenseField label="Briefing summary" value={summary} />
        <DenseField label="Decision posture" value={decision} />
      </div>

      {keyFindings.length > 0 && (
        <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 md:grid-cols-3">
          {keyFindings.map((finding, index) => (
            <DenseField key={`${finding}-${index}`} label="Key point" value={finding} />
          ))}
        </div>
      )}

      <details className="rounded-md border border-slate-800 bg-slate-950">
        <summary className="cursor-pointer px-2.5 py-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400 hover:text-cyan-200">
          Full assessment detail
        </summary>
        <div className="max-h-64 space-y-1.5 overflow-auto border-t border-slate-800 p-2.5">
          {flattenedLines.map((line, index) => (
            <div key={`${line}-${index}`} className="text-xs leading-5 text-slate-300">
              {line}
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

function DecisionMatrix({ incident }: { incident: IncidentAiAssessmentInput }) {
  const fields: Array<[string, string | number | null | undefined]> = [
    ["Correlation type", incident.correlation_type],
    ["Attack chain", incident.attack_chain],
    ["Escalation reason", incident.escalation_reason],
    ["Affected host", incident.agent],
    ["Detection rule", incident.rule],
  ];

  return (
    <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 md:grid-cols-2 xl:grid-cols-5">
      {fields.map(([label, value]) => (
        <DenseField key={label} label={label} value={value} />
      ))}
    </div>
  );
}

function ResponseBoard({
  incident,
  sections,
}: {
  incident: IncidentAiAssessmentInput;
  sections: ParsedAiSection[];
}) {
  const aiItems = remediationItemsFromAiSections(sections);
  const items = aiItems.length > 0 ? aiItems : contextRemediationItems(incident);
  const sourceLabel = aiItems.length > 0 ? "AI output" : "Context generated";
  const phases: Array<{
    key: RemediationPhase;
    description: string;
    items: HierarchicalAiItem[];
  }> = [
    {
      key: "Validate",
      description: "Confirm evidence and scope.",
      items: items.filter((item) => remediationPhase(item) === "Validate"),
    },
    {
      key: "Contain",
      description: "Limit impact and exposure.",
      items: items.filter((item) => remediationPhase(item) === "Contain"),
    },
    {
      key: "Remediate",
      description: "Remove cause and recover.",
      items: items.filter((item) => remediationPhase(item) === "Remediate"),
    },
    {
      key: "Close",
      description: "Document outcome and residual risk.",
      items: items.filter((item) => remediationPhase(item) === "Close"),
    },
  ];

  return (
    <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950">
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/70 px-2.5 py-1.5">
        <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          Response board
        </div>
        <span className="inline-flex h-5 items-center rounded-sm border border-slate-700 bg-slate-950 px-2 text-[10px] leading-none text-slate-400">
          {sourceLabel}
        </span>
      </div>

      <div className="grid gap-px bg-slate-800 lg:grid-cols-4">
        {phases.map((phase) => (
          <div key={phase.key} className="min-h-32 bg-slate-950">
            <div className="border-b border-slate-800 px-2.5 py-2">
              <div className="text-[10px] font-semibold uppercase tracking-wide text-emerald-300">
                {phase.key}
              </div>
              <div className="mt-0.5 text-[11px] leading-4 text-slate-500">
                {phase.description}
              </div>
            </div>

            <div className="divide-y divide-slate-800">
              {phase.items.length === 0 ? (
                <div className="px-2.5 py-2 text-xs text-slate-600">No action.</div>
              ) : (
                phase.items.map((item, index) => (
                  <div key={`${phase.key}-${item.title}-${index}`} className="px-2.5 py-2">
                    <div className="text-xs font-semibold leading-5 text-slate-100">
                      {item.title}
                    </div>
                    <div className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-slate-400">
                      {item.children.join(" ") || "-"}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReviewChecklist() {
  return (
    <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 sm:grid-cols-2">
      {REVIEW_CHECKS.map((item) => (
        <div key={item} className="flex gap-2 bg-slate-950 px-2.5 py-2">
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300" />
          <div className="text-xs leading-5 text-slate-300">{item}</div>
        </div>
      ))}
    </div>
  );
}

function AnalystNotesPanel({
  notes,
  noteDraft,
  savingNote,
  canOperate,
  isViewer,
  onNoteDraftChange,
  onAddNote,
}: {
  notes: IncidentNote[];
  noteDraft: string;
  savingNote: boolean;
  canOperate: boolean;
  isViewer: boolean;
  onNoteDraftChange: (value: string) => void;
  onAddNote: () => void;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
          Investigation rationale
        </div>
        <span className="inline-flex h-5 items-center rounded-sm border border-slate-700 bg-slate-900 px-2 text-[10px] leading-none text-slate-400">
          {notes.length} notes
        </span>
      </div>

      {isViewer && (
        <p className="rounded-md border border-slate-800 bg-slate-900/70 px-2 py-1.5 text-[11px] leading-4 text-slate-500">
          Read-only access: your role can review existing analyst notes but cannot add new notes.
        </p>
      )}

      {canOperate && (
        <div className="grid gap-2 lg:grid-cols-[1fr_auto] lg:items-end">
          <textarea
            value={noteDraft}
            onChange={(event) => onNoteDraftChange(event.target.value)}
            placeholder="Write an analyst note..."
            className="min-h-14 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-400"
          />

          <button
            onClick={onAddNote}
            disabled={savingNote || !noteDraft.trim()}
            className="inline-flex h-8 items-center justify-center rounded-md bg-cyan-500 px-3 text-xs font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {savingNote ? "Saving..." : "Add note"}
          </button>
        </div>
      )}

      {notes.length === 0 ? (
        <EmptyState label="No analyst notes available." />
      ) : (
        <div className="max-h-48 divide-y divide-slate-800 overflow-auto rounded-md border border-slate-800 bg-slate-950">
          {notes.map((note) => (
            <div key={note.id} className="px-2.5 py-2">
              <div className="mb-1 text-[10px] uppercase tracking-wide text-slate-500">
                {formatTimestamp(note.created_at)} · {note.created_by ?? "local_analyst"}
              </div>
              <p className="whitespace-pre-wrap text-xs leading-5 text-slate-200">{note.note}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ConsoleRow({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="grid border-b border-slate-800 last:border-b-0 xl:grid-cols-[220px_1fr]">
      <div className="border-b border-slate-800 bg-slate-900/60 px-3 py-2.5 xl:border-b-0 xl:border-r">
        <h3 className="text-[11px] font-semibold uppercase tracking-wide text-slate-100">
          {title}
        </h3>
        <p className="mt-1 text-[11px] leading-4 text-slate-500">{description}</p>
      </div>

      <div className="min-w-0 bg-slate-950 px-3 py-2.5">{children}</div>
    </section>
  );
}

function InvestigationConsole({
  incident,
  notes,
  noteDraft,
  savingNote,
  canOperate,
  isViewer,
  onNoteDraftChange,
  onAddNote,
}: {
  incident: IncidentAiAssessmentInput;
  notes: IncidentNote[];
  noteDraft: string;
  savingNote: boolean;
  canOperate: boolean;
  isViewer: boolean;
  onNoteDraftChange: (value: string) => void;
  onAddNote: () => void;
}) {
  const analysis = (incident.ai_analysis ?? "").trim();
  const sections = analysis ? parseAiAnalysis(analysis) : [];
  const primary = sections[0];
  const secondary = sections
    .slice(1)
    .filter((section) => !isAiRemediationHeading(section.title));
  const decision = assessmentDecision(incident);

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950 shadow-sm">
        <div className="border-b border-slate-800 bg-slate-900/80 p-3">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wide text-violet-300">
                AI investigation console
              </div>
              <h3 className="mt-1 text-sm font-semibold tracking-tight text-slate-100">
                {decision}
              </h3>
              <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">
                One review surface for assessment, response planning, validation and notes.
              </p>
            </div>

            <div className="flex flex-wrap gap-1.5">
              <Badge tone={toneForRisk(incident.risk_score)}>
                {riskLabel(incident.risk_score)}
              </Badge>
              <Badge tone={toneForStatus(incident.status)}>
                {incident.status ?? "NEW"}
              </Badge>
              <Badge tone="warning">Human approval</Badge>
            </div>
          </div>
        </div>

        <ConsoleRow
          title="Executive brief"
          description="Compact AI summary with full detail collapsed."
        >
          {analysis ? (
            <ExecutiveBrief
              lines={primary?.lines ?? splitAiSentences(analysis)}
              decision={decision}
            />
          ) : (
            <EmptyState label="No AI analysis available." />
          )}

          {secondary.length > 0 && (
            <details className="mt-2 rounded-md border border-slate-800 bg-slate-950">
              <summary className="cursor-pointer px-2.5 py-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400 hover:text-cyan-200">
                Additional AI context
              </summary>
              <div className="grid gap-2 border-t border-slate-800 p-2.5 xl:grid-cols-2">
                {secondary.map((section) => (
                  <div key={section.title} className="space-y-1.5">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">
                      {section.title}
                    </div>
                    {flattenAiItems(buildHierarchicalAiItems(section.lines)).slice(0, 4).map((line) => (
                      <div key={line} className="line-clamp-2 text-xs leading-5 text-slate-300">
                        {line}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </details>
          )}
        </ConsoleRow>

        <ConsoleRow
          title="Decision facts"
          description="Incident facts needed before escalation or closure."
        >
          <DecisionMatrix incident={incident} />
        </ConsoleRow>

        <ConsoleRow
          title="Response plan"
          description="Actions grouped by operational phase."
        >
          <ResponseBoard incident={incident} sections={sections} />
        </ConsoleRow>

        <ConsoleRow
          title="Human review"
          description="Validation gates and analyst rationale."
        >
          <div className="grid gap-3 xl:grid-cols-[0.95fr_1.05fr]">
            <ReviewChecklist />
            <AnalystNotesPanel
              notes={notes}
              noteDraft={noteDraft}
              savingNote={savingNote}
              canOperate={canOperate}
              isViewer={isViewer}
              onNoteDraftChange={onNoteDraftChange}
              onAddNote={onAddNote}
            />
          </div>
        </ConsoleRow>
      </div>

      <details className="rounded-md border border-slate-800 bg-slate-950">
        <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-slate-300 hover:text-cyan-200">
          Show original AI output
        </summary>
        <pre className="max-h-56 overflow-auto whitespace-pre-wrap border-t border-slate-800 p-3 text-xs leading-5 text-slate-400">
          {analysis || "No AI analysis available."}
        </pre>
      </details>
    </div>
  );
}

function CorrelationConsole({
  incident,
  parsedCorrelationSummary,
  matchedPatterns,
  matchedAttackChains,
  relatedCorrelationEvents,
}: {
  incident: IncidentDetail;
  parsedCorrelationSummary: CorrelationSummary | null;
  matchedPatterns: Array<[string, { keywords?: string[]; weight?: number }]>;
  matchedAttackChains: NonNullable<CorrelationSummary["matched_attack_chains"]>;
  relatedCorrelationEvents: NonNullable<CorrelationSummary["related_event_details"]>;
}) {
  const mitreTags = parseMitreTags(incident.mitre);
  const finalScore =
    parsedCorrelationSummary?.final_correlation_score ??
    incident.correlation_score ??
    0;
  const relatedCount =
    parsedCorrelationSummary?.related_events ?? relatedCorrelationEvents.length;
  const whyIncident = correlationReason(
    incident,
    parsedCorrelationSummary,
    matchedAttackChains,
    matchedPatterns
  );
  const timelineEvents: CorrelationTimelineEvent[] = [
    {
      id: incident.id,
      timestamp: incident.timestamp,
      agent: incident.agent,
      rule: incident.rule,
      level: incident.level,
      risk_score: incident.risk_score,
      status: incident.status,
      correlation_score: incident.correlation_score,
      relationship: "current" as const,
    },
    ...relatedCorrelationEvents.map((event) => ({
      ...event,
      relationship: "related" as const,
    })),
  ]
    .sort((a, b) => {
      const aTime = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const bTime = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return aTime - bTime;
    })
    .slice(0, 8);
  const hasStructuredCorrelation = Boolean(parsedCorrelationSummary);

  return (
    <div className="space-y-2.5">
      <div className="rounded-md border border-slate-800 bg-slate-950 px-3 py-2">
        <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">
              Why this became an incident
            </div>
            <p className="mt-1 text-xs leading-5 text-slate-300">
              {whyIncident}
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-1.5">
            <Badge tone={toneForRisk(finalScore)}>Score {finalScore}</Badge>
            <Badge tone={incident.correlated ? "executive" : "neutral"}>
              {incident.correlated ? "Correlated" : "Single signal"}
            </Badge>
          </div>
        </div>
      </div>

      <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 sm:grid-cols-2 xl:grid-cols-5">
        <DenseField label="Correlation type" value={formatCorrelationLabel(incident.correlation_type)} />
        <DenseField label="Attack chain" value={incident.attack_chain ?? "-"} />
        <DenseField label="MITRE" value={mitreTags.length ? mitreTags.join(", ") : "-"} />
        <DenseField label="Related events" value={relatedCount} />
        <DenseField label="Decision score" value={finalScore} />
      </div>

      {!hasStructuredCorrelation && (
        <EmptyState label="No structured correlation payload is available yet. Showing incident-level correlation metadata only." />
      )}

      <div className="grid gap-2 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="rounded-md border border-slate-800 bg-slate-950">
          <div className="border-b border-slate-800 bg-slate-900/70 px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-300">
            Event timeline
          </div>
          <div className="divide-y divide-slate-800">
            {timelineEvents.length === 0 ? (
              <div className="p-2">
                <EmptyState label="No timeline events available." />
              </div>
            ) : (
              timelineEvents.map((event, index) => (
                <div key={`${event.relationship}-${event.id ?? index}`} className="grid grid-cols-[82px_1fr] gap-2 px-2.5 py-2">
                  <div className="text-[10px] leading-4 text-slate-500">
                    {event.relationship === "current" ? "Current" : "Related"}
                    <div className="mt-0.5 h-full border-l border-slate-800 pl-2 text-slate-600">
                      {index + 1}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      {event.id ? (
                        <Link
                          href={`/incidents/${event.id}`}
                          className="text-xs font-semibold text-cyan-300 hover:text-cyan-200"
                        >
                          Incident #{event.id}
                        </Link>
                      ) : (
                        <span className="text-xs font-semibold text-slate-200">
                          Related signal
                        </span>
                      )}
                      <span className="shrink-0 text-[10px] text-slate-500">
                        risk {event.risk_score ?? 0}
                      </span>
                    </div>
                    <div className="mt-0.5 text-[10px] uppercase tracking-wide text-slate-500">
                      {shortTimestamp(event.timestamp)}
                    </div>
                    <div className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-slate-300">
                      {event.rule ?? "-"}
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      <span className="rounded-sm border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] leading-none text-slate-400">
                        {event.agent ?? "unknown host"}
                      </span>
                      <span className="rounded-sm border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] leading-none text-slate-400">
                        level {event.level ?? "-"}
                      </span>
                      <span className="rounded-sm border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] leading-none text-slate-400">
                        corr {event.correlation_score ?? 0}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="grid gap-2">
          <DenseList title="Matched patterns" emptyLabel="No security patterns matched.">
            {matchedPatterns.slice(0, 6).map(([name, pattern]) => (
              <div key={name} className="grid gap-1.5 border-b border-slate-800 px-2.5 py-2 last:border-b-0">
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate text-xs font-semibold text-cyan-300">
                    {formatCorrelationLabel(name)}
                  </div>
                  <span className="min-w-10 text-right text-[11px] text-slate-500">
                    w {pattern.weight ?? 0}
                  </span>
                </div>
                <div className="line-clamp-2 text-[11px] leading-4 text-slate-400">
                  {(pattern.keywords ?? []).join(", ") || "No keywords recorded."}
                </div>
              </div>
            ))}
          </DenseList>

          <DenseList title="Attack chain evidence" emptyLabel="No multi-step attack chain matched.">
            {matchedAttackChains.slice(0, 4).map((chain, index) => (
              <div key={`${chain.name ?? "chain"}-${index}`} className="border-b border-slate-800 px-2.5 py-2 last:border-b-0">
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate text-xs font-semibold text-cyan-300">
                    {chain.name ?? "Unnamed chain"}
                  </div>
                  <span className="min-w-8 text-right text-[11px] text-slate-500">
                    +{chain.score_bonus ?? 0}
                  </span>
                </div>
                <div className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-slate-400">
                  {chain.reason ?? "No explanation available."}
                </div>
                {chain.correlation_type && (
                  <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-600">
                    {formatCorrelationLabel(chain.correlation_type)}
                  </div>
                )}
              </div>
            ))}
          </DenseList>
        </div>
      </div>

      <div className="rounded-md border border-slate-800 bg-slate-950">
        <div className="border-b border-slate-800 bg-slate-900/70 px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-300">
          Related alerts / incidents
        </div>
        {relatedCorrelationEvents.length === 0 ? (
          <div className="p-2">
            <EmptyState label="No related alerts or incidents were recorded in the correlation summary." />
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {relatedCorrelationEvents.slice(0, 8).map((event, index) => (
              <div key={`${event.id ?? "related"}-${index}`} className="grid gap-2 px-2.5 py-2 md:grid-cols-[90px_1fr_80px_80px] md:items-center">
                {event.id ? (
                  <Link
                    href={`/incidents/${event.id}`}
                    className="text-xs font-semibold text-cyan-300 hover:text-cyan-200"
                  >
                    #{event.id}
                  </Link>
                ) : (
                  <span className="text-xs font-semibold text-slate-400">
                    related
                  </span>
                )}
                <div className="min-w-0">
                  <div className="truncate text-xs text-slate-300">
                    {event.rule ?? "-"}
                  </div>
                  <div className="mt-0.5 truncate text-[10px] text-slate-500">
                    {event.agent ?? "unknown host"} · {shortTimestamp(event.timestamp)}
                  </div>
                </div>
                <div className="text-[11px] text-slate-400">
                  risk {event.risk_score ?? 0}
                </div>
                <div className="text-[11px] text-slate-400">
                  corr {event.correlation_score ?? 0}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {hasStructuredCorrelation && (
        <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 sm:grid-cols-2 lg:grid-cols-4">
          <DenseField label="Base score" value={parsedCorrelationSummary?.base_score ?? 0} />
          <DenseField label="Pattern score" value={parsedCorrelationSummary?.pattern_score ?? 0} />
          <DenseField label="Volume score" value={parsedCorrelationSummary?.volume_score ?? 0} />
          <DenseField label="Chain bonus" value={parsedCorrelationSummary?.chain_bonus ?? 0} />
        </div>
      )}
    </div>
  );
}

function DenseList({
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
    <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950">
      <div className="border-b border-slate-800 bg-slate-900/70 px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-300">
        {title}
      </div>
      {!hasChildren ? (
        <div className="p-2">
          <EmptyState label={emptyLabel} />
        </div>
      ) : (
        <div className="max-h-56 overflow-auto">{children}</div>
      )}
    </div>
  );
}

function AuditTrail({ auditEvents }: { auditEvents: AuditEvent[] }) {
  if (auditEvents.length === 0) {
    return <EmptyState label="No audit events available." />;
  }

  return (
    <div className="max-h-72 divide-y divide-slate-800 overflow-auto rounded-md border border-slate-800 bg-slate-950">
      {auditEvents.map((event) => (
        <div key={event.id} className="px-2.5 py-2">
          <div className="flex items-center justify-between gap-2">
            <div className="truncate text-xs font-semibold text-slate-200">
              {event.event_type}
            </div>
            <div className="shrink-0 text-right text-[10px] text-slate-500">
              {formatTimestamp(event.created_at)}
            </div>
          </div>
          <div className="mt-1 line-clamp-1 text-[11px] text-slate-400">
            {event.old_value ?? "-"} -&gt; {event.new_value ?? "-"}
          </div>
          {event.comment && (
            <div className="mt-1 line-clamp-2 rounded-sm bg-slate-900 px-2 py-1 text-[11px] text-slate-300">
              {event.comment}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function EvidenceBlock({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details open={defaultOpen} className="rounded-md border border-slate-800 bg-slate-950">
      <summary className="cursor-pointer px-3 py-2 text-[10px] font-semibold uppercase tracking-wide text-slate-500 hover:text-cyan-200">
        {title}
      </summary>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap border-t border-slate-800 p-3 text-xs leading-5 text-slate-300">
        {children}
      </pre>
    </details>
  );
}

function reportId(value: string | number) {
  return String(value).padStart(6, "0");
}


function formatNetworkEvidenceTimestamp(value: string | null) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function NetworkEvidencePanel({
  evidence,
}: {
  evidence: IncidentNetworkEvidence | null;
}) {
  const summary = evidence?.summary;

  return (
    <Panel title="Network evidence" icon={<Network className="h-3.5 w-3.5" />}>
      {!evidence ? (
        <p className="text-xs leading-5 text-slate-500">
          Network telemetry is not available for this incident.
        </p>
      ) : (
        <div className="space-y-3">
          <div className="grid gap-2 sm:grid-cols-3">
            <DenseField label="Related events" value={summary?.total ?? 0} />
            <DenseField label="Window" value={`${evidence.correlation_window_minutes} min`} />
            <DenseField label="Latest source" value="Suricata" />
          </div>

          <div className="grid gap-2 sm:grid-cols-5">
            <DenseField label="Alerts" value={summary?.alert ?? 0} />
            <DenseField label="DNS" value={summary?.dns ?? 0} />
            <DenseField label="HTTP" value={summary?.http ?? 0} />
            <DenseField label="TLS" value={summary?.tls ?? 0} />
            <DenseField label="Flows" value={summary?.flow ?? 0} />
          </div>

          {(evidence.matched_ips.length > 0 || evidence.matched_hostnames.length > 0) && (
            <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
              <div className="grid gap-3 md:grid-cols-2">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    Matched IPs
                  </p>
                  <p className="mt-1 break-words font-mono text-xs leading-5 text-slate-300">
                    {evidence.matched_ips.length > 0 ? evidence.matched_ips.join(", ") : "-"}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    Matched hosts
                  </p>
                  <p className="mt-1 break-words font-mono text-xs leading-5 text-slate-300">
                    {evidence.matched_hostnames.length > 0
                      ? evidence.matched_hostnames.join(", ")
                      : "-"}
                  </p>
                </div>
              </div>
            </div>
          )}

          {evidence.items.length === 0 ? (
            <div className="rounded-sm border border-dashed border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-500">
              No related Suricata network telemetry was found in the selected correlation window.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-sm border border-slate-800">
              <table className="min-w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-slate-950 text-[10px] uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2">Time</th>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Destination</th>
                    <th className="px-3 py-2">Host / SNI</th>
                    <th className="px-3 py-2">Alert</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900">
                  {evidence.items.slice(0, 8).map((item) => (
                    <tr key={item.id} className="align-top text-slate-300">
                      <td className="px-3 py-2 text-slate-500">
                        {formatNetworkEvidenceTimestamp(item.event_timestamp)}
                      </td>
                      <td className="px-3 py-2 font-mono uppercase text-slate-300">
                        {item.event_type}
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-400">
                        {item.src_ip ?? "-"}
                        {item.src_port ? `:${item.src_port}` : ""}
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-400">
                        {item.dest_ip ?? "-"}
                        {item.dest_port ? `:${item.dest_port}` : ""}
                      </td>
                      <td className="max-w-[220px] truncate px-3 py-2 text-slate-300">
                        {item.hostname ?? item.tls_sni ?? "-"}
                      </td>
                      <td className="max-w-[260px] truncate px-3 py-2 text-slate-400">
                        {item.alert_signature ?? "No IDS alert"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}


export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const incidentId = String(params.id);
  const incidentReportId = reportId(incidentId);

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [networkEvidence, setNetworkEvidence] = useState<IncidentNetworkEvidence | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [creatingCase, setCreatingCase] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);

  const canOperate =
    currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";
  const isViewer = currentUser?.role === "VIEWER";

  useEffect(() => {
    setCurrentUser(getStoredUser());

    fetchCurrentUser()
      .then((current) => setCurrentUser(current))
      .catch(() => {
        // authFetch handles expired/invalid sessions globally
      });
  }, []);

  async function loadIncident() {
    try {
      setRefreshing(true);
      setError(null);
      const [data, auditData, notesData, networkEvidenceData] = await Promise.all([
        fetchIncident(incidentId),
        fetchIncidentAudit(incidentId),
        fetchIncidentNotes(incidentId),
        fetchIncidentNetworkEvidence(incidentId),
      ]);

      setIncident(data);
      setAuditEvents(auditData);
      setNotes(notesData);
      setNetworkEvidence(networkEvidenceData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  async function updateStatus(status: string) {
    if (!canOperate) return;
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
    if (!canOperate) return;

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

  async function createCaseFromIncident() {
    if (!canOperate) return;

    try {
      setCreatingCase(true);
      setError(null);

      const response = await authFetch(`/incidents/${incidentId}/case`, {
        method: "POST",
      });

      const body = await response.json().catch(() => null);

      if (!response.ok) {
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      const caseId = body?.case_id ?? body?.item?.id;

      if (!caseId) {
        throw new Error("Case was created but the response did not include a case id.");
      }

      router.push(`/cases/${caseId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setCreatingCase(false);
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
      <div className="mx-auto max-w-[1600px] px-4 py-3">
        <AppNavigation />

        <header className="mb-3 flex flex-col gap-3 border-b border-slate-900 pb-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-1.5 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              Back to dashboard
            </Link>

            <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-cyan-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              Incident command record
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Incident #{incidentId}
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Enterprise SOC console for triage, lifecycle, AI assessment, response planning and evidence review.
            </p>
          </div>

          <div className="flex flex-wrap gap-1.5">
            <CommandButton onClick={loadIncident}>
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </CommandButton>

            {canOperate && (
              <CommandButton
                tone="success"
                disabled={creatingCase}
                onClick={createCaseFromIncident}
              >
                {creatingCase ? "Creating case..." : "Create case"}
              </CommandButton>
            )}

            <LinkCommand
              tone="primary"
              onClick={() =>
                downloadBackendFile(
                  `/reports/incidents/${incidentId}?format=markdown`,
                  `incident-${incidentReportId}-enterprise-report.md`
                ).catch((error) => alert(error.message))
              }
            >
              <FileDown className="h-3.5 w-3.5" />
              Markdown
            </LinkCommand>

            <LinkCommand
              onClick={() =>
                downloadBackendFile(
                  `/reports/incidents/${incidentId}?format=json`,
                  `incident-${incidentReportId}-enterprise-report.json`
                ).catch((error) => alert(error.message))
              }
            >
              <FileDown className="h-3.5 w-3.5" />
              JSON
            </LinkCommand>
          </div>
        </header>

        {loading && (
          <section className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading incident...
          </section>
        )}

        {error && (
          <div className="mb-3 rounded-md border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {incident && (
          <div className="space-y-3">
            <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
              <MetricTile
                title="Risk"
                value={`${riskLabel(incident.risk_score)} - ${incident.risk_score ?? 0}`}
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

            <section className="grid gap-3 xl:grid-cols-[340px_1fr]">
              {canOperate ? (
                <Panel title="Lifecycle" description="Controlled incident state transitions.">
                  <LifecycleConsole
                    status={incident.status}
                    timestamp={incident.timestamp_local ?? incident.timestamp}
                    onStatusChange={updateStatus}
                  />
                </Panel>
              ) : isViewer ? (
                <Panel title="Lifecycle" description="Read-only incident state.">
                  <LifecycleConsole
                    status={incident.status}
                    timestamp={incident.timestamp_local ?? incident.timestamp}
                    readOnly
                  />
                </Panel>
              ) : null}

              <Panel title="Detection record" description="Primary alert identity and source metadata.">
                <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 lg:grid-cols-4">
                  <DenseField
                    label="Timestamp"
                    value={incident.timestamp_local ?? formatTimestamp(incident.timestamp)}
                  />
                  <DenseField label="Agent" value={incident.agent ?? "-"} />
                  <DenseField label="Rule" value={shortText(incident.rule, 140)} />
                  <DenseField label="Wazuh doc ID" value={incident.wazuh_doc_id ?? "-"} />
                </div>
              </Panel>
            </section>

            <Panel
              title="Investigation console"
              description="AI brief, decision facts, response plan, review gates and notes in one surface."
              icon={<Brain className="h-3.5 w-3.5" />}
            >
              <InvestigationConsole
                incident={incident}
                notes={notes}
                noteDraft={noteDraft}
                savingNote={savingNote}
                canOperate={canOperate}
                isViewer={isViewer}
                onNoteDraftChange={setNoteDraft}
                onAddNote={addNote}
              />
            </Panel>

            <Panel
              title="Correlation intelligence"
              description="Explainable correlation score, matched patterns, attack chains and related events."
              icon={<Brain className="h-3.5 w-3.5" />}
            >
              <CorrelationConsole
                incident={incident}
                parsedCorrelationSummary={parsedCorrelationSummary}
                matchedPatterns={matchedPatterns}
                matchedAttackChains={matchedAttackChains}
                relatedCorrelationEvents={relatedCorrelationEvents}
              />
            </Panel>

            <section className="grid gap-3 xl:grid-cols-[1fr_420px]">
              <Panel title="Structured context" icon={<Database className="h-3.5 w-3.5" />}>
                <div className="grid gap-px overflow-hidden rounded-md border border-slate-800 bg-slate-800 lg:grid-cols-2">
                  <DenseField label="Correlation type" value={incident.correlation_type ?? "-"} />
                  <DenseField label="Recommended priority" value={incident.recommended_priority ?? "-"} />
                  <DenseField label="Attack chain" value={incident.attack_chain ?? "-"} />
                  <DenseField label="Escalation reason" value={incident.escalation_reason ?? "-"} />
                </div>
              </Panel>

              <Panel title="Audit trail" icon={<ClipboardList className="h-3.5 w-3.5" />}>
                <AuditTrail auditEvents={auditEvents} />
              </Panel>
            </section>

            <NetworkEvidencePanel evidence={networkEvidence} />

            <section className="grid gap-3 xl:grid-cols-2">
              <Panel title="MITRE / Metadata" icon={<Database className="h-3.5 w-3.5" />}>
                <EvidenceBlock title="MITRE evidence">
                  {incident.mitre ?? "No MITRE data available."}
                </EvidenceBlock>
              </Panel>

              <Panel title="Correlation summary" icon={<FileText className="h-3.5 w-3.5" />}>
                <EvidenceBlock title="Structured payload">
                  {correlationSummary || "No correlation summary available."}
                </EvidenceBlock>
              </Panel>
            </section>

            <Panel title="Raw Wazuh alert" icon={<FileText className="h-3.5 w-3.5" />}>
              <EvidenceBlock title="Raw JSON evidence">
                {rawAlert || "No raw alert available."}
              </EvidenceBlock>
            </Panel>
          </div>
        )}
      </div>
    </main>
  );
}
