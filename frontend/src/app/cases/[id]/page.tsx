"use client";

import { downloadBackendFile } from "@/lib/download";
import { authFetch } from "@/lib/auth";

import { Component, useCallback, useEffect, useMemo, useState, type ErrorInfo, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import InvestigationGraph from "../../../components/investigation-graph/InvestigationGraph";
import GovernedRemediationPanel, {
  type GovernedRemediationRecommendation,
} from "../../../components/remediation/GovernedRemediationPanel";
import { fetchCurrentUser, getStoredUser, type AuthUser } from "../../../lib/auth";
import { useParams } from "next/navigation";
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  Briefcase,
  CheckCircle2,
  CircleDashed,
  FileText,
  Loader2,
  Network,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

type IncidentCase = {
  id: number;
  group_key: string;
  title: string;
  status: string | null;
  severity: string | null;
  agent: string | null;
  correlation_type: string | null;
  risk_score: number | null;
  summary: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  incident_count: number;
  owner: string | null;
  assignee: string | null;
  sla_due_at: string | null;
  sla_status: string | null;
  sla_breach_risk: string | null;
  severity_review: string | null;
  status_reason: string | null;
  last_reviewed_by: string | null;
  last_reviewed_at: string | null;
};

type CaseIncident = {
  id: number;
  status: string | null;
  timestamp: string | null;
  timestamp_local?: string | null;
  timezone?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  risk_score: number | null;
  correlation_score: number | null;
  correlated: boolean | null;
  correlation_type: string | null;
  recommended_priority: string | null;
};

type CaseAIAnalysis = {
  id: number;
  case_id: number;
  model: string | null;
  analysis: string;
  recommended_status: string | null;
  recommended_severity: string | null;
  created_by: string | null;
  created_at: string | null;
};

type CaseAIAnalysisResponse = {
  item: CaseAIAnalysis | null;
};

type CaseAudit = {
  id: number;
  case_id: number;
  event_type: string;
  old_value: string | null;
  new_value: string | null;
  comment: string | null;
  created_by: string | null;
  created_at: string | null;
};

type CaseTimelineItem = {
  timestamp: string | null;
  event_type: string;
  title: string;
  description: string | null;
  actor: string | null;
  severity: string | null;
  status: string | null;
  source: string | null;
  reference_id: number | string | null;
  details: Record<string, unknown>;
};

type CaseTimelineResponse = {
  case_id: number;
  generated_at: string | null;
  count: number;
  items: CaseTimelineItem[];
};

type CaseClosureChecklist = {
  id: number;
  case_id: number;
  root_cause: string | null;
  evidence_reviewed: string | null;
  actions_summary: string | null;
  closure_reason: string | null;
  closure_decision: string | null;
  final_severity: string | null;
  residual_risk: string | null;
  closure_approved: boolean | null;
  closure_approved_by: string | null;
  closure_approved_at: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  created_at: string | null;
  updated_at: string | null;
};

type CaseClosureResponse = {
  case_id: number;
  case_status: string | null;
  ready_to_close: boolean;
  missing_items: string[];
  open_action_count: number;
  checklist: CaseClosureChecklist | null;
};

type ClosureForm = {
  root_cause: string;
  evidence_reviewed: string;
  actions_summary: string;
  closure_reason: string;
  closure_decision: string;
  final_severity: string;
  residual_risk: string;
  closure_approved: boolean;
  closure_approved_by: string;
};

type CaseAction = {
  id: number;
  case_id: number;
  title: string;
  description: string | null;
  category: string;
  priority: string;
  status: string;
  due_at: string | null;
  completed_at: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
};

type CaseActionSuggestion = {
  title: string;
  description?: string | null;
  category?: string | null;
  priority?: string | null;
  due_hours?: number | null;
  suggested_due_at?: string | null;
};

type CaseGenerationJobType = "analysis" | "action-suggestions";

type CaseGenerationJobStatus = "PENDING" | "RUNNING" | "SUCCESS" | "ERROR";

type CaseGenerationJob = {
  job_id: string;
  case_id: number;
  job_type: CaseGenerationJobType;
  status: CaseGenerationJobStatus;
  requested_by_username?: string | null;
  result_reference_id?: number | null;
  result?: unknown;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

type CaseGenerationJobResponse = {
  item: CaseGenerationJob | null;
};


type WorkflowForm = {
  owner: string;
  assignee: string;
  status: string;
  severity: string;
  sla_due_at: string;
  status_reason: string;
};

type ActionForm = {
  title: string;
  description: string;
  category: string;
  priority: string;
  due_at: string;
};

function severityClass(value: string | null | undefined) {
  const severity = value ?? "LOW";

  if (severity === "CRITICAL") return "bg-red-100 text-red-800 border-red-200";
  if (severity === "HIGH") return "bg-orange-100 text-orange-800 border-orange-200";
  if (severity === "MEDIUM") return "bg-yellow-100 text-yellow-800 border-yellow-200";

  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function statusClass(value: string | null | undefined) {
  const status = value ?? "OPEN";

  if (status === "ESCALATED") return "bg-red-100 text-red-800 border-red-200";
  if (status === "TRIAGED") return "bg-blue-100 text-blue-800 border-blue-200";
  if (status === "CLOSED") return "bg-slate-200 text-slate-800 border-slate-300";
  if (status === "FALSE_POSITIVE") return "bg-purple-100 text-purple-800 border-purple-200";

  return "bg-cyan-100 text-cyan-800 border-cyan-200";
}

function slaClass(value: string | null | undefined) {
  const status = value ?? "NOT_SET";

  if (status === "BREACHED") return "bg-red-100 text-red-800 border-red-200";
  if (status === "WITHIN_SLA") return "bg-emerald-100 text-emerald-800 border-emerald-200";
  if (status === "COMPLETED") return "bg-slate-200 text-slate-800 border-slate-300";

  return "bg-slate-100 text-slate-700 border-slate-200";
}

function timelineEventClass(value: string | null | undefined) {
  const eventType = value ?? "";

  if (eventType.includes("INCIDENT")) {
    return "border-orange-500 bg-orange-500";
  }

  if (eventType.includes("AI")) {
    return "border-violet-500 bg-violet-500";
  }

  if (eventType.includes("ACTION")) {
    return "border-cyan-500 bg-cyan-500";
  }

  if (eventType.includes("CLOSURE") || eventType.includes("CLOSED")) {
    return "border-emerald-500 bg-emerald-500";
  }

  if (eventType.includes("AUDIT") || eventType.includes("WORKFLOW")) {
    return "border-slate-500 bg-slate-500";
  }

  return "border-slate-400 bg-slate-400";
}

function timelineEventLabel(value: string | null | undefined) {
  if (!value) return "Event";
  return value.replaceAll("_", " ");
}

function slaLabel(value: string | null | undefined) {
  if (!value) return "NOT SET";
  return value.replace("_", " ");
}

function slaRiskLabel(value: string | null | undefined) {
  if (!value) return "UNKNOWN";
  return value.replaceAll("_", " ");
}

function slaRiskClass(value: string | null | undefined) {
  const risk = value ?? "UNKNOWN";

  if (risk === "BREACHED" || risk === "HIGH") {
    return "border-red-700 bg-red-950 text-red-200";
  }

  if (risk === "MEDIUM") {
    return "border-orange-700 bg-orange-950 text-orange-200";
  }

  if (risk === "LOW" || risk === "NONE") {
    return "border-emerald-700 bg-emerald-950 text-emerald-200";
  }

  return "border-slate-700 bg-slate-950 text-slate-300";
}

function toDatetimeLocalValue(value: string | null | undefined) {
  if (!value) return "";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "";
  }

  const offsetMs = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}

function workflowFormFromCase(item: IncidentCase): WorkflowForm {
  return {
    owner: item.owner ?? "",
    assignee: item.assignee ?? "",
    status: item.status ?? "OPEN",
    severity: item.severity_review ?? item.severity ?? "LOW",
    sla_due_at: toDatetimeLocalValue(item.sla_due_at),
    status_reason: item.status_reason ?? "",
  };
}

function closureFormFromResponse(
  response: CaseClosureResponse | null
): ClosureForm {
  const checklist = response?.checklist;

  return {
    root_cause: checklist?.root_cause ?? "",
    evidence_reviewed: checklist?.evidence_reviewed ?? "",
    actions_summary: checklist?.actions_summary ?? "",
    closure_reason: checklist?.closure_reason ?? "",
    closure_decision: checklist?.closure_decision ?? "RESOLVED",
    final_severity: checklist?.final_severity ?? "LOW",
    residual_risk: checklist?.residual_risk ?? "",
    closure_approved: Boolean(checklist?.closure_approved),
    closure_approved_by: checklist?.closure_approved_by ?? "",
  };
}

function actionStatusClass(value: string | null | undefined) {
  const status = value ?? "OPEN";

  if (status === "DONE") return "bg-emerald-100 text-emerald-800 border-emerald-200";
  if (status === "IN_PROGRESS") return "bg-blue-100 text-blue-800 border-blue-200";
  if (status === "CANCELLED") return "bg-slate-200 text-slate-800 border-slate-300";

  return "bg-cyan-100 text-cyan-800 border-cyan-200";
}

function actionPriorityClass(value: string | null | undefined) {
  const priority = value ?? "MEDIUM";

  if (priority === "CRITICAL") return "bg-red-100 text-red-800 border-red-200";
  if (priority === "HIGH") return "bg-orange-100 text-orange-800 border-orange-200";
  if (priority === "LOW") return "bg-slate-100 text-slate-700 border-slate-200";

  return "bg-yellow-100 text-yellow-800 border-yellow-200";
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

async function extractApiErrorMessage(
  response: Response,
  fallback: string
): Promise<string> {
  const payload = await response.json().catch(() => null);
  const detail = payload?.detail;

  if (typeof detail === "string") {
    return detail;
  }

  if (detail && typeof detail === "object") {
    const message =
      typeof detail.message === "string"
        ? detail.message
        : fallback;

    const missingItems = Array.isArray(detail.missing_items)
      ? detail.missing_items
      : [];

    const lines = [message];

    if (missingItems.length > 0) {
      lines.push("");
      lines.push("What still needs to be fixed:");

      for (const item of missingItems) {
        lines.push(`- ${item}`);
      }
    }

    if (
      typeof detail.open_action_count === "number" &&
      detail.open_action_count > 0
    ) {
      lines.push("");
      lines.push(
        "Resolve open or in-progress actions by marking them as DONE or CANCELLED before closing the case."
      );
    }

    return lines.join("\n");
  }

  return fallback;
}

async function fetchCase(id: string): Promise<IncidentCase> {
  const response = await authFetch(`/cases/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchCaseIncidents(id: string): Promise<CaseIncident[]> {
  const response = await authFetch(`/cases/${id}/incidents`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchCaseAnalysis(id: string): Promise<CaseAIAnalysis | null> {
  const response = await authFetch(`/cases/${id}/analysis`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  const data = (await response.json()) as CaseAIAnalysisResponse;
  return data.item;
}

async function fetchCaseAudit(id: string): Promise<CaseAudit[]> {
  const response = await authFetch(`/cases/${id}/audit`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function updateCaseWorkflow(
  id: string,
  payload: {
    owner: string;
    assignee?: string;
    status: string;
    severity: string;
    sla_due_at: string;
    status_reason: string;
    reviewed_by: string;
  }
): Promise<IncidentCase> {
  const response = await authFetch(`/cases/${id}/workflow`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(
      await extractApiErrorMessage(response, `API error ${response.status}`)
    );
  }

  return response.json();
}

async function fetchCaseTimeline(id: string): Promise<CaseTimelineResponse> {
  const response = await authFetch(`/cases/${id}/timeline`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(
      await extractApiErrorMessage(response, `API error ${response.status}`)
    );
  }

  return response.json();
}

async function fetchCaseClosure(id: string): Promise<CaseClosureResponse> {
  const response = await authFetch(`/cases/${id}/closure`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(
      await extractApiErrorMessage(response, `API error ${response.status}`)
    );
  }

  return response.json();
}

async function updateCaseClosure(
  id: string,
  payload: ClosureForm & {
    reviewed_by: string;
  }
): Promise<CaseClosureResponse> {
  const response = await authFetch(`/cases/${id}/closure`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(
      await extractApiErrorMessage(response, `API error ${response.status}`)
    );
  }

  return response.json();
}

async function fetchCaseActions(id: string): Promise<CaseAction[]> {
  const response = await authFetch(`/cases/${id}/actions`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}


function sleep(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function isRunningCaseGenerationJob(job: CaseGenerationJob | null): job is CaseGenerationJob {
  return job?.status === "PENDING" || job?.status === "RUNNING";
}

function caseGenerationJobError(job: CaseGenerationJob) {
  return job.error || `Generation job ${job.status.toLowerCase()}`;
}

function caseGenerationJobResultAsRecord(job: CaseGenerationJob) {
  if (!job.result || typeof job.result !== "object") {
    throw new Error("Generation job completed without a readable result.");
  }

  return job.result as Record<string, unknown>;
}

function caseAnalysisFromJob(job: CaseGenerationJob): CaseAIAnalysis {
  return caseGenerationJobResultAsRecord(job) as unknown as CaseAIAnalysis;
}

function actionSuggestionsFromJob(job: CaseGenerationJob): CaseActionSuggestion[] {
  const result = job.result;

  if (Array.isArray(result)) {
    return result as CaseActionSuggestion[];
  }

  const payload = caseGenerationJobResultAsRecord(job);

  if (Array.isArray(payload.actions)) {
    return payload.actions as CaseActionSuggestion[];
  }

  throw new Error("Generation job completed without action suggestions.");
}

async function startCaseGenerationJob(
  id: string,
  jobType: CaseGenerationJobType
): Promise<CaseGenerationJob> {
  const response = await authFetch(`/cases/${id}/ai-generation/${jobType}`, {
    method: "POST",
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.detail || `API error ${response.status}`);
  }

  return response.json();
}

async function fetchLatestCaseGenerationJob(
  id: string,
  jobType: CaseGenerationJobType
): Promise<CaseGenerationJob | null> {
  const response = await authFetch(`/cases/${id}/ai-generation/${jobType}/latest`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.detail || `API error ${response.status}`);
  }

  const payload = (await response.json()) as CaseGenerationJobResponse;
  return payload.item;
}

async function fetchCaseGenerationJob(
  id: string,
  jobId: string
): Promise<CaseGenerationJob> {
  const response = await authFetch(`/cases/${id}/ai-generation/jobs/${jobId}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.detail || `API error ${response.status}`);
  }

  return response.json();
}

async function waitForCaseGenerationJob(
  id: string,
  initialJob: CaseGenerationJob
): Promise<CaseGenerationJob> {
  let job = initialJob;

  for (let attempt = 0; attempt < 900; attempt += 1) {
    if (job.status === "SUCCESS") {
      return job;
    }

    if (job.status === "ERROR") {
      throw new Error(caseGenerationJobError(job));
    }

    await sleep(2000);
    job = await fetchCaseGenerationJob(id, job.job_id);
  }

  throw new Error("Generation job is still running after the client wait limit.");
}

async function generateCaseActionSuggestions(
  id: string
): Promise<CaseActionSuggestion[]> {
  const job = await waitForCaseGenerationJob(
    id,
    await startCaseGenerationJob(id, "action-suggestions")
  );

  return actionSuggestionsFromJob(job);
}

async function createCaseAction(
  id: string,
  payload: {
    title: string;
    description: string;
    category: string;
    priority: string;
    due_at: string;
    created_by: string;
  }
): Promise<CaseAction> {
  const response = await authFetch(`/cases/${id}/actions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function updateCaseAction(
  caseId: string,
  actionId: number,
  payload: {
    status?: string;
    priority?: string;
    updated_by: string;
  }
): Promise<CaseAction> {
  const response = await authFetch(`/cases/${caseId}/actions/${actionId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function generateCaseAnalysis(id: string): Promise<CaseAIAnalysis> {
  const job = await waitForCaseGenerationJob(
    id,
    await startCaseGenerationJob(id, "analysis")
  );

  return caseAnalysisFromJob(job);
}

type CaseJsonValue =
  | string
  | number
  | boolean
  | null
  | CaseJsonValue[]
  | { [key: string]: CaseJsonValue };

function cleanCaseAiRawAnalysis(value: string): string {
  return value
    .trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/```$/i, "")
    .trim();
}

function parseCaseAiJson(value: string): CaseJsonValue | null {
  const cleaned = cleanCaseAiRawAnalysis(value);

  try {
    return JSON.parse(cleaned) as CaseJsonValue;
  } catch {
    return null;
  }
}

function isCaseJsonObject(value: CaseJsonValue): value is { [key: string]: CaseJsonValue } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCaseEmptyJsonValue(value: CaseJsonValue): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "string") return value.trim().length === 0;
  if (Array.isArray(value)) return value.length === 0 || value.every(isCaseEmptyJsonValue);
  if (isCaseJsonObject(value)) return Object.values(value).every(isCaseEmptyJsonValue);
  return false;
}

function humanizeCaseAiKey(key: string): string {
  return key
    .replace(/^["']|["']$/g, "")
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

type CaseAiDecisionSectionId =
  | "executive_summary"
  | "risk_assessment"
  | "key_evidence"
  | "soc_hypothesis"
  | "recommended_immediate_actions"
  | "suggested_remediation"
  | "operational_recommendation";

type CaseAiDecisionSectionDefinition = {
  id: CaseAiDecisionSectionId;
  title: string;
  description: string;
  keywords: string[];
  tone: string;
};

type CaseAiDecisionSection = CaseAiDecisionSectionDefinition & {
  items: string[];
};

const CASE_AI_DECISION_SECTIONS: CaseAiDecisionSectionDefinition[] = [
  {
    id: "executive_summary",
    title: "Executive summary",
    description: "Short analyst-ready summary of the case.",
    keywords: ["executive summary", "summary"],
    tone: "border-violet-800 bg-violet-950/20",
  },
  {
    id: "risk_assessment",
    title: "Risk assessment",
    description: "Severity, impact and confidence drivers.",
    keywords: ["risk assessment", "risk", "severity", "impact"],
    tone: "border-orange-800 bg-orange-950/20",
  },
  {
    id: "key_evidence",
    title: "Key evidence",
    description: "Signals, incidents and correlations supporting the assessment.",
    keywords: ["key evidence", "evidence", "incidents", "mitre", "attack"],
    tone: "border-cyan-800 bg-cyan-950/20",
  },
  {
    id: "soc_hypothesis",
    title: "SOC hypothesis",
    description: "Possible interpretation, false positive angle and missing evidence.",
    keywords: ["soc hypothesis", "hypothesis", "false positive", "missing evidence", "legitimate"],
    tone: "border-slate-700 bg-slate-950",
  },
  {
    id: "recommended_immediate_actions",
    title: "Recommended immediate actions",
    description: "Checks the analyst should perform next.",
    keywords: ["recommended immediate actions", "immediate actions", "recommended actions", "actions"],
    tone: "border-emerald-800 bg-emerald-950/20",
  },
  {
    id: "suggested_remediation",
    title: "Suggested remediation",
    description: "Defensive improvements requiring human validation.",
    keywords: ["suggested remediation", "remediation", "hardening", "containment"],
    tone: "border-emerald-800 bg-emerald-950/20",
  },
  {
    id: "operational_recommendation",
    title: "Operational recommendation",
    description: "Recommended status, severity and single next step.",
    keywords: ["operational recommendation", "recommended status", "recommended severity", "next step"],
    tone: "border-blue-800 bg-blue-950/20",
  },
];

function normalizeCaseAiText(value: string) {
  return value
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/[^a-z0-9\s]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function cleanCaseAiLine(value: string) {
  return value
    .replace(/^[-*•]\s+/, "")
    .replace(/^\d+[.)]\s+/, "")
    .replace(/^#{1,6}\s*/, "")
    .replace(/^["']|["']$/g, "")
    .replace(/^\*\*(.*)\*\*$/, "$1")
    .trim();
}

function matchCaseAiSection(value: string): CaseAiDecisionSectionDefinition | null {
  const normalized = normalizeCaseAiText(cleanCaseAiLine(value));

  if (!normalized) return null;

  return (
    CASE_AI_DECISION_SECTIONS.find((section) =>
      section.keywords.some((keyword) => {
        const normalizedKeyword = normalizeCaseAiText(keyword);
        return (
          normalized === normalizedKeyword ||
          normalized.startsWith(`${normalizedKeyword} `) ||
          normalized.startsWith(`${normalizedKeyword}:`) ||
          normalized.includes(normalizedKeyword)
        );
      })
    ) ?? null
  );
}

function emptyCaseAiDecisionSections(): CaseAiDecisionSection[] {
  return CASE_AI_DECISION_SECTIONS.map((section) => ({
    ...section,
    items: [],
  }));
}

function pushCaseAiDecisionItem(
  sections: CaseAiDecisionSection[],
  sectionId: CaseAiDecisionSectionId,
  value: string
) {
  const cleaned = cleanCaseAiLine(value);

  if (!cleaned || ["{", "}", "[", "]", ",", ":"].includes(cleaned)) {
    return;
  }

  const section = sections.find((item) => item.id === sectionId);

  if (section && !section.items.includes(cleaned)) {
    section.items.push(cleaned);
  }
}

function caseJsonValueToDecisionLines(value: CaseJsonValue): string[] {
  if (isCaseEmptyJsonValue(value)) return [];

  if (typeof value !== "object" || value === null) {
    return [String(value)];
  }

  if (Array.isArray(value)) {
    return value.flatMap(caseJsonValueToDecisionLines);
  }

  return Object.entries(value).flatMap(([key, entryValue]) => {
    const lines = caseJsonValueToDecisionLines(entryValue);
    const title = humanizeCaseAiKey(key);

    if (lines.length === 0) return [];

    if (lines.length === 1) {
      return [`${title}: ${lines[0]}`];
    }

    return [`${title}:`, ...lines];
  });
}

function buildCaseAiDecisionSectionsFromJson(value: CaseJsonValue): CaseAiDecisionSection[] {
  const sections = emptyCaseAiDecisionSections();

  if (!isCaseJsonObject(value)) {
    for (const line of caseJsonValueToDecisionLines(value)) {
      pushCaseAiDecisionItem(sections, "executive_summary", line);
    }

    return sections;
  }

  for (const [key, entryValue] of Object.entries(value)) {
    const matchedSection = matchCaseAiSection(key);
    const targetSectionId = matchedSection?.id ?? "key_evidence";

    for (const line of caseJsonValueToDecisionLines(entryValue)) {
      pushCaseAiDecisionItem(sections, targetSectionId, line);
    }
  }

  return sections;
}

function stripCaseAiSectionHeadingRemainder(
  line: string,
  section: CaseAiDecisionSectionDefinition
) {
  const cleaned = cleanCaseAiLine(line);
  const normalizedLine = normalizeCaseAiText(cleaned);

  for (const keyword of section.keywords) {
    const normalizedKeyword = normalizeCaseAiText(keyword);

    if (normalizedLine === normalizedKeyword) {
      return "";
    }

    const colonPattern = new RegExp(`^${keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:\\s*`, "i");
    const withoutColonHeading = cleaned.replace(colonPattern, "").trim();

    if (withoutColonHeading !== cleaned) {
      return withoutColonHeading;
    }
  }

  return "";
}

function buildCaseAiDecisionSectionsFromText(value: string): CaseAiDecisionSection[] {
  const sections = emptyCaseAiDecisionSections();
  const lines = value
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map(cleanCaseAiLine)
    .filter(Boolean);
  let currentSectionId: CaseAiDecisionSectionId = "executive_summary";

  if (lines.length === 0) return sections;

  for (const line of lines) {
    const matchedSection = matchCaseAiSection(line);

    if (matchedSection) {
      currentSectionId = matchedSection.id;
      const remainder = stripCaseAiSectionHeadingRemainder(line, matchedSection);

      if (remainder) {
        pushCaseAiDecisionItem(sections, currentSectionId, remainder);
      }

      continue;
    }

    pushCaseAiDecisionItem(sections, currentSectionId, line);
  }

  if (sections.every((section) => section.items.length === 0)) {
    for (const line of splitCasePlainTextAnalysis(value)) {
      pushCaseAiDecisionItem(sections, "executive_summary", line);
    }
  }

  return sections;
}

function buildCaseAiDecisionSections(
  analysis: string,
  parsedJson: CaseJsonValue | null
): CaseAiDecisionSection[] {
  return parsedJson
    ? buildCaseAiDecisionSectionsFromJson(parsedJson)
    : buildCaseAiDecisionSectionsFromText(analysis);
}

function CaseAiDecisionSupportRenderer({
  analysis,
  parsedJson,
}: {
  analysis: string;
  parsedJson: CaseJsonValue | null;
}) {
  const sections = buildCaseAiDecisionSections(analysis, parsedJson);

  return (
    <div className="grid gap-3 xl:grid-cols-2">
      {sections.map((section) => (
        <div
          key={section.id}
          className={`rounded-xl border p-4 shadow-sm ${section.tone}`}
        >
          <div className="mb-3 border-b border-slate-800 pb-2">
            <div className="flex items-center justify-between gap-3">
              <h4 className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
                {section.title}
              </h4>
              <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5 text-[10px] text-slate-400">
                {section.items.length || "-"}
              </span>
            </div>
            <p className="mt-1 text-[11px] leading-4 text-slate-500">
              {section.description}
            </p>
          </div>

          {section.items.length > 0 ? (
            <div className="space-y-2">
              {section.items.map((item, index) => (
                <div
                  key={`${section.id}-${index}-${item}`}
                  className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/80 p-3"
                >
                  <span className="mt-[0.45rem] h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                  <p className="break-words text-sm leading-6 text-slate-300">
                    {item}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-xs leading-5 text-slate-500">
              Not explicitly provided by the model output.
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function splitCasePlainTextAnalysis(value: string): string[] {
  const normalized = value.replace(/\r\n/g, "\n").trim();

  if (!normalized) return [];

  const lines = normalized
    .split("\n")
    .map((line) =>
      line
        .replace(/^[-*•]\s+/, "")
        .replace(/^\d+[.)]\s+/, "")
        .replace(/^#{1,4}\s*/, "")
        .replace(/^\*\*(.*)\*\*$/, "$1")
        .trim(),
    )
    .filter(Boolean)
    .filter((line) => !["{", "}", "[", "]", ",", ":"].includes(line));

  if (lines.length > 1) return lines;

  return normalized
    .split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
    .map((line) => line.trim())
    .filter(Boolean);
}

type CaseAiAnalysisBoundaryProps = {
  children: ReactNode;
  fallback: ReactNode;
  resetKey: string | number | null;
};

type CaseAiAnalysisBoundaryState = {
  hasError: boolean;
};

class CaseAiAnalysisBoundary extends Component<
  CaseAiAnalysisBoundaryProps,
  CaseAiAnalysisBoundaryState
> {
  state: CaseAiAnalysisBoundaryState = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidUpdate(previousProps: CaseAiAnalysisBoundaryProps) {
    if (previousProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false });
    }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Case AI analysis render failed", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback;
    }

    return this.props.children;
  }
}

function CaseAiAnalysisFallback({ analysis }: { analysis: string }) {
  return (
    <div className="space-y-3 rounded-xl border border-orange-800 bg-orange-950/20 p-4">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-orange-300">
          AI analysis fallback
        </div>
        <p className="mt-2 text-sm leading-6 text-slate-300">
          The structured AI analysis could not be rendered safely. The original analyst-facing output is available below.
        </p>
      </div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-400">
        {analysis || "No AI analysis available."}
      </pre>
    </div>
  );
}

function displayCaseGeneratedBy(value?: string | null): string {
  const normalized = (value ?? "").trim();

  if (!normalized || normalized.toLowerCase() === "llm") {
    return "SOC AI Agent";
  }

  return normalized;
}

function CaseDecisionField({
  label,
  value,
}: {
  label: string;
  value?: string | number | null;
}) {
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

function EnterpriseCaseAiAnalysis({
  caseAnalysis,
  action,
}: {
  caseAnalysis: CaseAIAnalysis;
  action?: ReactNode;
}) {
  const analysis = (caseAnalysis.analysis ?? "").trim();

  if (!analysis) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No AI analysis available.
      </div>
    );
  }

  const parsedJson = parseCaseAiJson(analysis);

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-xl">
        <div className="border-b border-slate-800 bg-gradient-to-r from-slate-900 via-violet-950/40 to-slate-900 p-4">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-violet-300">
                Sovereign AI Case Assessment
              </div>
              <h3 className="mt-2 text-lg font-semibold tracking-tight text-slate-100">
                Investigation decision support
              </h3>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                AI-assisted case analysis structured for triage, escalation, remediation planning and closure readiness review.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-violet-700 bg-violet-950 px-3 py-1 text-xs font-medium text-violet-200">
                AI-assisted
              </span>
              <span className="rounded-full border border-orange-700 bg-orange-950 px-3 py-1 text-xs font-medium text-orange-200">
                Human approval required
              </span>
              <span className="rounded-full border border-cyan-700 bg-cyan-950 px-3 py-1 text-xs font-medium text-cyan-200">
                Normalized view
              </span>
              {action}
            </div>
          </div>

          <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <CaseDecisionField label="Model" value={caseAnalysis.model} />
            <CaseDecisionField label="Recommended status" value={caseAnalysis.recommended_status} />
            <CaseDecisionField label="Recommended severity" value={caseAnalysis.recommended_severity} />
            <CaseDecisionField label="Generated by" value={displayCaseGeneratedBy(caseAnalysis.created_by)} />
          </div>
        </div>

        <div className="p-4">
          <CaseAiDecisionSupportRenderer analysis={analysis} parsedJson={parsedJson} />
        </div>
      </div>

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

function reportId(value: string | number) {
  return String(value).padStart(6, "0");
}

function CaseCollapsibleSection({
  id,
  title,
  description,
  icon,
  open,
  onOpenChange,
  children,
}: {
  id: string;
  title: string;
  description?: string;
  icon?: ReactNode;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: ReactNode;
}) {
  return (
    <details
      open={open}
      onToggle={(event) => onOpenChange(event.currentTarget.open)}
      className="rounded-md border border-slate-800 bg-slate-950"
      id={id}
    >
      <summary className="cursor-pointer list-none px-3 py-2 hover:bg-slate-900/60">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-100">
              {icon && <span className="text-cyan-300">{icon}</span>}
              <span>{title}</span>
            </div>
            {description && (
              <p className="mt-0.5 text-[11px] leading-4 text-slate-500">{description}</p>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span className="text-[10px] uppercase tracking-wide text-cyan-300">
              {open ? "Close" : "Open"}
            </span>
          </div>
        </div>
      </summary>

      {open && (
        <div
          className="border-t border-slate-800 p-3"
          data-case-section-body="true"
          id={`${id}-body`}
        >
          {children}
        </div>
      )}
    </details>
  );
}

export default function CaseDetailPage() {
  const params = useParams();
  const caseId = String(params.id);
  const caseReportId = reportId(caseId);

  const [caseData, setCaseData] = useState<IncidentCase | null>(null);
  const [incidents, setIncidents] = useState<CaseIncident[]>([]);
  const [caseAnalysis, setCaseAnalysis] = useState<CaseAIAnalysis | null>(null);
  const [auditTrail, setAuditTrail] = useState<CaseAudit[]>([]);
  const [caseActions, setCaseActions] = useState<CaseAction[]>([]);
  const [caseClosure, setCaseClosure] = useState<CaseClosureResponse | null>(null);
  const [caseTimeline, setCaseTimeline] = useState<CaseTimelineItem[]>([]);
  const [timelineExpanded, setTimelineExpanded] = useState(false);
  const [auditTrailExpanded, setAuditTrailExpanded] = useState(false);
  const [relatedIncidentsExpanded, setRelatedIncidentsExpanded] = useState(false);
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({});
  const [closureForm, setClosureForm] = useState<ClosureForm>({
    root_cause: "",
    evidence_reviewed: "",
    actions_summary: "",
    closure_reason: "",
    closure_decision: "RESOLVED",
    final_severity: "LOW",
    residual_risk: "",
    closure_approved: false,
    closure_approved_by: "",
  });
  const [savingClosureChecklist, setSavingClosureChecklist] = useState(false);
  const [actionForm, setActionForm] = useState<ActionForm>({
    title: "",
    description: "",
    category: "INVESTIGATION",
    priority: "MEDIUM",
    due_at: "",
  });
  const [creatingAction, setCreatingAction] = useState(false);
  const [updatingActionId, setUpdatingActionId] = useState<number | null>(null);
  const [aiActionSuggestions, setAiActionSuggestions] = useState<
    CaseActionSuggestion[]
  >([]);
  const [generatingSuggestions, setGeneratingSuggestions] = useState(false);
  const [suggestionError, setSuggestionError] = useState<string | null>(null);
  const [creatingSuggestionIndex, setCreatingSuggestionIndex] = useState<
    number | null
  >(null);
  const [workflowForm, setWorkflowForm] = useState<WorkflowForm>({
    owner: "",
    assignee: "",
    status: "OPEN",
    severity: "LOW",
    sla_due_at: "",
    status_reason: "",
  });
  const [generatingAnalysis, setGeneratingAnalysis] = useState(false);
  const [savingWorkflow, setSavingWorkflow] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [quickActionRunning, setQuickActionRunning] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const canOperate =
    currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";
  const isViewer = currentUser?.role === "VIEWER";

  function assertCanOperate() {
    if (canOperate) return true;

    setError("Read-only access: your role can review this case but cannot modify it.");
    return false;
  }

  const currentUsername = currentUser?.username || "local_analyst";

  const loadCase = useCallback(async () => {
    try {
      setError(null);

      const [
        caseResponse,
        incidentsResponse,
        analysisResponse,
        auditResponse,
        actionsResponse,
        closureResponse,
        timelineResponse,
        latestAnalysisJob,
        latestSuggestionsJob,
      ] = await Promise.all([
        fetchCase(caseId),
        fetchCaseIncidents(caseId),
        fetchCaseAnalysis(caseId),
        fetchCaseAudit(caseId),
        fetchCaseActions(caseId),
        fetchCaseClosure(caseId),
        fetchCaseTimeline(caseId),
        fetchLatestCaseGenerationJob(caseId, "analysis").catch(() => null),
        fetchLatestCaseGenerationJob(caseId, "action-suggestions").catch(() => null),
      ]);

      setCaseData(caseResponse);
      setWorkflowForm(workflowFormFromCase(caseResponse));
      setIncidents(incidentsResponse);
      setCaseAnalysis(
        latestAnalysisJob?.status === "SUCCESS"
          ? caseAnalysisFromJob(latestAnalysisJob)
          : analysisResponse
      );
      setAuditTrail(auditResponse);
      setCaseActions(actionsResponse);
      if (latestSuggestionsJob?.status === "SUCCESS") {
        setAiActionSuggestions(actionSuggestionsFromJob(latestSuggestionsJob));
      }
      setCaseClosure(closureResponse);
      setClosureForm(closureFormFromResponse(closureResponse));
      setCaseTimeline(timelineResponse.items || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  async function runCaseActionSuggestionGeneration() {
    try {
      setGeneratingSuggestions(true);
      setSuggestionError(null);
      setError(null);

      const suggestions = await generateCaseActionSuggestions(caseId);
      setAiActionSuggestions(suggestions);
    } catch (err) {
      setSuggestionError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setGeneratingSuggestions(false);
    }
  }

  async function handleGenerateActionSuggestions() {
    if (!assertCanOperate()) return;

    await runCaseActionSuggestionGeneration();
  }

  async function handleCreateActionFromSuggestion(
    suggestion: CaseActionSuggestion,
    index: number
  ) {
    const title = suggestion.title.trim();

    if (!title) {
      setError("Suggested action title cannot be empty");
      return;
    }

    try {
      setCreatingSuggestionIndex(index);
      setError(null);

      await createCaseAction(caseId, {
        title,
        description: suggestion.description || "",
        category: suggestion.category || "INVESTIGATION",
        priority: suggestion.priority || "MEDIUM",
        due_at: suggestion.suggested_due_at || "",
        created_by: currentUsername,
      });

      setAiActionSuggestions((current) =>
        current.filter((_, itemIndex) => itemIndex !== index)
      );

      setCaseActions(await fetchCaseActions(caseId));
      setAuditTrail(await fetchCaseAudit(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setCreatingSuggestionIndex(null);
    }
  }

  async function handleCreateAction() {
    if (!assertCanOperate()) return;

    const title = actionForm.title.trim();

    if (!title) {
      setError("Action title cannot be empty");
      return;
    }

    try {
      setCreatingAction(true);
      setError(null);

      await createCaseAction(caseId, {
        title,
        description: actionForm.description,
        category: actionForm.category,
        priority: actionForm.priority,
        due_at: actionForm.due_at
          ? new Date(actionForm.due_at).toISOString()
          : "",
        created_by: currentUsername,
      });

      setActionForm({
        title: "",
        description: "",
        category: "INVESTIGATION",
        priority: "MEDIUM",
        due_at: "",
      });

      setCaseActions(await fetchCaseActions(caseId));
      setAuditTrail(await fetchCaseAudit(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setCreatingAction(false);
    }
  }

  async function handleUpdateActionStatus(actionId: number, status: string) {
    if (!assertCanOperate()) return;

    try {
      setUpdatingActionId(actionId);
      setError(null);

      const updated = await updateCaseAction(caseId, actionId, {
        status,
        updated_by: currentUsername,
      });

      setCaseActions((current) =>
        current.map((action) => (action.id === updated.id ? updated : action))
      );

      setAuditTrail(await fetchCaseAudit(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setUpdatingActionId(null);
    }
  }

  async function handleUpdateActionPriority(actionId: number, priority: string) {
    if (!assertCanOperate()) return;

    try {
      setUpdatingActionId(actionId);
      setError(null);

      const updated = await updateCaseAction(caseId, actionId, {
        priority,
        updated_by: currentUsername,
      });

      setCaseActions((current) =>
        current.map((action) => (action.id === updated.id ? updated : action))
      );

      setAuditTrail(await fetchCaseAudit(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setUpdatingActionId(null);
    }
  }

  async function handleSaveClosureChecklist() {
    if (!assertCanOperate()) return;

    try {
      setSavingClosureChecklist(true);
      setError(null);

      const response = await updateCaseClosure(caseId, {
        ...closureForm,
        closure_approved_by: closureForm.closure_approved
          ? closureForm.closure_approved_by.trim() || currentUsername
          : "",
        reviewed_by: currentUsername,
      });

      setCaseClosure(response);
      setClosureForm(closureFormFromResponse(response));
      setAuditTrail(await fetchCaseAudit(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setSavingClosureChecklist(false);
    }
  }

  async function handleSaveWorkflow() {
    if (!assertCanOperate()) return;

    try {
      setSavingWorkflow(true);
      setError(null);

      const updatedCase = await updateCaseWorkflow(caseId, {
        owner: workflowForm.owner,
        assignee: workflowForm.assignee,
        status: workflowForm.status,
        severity: workflowForm.severity,
        sla_due_at: workflowForm.sla_due_at
          ? new Date(workflowForm.sla_due_at).toISOString()
          : "",
        status_reason: workflowForm.status_reason,
        reviewed_by: currentUsername,
      });

      setCaseData(updatedCase);
      setWorkflowForm(workflowFormFromCase(updatedCase));
      setAuditTrail(await fetchCaseAudit(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setSavingWorkflow(false);
    }
  }

  async function runCaseAnalysisGeneration() {
    try {
      setGeneratingAnalysis(true);
      setError(null);

      const result = await generateCaseAnalysis(caseId);
      setCaseAnalysis(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setGeneratingAnalysis(false);
    }
  }

  async function handleGenerateAnalysis() {
    if (!assertCanOperate()) return;

    await runCaseAnalysisGeneration();
  }

  function scrollToCaseSection(sectionId: string) {
    window.setTimeout(() => {
      document.getElementById(sectionId)?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 50);
  }

  function setCaseSectionOpen(sectionId: string, open: boolean) {
    setOpenSections((current) => ({
      ...current,
      [sectionId]: open,
    }));
  }

  function openAndScrollToCaseSection(sectionId: string) {
    setCaseSectionOpen(sectionId, true);
    scrollToCaseSection(sectionId);
  }

  async function handleCaseQuickAction(
    action:
      | "ASSIGN_TO_ME"
      | "START_INVESTIGATION"
      | "ESCALATE_CASE"
      | "GENERATE_AI_ANALYSIS"
      | "GENERATE_AI_ACTION_PLAN"
      | "PREPARE_CLOSURE"
      | "CLOSE_CASE"
  ) {
    if (!caseData) {
      return;
    }

    try {
      setQuickActionRunning(action);
      setError(null);

      if (action === "GENERATE_AI_ANALYSIS") {
        await runCaseAnalysisGeneration();
        scrollToCaseSection("case-ai-analysis");
        return;
      }

      if (action === "GENERATE_AI_ACTION_PLAN") {
        await runCaseActionSuggestionGeneration();
        openAndScrollToCaseSection("case-action-plan");
        return;
      }

      if (action === "PREPARE_CLOSURE") {
        openAndScrollToCaseSection("case-closure-checklist");
        return;
      }

      const nextWorkflow = {
        owner: workflowForm.owner,
        status: workflowForm.status,
        severity: workflowForm.severity,
        sla_due_at: workflowForm.sla_due_at
          ? new Date(workflowForm.sla_due_at).toISOString()
          : "",
        status_reason: workflowForm.status_reason,
        reviewed_by: currentUsername,
      };

      if (action === "ASSIGN_TO_ME") {
        nextWorkflow.owner = currentUsername;
        nextWorkflow.status_reason =
          workflowForm.status_reason ||
          "Case assigned through quick action.";
      }

      if (action === "START_INVESTIGATION") {
        nextWorkflow.owner = workflowForm.owner || currentUsername;
        nextWorkflow.status = "INVESTIGATING";
        nextWorkflow.status_reason =
          workflowForm.status_reason ||
          "Investigation started through quick action.";
      }

      if (action === "ESCALATE_CASE") {
        nextWorkflow.owner = workflowForm.owner || currentUsername;
        nextWorkflow.status = "ESCALATED";
        nextWorkflow.status_reason =
          workflowForm.status_reason ||
          "Case escalated through quick action.";
      }

      if (action === "CLOSE_CASE") {
        nextWorkflow.status = "CLOSED";
        nextWorkflow.status_reason =
          workflowForm.status_reason ||
          "Case closed through quick action after closure readiness review.";
      }

      const updatedCase = await updateCaseWorkflow(caseId, nextWorkflow);

      setCaseData(updatedCase);
      setWorkflowForm(workflowFormFromCase(updatedCase));
      setAuditTrail(await fetchCaseAudit(caseId));
      setCaseTimeline((await fetchCaseTimeline(caseId)).items || []);

      if (
        action === "ASSIGN_TO_ME" ||
        action === "START_INVESTIGATION" ||
        action === "ESCALATE_CASE"
      ) {
        openAndScrollToCaseSection("case-workflow");
      }

      if (action === "CLOSE_CASE") {
        openAndScrollToCaseSection("case-workflow");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setQuickActionRunning(null);
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setCurrentUser(getStoredUser());

      fetchCurrentUser()
        .then((current) => setCurrentUser(current))
        .catch(() => {
          // authFetch handles expired/invalid sessions globally
        });
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!isViewer) return;

    const styleId = "ai-soc-case-viewer-readonly-style";
    document.getElementById(styleId)?.remove();

    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      #case-workflow [data-case-section-body] input,
      #case-workflow [data-case-section-body] select,
      #case-workflow [data-case-section-body] textarea,
      #case-workflow [data-case-section-body] button,
      #case-action-plan [data-case-section-body] input,
      #case-action-plan [data-case-section-body] select,
      #case-action-plan [data-case-section-body] textarea,
      #case-action-plan [data-case-section-body] button,
      #case-closure-checklist [data-case-section-body] input,
      #case-closure-checklist [data-case-section-body] select,
      #case-closure-checklist [data-case-section-body] textarea,
      #case-closure-checklist [data-case-section-body] button {
        display: none !important;
      }

      #case-workflow [data-case-section-body]::before,
      #case-action-plan [data-case-section-body]::before,
      #case-closure-checklist [data-case-section-body]::before {
        content: "Read-only access: your role can review this section but cannot modify it.";
        display: block;
        margin-bottom: 0.75rem;
        border: 1px solid rgb(30 41 59);
        border-radius: 0.5rem;
        background: rgb(2 6 23);
        padding: 0.5rem 0.75rem;
        color: rgb(100 116 139);
        font-size: 0.75rem;
        line-height: 1rem;
      }
    `;

    document.head.appendChild(style);

    return () => {
      style.remove();
    };
  }, [isViewer]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadCase();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadCase]);

  useEffect(() => {
    let active = true;

    async function reattachGenerationJobs() {
      try {
        const [analysisJob, suggestionsJob] = await Promise.all([
          fetchLatestCaseGenerationJob(caseId, "analysis").catch(() => null),
          fetchLatestCaseGenerationJob(caseId, "action-suggestions").catch(() => null),
        ]);

        if (!active) return;

        if (analysisJob?.status === "SUCCESS") {
          setCaseAnalysis(caseAnalysisFromJob(analysisJob));
        } else if (isRunningCaseGenerationJob(analysisJob)) {
          setGeneratingAnalysis(true);
          waitForCaseGenerationJob(caseId, analysisJob)
            .then((job) => {
              if (!active) return;
              setCaseAnalysis(caseAnalysisFromJob(job));
            })
            .catch((err) => {
              if (!active) return;
              setError(err instanceof Error ? err.message : "Unknown error");
            })
            .finally(() => {
              if (active) setGeneratingAnalysis(false);
            });
        }

        if (suggestionsJob?.status === "SUCCESS") {
          setAiActionSuggestions(actionSuggestionsFromJob(suggestionsJob));
        } else if (isRunningCaseGenerationJob(suggestionsJob)) {
          setGeneratingSuggestions(true);
          setSuggestionError(null);
          waitForCaseGenerationJob(caseId, suggestionsJob)
            .then((job) => {
              if (!active) return;
              setAiActionSuggestions(actionSuggestionsFromJob(job));
            })
            .catch((err) => {
              if (!active) return;
              setSuggestionError(err instanceof Error ? err.message : "Unknown error");
            })
            .finally(() => {
              if (active) setGeneratingSuggestions(false);
            });
        }
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Unknown error");
      }
    }

    void reattachGenerationJobs();

    return () => {
      active = false;
    };
  }, [caseId]);

  const visibleTimeline = useMemo(() => {
    if (timelineExpanded) {
      return caseTimeline;
    }

    return caseTimeline.slice(-12);
  }, [caseTimeline, timelineExpanded]);

  const hiddenTimelineEvents = Math.max(
    caseTimeline.length - visibleTimeline.length,
    0
  );

  const visibleAuditTrail = useMemo(() => {
    if (auditTrailExpanded) {
      return auditTrail;
    }

    return auditTrail.slice(-10);
  }, [auditTrail, auditTrailExpanded]);

  const hiddenAuditEvents = Math.max(
    auditTrail.length - visibleAuditTrail.length,
    0
  );

  const visibleRelatedIncidents = useMemo(() => {
    if (relatedIncidentsExpanded) {
      return incidents;
    }

    return incidents.slice(-15);
  }, [incidents, relatedIncidentsExpanded]);

  const hiddenRelatedIncidents = Math.max(
    incidents.length - visibleRelatedIncidents.length,
    0
  );

  const openActionCount = useMemo(() => {
    return caseActions.filter(
      (action) => action.status !== "DONE" && action.status !== "CANCELLED"
    ).length;
  }, [caseActions]);

  const completedActionCount = useMemo(() => {
    return caseActions.filter((action) => action.status === "DONE").length;
  }, [caseActions]);

  const closureReady = Boolean(caseClosure?.ready_to_close);
  const hasAIAnalysis = Boolean(caseAnalysis);
  const caseAnalysisAction = canOperate ? (
    <button
      onClick={handleGenerateAnalysis}
      disabled={generatingAnalysis}
      className="inline-flex items-center gap-2 rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {generatingAnalysis && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
      {generatingAnalysis ? "Generating..." : caseAnalysis ? "Regenerate AI analysis" : "Generate AI analysis"}
    </button>
  ) : null;
  const governedRecommendations: GovernedRemediationRecommendation[] = [
    ...aiActionSuggestions.map((suggestion) => ({
      title: suggestion.title,
      description: suggestion.description || null,
      risk_level: suggestion.priority || null,
      reason: "Generated by case action suggestion workflow.",
    })),
    ...(caseAnalysis
      ? [
          {
            title: "Review Case AI analysis remediation guidance",
            description: caseAnalysis.analysis.slice(0, 500),
            risk_level: caseAnalysis.recommended_severity || null,
            reason: "Converted from Case AI analysis review.",
          },
        ]
      : []),
  ].filter((item) => item.title);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />
        <header className="mb-2">
          <Link
            href="/cases"
            className="mb-3 inline-flex items-center gap-2 text-xs text-cyan-300 hover:text-cyan-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to cases
          </Link>

          <div className="mb-1 flex items-center gap-2 text-xs text-cyan-300">
            <Briefcase className="h-4 w-4" />
            Investigation case
          </div>

          <h1 className="text-xl font-semibold tracking-tight">
            Case #{caseId}
          </h1>

          {caseData && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="rounded-full border border-slate-800 bg-slate-900/70 px-2.5 py-1 text-[11px] text-slate-400">
                Host{" "}
                <span className="font-medium text-slate-200">
                  {caseData.agent ?? "unknown"}
                </span>
              </span>

              <span className="rounded-full border border-slate-800 bg-slate-900/70 px-2.5 py-1 text-[11px] text-slate-400">
                Correlation{" "}
                <span className="font-medium text-slate-200">
                  {caseData.correlation_type ?? "unknown"}
                </span>
              </span>

              <span className="rounded-full border border-slate-800 bg-slate-900/70 px-2.5 py-1 text-[11px] text-slate-400">
                Opened{" "}
                <span className="font-medium text-slate-200">
                  {formatTimestamp(caseData.created_at)}
                </span>
              </span>
            </div>
          )}


        </header>

        {loading && (
          <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-slate-300">
            Loading case...
          </div>
        )}

        {error && (
          <div className="whitespace-pre-wrap rounded-lg border border-red-800 bg-red-950/60 p-3 text-sm text-red-200">
            Operation error: {error}
          </div>
        )}

        {caseData && (
          <div className="space-y-3" data-case-focus="ALL">
            <style>{`
              /*
                AI SOC case detail enterprise alignment.
                Conservative scoped density layer: keeps all workflows intact,
                but aligns visual density with Dashboard / Kanban / Executive.
              */

              [data-case-focus] section {
                padding: 0.75rem !important;
                border-radius: 0.75rem !important;
              }

              [data-case-focus] section > div:first-child {
                margin-bottom: 0.5rem !important;
              }

              [data-case-focus] h2 {
                font-size: 0.875rem !important;
                line-height: 1.25rem !important;
                font-weight: 600 !important;
              }

              [data-case-focus] h3,
              [data-case-focus] h4 {
                font-size: 0.8125rem !important;
                line-height: 1.15rem !important;
                font-weight: 600 !important;
              }

              [data-case-focus] p {
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
              }

              [data-case-focus] input,
              [data-case-focus] select {
                height: 2rem !important;
                min-height: 2rem !important;
                padding: 0.25rem 0.5rem !important;
                border-radius: 0.5rem !important;
                font-size: 0.75rem !important;
              }

              [data-case-focus] textarea {
                min-height: 4rem !important;
                padding: 0.375rem 0.5rem !important;
                border-radius: 0.5rem !important;
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
              }

              [data-case-focus] button,
              [data-case-focus] a[download],
              [data-case-focus] a[href^="#"] {
                min-height: 2rem !important;
                padding: 0.375rem 0.625rem !important;
                border-radius: 0.5rem !important;
                font-size: 0.75rem !important;
                line-height: 1rem !important;
              }

              [data-case-focus] pre {
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
                padding: 0.75rem !important;
                border-radius: 0.5rem !important;
              }

              [data-case-focus] table {
                font-size: 0.75rem !important;
              }

              [data-case-focus] th,
              [data-case-focus] td {
                padding-top: 0.375rem !important;
                padding-bottom: 0.375rem !important;
                padding-right: 0.625rem !important;
              }

              [data-case-focus] .rounded-lg {
                border-radius: 0.75rem !important;
              }

              [data-case-focus] .rounded-md {
                border-radius: 0.625rem !important;
              }

              [data-case-focus] .p-6,
              [data-case-focus] .p-5,
              [data-case-focus] .p-4 {
                padding: 0.75rem !important;
              }

              [data-case-focus] .gap-6,
              [data-case-focus] .gap-5,
              [data-case-focus] .gap-4 {
                gap: 0.75rem !important;
              }

              [data-case-focus] .space-y-3 > :not([hidden]) ~ :not([hidden]),
              [data-case-focus] .space-y-3 > :not([hidden]) ~ :not([hidden]),
              [data-case-focus] .space-y-3 > :not([hidden]) ~ :not([hidden]) {
                margin-top: 0.75rem !important;
              }

              [data-case-focus] .text-xl,
              [data-case-focus] .text-lg {
                font-size: 1.125rem !important;
                line-height: 1.5rem !important;
              }

              [data-case-focus] .text-xl,
              [data-case-focus] .text-lg,
              [data-case-focus] .text-base {
                font-size: 0.875rem !important;
                line-height: 1.25rem !important;
              }

              [data-case-focus] .text-sm {
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
              }

              [data-case-focus] .max-h-96 {
                max-height: 14rem !important;
              }

              [data-case-focus] .max-h-72 {
                max-height: 12rem !important;
              }

              [data-case-focus] .max-h-48 {
                max-height: 8rem !important;
              }

              /*
                Enterprise density mode for case detail.
                This keeps the existing layout and logic intact while reducing
                vertical space, card size, control height and font size.
              */

              [data-case-focus] section {
                padding: 0.75rem !important;
                border-radius: 0.75rem !important;
              }

              [data-case-focus] section > div:first-child {
                margin-bottom: 0.75rem !important;
              }

              [data-case-focus] h2 {
                font-size: 0.875rem !important;
                line-height: 1.25rem !important;
                font-weight: 600 !important;
              }

              [data-case-focus] h3,
              [data-case-focus] h4 {
                font-size: 0.8125rem !important;
                line-height: 1.15rem !important;
                font-weight: 600 !important;
              }

              [data-case-focus] p {
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
              }

              [data-case-focus] label span,
              [data-case-focus] .uppercase {
                font-size: 0.625rem !important;
                letter-spacing: 0.04em !important;
              }

              [data-case-focus] input,
              [data-case-focus] select {
                min-height: 2rem !important;
                height: 2rem !important;
                padding: 0.25rem 0.5rem !important;
                border-radius: 0.5rem !important;
                font-size: 0.75rem !important;
              }

              [data-case-focus] textarea {
                min-height: 4.5rem !important;
                padding: 0.375rem 0.5rem !important;
                border-radius: 0.5rem !important;
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
              }

              [data-case-focus] button,
              [data-case-focus] a[download],
              [data-case-focus] a[href^="#"] {
                min-height: 2rem !important;
                padding: 0.375rem 0.625rem !important;
                border-radius: 0.5rem !important;
                font-size: 0.75rem !important;
                line-height: 1rem !important;
              }

              [data-case-focus] pre {
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
                padding: 0.75rem !important;
                border-radius: 0.5rem !important;
              }

              [data-case-focus] table {
                font-size: 0.75rem !important;
              }

              [data-case-focus] th,
              [data-case-focus] td {
                padding-top: 0.375rem !important;
                padding-bottom: 0.375rem !important;
                padding-right: 0.625rem !important;
              }

              [data-case-focus] .rounded-lg {
                border-radius: 0.75rem !important;
              }

              [data-case-focus] .rounded-md {
                border-radius: 0.625rem !important;
              }

              [data-case-focus] .p-5,
              [data-case-focus] .p-4 {
                padding: 0.75rem !important;
              }

              [data-case-focus] .px-4 {
                padding-left: 0.625rem !important;
                padding-right: 0.625rem !important;
              }

              [data-case-focus] .py-2 {
                padding-top: 0.375rem !important;
                padding-bottom: 0.375rem !important;
              }

              [data-case-focus] .gap-4 {
                gap: 0.75rem !important;
              }

              [data-case-focus] .gap-3 {
                gap: 0.5rem !important;
              }

              [data-case-focus] .mt-3,
              [data-case-focus] .mt-2 {
                margin-top: 0.75rem !important;
              }

              [data-case-focus] .mb-3,
              [data-case-focus] .mb-2 {
                margin-bottom: 0.75rem !important;
              }

              [data-case-focus] .space-y-3 > :not([hidden]) ~ :not([hidden]),
              [data-case-focus] .space-y-3 > :not([hidden]) ~ :not([hidden]) {
                margin-top: 0.75rem !important;
              }

              [data-case-focus] .text-lg,
              [data-case-focus] .text-base {
                font-size: 0.875rem !important;
                line-height: 1.25rem !important;
              }

              [data-case-focus] .text-sm {
                font-size: 0.75rem !important;
                line-height: 1.15rem !important;
              }

              [data-case-focus] .text-xl {
                font-size: 1rem !important;
                line-height: 1.35rem !important;
              }

              [data-case-focus] .text-xl,
              [data-case-focus] .text-lg {
                font-size: 1.125rem !important;
                line-height: 1.5rem !important;
              }

              [data-case-focus] [class*="px-3"][class*="py-1"] {
                padding: 0.125rem 0.5rem !important;
                font-size: 0.6875rem !important;
                border-radius: 0.375rem !important;
              }

              [data-case-focus] .max-h-96 {
                max-height: 14rem !important;
              }

              [data-case-focus] .max-h-48 {
                max-height: 8rem !important;
              }

              [data-case-focus="OVERVIEW"] #case-workflow,
              [data-case-focus="OVERVIEW"] #case-action-plan,
              [data-case-focus="OVERVIEW"] #case-closure-checklist,
              [data-case-focus="OVERVIEW"] #case-timeline,
              [data-case-focus="OVERVIEW"] #case-audit,
              [data-case-focus="OVERVIEW"] #related-incidents {
                display: none;
              }

              [data-case-focus="WORKBENCH"] #reports-center,
              [data-case-focus="WORKBENCH"] #case-investigation-graph,
              [data-case-focus="WORKBENCH"] #case-timeline,
              [data-case-focus="WORKBENCH"] #case-audit,
              [data-case-focus="WORKBENCH"] #related-incidents {
                display: none;
              }

              [data-case-focus="EVIDENCE"] #reports-center,
              [data-case-focus="EVIDENCE"] #case-workflow,
              [data-case-focus="EVIDENCE"] #case-action-plan,
              [data-case-focus="EVIDENCE"] #case-closure-checklist {
                display: none;
              }

              [data-case-focus="REPORTS"] #case-workflow,
              [data-case-focus="REPORTS"] #case-action-plan,
              [data-case-focus="REPORTS"] #case-closure-checklist,
              [data-case-focus="REPORTS"] #case-investigation-graph,
              [data-case-focus="REPORTS"] #case-timeline,
              [data-case-focus="REPORTS"] #case-audit,
              [data-case-focus="REPORTS"] #related-incidents {
                display: none;
              }
            `}</style>
            <section className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              <InfoCard title="Host" value={caseData.agent ?? "unknown"} />
              <InfoCard title="Incidents" value={caseData.incident_count} />
              <InfoCard title="Risk score" value={caseData.risk_score ?? 0} />
              <InfoCard title="Updated" value={formatTimestamp(caseData.updated_at)} />
            </section>
            <CaseCommandCenter
              caseData={caseData}
              actionCount={caseActions.length}
              openActionCount={openActionCount}
              completedActionCount={completedActionCount}
              closureReady={closureReady}
              hasAIAnalysis={hasAIAnalysis}
            />

            <CaseQuickActions
              caseData={caseData}
              actionCount={caseActions.length}
              openActionCount={openActionCount}
              closureReady={closureReady}
              hasAIAnalysis={hasAIAnalysis}
              quickActionRunning={quickActionRunning}
              generatingAnalysis={generatingAnalysis}
              generatingSuggestions={generatingSuggestions}
              onAction={handleCaseQuickAction}
            />

            <section id="case-ai-analysis">
              {!caseAnalysis ? (
                <div className="flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950 p-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <div className="text-xs text-slate-500">
                      No AI analysis available yet for this case.
                    </div>
                    {generatingAnalysis && (
                      <div className="mt-2 inline-flex items-center gap-2 rounded-md border border-cyan-900/60 bg-cyan-950/30 px-3 py-2 text-xs text-cyan-100">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        AI analysis generation is running in background.
                      </div>
                    )}
                  </div>
                  {caseAnalysisAction}
                </div>
              ) : (
                <CaseAiAnalysisBoundary
                  resetKey={caseAnalysis.id}
                  fallback={<CaseAiAnalysisFallback analysis={caseAnalysis.analysis} />}
                >
                  <EnterpriseCaseAiAnalysis
                    caseAnalysis={caseAnalysis}
                    action={caseAnalysisAction}
                  />
                </CaseAiAnalysisBoundary>
              )}
            </section>

            <CaseCollapsibleSection
              id="case-workflow"
              title="Case workflow"
              description="Assign ownership, review severity and track SLA for the investigation."
              icon={<Briefcase className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-workflow"])}
              onOpenChange={(open) => setCaseSectionOpen("case-workflow", open)}
            >

              <div className="grid gap-3 md:grid-cols-2">
                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Owner
                  </span>
                  <input
                    value={workflowForm.owner}
                    onChange={(event) =>
                      setWorkflowForm((current) => ({
                        ...current,
                        owner: event.target.value,
                      }))
                    }
                    placeholder={currentUsername}
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Assignee
                  </span>
                  <input
                    value={workflowForm.assignee}
                    onChange={(event) =>
                      setWorkflowForm((current) => ({
                        ...current,
                        assignee: event.target.value,
                      }))
                    }
                    placeholder={currentUsername}
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    SLA due date
                  </span>
                  <input
                    type="datetime-local"
                    value={workflowForm.sla_due_at}
                    onChange={(event) =>
                      setWorkflowForm((current) => ({
                        ...current,
                        sla_due_at: event.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Status
                  </span>
                  <select
                    value={workflowForm.status}
                    onChange={(event) =>
                      setWorkflowForm((current) => ({
                        ...current,
                        status: event.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="OPEN">OPEN</option>
                    <option value="TRIAGED">TRIAGED</option>
                    <option value="INVESTIGATING">INVESTIGATING</option>
                    <option value="ESCALATED">ESCALATED</option>
                    <option value="CLOSED">CLOSED</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  </select>
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Severity review
                  </span>
                  <select
                    value={workflowForm.severity}
                    onChange={(event) =>
                      setWorkflowForm((current) => ({
                        ...current,
                        severity: event.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </label>
              </div>

              <label className="mt-2 block">
                <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                  Status reason / analyst comment
                </span>
                <textarea
                  value={workflowForm.status_reason}
                  onChange={(event) =>
                    setWorkflowForm((current) => ({
                      ...current,
                      status_reason: event.target.value,
                    }))
                  }
                  rows={3}
                  placeholder="Why is this case in the selected state?"
                  className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                />
              </label>

              <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs text-slate-500">
                  Last reviewed by {caseData.last_reviewed_by ?? "-"} ·{" "}
                  {formatTimestamp(caseData.last_reviewed_at)}
                </div>

                <button
                  onClick={handleSaveWorkflow}
                  disabled={savingWorkflow}
                  className="rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {savingWorkflow ? "Saving..." : "Save workflow"}
                </button>
              </div>
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="case-action-plan"
              title="Case action plan"
              description="Track concrete analyst tasks required to investigate, contain, escalate or close the case."
              icon={<CheckCircle2 className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-action-plan"])}
              onOpenChange={(open) => setCaseSectionOpen("case-action-plan", open)}
            >

              <div className="mb-3 rounded-md border border-cyan-900/60 bg-cyan-950/20 p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h3 className="text-sm font-medium text-cyan-200">
                      AI-suggested action plan
                    </h3>
                    <p className="mt-1 text-xs text-slate-500">
                      Generate recommended analyst tasks from the current case evidence.
                      Suggestions are not saved until you explicitly create them.
                    </p>
                  </div>

                  <button
                    onClick={handleGenerateActionSuggestions}
                    disabled={generatingSuggestions}
                    className="inline-flex items-center gap-2 rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {generatingSuggestions && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                    {generatingSuggestions ? "Generating..." : "Generate AI action plan"}
                  </button>
                </div>

                {generatingSuggestions && (
                  <div className="mt-3 inline-flex items-center gap-2 rounded-md border border-cyan-900/60 bg-slate-950 px-3 py-2 text-xs text-cyan-100">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    AI action plan generation is running in background.
                  </div>
                )}

                {suggestionError && (
                  <div className="mt-2 rounded-md border border-red-800 bg-red-950/60 p-3 text-sm text-red-200">
                    {suggestionError}
                  </div>
                )}

                {aiActionSuggestions.length > 0 && (
                  <div className="mt-3 space-y-3">
                    {aiActionSuggestions.map((suggestion, index) => (
                      <div
                        key={`${suggestion.title}-${index}`}
                        className="rounded-md border border-slate-800 bg-slate-950 p-4"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div>
                            <div className="mb-2 flex flex-wrap items-center gap-2">
                              <span
                                className={`rounded-full border px-2 py-0.5 text-[11px] ${actionPriorityClass(
                                  suggestion.priority
                                )}`}
                              >
                                {suggestion.priority || "MEDIUM"}
                              </span>

                              <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-300">
                                {suggestion.category || "INVESTIGATION"}
                              </span>
                            </div>

                            <h4 className="text-sm font-semibold text-slate-100">
                              {suggestion.title}
                            </h4>

                            <p className="mt-2 text-sm leading-6 text-slate-400">
                              {suggestion.description || "No description provided."}
                            </p>

                            <div className="mt-3 text-xs text-slate-500">
                              Suggested due date:{" "}
                              {formatTimestamp(suggestion.suggested_due_at)}
                            </div>
                          </div>

                          <button
                            onClick={() =>
                              handleCreateActionFromSuggestion(suggestion, index)
                            }
                            disabled={creatingSuggestionIndex === index}
                            className="rounded-md border border-emerald-500 bg-emerald-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            {creatingSuggestionIndex === index
                              ? "Creating..."
                              : "Create action"}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="mb-3 rounded-md border border-slate-800 bg-slate-950 p-4">
                <h3 className="mb-3 text-sm font-medium text-slate-200">
                  Add action
                </h3>

                <div className="grid gap-3 md:grid-cols-2">
                  <label className="block">
                    <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                      Title
                    </span>
                    <input
                      value={actionForm.title}
                      onChange={(event) =>
                        setActionForm((current) => ({
                          ...current,
                          title: event.target.value,
                        }))
                      }
                      placeholder="Review correlated incidents"
                      className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    />
                  </label>

                  <label className="block">
                    <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                      Due date
                    </span>
                    <input
                      type="datetime-local"
                      value={actionForm.due_at}
                      onChange={(event) =>
                        setActionForm((current) => ({
                          ...current,
                          due_at: event.target.value,
                        }))
                      }
                      className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    />
                  </label>

                  <label className="block">
                    <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                      Category
                    </span>
                    <select
                      value={actionForm.category}
                      onChange={(event) =>
                        setActionForm((current) => ({
                          ...current,
                          category: event.target.value,
                        }))
                      }
                      className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    >
                      <option value="INVESTIGATION">INVESTIGATION</option>
                      <option value="CONTAINMENT">CONTAINMENT</option>
                      <option value="EVIDENCE_REVIEW">EVIDENCE_REVIEW</option>
                      <option value="ESCALATION">ESCALATION</option>
                      <option value="CLOSURE">CLOSURE</option>
                      <option value="OTHER">OTHER</option>
                    </select>
                  </label>

                  <label className="block">
                    <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                      Priority
                    </span>
                    <select
                      value={actionForm.priority}
                      onChange={(event) =>
                        setActionForm((current) => ({
                          ...current,
                          priority: event.target.value,
                        }))
                      }
                      className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    >
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </label>
                </div>

                <label className="mt-2 block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Description
                  </span>
                  <textarea
                    value={actionForm.description}
                    onChange={(event) =>
                      setActionForm((current) => ({
                        ...current,
                        description: event.target.value,
                      }))
                    }
                    rows={3}
                    placeholder="Describe what the analyst needs to verify or execute."
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <div className="mt-2 flex justify-end">
                  <button
                    onClick={handleCreateAction}
                    disabled={creatingAction}
                    className="rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {creatingAction ? "Creating..." : "Add action"}
                  </button>
                </div>
              </div>

              {caseActions.length === 0 ? (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No actions available yet. Add the first analyst task for this case.
                </div>
              ) : (
                <div className="space-y-3">
                  {caseActions.map((action) => (
                    <div
                      key={action.id}
                      className="rounded-md border border-slate-800 bg-slate-950 p-4"
                    >
                      <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                        <div>
                          <div className="mb-2 flex flex-wrap items-center gap-2">
                            <span
                              className={`rounded-full border px-2 py-0.5 text-[11px] ${actionStatusClass(
                                action.status
                              )}`}
                            >
                              {action.status}
                            </span>
                            <span
                              className={`rounded-full border px-2 py-0.5 text-[11px] ${actionPriorityClass(
                                action.priority
                              )}`}
                            >
                              {action.priority}
                            </span>
                            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-300">
                              {action.category}
                            </span>
                          </div>

                          <h3 className="text-sm font-semibold text-slate-100">
                            {action.title}
                          </h3>

                          {action.description && (
                            <p className="mt-2 text-sm leading-6 text-slate-400">
                              {action.description}
                            </p>
                          )}
                        </div>

                        <div className="flex flex-col gap-2 md:min-w-48">
                          <select
                            value={action.status}
                            disabled={updatingActionId === action.id}
                            onChange={(event) =>
                              handleUpdateActionStatus(action.id, event.target.value)
                            }
                            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                          >
                            <option value="OPEN">OPEN</option>
                            <option value="IN_PROGRESS">IN_PROGRESS</option>
                            <option value="DONE">DONE</option>
                            <option value="CANCELLED">CANCELLED</option>
                          </select>

                          <select
                            value={action.priority}
                            disabled={updatingActionId === action.id}
                            onChange={(event) =>
                              handleUpdateActionPriority(action.id, event.target.value)
                            }
                            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                          >
                            <option value="LOW">LOW</option>
                            <option value="MEDIUM">MEDIUM</option>
                            <option value="HIGH">HIGH</option>
                            <option value="CRITICAL">CRITICAL</option>
                          </select>
                        </div>
                      </div>

                      <div className="grid gap-3 text-xs text-slate-500 md:grid-cols-4">
                        <div>Created by {action.created_by ?? "-"}</div>
                        <div>Created {formatTimestamp(action.created_at)}</div>
                        <div>Due {formatTimestamp(action.due_at)}</div>
                        <div>
                          Completed {formatTimestamp(action.completed_at)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="case-timeline"
              title="Case timeline"
              description="Chronological view of incidents, AI analysis, actions, workflow updates and closure events."
              icon={<CircleDashed className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-timeline"])}
              onOpenChange={(open) => setCaseSectionOpen("case-timeline", open)}
            >

              {caseTimeline.length > 0 && (
                <div>
                  <div className="mb-2 flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950 p-3 md:flex-row md:items-center md:justify-between">
                    <div className="text-xs text-slate-300">
                      {timelineExpanded ? (
                        <>Showing all {caseTimeline.length} events.</>
                      ) : (
                        <>
                          Showing latest {visibleTimeline.length} of {caseTimeline.length} events.
                          {hiddenTimelineEvents > 0 && (
                            <> {hiddenTimelineEvents} older events are hidden.</>
                          )}
                        </>
                      )}
                    </div>

                    {caseTimeline.length > 12 && (
                      <button
                        onClick={() => setTimelineExpanded((current) => !current)}
                        className="w-fit rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"
                      >
                        {timelineExpanded ? "Show latest only" : "Show all events"}
                      </button>
                    )}
                  </div>

                  <div className="relative space-y-3 border-l border-slate-700 pl-5">
                    {visibleTimeline.map((item, index) => (
                      <div
                        key={`${item.event_type}-${item.reference_id ?? index}-${index}`}
                        className="relative"
                      >
                        <span
                          className={`absolute -left-[29px] top-1 h-3 w-3 rounded-full border-2 ${timelineEventClass(
                            item.event_type
                          )}`}
                        />

                        <div className="rounded-md border border-slate-800 bg-slate-950 p-4">
                          <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                            <div>
                              <div className="text-sm font-medium text-slate-100">
                                {item.title}
                              </div>
                              <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">
                                {timelineEventLabel(item.event_type)}
                              </div>
                            </div>

                            <div className="text-xs text-slate-500">
                              {formatTimestamp(item.timestamp)}
                            </div>
                          </div>

                          {item.description && (
                            <p className="mt-3 whitespace-pre-wrap text-xs text-slate-300">
                              {item.description}
                            </p>
                          )}

                          <div className="mt-3 flex flex-wrap gap-2 text-xs">
                            {item.status && (
                              <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">
                                Status: {item.status}
                              </span>
                            )}

                            {item.severity && (
                              <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">
                                Severity: {item.severity}
                              </span>
                            )}

                            {item.actor && (
                              <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">
                                Actor: {item.actor}
                              </span>
                            )}

                            {item.source && (
                              <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">
                                Source: {item.source}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {caseTimeline.length === 0 && (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No timeline events available.
                </div>
              )}
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="related-incidents"
              title="Related incidents"
              description="Linked alerts and detections associated with this investigation case."
              icon={<ShieldAlert className="h-3.5 w-3.5" />}
              open={Boolean(openSections["related-incidents"])}
              onOpenChange={(open) => setCaseSectionOpen("related-incidents", open)}
            >

              {incidents.length === 0 && (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No incidents linked to this case.
                </div>
              )}

              {incidents.length > 0 && (
                <div>
                  <div className="mb-2 flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950 p-3 md:flex-row md:items-center md:justify-between">
                    <div className="text-xs text-slate-300">
                      {relatedIncidentsExpanded ? (
                        <>Showing all {incidents.length} linked incidents.</>
                      ) : (
                        <>
                          Showing latest {visibleRelatedIncidents.length} of {incidents.length} linked incidents.
                          {hiddenRelatedIncidents > 0 && (
                            <> {hiddenRelatedIncidents} older incidents are hidden.</>
                          )}
                        </>
                      )}
                    </div>

                    {incidents.length > 15 && (
                      <button
                        onClick={() =>
                          setRelatedIncidentsExpanded((current) => !current)
                        }
                        className="w-fit rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"
                      >
                        {relatedIncidentsExpanded ? "Show latest only" : "Show all incidents"}
                      </button>
                    )}
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
                        <tr>
                          <th className="py-3 pr-4">ID</th>
                          <th className="py-3 pr-4">Status</th>
                          <th className="py-3 pr-4">Time</th>
                          <th className="py-3 pr-4">Rule</th>
                          <th className="py-3 pr-4">Level</th>
                          <th className="py-3 pr-4">Risk</th>
                          <th className="py-3 pr-4">Priority</th>
                        </tr>
                      </thead>

                      <tbody>
                        {visibleRelatedIncidents.map((incident) => (
                          <tr
                            key={incident.id}
                            className="border-b border-slate-800/70"
                          >
                            <td className="py-3 pr-4">
                              <Link
                                href={`/incidents/${incident.id}`}
                                className="text-cyan-300 hover:text-cyan-200"
                              >
                                #{incident.id}
                              </Link>
                            </td>

                            <td className="py-3 pr-4">
                              <span
                                className={`rounded-full border px-2 py-0.5 text-[11px] ${statusClass(
                                  incident.status
                                )}`}
                              >
                                {incident.status ?? "NEW"}
                              </span>
                            </td>

                            <td className="py-3 pr-4 text-slate-400">
                              {incident.timestamp_local ??
                                formatTimestamp(incident.timestamp)}
                            </td>

                            <td className="max-w-xl py-3 pr-4 text-slate-300">
                              {incident.rule ?? "-"}
                            </td>

                            <td className="py-3 pr-4">{incident.level ?? 0}</td>

                            <td className="py-3 pr-4">
                              {incident.risk_score ?? 0}
                            </td>

                            <td className="py-3 pr-4 text-slate-400">
                              {incident.recommended_priority ?? "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="case-investigation-graph"
              title="Investigation Graph"
              description="Read-only relationship view across linked incidents, alerts, entities, timeline and AI context."
              icon={<Network className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-investigation-graph"])}
              onOpenChange={(open) => setCaseSectionOpen("case-investigation-graph", open)}
            >
              <InvestigationGraph scope="case" scopeId={caseData.id} />
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="case-governed-remediation"
              title="Governed Remediation"
              description="Create, review, approve and convert remediation proposals linked to this case."
              icon={<ShieldCheck className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-governed-remediation"])}
              onOpenChange={(open) => setCaseSectionOpen("case-governed-remediation", open)}
            >
              <GovernedRemediationPanel
                scope="case"
                caseId={caseData.id}
                currentUser={currentUser}
                canOperate={canOperate}
                aiRecommendations={governedRecommendations}
                onChanged={loadCase}
              />
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="case-closure-checklist"
              title="Case closure checklist"
              description="Document the minimum evidence required before closing or marking the case as false positive."
              icon={<ShieldCheck className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-closure-checklist"])}
              onOpenChange={(open) => setCaseSectionOpen("case-closure-checklist", open)}
            >

              {caseClosure && !caseClosure.ready_to_close && (
                <div className="mb-3 rounded-md border border-orange-800 bg-orange-950/50 p-4">
                  <div className="text-sm font-medium text-orange-200">
                    This case cannot be closed yet.
                  </div>

                  <div className="mt-2 text-xs text-slate-300">
                    Open actions: {caseClosure.open_action_count}
                  </div>

                  {caseClosure.missing_items.length > 0 && (
                    <div className="mt-3">
                      <div className="mb-2 text-xs uppercase tracking-wide text-orange-300">
                        What still needs to be fixed
                      </div>
                      <ul className="list-inside list-disc space-y-1 text-xs text-slate-300">
                        {caseClosure.missing_items.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {caseClosure?.ready_to_close && (
                <div className="mb-3 rounded-md border border-emerald-800 bg-emerald-950/40 p-3 text-sm text-emerald-200">
                  Closure checklist is complete, approved and all actions are resolved. The case can now be moved to CLOSED or FALSE_POSITIVE.
                </div>
              )}

              <div className="mb-3 rounded-md border border-slate-800 bg-slate-950 p-3">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Closure approval
                    </div>
                    <p className="mt-1 text-xs leading-5 text-slate-500">
                      Final human approval is required before the case can be closed.
                    </p>
                  </div>

                  <span
                    className={`w-fit rounded-full border px-3 py-1.5 text-xs ${
                      closureForm.closure_approved
                        ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                        : "border-orange-700 bg-orange-950 text-orange-200"
                    }`}
                  >
                    {closureForm.closure_approved ? "Approved" : "Not approved"}
                  </span>
                </div>

                <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(240px,320px)] md:items-end">
                  <label className="flex min-h-10 items-start gap-3 rounded-md border border-slate-800 bg-slate-900/70 px-3 py-2">
                    <input
                      type="checkbox"
                      checked={closureForm.closure_approved}
                      onChange={(event) =>
                        setClosureForm((current) => ({
                          ...current,
                          closure_approved: event.target.checked,
                          closure_approved_by: event.target.checked
                            ? current.closure_approved_by || currentUsername
                            : "",
                        }))
                      }
                      className="mt-1 h-4 w-4 rounded border-slate-700 bg-slate-950"
                    />
                    <span>
                      <span className="block text-sm font-medium text-slate-200">
                        I approve this case for closure
                      </span>
                      <span className="mt-0.5 block text-xs leading-5 text-slate-500">
                        Use this only after evidence, actions, residual risk and closure decision have been reviewed.
                      </span>
                    </span>
                  </label>

                  <label className="block">
                    <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                      Approved by
                    </span>
                    <input
                      value={closureForm.closure_approved_by}
                      onChange={(event) =>
                        setClosureForm((current) => ({
                          ...current,
                          closure_approved_by: event.target.value,
                        }))
                      }
                      placeholder={currentUsername}
                      disabled={!closureForm.closure_approved}
                      className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
                    />
                  </label>
                </div>

                <div className="mt-3 text-xs text-slate-500">
                  Last approved by {caseClosure?.checklist?.closure_approved_by ?? "-"} ·{" "}
                  {formatTimestamp(caseClosure?.checklist?.closure_approved_at)}
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Closure decision
                  </span>
                  <select
                    value={closureForm.closure_decision}
                    onChange={(event) =>
                      setClosureForm((current) => ({
                        ...current,
                        closure_decision: event.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="RESOLVED">RESOLVED</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                    <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
                    <option value="DUPLICATE">DUPLICATE</option>
                    <option value="OTHER">OTHER</option>
                  </select>
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Final severity
                  </span>
                  <select
                    value={closureForm.final_severity}
                    onChange={(event) =>
                      setClosureForm((current) => ({
                        ...current,
                        final_severity: event.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </label>
              </div>

              <div className="mt-2 grid gap-3 md:grid-cols-2">
                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Root cause / conclusion
                  </span>
                  <textarea
                    value={closureForm.root_cause}
                    onChange={(event) =>
                      setClosureForm((current) => ({
                        ...current,
                        root_cause: event.target.value,
                      }))
                    }
                    rows={4}
                    placeholder="What caused the case or what conclusion was reached?"
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Evidence reviewed
                  </span>
                  <textarea
                    value={closureForm.evidence_reviewed}
                    onChange={(event) =>
                      setClosureForm((current) => ({
                        ...current,
                        evidence_reviewed: event.target.value,
                      }))
                    }
                    rows={4}
                    placeholder="Which alerts, logs, correlations, AI analysis or artifacts were reviewed?"
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Actions summary
                  </span>
                  <textarea
                    value={closureForm.actions_summary}
                    onChange={(event) =>
                      setClosureForm((current) => ({
                        ...current,
                        actions_summary: event.target.value,
                      }))
                    }
                    rows={4}
                    placeholder="Summarize completed, cancelled or waived actions."
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                    Residual risk
                  </span>
                  <textarea
                    value={closureForm.residual_risk}
                    onChange={(event) =>
                      setClosureForm((current) => ({
                        ...current,
                        residual_risk: event.target.value,
                      }))
                    }
                    rows={4}
                    placeholder="What risk remains after closure?"
                    className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>
              </div>

              <label className="mt-2 block">
                <span className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
                  Closure reason
                </span>
                <textarea
                  value={closureForm.closure_reason}
                  onChange={(event) =>
                    setClosureForm((current) => ({
                      ...current,
                      closure_reason: event.target.value,
                    }))
                  }
                  rows={3}
                  placeholder="Why is this case ready to be closed?"
                  className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                />
              </label>

              <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs text-slate-500">
                  Last reviewed by {caseClosure?.checklist?.reviewed_by ?? "-"} ·{" "}
                  {formatTimestamp(caseClosure?.checklist?.reviewed_at)}
                </div>

                <button
                  onClick={handleSaveClosureChecklist}
                  disabled={savingClosureChecklist}
                  className="rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {savingClosureChecklist ? "Saving..." : "Save closure checklist"}
                </button>
              </div>
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="case-audit"
              title="Case workflow audit"
              description="Chronological audit events for workflow updates, actions and closure checklist changes."
              icon={<ShieldAlert className="h-3.5 w-3.5" />}
              open={Boolean(openSections["case-audit"])}
              onOpenChange={(open) => setCaseSectionOpen("case-audit", open)}
            >

              {auditTrail.length === 0 && (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No audit events available for this case.
                </div>
              )}

              {auditTrail.length > 0 && (
                <div>
                  <div className="mb-2 flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950 p-3 md:flex-row md:items-center md:justify-between">
                    <div className="text-xs text-slate-300">
                      {auditTrailExpanded ? (
                        <>Showing all {auditTrail.length} audit events.</>
                      ) : (
                        <>
                          Showing latest {visibleAuditTrail.length} of {auditTrail.length} audit events.
                          {hiddenAuditEvents > 0 && (
                            <> {hiddenAuditEvents} older audit events are hidden.</>
                          )}
                        </>
                      )}
                    </div>

                    {auditTrail.length > 10 && (
                      <button
                        onClick={() => setAuditTrailExpanded((current) => !current)}
                        className="w-fit rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"
                      >
                        {auditTrailExpanded ? "Show latest only" : "Show all audit events"}
                      </button>
                    )}
                  </div>

                  <div className="space-y-3">
                    {visibleAuditTrail.map((event) => (
                      <div
                        key={event.id}
                        className="rounded-md border border-slate-800 bg-slate-950 p-4"
                      >
                        <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                          <div>
                            <div className="text-sm font-medium text-slate-100">
                              {event.event_type}
                            </div>
                            <div className="mt-1 text-xs text-slate-500">
                              Created by {event.created_by ?? "-"}
                            </div>
                          </div>

                          <div className="text-xs text-slate-500">
                            {formatTimestamp(event.created_at)}
                          </div>
                        </div>

                        {event.comment && (
                          <p className="mt-3 whitespace-pre-wrap text-xs text-slate-300">
                            {event.comment}
                          </p>
                        )}

                        {(event.old_value || event.new_value) && (
                          <div className="mt-3 grid gap-3 md:grid-cols-2">
                            <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                              <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
                                Old value
                              </div>
                              <pre className="max-h-48 overflow-auto whitespace-pre-wrap text-xs text-slate-400">
                                {event.old_value ?? "-"}
                              </pre>
                            </div>

                            <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                              <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
                                New value
                              </div>
                              <pre className="max-h-48 overflow-auto whitespace-pre-wrap text-xs text-slate-400">
                                {event.new_value ?? "-"}
                              </pre>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CaseCollapsibleSection>
            <CaseCollapsibleSection
              id="reports-center"
              title="Reports Center"
              description="Export executive, analyst and machine-readable reports for this case."
              icon={<FileText className="h-3.5 w-3.5" />}
              open={Boolean(openSections["reports-center"])}
              onOpenChange={(open) => setCaseSectionOpen("reports-center", open)}
            >
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
                <ReportDownloadCard
                  title="Executive PDF"
                  description="Board-ready PDF with summary, risk, actions and closure readiness."
                  href={`/reports/cases/${caseId}/executive-pdf`}
                  fallbackFilename={`case-${caseReportId}-executive-ai-soc-report.pdf`}
                  format="PDF"
                  tone="executive"
                />

                <ReportDownloadCard
                  title="Analyst Evidence Pack"
                  description="Evidence package with alerts, actions, audit trail and closure evidence."
                  href={`/reports/cases/${caseId}/evidence-pack?format=markdown`}
                  fallbackFilename={`case-${caseReportId}-evidence-pack.md`}
                  format="MD"
                  tone="evidence"
                />

                <ReportDownloadCard
                  title="Markdown Case Report"
                  description="Readable case report for review, notes, ticketing and documentation."
                  href={`/reports/cases/${caseId}?format=markdown`}
                  fallbackFilename={`case-${caseReportId}-enterprise-report.md`}
                  format="MD"
                  tone="standard"
                />

                <ReportDownloadCard
                  title="JSON Case Payload"
                  description="Structured export for automation, integrations and downstream processing."
                  href={`/reports/cases/${caseId}?format=json`}
                  fallbackFilename={`case-${caseReportId}-enterprise-report.json`}
                  format="JSON"
                  tone="json"
                />
              </div>
            </CaseCollapsibleSection>

          </div>
        )}
      </div>
    </main>
  );
}





function CaseQuickActions({
  caseData,
  actionCount,
  openActionCount,
  closureReady,
  hasAIAnalysis,
  quickActionRunning,
  generatingAnalysis,
  generatingSuggestions,
  onAction,
}: {
  caseData: IncidentCase;
  actionCount: number;
  openActionCount: number;
  closureReady: boolean;
  hasAIAnalysis: boolean;
  quickActionRunning: string | null;
  generatingAnalysis: boolean;
  generatingSuggestions: boolean;
  onAction: (
    action:
      | "ASSIGN_TO_ME"
      | "START_INVESTIGATION"
      | "ESCALATE_CASE"
      | "GENERATE_AI_ANALYSIS"
      | "GENERATE_AI_ACTION_PLAN"
      | "PREPARE_CLOSURE"
      | "CLOSE_CASE"
  ) => void;
}) {
  const status = caseData.status ?? "OPEN";
  const isTerminal = status === "CLOSED" || status === "FALSE_POSITIVE";

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg">
      <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <h2 className="text-sm font-semibold">Case Quick Actions</h2>
          <p className="mt-1 text-xs text-slate-500">
            Execute common analyst actions without scrolling through the full case page.
          </p>
        </div>

        <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
          Status {status}
        </span>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-8">
        <QuickActionButton
          title="Assign to me"
          description="Take ownership as the signed-in user."
          action="ASSIGN_TO_ME"
          running={quickActionRunning}
          disabled={isTerminal}
          onAction={onAction}
        />

        <QuickActionButton
          title="Start investigation"
          description="Set status to INVESTIGATING and assign owner if missing."
          action="START_INVESTIGATION"
          running={quickActionRunning}
          disabled={isTerminal}
          onAction={onAction}
        />

        <QuickActionButton
          title="Escalate case"
          description="Move the case to ESCALATED for senior review."
          action="ESCALATE_CASE"
          running={quickActionRunning}
          disabled={isTerminal}
          danger
          onAction={onAction}
        />

        <QuickActionButton
          title={hasAIAnalysis ? "Regenerate AI analysis" : "Generate AI analysis"}
          description={
            hasAIAnalysis
              ? "Refresh the AI assessment with current case evidence."
              : "Create the first AI assessment for this case."
          }
          action="GENERATE_AI_ANALYSIS"
          running={quickActionRunning ?? (generatingAnalysis ? "GENERATE_AI_ANALYSIS" : null)}
          disabled={false}
          onAction={onAction}
        />

        <QuickActionButton
          title="Generate AI action plan"
          description="Suggest analyst tasks from the current case evidence."
          action="GENERATE_AI_ACTION_PLAN"
          running={quickActionRunning ?? (generatingSuggestions ? "GENERATE_AI_ACTION_PLAN" : null)}
          disabled={isTerminal}
          onAction={onAction}
        />

        <QuickActionButton
          title="Prepare closure review"
          description="Jump to the closure checklist and readiness controls."
          action="PREPARE_CLOSURE"
          running={quickActionRunning}
          disabled={false}
          onAction={onAction}
        />

        <QuickActionButton
          title="Close case"
          description={
            closureReady
              ? "Move the case to CLOSED."
              : "Backend will block closure until requirements are complete."
          }
          action="CLOSE_CASE"
          running={quickActionRunning}
          disabled={isTerminal}
          success={closureReady}
          danger={!closureReady}
          onAction={onAction}
        />

        <div className="flex min-h-20 flex-col justify-between rounded-md border border-slate-800 bg-slate-950 p-2.5">
          <div className="truncate text-xs font-semibold text-slate-200">Current blockers</div>
          <div className="mt-1 space-y-0.5 text-[11px] leading-4 text-slate-500">
            <div className="truncate">Actions: {actionCount} total · {openActionCount} open</div>
            <div className="truncate">AI: {hasAIAnalysis ? "available" : "missing"}</div>
            <div className="truncate">Closure: {closureReady ? "ready" : "blocked"}</div>
          </div>
        </div>
      </div>
    </section>
  );
}

function QuickActionButton({
  title,
  description,
  action,
  running,
  disabled,
  danger = false,
  success = false,
  onAction,
}: {
  title: string;
  description: string;
  action:
    | "ASSIGN_TO_ME"
    | "START_INVESTIGATION"
    | "ESCALATE_CASE"
    | "GENERATE_AI_ANALYSIS"
    | "GENERATE_AI_ACTION_PLAN"
    | "PREPARE_CLOSURE"
    | "CLOSE_CASE";
  running: string | null;
  disabled: boolean;
  danger?: boolean;
  success?: boolean;
  onAction: (
    action:
      | "ASSIGN_TO_ME"
      | "START_INVESTIGATION"
      | "ESCALATE_CASE"
      | "GENERATE_AI_ANALYSIS"
      | "GENERATE_AI_ACTION_PLAN"
      | "PREPARE_CLOSURE"
      | "CLOSE_CASE"
  ) => void;
}) {
  const isRunning = running === action;
  const isAnyRunning = running !== null;

  const className = success
    ? "border-emerald-700 bg-emerald-500 text-slate-950 hover:bg-emerald-400"
    : danger
      ? "border-red-800 bg-red-950/50 text-red-200 hover:bg-red-950"
      : "border-slate-700 bg-slate-950 text-slate-200 hover:border-cyan-700 hover:bg-slate-900";

  return (
    <button
      type="button"
      onClick={() => onAction(action)}
      disabled={disabled || isAnyRunning}
      className={`flex min-h-20 flex-col justify-between rounded-md border p-2.5 text-left transition disabled:cursor-not-allowed disabled:opacity-40 ${className}`}
    >
      <div className="flex items-center gap-1.5 truncate text-xs font-semibold">
        {isRunning && <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />}
        <span className="truncate">{isRunning ? "Working..." : title}</span>
      </div>
      <div
        className={`mt-1 line-clamp-2 text-[11px] leading-4 ${
          success ? "text-slate-800" : danger ? "text-red-300" : "text-slate-500"
        }`}
      >
        {description}
      </div>
    </button>
  );
}

function CaseCommandCenter({
  caseData,
  actionCount,
  openActionCount,
  completedActionCount,
  closureReady,
  hasAIAnalysis,
}: {
  caseData: IncidentCase;
  actionCount: number;
  openActionCount: number;
  completedActionCount: number;
  closureReady: boolean;
  hasAIAnalysis: boolean;
}) {
  const effectiveSeverity = caseData.severity_review ?? caseData.severity ?? "LOW";

  return (
    <section className="rounded-lg border border-cyan-900/60 bg-cyan-950/10 p-3 shadow-lg">
      <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <h2 className="text-sm font-semibold">Case Command Center</h2>
          <p className="mt-1 text-xs text-slate-500">
            Operational summary and shortcuts for the current investigation.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <span className={`rounded-full border px-2 py-0.5 text-[11px] ${statusClass(caseData.status)}`}>
            {caseData.status ?? "OPEN"}
          </span>
          <span className={`rounded-full border px-2 py-0.5 text-[11px] ${severityClass(effectiveSeverity)}`}>
            {effectiveSeverity}
          </span>
          <span className={`rounded-full border px-2 py-0.5 text-[11px] ${slaClass(caseData.sla_status)}`}>
            SLA {slaLabel(caseData.sla_status)}
          </span>
        </div>
      </div>

      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        <CommandMetric
          title="Owner"
          value={caseData.owner ?? "unassigned"}
          description={caseData.owner ? "Case ownership assigned." : "Ownership missing."}
          tone={caseData.owner ? "neutral" : "warning"}
        />

        <CommandMetric
          title="AI analysis"
          value={hasAIAnalysis ? "Available" : "Missing"}
          description={hasAIAnalysis ? "AI case assessment is available." : "Generate AI analysis before closure review."}
          tone={hasAIAnalysis ? "success" : "warning"}
          icon={hasAIAnalysis ? "bot" : "warning"}
        />

        <CommandMetric
          title="Action progress"
          value={`${completedActionCount}/${actionCount} done`}
          description={
            openActionCount > 0
              ? `${openActionCount} open or in-progress action(s).`
              : "No open actions blocking the case."
          }
          tone={openActionCount > 0 ? "warning" : "success"}
          icon={openActionCount > 0 ? "progress" : "check"}
        />

        <CommandMetric
          title="Closure readiness"
          value={closureReady ? "Ready" : "Blocked"}
          description={
            closureReady
              ? "Checklist complete and actions resolved."
              : "Closure requirements are not fully met."
          }
          tone={closureReady ? "success" : "warning"}
          icon={closureReady ? "check" : "progress"}
        />
      </div>

    </section>
  );
}

function CommandMetric({
  title,
  value,
  description,
  tone,
  icon = "none",
}: {
  title: string;
  value: string;
  description: string;
  tone: "success" | "warning" | "neutral";
  icon?: "check" | "warning" | "progress" | "bot" | "none";
}) {
  const toneClass =
    tone === "success"
      ? "border-emerald-900/80 bg-emerald-950/20"
      : tone === "warning"
        ? "border-orange-900/80 bg-orange-950/20"
        : "border-slate-800 bg-slate-950/70";

  const iconClass =
    tone === "success"
      ? "text-emerald-300"
      : tone === "warning"
        ? "text-orange-300"
        : "text-slate-400";

  return (
    <div className={`flex h-14 min-w-0 items-center justify-between gap-3 rounded-md border px-2.5 py-2 ${toneClass}`}>
      <div className="min-w-0">
        <div className="truncate text-[10px] uppercase tracking-wide text-slate-500">{title}</div>
        <div className="truncate text-sm font-semibold text-slate-100">
          {value}
        </div>
        <div className="truncate text-[10px] leading-3 text-slate-500">
          {description}
        </div>
      </div>
      <div className="flex items-center justify-between gap-2">
        {icon === "check" && <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${iconClass}`} />}
        {icon === "warning" && <AlertTriangle className={`h-3.5 w-3.5 shrink-0 ${iconClass}`} />}
        {icon === "progress" && <CircleDashed className={`h-3.5 w-3.5 shrink-0 ${iconClass}`} />}
        {icon === "bot" && <Bot className={`h-3.5 w-3.5 shrink-0 ${iconClass}`} />}
      </div>
    </div>
  );
}

function ReportDownloadCard({
  title,
  description,
  href,
  fallbackFilename,
  format,
  tone,
}: {
  title: string;
  description: string;
  href: string;
  fallbackFilename: string;
  format: string;
  tone: "executive" | "evidence" | "standard" | "json";
}) {
  const toneClass =
    tone === "executive"
      ? "border-violet-800 bg-violet-950/30 text-violet-200"
      : tone === "evidence"
        ? "border-emerald-800 bg-emerald-950/30 text-emerald-200"
        : tone === "json"
          ? "border-slate-700 bg-slate-950 text-slate-300"
          : "border-cyan-800 bg-cyan-950/30 text-cyan-200";

  const buttonClass =
    tone === "executive"
      ? "border-violet-700 bg-violet-500 text-white hover:bg-violet-400"
      : tone === "evidence"
        ? "border-emerald-700 bg-emerald-500 text-slate-950 hover:bg-emerald-400"
        : tone === "json"
          ? "border-slate-700 bg-slate-800 text-slate-100 hover:bg-slate-700"
          : "border-cyan-700 bg-cyan-500 text-slate-950 hover:bg-cyan-400";

  return (
    <div className={`flex h-full min-h-28 flex-col rounded-md border p-2.5 ${toneClass}`}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-xs font-semibold text-slate-100">{title}</h3>
          <p className="mt-1 text-[11px] leading-4 text-slate-400">
            {description}
          </p>
        </div>

        <span className="shrink-0 rounded-full border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[10px] text-slate-300">
          {format}
        </span>
      </div>

      <div className="mt-auto pt-2">
        <button
          type="button"
          onClick={() =>
            downloadBackendFile(href, fallbackFilename).catch((error) => alert(error.message))
          }
          className={`inline-flex h-7 w-full items-center justify-center gap-2 rounded-md border px-2 text-[11px] font-medium shadow-sm ${buttonClass}`}
        >
          Download
        </button>
      </div>
    </div>
  );
}

function InfoCard({
  title,
  value,
}: {
  title: string;
  value: string | number;
}) {
  return (
    <div className="flex h-16 min-w-0 flex-col justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2">
      <div className="truncate text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </div>
      <div className="truncate text-sm font-semibold text-slate-100">
        {value}
      </div>
    </div>
  );
}
