"use client";

import { downloadBackendFile } from "@/lib/download";
import { authFetch } from "@/lib/auth";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import { fetchCurrentUser, getStoredUser, type AuthUser } from "../../../lib/auth";
import { useParams } from "next/navigation";
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  Briefcase,
  CheckCircle2,
  CircleDashed,
  FileDown,
  ShieldAlert,
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
  sla_due_at: string | null;
  sla_status: string | null;
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


type WorkflowForm = {
  owner: string;
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

type CaseSectionFocus =
  | "ALL"
  | "OVERVIEW"
  | "WORKBENCH"
  | "EVIDENCE"
  | "REPORTS";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

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

function prettyJson(value: string | null) {
  if (!value) return "";

  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
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


async function generateCaseActionSuggestions(
  id: string
): Promise<CaseActionSuggestion[]> {
  const response = await authFetch(`/cases/${id}/actions/suggestions`, {
    method: "POST",
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(
      payload?.detail || `API error ${response.status}`
    );
  }

  const payload = await response.json();
  return payload.actions || [];
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
  const response = await authFetch(`/cases/${id}/analysis`, {
    method: "POST",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}




type CaseAiAnalysisInput = {
  analysis: string | null;
  model?: string | null;
  recommended_status?: string | null;
  recommended_severity?: string | null;
  created_at?: string | null;
  created_by?: string | null;
};

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

function caseAiSectionTone(key: string): string {
  const normalized = key.toLowerCase();

  if (normalized.includes("risk") || normalized.includes("severity")) {
    return "border-orange-800 bg-orange-950/20";
  }

  if (normalized.includes("remediation") || normalized.includes("action")) {
    return "border-emerald-800 bg-emerald-950/20";
  }

  if (normalized.includes("evidence") || normalized.includes("hypothesis")) {
    return "border-cyan-800 bg-cyan-950/20";
  }

  if (normalized.includes("summary") || normalized.includes("executive")) {
    return "border-violet-800 bg-violet-950/20";
  }

  return "border-slate-800 bg-slate-950";
}

function renderCaseScalar(value: string | number | boolean | null) {
  if (value === null) {
    return <span className="text-slate-500">-</span>;
  }

  if (typeof value === "boolean") {
    return (
      <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-xs text-slate-300">
        {value ? "Yes" : "No"}
      </span>
    );
  }

  return <span>{String(value)}</span>;
}

function CaseJsonValueRenderer({
  value,
  depth = 0,
}: {
  value: CaseJsonValue;
  depth?: number;
}) {
  if (isCaseEmptyJsonValue(value)) {
    return null;
  }

  if (typeof value !== "object" || value === null) {
    return (
      <p className="text-sm leading-6 text-slate-300">
        {renderCaseScalar(value)}
      </p>
    );
  }

  if (Array.isArray(value)) {
    const items = value.filter((item) => !isCaseEmptyJsonValue(item));

    if (items.length === 0) return null;

    return (
      <div className="space-y-2">
        {items.map((item, index) => {
          if (isCaseJsonObject(item)) {
            return (
              <div
                key={`array-object-${index}`}
                className="rounded-lg border border-slate-800 bg-slate-900/70 p-3"
              >
                <CaseJsonValueRenderer value={item} depth={depth + 1} />
              </div>
            );
          }

          return (
            <div
              key={`array-item-${index}`}
              className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-900/70 p-3"
            >
              <span className="mt-[0.55rem] h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
              <div className="text-sm leading-6 text-slate-300">
                <CaseJsonValueRenderer value={item} depth={depth + 1} />
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  const entries = Object.entries(value).filter(([, entryValue]) => !isCaseEmptyJsonValue(entryValue));

  if (entries.length === 0) return null;

  return (
    <div className={depth === 0 ? "grid gap-3 xl:grid-cols-2" : "space-y-3"}>
      {entries.map(([key, entryValue]) => {
        const title = humanizeCaseAiKey(key);
        const isNestedObject = isCaseJsonObject(entryValue) || Array.isArray(entryValue);

        return (
          <div
            key={key}
            className={`rounded-xl border p-4 shadow-sm ${caseAiSectionTone(key)}`}
          >
            <div className="mb-3 flex items-center justify-between gap-3 border-b border-slate-800 pb-2">
              <h4 className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
                {title}
              </h4>

              {isNestedObject && (
                <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5 text-[10px] text-slate-400">
                  Structured
                </span>
              )}
            </div>

            <div className="text-sm leading-6 text-slate-300">
              <CaseJsonValueRenderer value={entryValue} depth={depth + 1} />
            </div>
          </div>
        );
      })}
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

function CasePlainTextAnalysis({ value }: { value: string }) {
  const lines = splitCasePlainTextAnalysis(value);

  if (lines.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
        No readable AI analysis available.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {lines.map((line, index) => (
        <div
          key={`${line}-${index}`}
          className="flex gap-3 rounded-lg border border-slate-800 bg-slate-950 p-3"
        >
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-800 bg-cyan-950 text-xs font-semibold text-cyan-200">
            {index + 1}
          </div>
          <p className="text-sm leading-6 text-slate-300">{line}</p>
        </div>
      ))}
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
}: {
  caseAnalysis: CaseAiAnalysisInput;
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

            <div className="flex flex-wrap gap-2">
              <span className="rounded-full border border-violet-700 bg-violet-950 px-3 py-1 text-xs font-medium text-violet-200">
                AI-assisted
              </span>
              <span className="rounded-full border border-orange-700 bg-orange-950 px-3 py-1 text-xs font-medium text-orange-200">
                Human approval required
              </span>
              {parsedJson && (
                <span className="rounded-full border border-cyan-700 bg-cyan-950 px-3 py-1 text-xs font-medium text-cyan-200">
                  Structured JSON
                </span>
              )}
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
          {parsedJson ? (
            <CaseJsonValueRenderer value={parsedJson} />
          ) : (
            <CasePlainTextAnalysis value={analysis} />
          )}
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

export default function CaseDetailPage() {
  const params = useParams();
  const caseId = String(params.id);

  const [caseData, setCaseData] = useState<IncidentCase | null>(null);
  const [incidents, setIncidents] = useState<CaseIncident[]>([]);
  const [caseAnalysis, setCaseAnalysis] = useState<CaseAIAnalysis | null>(null);
  const [auditTrail, setAuditTrail] = useState<CaseAudit[]>([]);
  const [caseActions, setCaseActions] = useState<CaseAction[]>([]);
  const [caseClosure, setCaseClosure] = useState<CaseClosureResponse | null>(null);
  const [caseTimeline, setCaseTimeline] = useState<CaseTimelineItem[]>([]);
  const [timelineOpen, setTimelineOpen] = useState(false);
  const [timelineExpanded, setTimelineExpanded] = useState(false);
  const [auditTrailOpen, setAuditTrailOpen] = useState(false);
  const [auditTrailExpanded, setAuditTrailExpanded] = useState(false);
  const [relatedIncidentsOpen, setRelatedIncidentsOpen] = useState(false);
  const [relatedIncidentsExpanded, setRelatedIncidentsExpanded] = useState(false);
  const [closureForm, setClosureForm] = useState<ClosureForm>({
    root_cause: "",
    evidence_reviewed: "",
    actions_summary: "",
    closure_reason: "",
    closure_decision: "RESOLVED",
    final_severity: "LOW",
    residual_risk: "",
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
    status: "OPEN",
    severity: "LOW",
    sla_due_at: "",
    status_reason: "",
  });
  const [generatingAnalysis, setGeneratingAnalysis] = useState(false);
  const [savingWorkflow, setSavingWorkflow] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sectionFocus, setSectionFocus] = useState<CaseSectionFocus>("ALL");
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

  async function loadCase() {
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
      ] = await Promise.all([
        fetchCase(caseId),
        fetchCaseIncidents(caseId),
        fetchCaseAnalysis(caseId),
        fetchCaseAudit(caseId),
        fetchCaseActions(caseId),
        fetchCaseClosure(caseId),
        fetchCaseTimeline(caseId),
      ]);

      setCaseData(caseResponse);
      setWorkflowForm(workflowFormFromCase(caseResponse));
      setIncidents(incidentsResponse);
      setCaseAnalysis(analysisResponse);
      setAuditTrail(auditResponse);
      setCaseActions(actionsResponse);
      setCaseClosure(closureResponse);
      setClosureForm(closureFormFromResponse(closureResponse));
      setCaseTimeline(timelineResponse.items || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerateActionSuggestions() {
    if (!assertCanOperate()) return;

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

  async function handleGenerateAnalysis() {
    if (!assertCanOperate()) return;

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

  function scrollToCaseSection(sectionId: string) {
    window.setTimeout(() => {
      document.getElementById(sectionId)?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 50);
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
        const result = await generateCaseAnalysis(caseId);
        setCaseAnalysis(result);
        setSectionFocus("WORKBENCH");
        scrollToCaseSection("case-ai-analysis");
        return;
      }

      if (action === "GENERATE_AI_ACTION_PLAN") {
        const suggestions = await generateCaseActionSuggestions(caseId);
        setAiActionSuggestions(suggestions);
        setSectionFocus("WORKBENCH");
        scrollToCaseSection("case-action-plan");
        return;
      }

      if (action === "PREPARE_CLOSURE") {
        setSectionFocus("WORKBENCH");
        scrollToCaseSection("case-closure-checklist");
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
        setSectionFocus("WORKBENCH");
        scrollToCaseSection("case-workflow");
      }

      if (action === "CLOSE_CASE") {
        setSectionFocus("OVERVIEW");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setQuickActionRunning(null);
    }
  }

  useEffect(() => {
    setCurrentUser(getStoredUser());

    fetchCurrentUser()
      .then((current) => setCurrentUser(current))
      .catch(() => {
        // authFetch handles expired/invalid sessions globally
      });
  }, []);

  useEffect(() => {
    if (!isViewer) return;

    const styleId = "ai-soc-case-viewer-readonly-style";
    document.getElementById(styleId)?.remove();

    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      #case-workflow input,
      #case-workflow select,
      #case-workflow textarea,
      #case-workflow button,
      #case-action-plan input,
      #case-action-plan select,
      #case-action-plan textarea,
      #case-action-plan button,
      #case-closure-checklist input,
      #case-closure-checklist select,
      #case-closure-checklist textarea,
      #case-closure-checklist button {
        display: none !important;
      }

      #case-workflow::before,
      #case-action-plan::before,
      #case-closure-checklist::before {
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
    loadCase();
  }, [caseId]);

  const summary = useMemo(() => {
    return prettyJson(caseData?.summary ?? null);
  }, [caseData]);

  const visibleTimeline = useMemo(() => {
    if (!timelineOpen) {
      return [];
    }

    if (timelineExpanded) {
      return caseTimeline;
    }

    return caseTimeline.slice(-12);
  }, [caseTimeline, timelineExpanded, timelineOpen]);

  const hiddenTimelineEvents = Math.max(
    caseTimeline.length - visibleTimeline.length,
    0
  );

  const visibleAuditTrail = useMemo(() => {
    if (!auditTrailOpen) {
      return [];
    }

    if (auditTrailExpanded) {
      return auditTrail;
    }

    return auditTrail.slice(-10);
  }, [auditTrail, auditTrailExpanded, auditTrailOpen]);

  const hiddenAuditEvents = Math.max(
    auditTrail.length - visibleAuditTrail.length,
    0
  );

  const visibleRelatedIncidents = useMemo(() => {
    if (!relatedIncidentsOpen) {
      return [];
    }

    if (relatedIncidentsExpanded) {
      return incidents;
    }

    return incidents.slice(-15);
  }, [incidents, relatedIncidentsExpanded, relatedIncidentsOpen]);

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
            <p className="mt-1 max-w-5xl text-xs text-slate-500">
              {caseData.title}
            </p>
          )}


        </header>

        {loading && (
          <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-slate-300">
            Loading case...
          </div>
        )}

        {error && (
          <div className="whitespace-pre-wrap rounded-lg border border-red-800 bg-red-950/60 p-3 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {caseData && (
          <div className="space-y-3" data-case-focus={sectionFocus}>
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
              [data-case-focus="WORKBENCH"] #case-timeline,
              [data-case-focus="WORKBENCH"] #case-audit,
              [data-case-focus="WORKBENCH"] #case-summary,
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
              [data-case-focus="REPORTS"] #case-timeline,
              [data-case-focus="REPORTS"] #case-audit,
              [data-case-focus="REPORTS"] #related-incidents {
                display: none;
              }
            `}</style>
            <section className="grid gap-3 md:grid-cols-4">
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

            <CaseFocusMode
              value={sectionFocus}
              onChange={setSectionFocus}
            />

            <CaseQuickActions
              caseData={caseData}
              actionCount={caseActions.length}
              openActionCount={openActionCount}
              closureReady={closureReady}
              hasAIAnalysis={hasAIAnalysis}
              quickActionRunning={quickActionRunning}
              onAction={handleCaseQuickAction}
            />

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="reports-center">
              <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Reports Center</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Export executive, analyst and machine-readable reports for this case.
                  </p>
                </div>

                <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
                  4 exports
                </span>
              </div>

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <ReportDownloadCard
                  title="Executive PDF"
                  description="Board-ready PDF with executive summary, risk, actions and closure readiness."
                  href={`/reports/cases/${caseId}/executive-pdf`}
                  format="PDF"
                  tone="executive"
                />

                <ReportDownloadCard
                  title="Analyst Evidence Pack"
                  description="Detailed evidence package with raw alerts, action plan, audit trail and closure evidence."
                  href={`/reports/cases/${caseId}/evidence-pack?format=markdown`}
                  format="MD"
                  tone="evidence"
                />

                <ReportDownloadCard
                  title="Markdown Case Report"
                  description="Readable case report suitable for review, notes, ticketing systems and documentation."
                  href={`/reports/cases/${caseId}?format=markdown`}
                  format="MD"
                  tone="standard"
                />

                <ReportDownloadCard
                  title="JSON Case Payload"
                  description="Structured export for automation, integrations, testing or downstream processing."
                  href={`/reports/cases/${caseId}?format=json`}
                  format="JSON"
                  tone="json"
                />
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="case-timeline">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case timeline</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Chronological view of incidents, AI analysis, actions, workflow updates and closure events.
                  </p>

                  {!timelineOpen && caseTimeline.length > 12 && (
                    <p className="mt-2 text-xs text-slate-500">
                      Timeline is collapsed to avoid long scrolling. Open it to review the latest events.
                    </p>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
                    {caseTimeline.length} events
                  </span>

                  <button
                    onClick={() => setTimelineOpen((current) => !current)}
                    className="rounded-md border border-cyan-700 bg-slate-950 px-3 py-1.5 text-xs text-cyan-200 hover:bg-slate-800"
                  >
                    {timelineOpen ? "Hide timeline" : "Show timeline"}
                  </button>
                </div>
              </div>

              {timelineOpen && caseTimeline.length > 0 && (
                <div className="mt-3">
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

              {timelineOpen && caseTimeline.length === 0 && (
                <div className="mt-3 rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No timeline events available.
                </div>
              )}
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="case-workflow">
              <div className="mb-2 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case workflow</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Assign ownership, review severity and track SLA for the investigation.
                  </p>
                </div>

                <span
                  className={`w-fit rounded-full border px-3 py-1.5 text-xs ${slaClass(
                    caseData.sla_status
                  )}`}
                >
                  SLA {slaLabel(caseData.sla_status)}
                </span>
              </div>

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
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="case-audit">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case workflow audit</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Chronological audit events for workflow updates, actions and closure checklist changes.
                  </p>

                  {!auditTrailOpen && auditTrail.length > 10 && (
                    <p className="mt-2 text-xs text-slate-500">
                      Audit trail is collapsed to avoid long scrolling. Open it to review the latest audit events.
                    </p>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
                    {auditTrail.length} audit events
                  </span>

                  <button
                    onClick={() => setAuditTrailOpen((current) => !current)}
                    className="rounded-md border border-cyan-700 bg-slate-950 px-3 py-1.5 text-xs text-cyan-200 hover:bg-slate-800"
                  >
                    {auditTrailOpen ? "Hide audit trail" : "Show audit trail"}
                  </button>
                </div>
              </div>

              {auditTrailOpen && auditTrail.length === 0 && (
                <div className="mt-3 rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No audit events available for this case.
                </div>
              )}

              {auditTrailOpen && auditTrail.length > 0 && (
                <div className="mt-3">
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
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="case-action-plan">
              <div className="mb-2 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case action plan</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Track concrete analyst tasks required to investigate, contain, escalate or close the case.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2 text-xs">
                  <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-slate-300">
                    {caseActions.length} total
                  </span>
                  <span className="rounded-full border border-cyan-700 bg-cyan-950 px-3 py-1 text-cyan-200">
                    {
                      caseActions.filter(
                        (action) =>
                          action.status !== "DONE" &&
                          action.status !== "CANCELLED"
                      ).length
                    } open
                  </span>
                  <span className="rounded-full border border-emerald-700 bg-emerald-950 px-3 py-1 text-emerald-200">
                    {caseActions.filter((action) => action.status === "DONE").length} done
                  </span>
                </div>
              </div>

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
                    className="rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {generatingSuggestions ? "Generating..." : "Generate AI action plan"}
                  </button>
                </div>

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
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="case-closure-checklist">
              <div className="mb-2 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case closure checklist</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Document the minimum evidence required before closing or marking the case as false positive.
                  </p>
                </div>

                <span
                  className={`w-fit rounded-full border px-3 py-1.5 text-xs ${
                    caseClosure?.ready_to_close
                      ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                      : "border-orange-700 bg-orange-950 text-orange-200"
                  }`}
                >
                  {caseClosure?.ready_to_close ? "Ready to close" : "Closure blocked"}
                </span>
              </div>

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
                  Closure checklist is complete and all actions are resolved. The case can now be moved to CLOSED or FALSE_POSITIVE.
                </div>
              )}

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
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg">
              <div className="mb-2 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case status</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Current grouped investigation status and severity.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2">
                  <span
                    className={`rounded-full border px-3 py-1.5 text-xs ${statusClass(
                      caseData.status
                    )}`}
                  >
                    {caseData.status ?? "OPEN"}
                  </span>

                  <span
                    className={`rounded-full border px-3 py-1.5 text-xs ${severityClass(
                      caseData.severity
                    )}`}
                  >
                    {caseData.severity ?? "LOW"} · {caseData.risk_score ?? 0}
                  </span>
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <DetailRow
                  label="Correlation type"
                  value={caseData.correlation_type ?? "-"}
                />
                <DetailRow label="Group key" value={caseData.group_key} />
                <DetailRow
                  label="Created"
                  value={formatTimestamp(caseData.created_at)}
                />
                <DetailRow
                  label="Created by"
                  value={caseData.created_by ?? "system"}
                />
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg">
              <div className="mb-2 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Case AI analysis</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    LLM-generated investigation summary, risk interpretation and recommended next actions.
                  </p>
                </div>

                {canOperate && (
                <button
                  onClick={handleGenerateAnalysis}
                  disabled={generatingAnalysis}
                  className="rounded-md border border-cyan-500 bg-cyan-500 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {generatingAnalysis ? "Generating..." : caseAnalysis ? "Regenerate AI analysis" : "Generate AI analysis"}
                </button>
                )}
              </div>

              {!caseAnalysis ? (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No AI analysis available yet for this case.
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="grid gap-3 md:grid-cols-3">
                    <DetailRow label="Model" value={caseAnalysis.model ?? "-"} />
                    <DetailRow
                      label="Recommended status"
                      value={caseAnalysis.recommended_status ?? "-"}
                    />
                    <DetailRow
                      label="Recommended severity"
                      value={caseAnalysis.recommended_severity ?? "-"}
                    />
                  </div>

                  <div className="text-xs text-slate-500">
                    Generated {formatTimestamp(caseAnalysis.created_at)} by{" "}
                    {caseAnalysis.created_by ?? "llm"}
                  </div>

                  <EnterpriseCaseAiAnalysis caseAnalysis={caseAnalysis} />
                </div>
              )}
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg">
              <h2 className="mb-2 text-sm font-semibold">Case summary</h2>

              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">
                {summary || "No case summary available."}
              </pre>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg" id="related-incidents">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-5 w-5 text-cyan-300" />
                    <h2 className="text-sm font-semibold">Related incidents</h2>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    Linked alerts and detections associated with this investigation case.
                  </p>

                  {!relatedIncidentsOpen && incidents.length > 15 && (
                    <p className="mt-2 text-xs text-slate-500">
                      Incident list is collapsed to avoid long scrolling. Open it to review the latest linked incidents.
                    </p>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
                    {incidents.length} incidents
                  </span>

                  <button
                    onClick={() => setRelatedIncidentsOpen((current) => !current)}
                    className="rounded-md border border-cyan-700 bg-slate-950 px-3 py-1.5 text-xs text-cyan-200 hover:bg-slate-800"
                  >
                    {relatedIncidentsOpen ? "Hide related incidents" : "Show related incidents"}
                  </button>
                </div>
              </div>

              {relatedIncidentsOpen && incidents.length === 0 && (
                <div className="mt-3 rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                  No incidents linked to this case.
                </div>
              )}

              {relatedIncidentsOpen && incidents.length > 0 && (
                <div className="mt-3">
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
            </section>

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
  onAction,
}: {
  caseData: IncidentCase;
  actionCount: number;
  openActionCount: number;
  closureReady: boolean;
  hasAIAnalysis: boolean;
  quickActionRunning: string | null;
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

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
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
          running={quickActionRunning}
          disabled={false}
          onAction={onAction}
        />

        <QuickActionButton
          title="Generate AI action plan"
          description="Suggest analyst tasks from the current case evidence."
          action="GENERATE_AI_ACTION_PLAN"
          running={quickActionRunning}
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

        <div className="rounded-md border border-slate-800 bg-slate-950 p-4">
          <div className="text-sm font-medium text-slate-200">Current blockers</div>
          <div className="mt-2 space-y-1 text-xs leading-5 text-slate-500">
            <div>Actions: {actionCount} total · {openActionCount} open</div>
            <div>AI analysis: {hasAIAnalysis ? "available" : "missing"}</div>
            <div>Closure: {closureReady ? "ready" : "blocked"}</div>
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
      className={`rounded-md border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-40 ${className}`}
    >
      <div className="text-sm font-medium">
        {isRunning ? "Working..." : title}
      </div>
      <div
        className={`mt-2 text-xs leading-5 ${
          success ? "text-slate-800" : danger ? "text-red-300" : "text-slate-500"
        }`}
      >
        {description}
      </div>
    </button>
  );
}

function CaseFocusMode({
  value,
  onChange,
}: {
  value: CaseSectionFocus;
  onChange: (value: CaseSectionFocus) => void;
}) {
  const modes: {
    value: CaseSectionFocus;
    label: string;
    description: string;
  }[] = [
    {
      value: "ALL",
      label: "All sections",
      description: "Show the full case detail page.",
    },
    {
      value: "OVERVIEW",
      label: "Overview",
      description: "Summary, reports and AI analysis.",
    },
    {
      value: "WORKBENCH",
      label: "Analyst workbench",
      description: "Workflow, actions, closure and AI analysis.",
    },
    {
      value: "EVIDENCE",
      label: "Evidence review",
      description: "Timeline, audit trail, related incidents and evidence.",
    },
    {
      value: "REPORTS",
      label: "Reports",
      description: "Exports, executive report and machine-readable payload.",
    },
  ];

  const activeMode = modes.find((mode) => mode.value === value) ?? modes[0];

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg">
      <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <h2 className="text-sm font-semibold">Focus Mode</h2>
          <p className="mt-1 text-xs text-slate-500">
            Collapse non-relevant sections and focus on the current analyst workflow.
          </p>
        </div>

        <span className="w-fit rounded-full border border-cyan-700 bg-cyan-950 px-3 py-1.5 text-xs text-cyan-200">
          {activeMode.label}
        </span>
      </div>

      <div className="grid gap-3 md:grid-cols-5">
        {modes.map((mode) => (
          <button
            key={mode.value}
            onClick={() => onChange(mode.value)}
            className={`rounded-md border p-3 text-left transition ${
              value === mode.value
                ? "border-cyan-500 bg-cyan-500 text-slate-950"
                : "border-slate-800 bg-slate-950 text-slate-300 hover:border-cyan-800 hover:bg-slate-900"
            }`}
          >
            <div className="text-sm font-medium">{mode.label}</div>
            <div
              className={`mt-2 text-xs leading-5 ${
                value === mode.value ? "text-slate-800" : "text-slate-500"
              }`}
            >
              {mode.description}
            </div>
          </button>
        ))}
      </div>
    </section>
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

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
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

      <div className="mt-3 rounded-md border border-slate-800 bg-slate-950 p-4">
        <div className="mb-3 text-xs uppercase tracking-wide text-slate-500">
          Quick navigation
        </div>

        <div className="flex flex-wrap gap-2">
          <QuickAnchor href="#reports-center" label="Reports" />
          <QuickAnchor href="#case-workflow" label="Workflow" />
          <QuickAnchor href="#case-action-plan" label="Actions" />
          <QuickAnchor href="#case-closure-checklist" label="Closure" />
          <QuickAnchor href="#case-ai-analysis" label="AI analysis" />
          <QuickAnchor href="#case-timeline" label="Timeline" />
          <QuickAnchor href="#case-audit" label="Audit" />
          <QuickAnchor href="#related-incidents" label="Incidents" />
        </div>
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
      ? "border-emerald-800 bg-emerald-950/30"
      : tone === "warning"
        ? "border-orange-800 bg-orange-950/30"
        : "border-slate-800 bg-slate-950";

  const iconClass =
    tone === "success"
      ? "text-emerald-300"
      : tone === "warning"
        ? "text-orange-300"
        : "text-slate-400";

  return (
    <div className={`rounded-md border p-3 ${toneClass}`}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="text-xs text-slate-500">{title}</div>
        {icon === "check" && <CheckCircle2 className={`h-4 w-4 ${iconClass}`} />}
        {icon === "warning" && <AlertTriangle className={`h-4 w-4 ${iconClass}`} />}
        {icon === "progress" && <CircleDashed className={`h-4 w-4 ${iconClass}`} />}
        {icon === "bot" && <Bot className={`h-4 w-4 ${iconClass}`} />}
      </div>

      <div className="text-xl font-semibold text-slate-100">{value}</div>
      <div className="mt-2 text-xs leading-5 text-slate-500">{description}</div>
    </div>
  );
}

function QuickAnchor({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-700 hover:text-cyan-200"
    >
      {label}
    </a>
  );
}

function ReportDownloadCard({
  title,
  description,
  href,
  format,
  tone,
}: {
  title: string;
  description: string;
  href: string;
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
    <div className={`flex h-full flex-col rounded-md border p-3 ${toneClass}`}>
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            {description}
          </p>
        </div>

        <span className="shrink-0 rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-300">
          {format}
        </span>
      </div>

      <div className="mt-auto pt-3">
        <button
          type="button"
          onClick={() =>
            downloadBackendFile(href).catch((error) => alert(error.message))
          }
          className={`inline-flex w-full items-center justify-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium shadow-sm ${buttonClass}`}
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
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-lg">
      <div className="mb-3 text-xs text-slate-500">{title}</div>
      <div className="break-words text-xl font-semibold">{value}</div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-4">
      <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="break-words text-sm text-slate-200">{value}</div>
    </div>
  );
}
