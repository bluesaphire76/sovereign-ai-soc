"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Briefcase, FileDown, ShieldAlert } from "lucide-react";

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
  const response = await fetch(`${API_BASE}/cases/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchCaseIncidents(id: string): Promise<CaseIncident[]> {
  const response = await fetch(`${API_BASE}/cases/${id}/incidents`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchCaseAnalysis(id: string): Promise<CaseAIAnalysis | null> {
  const response = await fetch(`${API_BASE}/cases/${id}/analysis`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  const data = (await response.json()) as CaseAIAnalysisResponse;
  return data.item;
}

async function fetchCaseAudit(id: string): Promise<CaseAudit[]> {
  const response = await fetch(`${API_BASE}/cases/${id}/audit`, {
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
  const response = await fetch(`${API_BASE}/cases/${id}/workflow`, {
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

async function fetchCaseClosure(id: string): Promise<CaseClosureResponse> {
  const response = await fetch(`${API_BASE}/cases/${id}/closure`, {
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
  const response = await fetch(`${API_BASE}/cases/${id}/closure`, {
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
  const response = await fetch(`${API_BASE}/cases/${id}/actions`, {
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
  const response = await fetch(`${API_BASE}/cases/${id}/actions/suggestions`, {
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
  const response = await fetch(`${API_BASE}/cases/${id}/actions`, {
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
  const response = await fetch(`${API_BASE}/cases/${caseId}/actions/${actionId}`, {
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
  const response = await fetch(`${API_BASE}/cases/${id}/analysis`, {
    method: "POST",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
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
      ] = await Promise.all([
        fetchCase(caseId),
        fetchCaseIncidents(caseId),
        fetchCaseAnalysis(caseId),
        fetchCaseAudit(caseId),
        fetchCaseActions(caseId),
        fetchCaseClosure(caseId),
      ]);

      setCaseData(caseResponse);
      setWorkflowForm(workflowFormFromCase(caseResponse));
      setIncidents(incidentsResponse);
      setCaseAnalysis(analysisResponse);
      setAuditTrail(auditResponse);
      setCaseActions(actionsResponse);
      setCaseClosure(closureResponse);
      setClosureForm(closureFormFromResponse(closureResponse));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerateActionSuggestions() {
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
        created_by: "local_analyst",
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
        created_by: "local_analyst",
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
    try {
      setUpdatingActionId(actionId);
      setError(null);

      const updated = await updateCaseAction(caseId, actionId, {
        status,
        updated_by: "local_analyst",
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
    try {
      setUpdatingActionId(actionId);
      setError(null);

      const updated = await updateCaseAction(caseId, actionId, {
        priority,
        updated_by: "local_analyst",
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
    try {
      setSavingClosureChecklist(true);
      setError(null);

      const response = await updateCaseClosure(caseId, {
        ...closureForm,
        reviewed_by: "local_analyst",
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
        reviewed_by: "local_analyst",
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

  useEffect(() => {
    loadCase();
  }, [caseId]);

  const summary = useMemo(() => {
    return prettyJson(caseData?.summary ?? null);
  }, [caseData]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8">
          <Link
            href="/cases"
            className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to cases
          </Link>

          <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
            <Briefcase className="h-4 w-4" />
            Investigation case
          </div>

          <h1 className="text-3xl font-semibold tracking-tight">
            Case #{caseId}
          </h1>

          {caseData && (
            <p className="mt-2 max-w-4xl text-sm text-slate-400">
              {caseData.title}
            </p>
          )}
          <div className="mt-5 flex flex-wrap gap-3">
            <a
              href={`${API_BASE}/reports/cases/${caseId}?format=markdown`}
              download
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-700 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 shadow-sm hover:bg-cyan-400"
            >
              <FileDown className="h-4 w-4" />
              Download Markdown report
            </a>

            <a
              href={`${API_BASE}/reports/cases/${caseId}?format=json`}
              download
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <FileDown className="h-4 w-4" />
              Download JSON
            </a>

            <a
              href={`/reports/cases/${caseId}/evidence-pack?format=markdown`}
              download
              className="inline-flex items-center gap-2 rounded-xl border border-emerald-700 bg-emerald-500 px-4 py-2 text-sm font-medium text-slate-950 shadow-sm hover:bg-emerald-400"
            >
              <FileDown className="h-4 w-4" />
              Download Evidence Pack
            </a>

            <a
              href={`/reports/cases/${caseId}/executive-pdf`}
              download
              className="inline-flex items-center gap-2 rounded-xl border border-violet-700 bg-violet-500 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-violet-400"
            >
              <FileDown className="h-4 w-4" />
              Download Executive PDF
            </a>
          </div>

        </header>

        {loading && (
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-300">
            Loading case...
          </div>
        )}

        {error && (
          <div className="whitespace-pre-wrap rounded-2xl border border-red-800 bg-red-950/60 p-4 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {caseData && (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-4">
              <InfoCard title="Host" value={caseData.agent ?? "unknown"} />
              <InfoCard title="Incidents" value={caseData.incident_count} />
              <InfoCard title="Risk score" value={caseData.risk_score ?? 0} />
              <InfoCard title="Updated" value={formatTimestamp(caseData.updated_at)} />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">Case workflow</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Assign ownership, review severity and track SLA for the investigation.
                  </p>
                </div>

                <span
                  className={`w-fit rounded-full border px-4 py-2 text-sm ${slaClass(
                    caseData.sla_status
                  )}`}
                >
                  SLA {slaLabel(caseData.sla_status)}
                </span>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
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
                    placeholder="local_analyst"
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </label>
              </div>

              <label className="mt-4 block">
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
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                />
              </label>

              <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs text-slate-500">
                  Last reviewed by {caseData.last_reviewed_by ?? "-"} ·{" "}
                  {formatTimestamp(caseData.last_reviewed_at)}
                </div>

                <button
                  onClick={handleSaveWorkflow}
                  disabled={savingWorkflow}
                  className="rounded-xl border border-cyan-500 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {savingWorkflow ? "Saving..." : "Save workflow"}
                </button>
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-2">
                <h2 className="text-lg font-medium">Case workflow audit</h2>
                <p className="text-sm text-slate-400">
                  Persistent history of workflow changes made by the analyst.
                </p>
              </div>

              {auditTrail.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No workflow audit events available yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {auditTrail.slice().reverse().map((event) => (
                    <div
                      key={event.id}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-4"
                    >
                      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                        <div className="text-sm font-medium text-slate-200">
                          {event.event_type}
                        </div>
                        <div className="text-xs text-slate-500">
                          {formatTimestamp(event.created_at)} ·{" "}
                          {event.created_by ?? "local_analyst"}
                        </div>
                      </div>

                      {event.comment && (
                        <div className="mb-2 text-sm text-slate-300">
                          {event.comment}
                        </div>
                      )}

                      <div className="grid gap-3 md:grid-cols-2">
                        <DetailRow label="Old value" value={event.old_value ?? "-"} />
                        <DetailRow label="New value" value={event.new_value ?? "-"} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">Case action plan</h2>
                  <p className="mt-1 text-sm text-slate-400">
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

              <div className="mb-5 rounded-xl border border-cyan-900/60 bg-cyan-950/20 p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h3 className="text-sm font-medium text-cyan-200">
                      AI-suggested action plan
                    </h3>
                    <p className="mt-1 text-sm text-slate-400">
                      Generate recommended analyst tasks from the current case evidence.
                      Suggestions are not saved until you explicitly create them.
                    </p>
                  </div>

                  <button
                    onClick={handleGenerateActionSuggestions}
                    disabled={generatingSuggestions}
                    className="rounded-xl border border-cyan-500 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {generatingSuggestions ? "Generating..." : "Generate AI action plan"}
                  </button>
                </div>

                {suggestionError && (
                  <div className="mt-4 rounded-xl border border-red-800 bg-red-950/60 p-3 text-sm text-red-200">
                    {suggestionError}
                  </div>
                )}

                {aiActionSuggestions.length > 0 && (
                  <div className="mt-5 space-y-3">
                    {aiActionSuggestions.map((suggestion, index) => (
                      <div
                        key={`${suggestion.title}-${index}`}
                        className="rounded-xl border border-slate-800 bg-slate-950 p-4"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div>
                            <div className="mb-2 flex flex-wrap items-center gap-2">
                              <span
                                className={`rounded-full border px-3 py-1 text-xs ${actionPriorityClass(
                                  suggestion.priority
                                )}`}
                              >
                                {suggestion.priority || "MEDIUM"}
                              </span>

                              <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300">
                                {suggestion.category || "INVESTIGATION"}
                              </span>
                            </div>

                            <h4 className="text-base font-medium text-slate-100">
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
                            className="rounded-xl border border-emerald-500 bg-emerald-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
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

              <div className="mb-5 rounded-xl border border-slate-800 bg-slate-950 p-4">
                <h3 className="mb-3 text-sm font-medium text-slate-200">
                  Add action
                </h3>

                <div className="grid gap-4 md:grid-cols-2">
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
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    >
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </label>
                </div>

                <label className="mt-4 block">
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <div className="mt-4 flex justify-end">
                  <button
                    onClick={handleCreateAction}
                    disabled={creatingAction}
                    className="rounded-xl border border-cyan-500 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {creatingAction ? "Creating..." : "Add action"}
                  </button>
                </div>
              </div>

              {caseActions.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No actions available yet. Add the first analyst task for this case.
                </div>
              ) : (
                <div className="space-y-3">
                  {caseActions.map((action) => (
                    <div
                      key={action.id}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-4"
                    >
                      <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                        <div>
                          <div className="mb-2 flex flex-wrap items-center gap-2">
                            <span
                              className={`rounded-full border px-3 py-1 text-xs ${actionStatusClass(
                                action.status
                              )}`}
                            >
                              {action.status}
                            </span>
                            <span
                              className={`rounded-full border px-3 py-1 text-xs ${actionPriorityClass(
                                action.priority
                              )}`}
                            >
                              {action.priority}
                            </span>
                            <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300">
                              {action.category}
                            </span>
                          </div>

                          <h3 className="text-base font-medium text-slate-100">
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
                            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">Case closure checklist</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Document the minimum evidence required before closing or marking the case as false positive.
                  </p>
                </div>

                <span
                  className={`w-fit rounded-full border px-4 py-2 text-sm ${
                    caseClosure?.ready_to_close
                      ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                      : "border-orange-700 bg-orange-950 text-orange-200"
                  }`}
                >
                  {caseClosure?.ready_to_close ? "Ready to close" : "Closure blocked"}
                </span>
              </div>

              {caseClosure && !caseClosure.ready_to_close && (
                <div className="mb-5 rounded-xl border border-orange-800 bg-orange-950/50 p-4">
                  <div className="text-sm font-medium text-orange-200">
                    This case cannot be closed yet.
                  </div>

                  <div className="mt-2 text-sm text-slate-300">
                    Open actions: {caseClosure.open_action_count}
                  </div>

                  {caseClosure.missing_items.length > 0 && (
                    <div className="mt-3">
                      <div className="mb-2 text-xs uppercase tracking-wide text-orange-300">
                        What still needs to be fixed
                      </div>
                      <ul className="list-inside list-disc space-y-1 text-sm text-slate-300">
                        {caseClosure.missing_items.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {caseClosure?.ready_to_close && (
                <div className="mb-5 rounded-xl border border-emerald-800 bg-emerald-950/40 p-4 text-sm text-emerald-200">
                  Closure checklist is complete and all actions are resolved. The case can now be moved to CLOSED or FALSE_POSITIVE.
                </div>
              )}

              <div className="grid gap-4 md:grid-cols-2">
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </label>
              </div>

              <div className="mt-4 grid gap-4 md:grid-cols-2">
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
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
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>
              </div>

              <label className="mt-4 block">
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
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                />
              </label>

              <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs text-slate-500">
                  Last reviewed by {caseClosure?.checklist?.reviewed_by ?? "-"} ·{" "}
                  {formatTimestamp(caseClosure?.checklist?.reviewed_at)}
                </div>

                <button
                  onClick={handleSaveClosureChecklist}
                  disabled={savingClosureChecklist}
                  className="rounded-xl border border-cyan-500 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {savingClosureChecklist ? "Saving..." : "Save closure checklist"}
                </button>
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">Case status</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Current grouped investigation status and severity.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2">
                  <span
                    className={`rounded-full border px-4 py-2 text-sm ${statusClass(
                      caseData.status
                    )}`}
                  >
                    {caseData.status ?? "OPEN"}
                  </span>

                  <span
                    className={`rounded-full border px-4 py-2 text-sm ${severityClass(
                      caseData.severity
                    )}`}
                  >
                    {caseData.severity ?? "LOW"} · {caseData.risk_score ?? 0}
                  </span>
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
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

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">Case AI analysis</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    LLM-generated investigation summary, risk interpretation and recommended next actions.
                  </p>
                </div>

                <button
                  onClick={handleGenerateAnalysis}
                  disabled={generatingAnalysis}
                  className="rounded-xl border border-cyan-500 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {generatingAnalysis ? "Generating..." : caseAnalysis ? "Regenerate AI analysis" : "Generate AI analysis"}
                </button>
              </div>

              {!caseAnalysis ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No AI analysis available yet for this case.
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
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

                  <pre className="whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm leading-6 text-slate-200">
                    {caseAnalysis.analysis}
                  </pre>
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <h2 className="mb-4 text-lg font-medium">Case summary</h2>

              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300">
                {summary || "No case summary available."}
              </pre>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Related incidents</h2>
              </div>

              {incidents.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No incidents linked to this case.
                </div>
              ) : (
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
                      {incidents.map((incident) => (
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
                              className={`rounded-full border px-3 py-1 text-xs ${statusClass(
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
              )}
            </section>
          </div>
        )}
      </div>
    </main>
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
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-3 text-sm text-slate-400">{title}</div>
      <div className="break-words text-xl font-semibold">{value}</div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
      <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="break-words text-sm text-slate-200">{value}</div>
    </div>
  );
}
