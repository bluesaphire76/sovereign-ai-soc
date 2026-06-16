"use client";

import { authFetch, type AuthUser } from "@/lib/auth";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ExternalLink,
  FileText,
  Plus,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";

type ActionCatalogItem = {
  action_type: string;
  display_name: string;
  risk_level: string;
  execution_mode: string;
  connector_key: string;
  execution_supported_in_step13: boolean;
  requires_admin_approval: boolean;
};

type PlaybookTemplate = {
  playbook_key: string;
  display_name: string;
  description: string;
  risk_level: string;
  recommended_actions: string[];
  checklist_items: string[];
};

export type GovernedRemediationRecommendation = {
  title: string;
  description?: string | null;
  action_type?: string | null;
  risk_level?: string | null;
  reason?: string | null;
};

type RemediationProposal = {
  id: number;
  title: string;
  description: string | null;
  action_type: string;
  status: string;
  risk_level: string;
  execution_mode: string;
  connector_key: string;
  source_type: string | null;
  incident_id: number | null;
  case_id: number | null;
  reason: string | null;
  business_justification: string | null;
  expected_impact: string | null;
  required_approval_role: string | null;
  converted_target_type: string | null;
  converted_target_id: string | null;
  payload_json: Record<string, unknown>;
  safe_summary: string | null;
  allowed_transitions: string[];
  created_at: string | null;
  updated_at: string | null;
};

type ProposalResponse = {
  items: RemediationProposal[];
  summary: {
    total: number;
    states: Record<string, number>;
    proposal_only: number;
    requires_admin: number;
  };
};

type Props = {
  scope: "incident" | "case";
  incidentId?: number;
  caseId?: number;
  currentUser: AuthUser | null;
  canOperate: boolean;
  aiRecommendations?: GovernedRemediationRecommendation[];
  onChanged?: () => void;
};

type ProposalDraft = {
  action_type: string;
  title: string;
  description: string;
  risk_level: string;
  reason: string;
  business_justification: string;
  expected_impact: string;
  payload_json: string;
};

const DEFAULT_DRAFT: ProposalDraft = {
  action_type: "CREATE_CASE_ACTION",
  title: "",
  description: "",
  risk_level: "LOW",
  reason: "",
  business_justification: "",
  expected_impact: "",
  payload_json: "{}",
};

function toneForStatus(status: string) {
  const value = status.toUpperCase();
  if (value === "APPROVED" || value === "CONVERTED") return "border-emerald-700 bg-emerald-950 text-emerald-200";
  if (value === "PROPOSED") return "border-cyan-700 bg-cyan-950 text-cyan-200";
  if (value === "REJECTED" || value === "CANCELLED") return "border-red-800 bg-red-950 text-red-200";
  return "border-slate-700 bg-slate-950 text-slate-300";
}

function toneForRisk(risk: string) {
  const value = risk.toUpperCase();
  if (value === "HIGH" || value === "CRITICAL") return "border-red-800 bg-red-950 text-red-200";
  if (value === "MEDIUM") return "border-orange-700 bg-orange-950 text-orange-200";
  return "border-emerald-700 bg-emerald-950 text-emerald-200";
}

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("it-CH", {
    timeZone: "Europe/Zurich",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function parsePayload(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return {};
  const parsed = JSON.parse(trimmed);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Payload/details must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function Button({
  children,
  onClick,
  disabled,
  tone = "neutral",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  tone?: "neutral" | "primary" | "success" | "danger";
}) {
  const classes = {
    neutral: "border-slate-700 bg-slate-950 text-slate-200 hover:border-cyan-600",
    primary: "border-cyan-600 bg-cyan-600 text-slate-950 hover:bg-cyan-500",
    success: "border-emerald-700 bg-emerald-950 text-emerald-200 hover:border-emerald-500",
    danger: "border-red-800 bg-red-950 text-red-200 hover:border-red-600",
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex h-8 items-center gap-1.5 rounded-sm border px-2.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-40 ${classes[tone]}`}
    >
      {children}
    </button>
  );
}

function Badge({ children, tone }: { children: ReactNode; tone: string }) {
  return (
    <span className={`inline-flex max-w-full items-center rounded-sm border px-2 py-0.5 text-[10px] font-medium ${tone}`}>
      <span className="truncate">{children}</span>
    </span>
  );
}

function linkedObjectHref(proposal: RemediationProposal) {
  if (!proposal.converted_target_type || !proposal.converted_target_id) return null;
  if (proposal.converted_target_type === "case_action" && proposal.case_id) return `/cases/${proposal.case_id}`;
  if (proposal.converted_target_type === "incident_note" && proposal.incident_id) return `/incidents/${proposal.incident_id}`;
  if (proposal.converted_target_type === "detection_lifecycle_item") return "/settings/detection-control";
  if (proposal.converted_target_type === "service_operations_link") return "/settings/detection-control";
  return null;
}

export default function GovernedRemediationPanel({
  scope,
  incidentId,
  caseId,
  currentUser,
  canOperate,
  aiRecommendations = [],
  onChanged,
}: Props) {
  const [actions, setActions] = useState<ActionCatalogItem[]>([]);
  const [playbooks, setPlaybooks] = useState<PlaybookTemplate[]>([]);
  const [proposals, setProposals] = useState<RemediationProposal[]>([]);
  const [summary, setSummary] = useState<ProposalResponse["summary"] | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [draft, setDraft] = useState<ProposalDraft>(DEFAULT_DRAFT);
  const [playbookKey, setPlaybookKey] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const isAdmin = currentUser?.role === "ADMIN";
  const selected = proposals.find((item) => item.id === selectedId) ?? proposals[0] ?? null;
  const endpoint = scope === "incident"
    ? `/remediation/incidents/${incidentId}/proposals`
    : `/remediation/cases/${caseId}/proposals`;

  const actionByType = useMemo(() => {
    const mapped: Record<string, ActionCatalogItem> = {};
    for (const item of actions) mapped[item.action_type] = item;
    return mapped;
  }, [actions]);

  const load = useCallback(async () => {
    if ((scope === "incident" && !incidentId) || (scope === "case" && !caseId)) return;
    setLoading(true);
    setError(null);
    try {
      const [proposalResponse, actionResponse, playbookResponse] = await Promise.all([
        authFetch(endpoint, { cache: "no-store" }),
        authFetch("/remediation/catalog/actions", { cache: "no-store" }),
        authFetch("/remediation/catalog/playbooks", { cache: "no-store" }),
      ]);

      if (!proposalResponse.ok) throw new Error(`Proposal API error ${proposalResponse.status}`);
      if (!actionResponse.ok) throw new Error(`Action catalog API error ${actionResponse.status}`);
      if (!playbookResponse.ok) throw new Error(`Playbook catalog API error ${playbookResponse.status}`);

      const proposalPayload = (await proposalResponse.json()) as ProposalResponse;
      const actionPayload = (await actionResponse.json()) as { items: ActionCatalogItem[] };
      const playbookPayload = (await playbookResponse.json()) as { items: PlaybookTemplate[] };

      setProposals(proposalPayload.items || []);
      setSummary(proposalPayload.summary || null);
      setActions(actionPayload.items || []);
      setPlaybooks(playbookPayload.items || []);
      setPlaybookKey((current) => current || playbookPayload.items?.[0]?.playbook_key || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load governed remediation.");
    } finally {
      setLoading(false);
    }
  }, [caseId, endpoint, incidentId, scope]);

  useEffect(() => {
    void load();
  }, [load]);

  async function mutate(path: string, body: Record<string, unknown>, successMessage: string) {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const response = await authFetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(String(payload?.detail ?? `API error ${response.status}`));
      }
      setNotice(successMessage);
      await load();
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update proposal.");
    } finally {
      setSaving(false);
    }
  }

  async function handleCreateManual() {
    if (!canOperate) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const response = await authFetch("/remediation/proposals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: incidentId,
          case_id: caseId,
          action_type: draft.action_type,
          title: draft.title,
          description: draft.description,
          risk_level: draft.risk_level,
          reason: draft.reason,
          business_justification: draft.business_justification,
          expected_impact: draft.expected_impact,
          payload_json: parsePayload(draft.payload_json),
        }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) throw new Error(String(payload?.detail ?? `API error ${response.status}`));
      setDraft(DEFAULT_DRAFT);
      setFormOpen(false);
      setNotice("Remediation proposal created.");
      await load();
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create proposal.");
    } finally {
      setSaving(false);
    }
  }

  async function handleCreateFromRecommendation(recommendation: GovernedRemediationRecommendation) {
    if (!canOperate) return;
    await mutate(
      "/remediation/proposals/from-ai-recommendation",
      {
        incident_id: incidentId,
        case_id: caseId,
        recommendation,
        reason: recommendation.reason || "Analyst selected AI recommendation for governed proposal review.",
      },
      "AI recommendation converted to a governed proposal.",
    );
  }

  async function handleCreateFromPlaybook() {
    if (!canOperate || !playbookKey) return;
    await mutate(
      "/remediation/proposals/from-playbook",
      {
        incident_id: incidentId,
        case_id: caseId,
        playbook_key: playbookKey,
        reason: "Create governed proposal from selected playbook template.",
      },
      "Playbook proposal created.",
    );
  }

  function canConvert(proposal: RemediationProposal) {
    if (!canOperate) return false;
    if (proposal.status === "APPROVED") return isAdmin || proposal.required_approval_role !== "ADMIN";
    return proposal.status === "DRAFT" && proposal.risk_level === "LOW";
  }

  const visibleRecommendations = aiRecommendations
    .filter((item) => item.title?.trim())
    .slice(0, 4);

  return (
    <div className="space-y-3">
      <div className="grid gap-2 md:grid-cols-4">
        <div className="rounded-sm border border-slate-800 bg-slate-950 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Proposals</div>
          <div className="mt-1 text-lg font-semibold text-slate-100">{summary?.total ?? proposals.length}</div>
        </div>
        <div className="rounded-sm border border-slate-800 bg-slate-950 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Proposed</div>
          <div className="mt-1 text-lg font-semibold text-cyan-200">{summary?.states?.PROPOSED ?? 0}</div>
        </div>
        <div className="rounded-sm border border-slate-800 bg-slate-950 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Admin review</div>
          <div className="mt-1 text-lg font-semibold text-orange-200">{summary?.requires_admin ?? 0}</div>
        </div>
        <div className="rounded-sm border border-slate-800 bg-slate-950 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Proposal-only</div>
          <div className="mt-1 text-lg font-semibold text-slate-200">{summary?.proposal_only ?? 0}</div>
        </div>
      </div>

      <div className="rounded-sm border border-orange-900/70 bg-orange-950/20 p-2 text-xs leading-5 text-orange-100">
        Governed remediation only: high-risk and external actions can be proposed, reviewed and tracked, but Step 13 does not execute firewall, SOAR, EDR, service restart or rule-apply actions.
      </div>

      <div className="flex flex-wrap gap-2">
        <Button onClick={load} disabled={loading || saving}>
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
        {canOperate && (
          <Button onClick={() => setFormOpen((current) => !current)} tone="primary">
            <Plus className="h-3.5 w-3.5" />
            Create proposal
          </Button>
        )}
      </div>

      {error && (
        <div className="rounded-sm border border-red-800 bg-red-950/60 p-2 text-xs text-red-200">{error}</div>
      )}
      {notice && (
        <div className="rounded-sm border border-emerald-800 bg-emerald-950/40 p-2 text-xs text-emerald-200">{notice}</div>
      )}

      {formOpen && canOperate && (
        <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
          <div className="mb-3 flex items-center gap-2 text-xs font-semibold text-slate-100">
            <Plus className="h-3.5 w-3.5 text-cyan-300" />
            Manual proposal
          </div>
          <div className="grid gap-2 lg:grid-cols-2">
            <label className="space-y-1 text-xs text-slate-400">
              <span>Action type</span>
              <select
                value={draft.action_type}
                onChange={(event) => setDraft((current) => ({ ...current, action_type: event.target.value }))}
                className="h-9 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
              >
                {actions.map((action) => (
                  <option key={action.action_type} value={action.action_type}>
                    {action.display_name} · {action.execution_mode}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-xs text-slate-400">
              <span>Risk level</span>
              <select
                value={draft.risk_level}
                onChange={(event) => setDraft((current) => ({ ...current, risk_level: event.target.value }))}
                className="h-9 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
              </select>
            </label>
            <label className="space-y-1 text-xs text-slate-400 lg:col-span-2">
              <span>Title</span>
              <input
                value={draft.title}
                onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))}
                className="h-9 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
              />
            </label>
            <label className="space-y-1 text-xs text-slate-400">
              <span>Reason</span>
              <textarea
                value={draft.reason}
                onChange={(event) => setDraft((current) => ({ ...current, reason: event.target.value }))}
                className="min-h-20 w-full rounded-sm border border-slate-700 bg-slate-950 p-2 text-xs text-slate-100"
              />
            </label>
            <label className="space-y-1 text-xs text-slate-400">
              <span>Business justification</span>
              <textarea
                value={draft.business_justification}
                onChange={(event) => setDraft((current) => ({ ...current, business_justification: event.target.value }))}
                className="min-h-20 w-full rounded-sm border border-slate-700 bg-slate-950 p-2 text-xs text-slate-100"
              />
            </label>
            <label className="space-y-1 text-xs text-slate-400 lg:col-span-2">
              <span>Description</span>
              <textarea
                value={draft.description}
                onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))}
                className="min-h-20 w-full rounded-sm border border-slate-700 bg-slate-950 p-2 text-xs text-slate-100"
              />
            </label>
            <label className="space-y-1 text-xs text-slate-400 lg:col-span-2">
              <span>Payload/details JSON</span>
              <textarea
                value={draft.payload_json}
                onChange={(event) => setDraft((current) => ({ ...current, payload_json: event.target.value }))}
                className="min-h-24 w-full rounded-sm border border-slate-700 bg-slate-950 p-2 font-mono text-xs text-slate-100"
              />
            </label>
          </div>
          <div className="mt-3 flex justify-end">
            <Button onClick={handleCreateManual} disabled={saving} tone="success">
              Create draft
            </Button>
          </div>
        </div>
      )}

      {canOperate && (
        <div className="grid gap-3 xl:grid-cols-2">
          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-100">
              <BookOpen className="h-3.5 w-3.5 text-cyan-300" />
              Create from playbook
            </div>
            <div className="flex gap-2">
              <select
                value={playbookKey}
                onChange={(event) => setPlaybookKey(event.target.value)}
                className="h-8 min-w-0 flex-1 rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
              >
                {playbooks.map((playbook) => (
                  <option key={playbook.playbook_key} value={playbook.playbook_key}>
                    {playbook.display_name}
                  </option>
                ))}
              </select>
              <Button onClick={handleCreateFromPlaybook} disabled={saving || !playbookKey} tone="primary">
                Create
              </Button>
            </div>
            <p className="mt-2 text-xs leading-5 text-slate-500">
              Creates a review proposal from the selected template. Playbook actions are not executed.
            </p>
          </div>

          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-100">
              <FileText className="h-3.5 w-3.5 text-cyan-300" />
              Create from AI recommendation
            </div>
            {visibleRecommendations.length === 0 ? (
              <p className="text-xs leading-5 text-slate-500">
                No structured AI recommendations are available for one-click conversion.
              </p>
            ) : (
              <div className="space-y-2">
                {visibleRecommendations.map((recommendation, index) => (
                  <div key={`${recommendation.title}-${index}`} className="flex items-start justify-between gap-2 rounded-sm border border-slate-800 bg-slate-900/70 p-2">
                    <div className="min-w-0">
                      <div className="truncate text-xs font-medium text-slate-200">{recommendation.title}</div>
                      <div className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-slate-500">
                        {recommendation.description || recommendation.reason || "AI-selected recommendation"}
                      </div>
                    </div>
                    <Button onClick={() => handleCreateFromRecommendation(recommendation)} disabled={saving}>
                      Create
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.65fr)]">
        <div className="rounded-sm border border-slate-800 bg-slate-950">
          <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-100">
            Proposals
          </div>
          {loading ? (
            <div className="p-3 text-xs text-slate-500">Loading proposals...</div>
          ) : proposals.length === 0 ? (
            <div className="p-3 text-xs text-slate-500">No remediation proposals linked to this {scope} yet.</div>
          ) : (
            <div className="divide-y divide-slate-800">
              {proposals.map((proposal) => {
                const action = actionByType[proposal.action_type];
                const isSelected = selected?.id === proposal.id;
                return (
                  <button
                    key={proposal.id}
                    type="button"
                    onClick={() => setSelectedId(proposal.id)}
                    className={`block w-full px-3 py-2 text-left hover:bg-slate-900 ${isSelected ? "bg-slate-900" : ""}`}
                  >
                    <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0">
                        <div className="truncate text-xs font-semibold text-slate-100">{proposal.title}</div>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          <Badge tone={toneForStatus(proposal.status)}>{proposal.status}</Badge>
                          <Badge tone={toneForRisk(proposal.risk_level)}>{proposal.risk_level}</Badge>
                          <Badge tone="border-slate-700 bg-slate-950 text-slate-300">
                            {action?.display_name ?? proposal.action_type}
                          </Badge>
                        </div>
                      </div>
                      <div className="text-[11px] text-slate-500">{formatTimestamp(proposal.updated_at)}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
          {!selected ? (
            <div className="text-xs text-slate-500">Select a proposal to review lifecycle, payload and actions.</div>
          ) : (
            <div className="space-y-3">
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-100">
                  <ShieldCheck className="h-3.5 w-3.5 text-cyan-300" />
                  Proposal #{selected.id}
                </div>
                <h3 className="mt-1 text-sm font-semibold text-slate-100">{selected.title}</h3>
                <p className="mt-1 text-xs leading-5 text-slate-500">{selected.safe_summary}</p>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <Detail label="Status" value={selected.status} />
                <Detail label="Mode" value={selected.execution_mode} />
                <Detail label="Connector" value={selected.connector_key} />
                <Detail label="Approval" value={selected.required_approval_role || "-"} />
              </div>

              {(selected.risk_level === "HIGH" || selected.execution_mode === "PROPOSAL_ONLY" || selected.execution_mode === "DISABLED") && (
                <div className="flex gap-2 rounded-sm border border-orange-900/70 bg-orange-950/20 p-2 text-xs leading-5 text-orange-100">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>This proposal is not executable in Step 13. It can be documented, reviewed and tracked only.</span>
                </div>
              )}

              <div className="rounded-sm border border-slate-800 bg-slate-900/60 p-2">
                <div className="text-[10px] uppercase tracking-wide text-slate-500">Reason</div>
                <p className="mt-1 text-xs leading-5 text-slate-300">{selected.reason || "-"}</p>
              </div>

              <details className="rounded-sm border border-slate-800 bg-slate-900/60">
                <summary className="cursor-pointer px-2 py-1.5 text-xs text-slate-300">Payload summary</summary>
                <pre className="max-h-56 overflow-auto border-t border-slate-800 p-2 text-[11px] leading-5 text-slate-400">
                  {JSON.stringify(selected.payload_json || {}, null, 2)}
                </pre>
              </details>

              <div className="flex flex-wrap gap-2">
                {canOperate && selected.status === "DRAFT" && (
                  <Button
                    onClick={() => mutate(`/remediation/proposals/${selected.id}/submit`, { comment: "Submitted from UI." }, "Proposal submitted.")}
                    disabled={saving}
                    tone="primary"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Submit
                  </Button>
                )}
                {isAdmin && selected.status === "PROPOSED" && (
                  <Button
                    onClick={() => mutate(`/remediation/proposals/${selected.id}/approve`, { approval_comment: "Approved from Governed Remediation UI." }, "Proposal approved.")}
                    disabled={saving}
                    tone="success"
                  >
                    Approve
                  </Button>
                )}
                {isAdmin && selected.status === "PROPOSED" && (
                  <Button
                    onClick={() => {
                      const reason = window.prompt("Rejection reason");
                      if (reason) {
                        void mutate(`/remediation/proposals/${selected.id}/reject`, { rejection_reason: reason }, "Proposal rejected.");
                      }
                    }}
                    disabled={saving}
                    tone="danger"
                  >
                    <XCircle className="h-3.5 w-3.5" />
                    Reject
                  </Button>
                )}
                {canConvert(selected) && (
                  <Button
                    onClick={() => mutate(`/remediation/proposals/${selected.id}/convert`, { comment: "Converted from Governed Remediation UI." }, "Proposal converted.")}
                    disabled={saving}
                    tone="success"
                  >
                    Convert
                  </Button>
                )}
                {linkedObjectHref(selected) && (
                  <Link
                    href={linkedObjectHref(selected) || "#"}
                    className="inline-flex h-8 items-center gap-1.5 rounded-sm border border-slate-700 bg-slate-950 px-2.5 text-xs font-medium text-slate-200 hover:border-cyan-600"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    Open linked object
                  </Link>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-slate-800 bg-slate-900/70 p-2">
      <div className="text-[10px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 truncate text-xs text-slate-200" title={value}>{value}</div>
    </div>
  );
}
