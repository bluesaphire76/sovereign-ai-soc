"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ChevronDown,
  CheckCircle2,
  Copy,
  Eye,
  History,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  Send,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { authFetch, type AuthUser } from "@/lib/auth";

type PolicyType = "DETECTION_RULE" | "NOISE_SUPPRESSION" | "EXCEPTION";
type LifecycleState =
  | "DRAFT"
  | "PROPOSED"
  | "APPROVED"
  | "ACTIVE"
  | "DISABLED"
  | "SUPERSEDED"
  | "FAILED_VALIDATION"
  | "ROLLED_BACK"
  | "REJECTED";

type ValidationFinding = {
  field: string;
  message: string;
};

type LifecycleItem = {
  id: number;
  policy_type: PolicyType;
  rule_key: string;
  version_number: number;
  title: string;
  description: string | null;
  content_json: Record<string, unknown>;
  state: LifecycleState;
  created_by_user_id: number | null;
  created_by_username: string | null;
  updated_by_username: string | null;
  submitted_at: string | null;
  approved_at: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  applied_at: string | null;
  disabled_at: string | null;
  disable_reason: string | null;
  superseded_by_item_id: number | null;
  cloned_from_item_id: number | null;
  related_config_version_id: number | null;
  validation_status: string;
  validation_errors: ValidationFinding[];
  validation_warnings: ValidationFinding[];
  expires_at: string | null;
  owner: string | null;
  business_reason: string | null;
  risk_note: string | null;
  source_system: string | null;
  config_domain: string;
  restart_recommended: boolean;
  affected_services: string[];
  allowed_transitions: string[];
  created_at: string | null;
  updated_at: string | null;
};

type LifecycleListResponse = {
  items: LifecycleItem[];
  summary: {
    total: number;
    validation_failed: number;
    restart_recommended: number;
    states: Record<string, number>;
  };
  states: LifecycleState[];
  policy_types: PolicyType[];
  source_systems: string[];
};

type LifecycleHistoryEvent = {
  id: number;
  timestamp: string | null;
  actor: string | null;
  actor_role: string | null;
  action: string;
  from_state: string | null;
  to_state: string | null;
  comment: string | null;
  details: Record<string, unknown>;
};

type LifecycleHistoryResponse = {
  item_id: number;
  events: LifecycleHistoryEvent[];
};

type LifecycleDiff = {
  added: Array<Record<string, unknown>>;
  removed: Array<Record<string, unknown>>;
  modified: Array<{
    rule_id: string;
    name?: string;
    type?: string;
    changes: Record<string, { from: unknown; to: unknown }>;
  }>;
  unchanged_count: number;
  summary: {
    added_count: number;
    removed_count: number;
    modified_count: number;
  };
};

type LifecycleMutationResponse = {
  item: LifecycleItem;
  validation?: {
    valid: boolean;
    validation_status: string;
    errors: ValidationFinding[];
    warnings: ValidationFinding[];
  };
  related_config_version_id?: number;
  related_config_version_number?: number;
  restart_recommended?: boolean;
  affected_services?: string[];
  message?: string;
};

type FormState = {
  policy_type: PolicyType;
  rule_key: string;
  title: string;
  description: string;
  business_reason: string;
  owner: string;
  source_system: string;
  scope: string;
  action: string;
  match_json: string;
  expires_at: string;
  risk_note: string;
  content_json: string;
};

const POLICY_TYPES: PolicyType[] = ["NOISE_SUPPRESSION", "EXCEPTION", "DETECTION_RULE"];
const SOURCE_SYSTEMS = ["WAZUH", "SURICATA", "AI_SOC", "DNS", "OTHER"];
const STATES: Array<LifecycleState | "ALL"> = [
  "ALL",
  "DRAFT",
  "PROPOSED",
  "APPROVED",
  "ACTIVE",
  "DISABLED",
  "SUPERSEDED",
  "FAILED_VALIDATION",
  "REJECTED",
  "ROLLED_BACK",
];
const VALIDATION_FILTERS = ["ALL", "not_validated", "passed", "failed"];

function emptyForm(owner = ""): FormState {
  const content = {
    source: "wazuh",
    match: {
      host: "atomicstar",
      rule_group: "pam,sudo",
    },
    action: "suppress",
    scope: "specific_host",
  };

  return {
    policy_type: "NOISE_SUPPRESSION",
    rule_key: "",
    title: "",
    description: "",
    business_reason: "",
    owner,
    source_system: "WAZUH",
    scope: "specific_host",
    action: "suppress",
    match_json: JSON.stringify(content.match, null, 2),
    expires_at: "",
    risk_note: "",
    content_json: JSON.stringify(content, null, 2),
  };
}

function prettyJson(value: unknown) {
  return JSON.stringify(value ?? {}, null, 2);
}

function formatDate(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "Europe/Zurich",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function dateInputValue(value: string | null | undefined) {
  if (!value) return "";

  try {
    return new Date(value).toISOString().slice(0, 10);
  } catch {
    return "";
  }
}

function parseJsonObject(value: string, label: string) {
  try {
    const parsed = JSON.parse(value || "{}");

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`${label} must be a JSON object`);
    }

    return parsed as Record<string, unknown>;
  } catch (err) {
    throw new Error(err instanceof Error ? err.message : `${label} is invalid`);
  }
}

function stateTone(state: string) {
  const normalized = state.toUpperCase();

  if (normalized === "ACTIVE" || normalized === "APPROVED") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if (normalized === "FAILED_VALIDATION" || normalized === "REJECTED") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  if (normalized === "PROPOSED" || normalized === "DRAFT") {
    return "border-cyan-800 bg-cyan-950/60 text-cyan-200";
  }

  return "border-slate-700 bg-slate-900 text-slate-300";
}

function validationTone(status: string) {
  if (status === "passed") return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  if (status === "failed") return "border-red-800 bg-red-950/60 text-red-200";
  return "border-slate-700 bg-slate-900 text-slate-300";
}

async function fetchLifecycle(queryString: string): Promise<LifecycleListResponse> {
  const response = await authFetch(`/detection-control/lifecycle/items?${queryString}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Lifecycle API returned ${response.status}`);
  }

  return (await response.json()) as LifecycleListResponse;
}

async function fetchHistory(itemId: number): Promise<LifecycleHistoryResponse> {
  const response = await authFetch(`/detection-control/lifecycle/items/${itemId}/history`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Lifecycle history API returned ${response.status}`);
  }

  return (await response.json()) as LifecycleHistoryResponse;
}

async function fetchDiff(itemId: number): Promise<LifecycleDiff> {
  const response = await authFetch(`/detection-control/lifecycle/items/${itemId}/diff`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Lifecycle diff API returned ${response.status}`);
  }

  return (await response.json()) as LifecycleDiff;
}

function formFromItem(item: LifecycleItem): FormState {
  const content = item.content_json || {};
  const match = content.match && typeof content.match === "object" ? content.match : {};

  return {
    policy_type: item.policy_type,
    rule_key: item.rule_key,
    title: item.title,
    description: item.description || "",
    business_reason: item.business_reason || "",
    owner: item.owner || "",
    source_system: item.source_system || "OTHER",
    scope: typeof content.scope === "string" ? content.scope : "",
    action: typeof content.action === "string" ? content.action : "suppress",
    match_json: prettyJson(match),
    expires_at: dateInputValue(item.expires_at),
    risk_note: item.risk_note || "",
    content_json: prettyJson(content),
  };
}

function requestPayload(form: FormState) {
  const content = parseJsonObject(form.content_json, "Content JSON");
  const match = parseJsonObject(form.match_json, "Match criteria");

  return {
    policy_type: form.policy_type,
    rule_key: form.rule_key || undefined,
    title: form.title,
    description: form.description,
    business_reason: form.business_reason,
    owner: form.owner,
    source_system: form.source_system,
    expires_at: form.expires_at || undefined,
    risk_note: form.risk_note,
    content_json: {
      ...content,
      source: form.source_system.toLowerCase(),
      source_system: form.source_system,
      scope: form.scope,
      action: form.action,
      match,
    },
  };
}

export default function LifecyclePanel({
  currentUser,
  onConfigChanged,
}: {
  currentUser: AuthUser | null;
  onConfigChanged: () => Promise<void>;
}) {
  const [data, setData] = useState<LifecycleListResponse | null>(null);
  const [selectedItem, setSelectedItem] = useState<LifecycleItem | null>(null);
  const [history, setHistory] = useState<LifecycleHistoryResponse | null>(null);
  const [diff, setDiff] = useState<LifecycleDiff | null>(null);
  const [form, setForm] = useState<FormState>(emptyForm(currentUser?.username || ""));
  const [editingItemId, setEditingItemId] = useState<number | null>(null);
  const [policyFilter, setPolicyFilter] = useState("ALL");
  const [stateFilter, setStateFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [validationFilter, setValidationFilter] = useState("ALL");
  const [ownerFilter, setOwnerFilter] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resultMessage, setResultMessage] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(true);

  const role = currentUser?.role || "";
  const canCreate = role === "ADMIN" || role === "ANALYST";
  const canAdmin = role === "ADMIN";
  const canOperate = role === "ADMIN" || role === "ANALYST";
  const selectedItemId = selectedItem?.id ?? null;

  const queryString = useMemo(() => {
    const params = new URLSearchParams();
    params.set("limit", "200");

    if (policyFilter !== "ALL") params.set("policy_type", policyFilter);
    if (stateFilter !== "ALL") params.set("state", stateFilter);
    if (sourceFilter !== "ALL") params.set("source_system", sourceFilter);
    if (validationFilter !== "ALL") params.set("validation_status", validationFilter);
    if (ownerFilter.trim()) params.set("owner", ownerFilter.trim());
    if (search.trim()) params.set("search", search.trim());

    return params.toString();
  }, [ownerFilter, policyFilter, search, sourceFilter, stateFilter, validationFilter]);

  const loadLifecycle = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetchLifecycle(queryString);
      setData(response);

      if (selectedItemId) {
        const refreshed = response.items.find((item) => item.id === selectedItemId) || null;
        setSelectedItem(refreshed);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load lifecycle items");
    } finally {
      setLoading(false);
    }
  }, [queryString, selectedItemId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadLifecycle();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadLifecycle]);

  useEffect(() => {
    let cancelled = false;

    if (!selectedItem) {
      const timer = window.setTimeout(() => {
        if (cancelled) return;

        setHistory(null);
        setDiff(null);
      }, 0);

      return () => {
        cancelled = true;
        window.clearTimeout(timer);
      };
    }

    Promise.all([fetchHistory(selectedItem.id), fetchDiff(selectedItem.id)])
      .then(([historyResult, diffResult]) => {
        if (cancelled) return;

        setHistory(historyResult);
        setDiff(diffResult);
      })
      .catch((err) => {
        if (cancelled) return;

        setError(err instanceof Error ? err.message : "Unable to load lifecycle detail");
      });

    return () => {
      cancelled = true;
    };
  }, [selectedItem]);

  function resetForm() {
    setEditingItemId(null);
    setForm(emptyForm(currentUser?.username || ""));
  }

  function startNewDraft() {
    setCollapsed(false);
    resetForm();
  }

  function editItem(item: LifecycleItem) {
    setCollapsed(false);
    setEditingItemId(item.id);
    setSelectedItem(item);
    setForm(formFromItem(item));
  }

  function canEdit(item: LifecycleItem) {
    if (role === "ADMIN") return ["DRAFT", "FAILED_VALIDATION"].includes(item.state);

    return (
      role === "ANALYST" &&
      ["DRAFT", "FAILED_VALIDATION"].includes(item.state) &&
      item.created_by_user_id === currentUser?.id
    );
  }

  async function submitForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!canCreate) return;

    try {
      setSaving(true);
      setError(null);
      setResultMessage(null);
      const payload = requestPayload(form);
      const url = editingItemId
        ? `/detection-control/lifecycle/items/${editingItemId}`
        : "/detection-control/lifecycle/items";
      const response = await authFetch(url, {
        method: editingItemId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail?.message || body?.detail || `API returned ${response.status}`));
      }

      const result = (await response.json()) as LifecycleMutationResponse;
      setSelectedItem(result.item);
      setEditingItemId(result.item.id);
      setResultMessage(editingItemId ? "Draft updated." : "Draft created.");
      await loadLifecycle();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save lifecycle draft");
    } finally {
      setSaving(false);
    }
  }

  async function runAction(
    item: LifecycleItem,
    action: string,
    payload: Record<string, unknown> = {}
  ) {
    try {
      setSaving(true);
      setError(null);
      setResultMessage(null);
      const response = await authFetch(
        `/detection-control/lifecycle/items/${item.id}/${action}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail?.message || body?.detail || `API returned ${response.status}`));
      }

      const result = (await response.json()) as LifecycleMutationResponse;
      setSelectedItem(result.item);
      setResultMessage(result.message || `${action.replaceAll("-", " ")} completed.`);

      if (action === "apply" || action === "disable") {
        await onConfigChanged();
      }

      await loadLifecycle();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Unable to run ${action}`);
    } finally {
      setSaving(false);
    }
  }

  async function deleteDraft(item: LifecycleItem) {
    if (!canEdit(item)) return;
    if (!window.confirm(`Delete draft ${item.title}?`)) return;

    try {
      setSaving(true);
      setError(null);
      const response = await authFetch(`/detection-control/lifecycle/items/${item.id}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail || `API returned ${response.status}`));
      }

      if (selectedItem?.id === item.id) {
        setSelectedItem(null);
      }
      resetForm();
      await loadLifecycle();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to delete draft");
    } finally {
      setSaving(false);
    }
  }

  const items = data?.items ?? [];
  const activeCount = items.filter((item) => item.state === "ACTIVE").length;
  const proposedCount = items.filter((item) => item.state === "PROPOSED").length;
  const draftCount = items.filter((item) => item.state === "DRAFT").length;

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Detection Lifecycle
          </h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            Draft, review, approve and activate governed detection changes.
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            aria-expanded={!collapsed}
            onClick={() => setCollapsed((value) => !value)}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-300 hover:bg-slate-800"
          >
            <ChevronDown className={`h-3.5 w-3.5 transition ${collapsed ? "" : "rotate-180"}`} />
            {collapsed ? "Open" : "Close"}
          </button>
          <button
            type="button"
            onClick={loadLifecycle}
            disabled={loading || saving}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          {canCreate && (
            <button
              type="button"
              onClick={startNewDraft}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400"
            >
              <Plus className="h-3.5 w-3.5" />
              New Draft
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {resultMessage && (
        <div className="mb-3 rounded-lg border border-emerald-800 bg-emerald-950/60 p-3 text-xs text-emerald-200">
          {resultMessage}
        </div>
      )}

      <div className="mb-3 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
        <LifecycleMetric label="Lifecycle items" value={data?.summary.total ?? 0} />
        <LifecycleMetric label="Drafts" value={draftCount} />
        <LifecycleMetric label="Proposed" value={proposedCount} />
        <LifecycleMetric label="Active" value={activeCount} />
      </div>

      {!collapsed && (
        <>
          <div className="mb-3 rounded-lg border border-slate-800 bg-slate-950 p-3">
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
              <FilterSelect label="Policy" value={policyFilter} onChange={setPolicyFilter} options={["ALL", ...POLICY_TYPES]} />
              <FilterSelect label="State" value={stateFilter} onChange={setStateFilter} options={STATES} />
              <FilterSelect label="Source" value={sourceFilter} onChange={setSourceFilter} options={["ALL", ...SOURCE_SYSTEMS]} />
              <FilterSelect label="Validation" value={validationFilter} onChange={setValidationFilter} options={VALIDATION_FILTERS} />
              <label>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                  Owner
                </span>
                <input
                  value={ownerFilter}
                  onChange={(event) => setOwnerFilter(event.target.value)}
                  className="h-8 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                />
              </label>
            </div>

            <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-2">
              <Search className="h-3.5 w-3.5 text-slate-500" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search title, key, owner, reason or content..."
                className="h-9 w-full bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600"
              />
            </div>
          </div>

          <div className="grid gap-3 2xl:grid-cols-[minmax(0,1.25fr)_minmax(420px,0.75fr)]">
            <div className="min-w-0 space-y-3">
              <LifecycleTable
                currentUser={currentUser}
                items={items}
                loading={loading}
                saving={saving}
                selectedId={selectedItem?.id ?? null}
                canAdmin={canAdmin}
                canOperate={canOperate}
                canEdit={canEdit}
                onDelete={deleteDraft}
                onEdit={editItem}
                onSelect={setSelectedItem}
                onAction={runAction}
              />

              {selectedItem && (
                <LifecycleDetail
                  diff={diff}
                  history={history}
                  item={selectedItem}
                  onEdit={editItem}
                  canEdit={canEdit(selectedItem)}
                />
              )}
            </div>

            <LifecycleForm
              canCreate={canCreate}
              editingItemId={editingItemId}
              form={form}
              saving={saving}
              onChange={setForm}
              onReset={resetForm}
              onSubmit={submitForm}
            />
          </div>
        </>
      )}
    </section>
  );
}

function LifecycleMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-sm border border-slate-800 bg-slate-950 px-2.5 py-2">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-xl font-semibold leading-6 text-slate-100">{value}</div>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
}) {
  return (
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
      >
        {options.map((item) => (
          <option key={item} value={item}>
            {item.replaceAll("_", " ")}
          </option>
        ))}
      </select>
    </label>
  );
}

function LifecycleTable({
  currentUser,
  items,
  loading,
  saving,
  selectedId,
  canAdmin,
  canOperate,
  canEdit,
  onDelete,
  onEdit,
  onSelect,
  onAction,
}: {
  currentUser: AuthUser | null;
  items: LifecycleItem[];
  loading: boolean;
  saving: boolean;
  selectedId: number | null;
  canAdmin: boolean;
  canOperate: boolean;
  canEdit: (item: LifecycleItem) => boolean;
  onDelete: (item: LifecycleItem) => void;
  onEdit: (item: LifecycleItem) => void;
  onSelect: (item: LifecycleItem) => void;
  onAction: (item: LifecycleItem, action: string, payload?: Record<string, unknown>) => void;
}) {
  if (loading) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">
        Loading lifecycle items...
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 text-center text-xs text-slate-500">
        <AlertTriangle className="mx-auto mb-2 h-5 w-5 text-slate-600" />
        No lifecycle items match the selected filters.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950">
      <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
        <thead className="bg-slate-900 text-[11px] uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-3 py-2">Title</th>
            <th className="px-3 py-2">Policy</th>
            <th className="px-3 py-2">State</th>
            <th className="px-3 py-2">Validation</th>
            <th className="px-3 py-2">Owner</th>
            <th className="px-3 py-2">Version</th>
            <th className="px-3 py-2">Updated</th>
            <th className="px-3 py-2">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {items.map((item) => (
            <tr
              key={item.id}
              className={`align-top hover:bg-slate-900/70 ${
                selectedId === item.id ? "bg-cyan-950/20" : ""
              }`}
            >
              <td className="max-w-xs px-3 py-2">
                <button
                  type="button"
                  onClick={() => onSelect(item)}
                  className="text-left font-medium text-slate-100 hover:text-cyan-200"
                >
                  {item.title}
                </button>
                <div className="mt-1 truncate text-[11px] text-slate-500">
                  {item.rule_key}
                </div>
              </td>
              <td className="px-3 py-2 text-slate-300">
                {item.policy_type.replaceAll("_", " ")}
              </td>
              <td className="px-3 py-2">
                <span className={`rounded-md border px-2 py-1 text-[11px] ${stateTone(item.state)}`}>
                  {item.state.replaceAll("_", " ")}
                </span>
              </td>
              <td className="px-3 py-2">
                <span className={`rounded-md border px-2 py-1 text-[11px] ${validationTone(item.validation_status)}`}>
                  {item.validation_status}
                </span>
              </td>
              <td className="px-3 py-2 text-slate-500">{item.owner || "-"}</td>
              <td className="px-3 py-2 text-slate-500">v{item.version_number}</td>
              <td className="px-3 py-2 text-slate-500">{formatDate(item.updated_at)}</td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap gap-1.5">
                  <IconButton label="View" disabled={false} onClick={() => onSelect(item)}>
                    <Eye className="h-3.5 w-3.5" />
                  </IconButton>
                  {canEdit(item) && (
                    <IconButton label="Edit" disabled={saving} onClick={() => onEdit(item)}>
                      <Pencil className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canOperate && ["DRAFT", "PROPOSED", "FAILED_VALIDATION"].includes(item.state) && (
                    <IconButton label="Validate" disabled={saving} onClick={() => onAction(item, "validate", {})}>
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canOperate && ["DRAFT", "FAILED_VALIDATION"].includes(item.state) && (
                    <IconButton
                      label="Submit"
                      disabled={saving}
                      onClick={() => onAction(item, "submit", { comment: "Ready for admin approval." })}
                    >
                      <Send className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canAdmin && item.state === "PROPOSED" && (
                    <IconButton
                      label="Approve"
                      disabled={saving}
                      onClick={() => onAction(item, "approve", { approval_comment: "Reviewed for controlled apply." })}
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canAdmin && ["PROPOSED", "APPROVED"].includes(item.state) && (
                    <IconButton
                      label="Reject"
                      disabled={saving}
                      onClick={() => {
                        const reason = window.prompt("Rejection reason:");
                        if (reason) onAction(item, "reject", { rejection_reason: reason });
                      }}
                    >
                      <XCircle className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canOperate && ["PROPOSED", "FAILED_VALIDATION", "REJECTED", "DISABLED"].includes(item.state) && (
                    <IconButton
                      label="Return to draft"
                      disabled={saving}
                      onClick={() => onAction(item, "return-to-draft", { comment: "Returned for editing." })}
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canAdmin && item.state === "APPROVED" && (
                    <IconButton
                      label="Apply"
                      disabled={saving}
                      onClick={() => {
                        if (window.confirm("Apply this approved lifecycle item to active configuration?")) {
                          onAction(item, "apply", { comment: "Apply approved lifecycle item." });
                        }
                      }}
                    >
                      <Save className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canAdmin && item.state === "ACTIVE" && (
                    <IconButton
                      label="Disable"
                      disabled={saving}
                      onClick={() => {
                        const reason = window.prompt("Disable reason:");
                        if (reason) onAction(item, "disable", { disable_reason: reason });
                      }}
                    >
                      <XCircle className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canOperate && ["REJECTED", "DISABLED", "ACTIVE", "SUPERSEDED"].includes(item.state) && (
                    <IconButton label="Clone" disabled={saving} onClick={() => onAction(item, "clone", {})}>
                      <Copy className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {canEdit(item) &&
                    item.state === "DRAFT" &&
                    (currentUser?.role === "ADMIN" || item.created_by_user_id === currentUser?.id) && (
                    <IconButton label="Delete draft" disabled={saving} onClick={() => onDelete(item)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IconButton({
  children,
  disabled,
  label,
  onClick,
}: {
  children: ReactNode;
  disabled: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
      className="flex h-7 w-7 items-center justify-center rounded-md border border-slate-700 bg-slate-900 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}

function LifecycleDetail({
  canEdit,
  diff,
  history,
  item,
  onEdit,
}: {
  canEdit: boolean;
  diff: LifecycleDiff | null;
  history: LifecycleHistoryResponse | null;
  item: LifecycleItem;
  onEdit: (item: LifecycleItem) => void;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">{item.title}</h3>
          <div className="mt-1 text-xs text-slate-500">
            {item.policy_type.replaceAll("_", " ")} / {item.rule_key} / v{item.version_number}
          </div>
        </div>
        {canEdit && (
          <button
            type="button"
            onClick={() => onEdit(item)}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-300 hover:text-cyan-200"
          >
            <Pencil className="h-3.5 w-3.5" />
            Edit
          </button>
        )}
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        <DetailBlock title="Overview">
          <InfoRow label="State" value={item.state.replaceAll("_", " ")} />
          <InfoRow label="Owner" value={item.owner || "-"} />
          <InfoRow label="Source" value={item.source_system || "-"} />
          <InfoRow label="Created by" value={item.created_by_username || "-"} />
          <InfoRow label="Approved" value={formatDate(item.approved_at)} />
          <InfoRow label="Config version" value={item.related_config_version_id ? `#${item.related_config_version_id}` : "-"} />
        </DetailBlock>

        <DetailBlock title="Validation">
          <FindingRows items={item.validation_errors} tone="red" empty="No blocking validation errors." />
          <FindingRows items={item.validation_warnings} tone="amber" empty="No validation warnings." />
        </DetailBlock>

        <DetailBlock title="Impact">
          <InfoRow label="Restart" value={item.restart_recommended ? "recommended" : "not flagged"} />
          <InfoRow label="Services" value={item.affected_services.join(", ") || "-"} />
          <InfoRow label="Expires" value={formatDate(item.expires_at)} />
          <InfoRow label="Disabled" value={formatDate(item.disabled_at)} />
          {item.restart_recommended && (
            <Link
              href="#service-operations"
              className="mt-2 inline-flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Open Service Operations
            </Link>
          )}
        </DetailBlock>
      </div>

      <div className="mt-3 grid gap-3 xl:grid-cols-2">
        <DetailBlock title="Rule Content">
          <pre className="max-h-72 overflow-auto rounded-md border border-slate-800 bg-slate-900 p-2 text-[11px] leading-4 text-slate-300">
            {prettyJson(item.content_json)}
          </pre>
        </DetailBlock>

        <DetailBlock title="Diff">
          {diff ? (
            <div className="space-y-2 text-xs text-slate-400">
              <div className="grid grid-cols-3 gap-1.5">
                <MiniCount label="Added" value={diff.summary.added_count} />
                <MiniCount label="Removed" value={diff.summary.removed_count} />
                <MiniCount label="Modified" value={diff.summary.modified_count} />
              </div>
              <div className="max-h-44 overflow-auto rounded-md border border-slate-800 bg-slate-900 p-2 text-[11px]">
                {diff.modified.slice(0, 6).map((entry) => (
                  <div key={entry.rule_id} className="mb-2">
                    <div className="font-medium text-slate-200">{entry.name || entry.rule_id}</div>
                    <div className="text-slate-500">{Object.keys(entry.changes).join(", ") || "-"}</div>
                  </div>
                ))}
                {diff.added.length + diff.removed.length + diff.modified.length === 0 && (
                  <div>No active-config differences.</div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500">Loading diff...</div>
          )}
        </DetailBlock>
      </div>

      <DetailBlock title="History" className="mt-3">
        {history ? (
          <div className="max-h-56 overflow-auto rounded-md border border-slate-800 bg-slate-900">
            {history.events.map((event) => (
              <div key={event.id} className="border-b border-slate-800 px-2 py-2 text-xs last:border-0">
                <div className="flex flex-wrap items-center gap-2">
                  <History className="h-3.5 w-3.5 text-cyan-300" />
                  <span className="font-medium text-slate-200">{event.action.replaceAll("_", " ")}</span>
                  <span className="text-slate-500">{event.from_state || "-"} -&gt; {event.to_state || "-"}</span>
                  <span className="text-slate-600">{formatDate(event.timestamp)}</span>
                </div>
                <div className="mt-1 text-[11px] text-slate-500">
                  {event.actor || "system"} {event.comment ? `/ ${event.comment}` : ""}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-xs text-slate-500">Loading history...</div>
        )}
      </DetailBlock>
    </div>
  );
}

function LifecycleForm({
  canCreate,
  editingItemId,
  form,
  saving,
  onChange,
  onReset,
  onSubmit,
}: {
  canCreate: boolean;
  editingItemId: number | null;
  form: FormState;
  saving: boolean;
  onChange: (value: FormState) => void;
  onReset: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form onSubmit={onSubmit} className="min-w-0 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">
            {editingItemId ? "Edit Draft" : "Create Draft"}
          </h3>
          <div className="mt-1 text-xs text-slate-500">
            {editingItemId ? `Lifecycle item #${editingItemId}` : "New lifecycle item"}
          </div>
        </div>
        <button
          type="button"
          onClick={onReset}
          className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-300 hover:text-slate-100"
        >
          <XCircle className="h-3.5 w-3.5" />
          Reset
        </button>
      </div>

      <div className="grid gap-2">
        <FilterSelect
          label="Policy type"
          value={form.policy_type}
          onChange={(value) => onChange({ ...form, policy_type: value as PolicyType })}
          options={POLICY_TYPES}
        />
        <TextInput label="Rule key" value={form.rule_key} onChange={(value) => onChange({ ...form, rule_key: value })} />
        <TextInput label="Title" value={form.title} onChange={(value) => onChange({ ...form, title: value })} />
        <TextInput label="Owner" value={form.owner} onChange={(value) => onChange({ ...form, owner: value })} />
        <FilterSelect
          label="Source system"
          value={form.source_system}
          onChange={(value) => onChange({ ...form, source_system: value })}
          options={SOURCE_SYSTEMS}
        />
        <TextInput label="Scope" value={form.scope} onChange={(value) => onChange({ ...form, scope: value })} />
        <TextInput label="Action" value={form.action} onChange={(value) => onChange({ ...form, action: value })} />
        <TextInput
          label="Expiration"
          type="date"
          value={form.expires_at}
          onChange={(value) => onChange({ ...form, expires_at: value })}
        />
        <TextArea
          label="Business reason"
          value={form.business_reason}
          onChange={(value) => onChange({ ...form, business_reason: value })}
          rows={3}
        />
        <TextArea
          label="Description"
          value={form.description}
          onChange={(value) => onChange({ ...form, description: value })}
          rows={3}
        />
        <TextArea
          label="Risk note"
          value={form.risk_note}
          onChange={(value) => onChange({ ...form, risk_note: value })}
          rows={2}
        />
        <TextArea
          label="Match criteria"
          value={form.match_json}
          onChange={(value) => onChange({ ...form, match_json: value })}
          rows={7}
          monospace
        />
        <TextArea
          label="Content JSON"
          value={form.content_json}
          onChange={(value) => onChange({ ...form, content_json: value })}
          rows={10}
          monospace
        />
      </div>

      <button
        type="submit"
        disabled={!canCreate || saving}
        className="mt-3 flex h-8 w-full items-center justify-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <Save className="h-3.5 w-3.5" />
        {editingItemId ? "Save Draft" : "Create Draft"}
      </button>
    </form>
  );
}

function TextInput({
  label,
  onChange,
  type = "text",
  value,
}: {
  label: string;
  onChange: (value: string) => void;
  type?: string;
  value: string;
}) {
  return (
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
      />
    </label>
  );
}

function TextArea({
  label,
  monospace = false,
  onChange,
  rows,
  value,
}: {
  label: string;
  monospace?: boolean;
  onChange: (value: string) => void;
  rows: number;
  value: string;
}) {
  return (
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <textarea
        value={value}
        rows={rows}
        onChange={(event) => onChange(event.target.value)}
        className={`w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-2 text-xs text-slate-100 outline-none focus:border-cyan-500 ${
          monospace ? "font-mono leading-5" : ""
        }`}
      />
    </label>
  );
}

function DetailBlock({
  children,
  className = "",
  title,
}: {
  children: ReactNode;
  className?: string;
  title: string;
}) {
  return (
    <div className={`rounded-md border border-slate-800 bg-slate-900 p-2 ${className}`}>
      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
        {title}
      </div>
      {children}
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="mb-1 grid grid-cols-[110px_minmax(0,1fr)] gap-2 text-xs">
      <span className="text-slate-500">{label}</span>
      <span className="min-w-0 truncate text-slate-200">{value}</span>
    </div>
  );
}

function MiniCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-2">
      <div className="text-[11px] text-slate-500">{label}</div>
      <div className="mt-1 text-sm font-semibold text-slate-100">{value}</div>
    </div>
  );
}

function FindingRows({
  empty,
  items,
  tone,
}: {
  empty: string;
  items: ValidationFinding[];
  tone: "red" | "amber";
}) {
  if (items.length === 0) {
    return <div className="mb-2 text-xs text-slate-500">{empty}</div>;
  }

  const className =
    tone === "red"
      ? "border-red-900/70 bg-red-950/30 text-red-100"
      : "border-amber-900/70 bg-amber-950/30 text-amber-100";

  return (
    <div className={`mb-2 rounded-md border p-2 text-xs ${className}`}>
      {items.map((item) => (
        <div key={`${item.field}:${item.message}`} className="mb-1 last:mb-0">
          <span className="font-medium">{item.field}</span>: {item.message}
        </div>
      ))}
    </div>
  );
}
