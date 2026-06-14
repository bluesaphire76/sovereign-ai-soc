"use client";

import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Eye,
  FileCog,
  Lock,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Save,
  ServerCog,
  Shield,
  SlidersHorizontal,
  Trash2,
  XCircle,
} from "lucide-react";

type InventoryItem = {
  id: string;
  name: string;
  type: string;
  source: string;
  scope: string;
  target: string;
  status: string;
  managed: boolean;
  requires_reload: boolean;
  last_seen: string | null;
  description: string;
  reason: string;
  metadata?: Record<string, unknown>;
};

type DetectionControlInventory = {
  summary: {
    total_items: number;
    total_rules: number;
    active_rules: number;
    disabled_rules: number;
    exceptions: number;
    telemetry_sources: number;
    policies: number;
    service_controls: number;
    managed_items: number;
    unmanaged_items: number;
    pending_review: number;
    read_only: boolean;
    generated_at: string;
  };
  rules: InventoryItem[];
  exceptions: InventoryItem[];
  telemetry_sources: InventoryItem[];
  policies: InventoryItem[];
  service_controls: InventoryItem[];
};

type ManagedRule = {
  id: string;
  name: string;
  type: RuleType;
  status: string;
  scope: string;
  matcher_kind: MatcherKind;
  matcher_value: string;
  reason: string;
  owner: string;
  enabled: boolean;
  description: string | null;
  created_at: string | null;
  updated_at: string | null;
  created_by: string | null;
  updated_by: string | null;
  last_validation_status: string | null;
  last_validation_message: string | null;
  metadata?: Record<string, unknown>;
  requires_apply: boolean;
  affected_service: string | null;
  restart_note: string;
};

type ManagedRulesResponse = {
  items: ManagedRule[];
  summary: {
    total: number;
    active: number;
    disabled: number;
    failed_validation: number;
    generated_at: string;
    restart_orchestration: string;
  };
  rbac: {
    role: string;
    can_write: boolean;
  };
};

type ValidationResult = {
  valid: boolean;
  severity: "OK" | "WARNING" | "ERROR" | string;
  messages: string[];
  warnings: string[];
};

type RuleMutationResponse = {
  rule: ManagedRule;
  validation?: ValidationResult;
};

type RuleType = "NOISE_SUPPRESSION" | "EXCEPTION" | "DETECTION_RULE" | "SOURCE_POLICY";
type MatcherKind = "CONTAINS" | "EXACT" | "REGEX" | "JSON" | "YAML";
type TabKey = "rules" | "exceptions" | "sources" | "policies" | "services";

type RuleFormState = {
  name: string;
  type: RuleType;
  scope: string;
  matcher_kind: MatcherKind;
  matcher_value: string;
  reason: string;
  owner: string;
  enabled: boolean;
  description: string;
};

const RULE_TYPES: RuleType[] = [
  "NOISE_SUPPRESSION",
  "EXCEPTION",
  "DETECTION_RULE",
  "SOURCE_POLICY",
];

const MATCHER_KINDS: MatcherKind[] = ["CONTAINS", "EXACT", "REGEX", "JSON", "YAML"];

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "rules", label: "Rules" },
  { key: "exceptions", label: "Exceptions" },
  { key: "sources", label: "Sources" },
  { key: "policies", label: "Policies" },
  { key: "services", label: "Service Control" },
];

function emptyForm(owner = ""): RuleFormState {
  return {
    name: "",
    type: "NOISE_SUPPRESSION",
    scope: "",
    matcher_kind: "CONTAINS",
    matcher_value: "",
    reason: "",
    owner,
    enabled: true,
    description: "",
  };
}

async function fetchInventory(): Promise<DetectionControlInventory> {
  const response = await authFetch("/settings/detection-control", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Inventory API returned ${response.status}`);
  }

  return (await response.json()) as DetectionControlInventory;
}

async function fetchManagedRules(): Promise<ManagedRulesResponse> {
  const response = await authFetch("/detection-control/rules", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Rules API returned ${response.status}`);
  }

  return (await response.json()) as ManagedRulesResponse;
}

function statusTone(status: string) {
  const normalized = status.toUpperCase();

  if (normalized === "ACTIVE" || normalized === "OK") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if (normalized === "DISABLED" || normalized === "READ_ONLY" || normalized === "EMPTY") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }

  if (normalized === "ERROR" || normalized === "FAILED_VALIDATION") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  return "border-amber-800 bg-amber-950/60 text-amber-200";
}

function sourceTone(source: string) {
  const normalized = source.toLowerCase();

  if (normalized.includes("wazuh")) {
    return "border-cyan-900/80 bg-cyan-950/40 text-cyan-200";
  }

  if (normalized.includes("suricata")) {
    return "border-violet-900/80 bg-violet-950/40 text-violet-200";
  }

  if (normalized.includes("dns")) {
    return "border-sky-900/80 bg-sky-950/40 text-sky-200";
  }

  return "border-slate-700 bg-slate-900 text-slate-300";
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

function metadataPreview(metadata?: Record<string, unknown>) {
  if (!metadata) return "-";

  const entries = Object.entries(metadata)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 4);

  if (entries.length === 0) return "-";

  return entries
    .map(([key, value]) => {
      if (Array.isArray(value)) {
        return `${key}: ${value.length}`;
      }

      if (typeof value === "object") {
        return `${key}: object`;
      }

      return `${key}: ${String(value)}`;
    })
    .join(" / ");
}

function isValidationResult(value: unknown): value is ValidationResult {
  if (!value || typeof value !== "object") return false;

  const candidate = value as Partial<ValidationResult>;

  return (
    typeof candidate.valid === "boolean" &&
    typeof candidate.severity === "string" &&
    Array.isArray(candidate.messages) &&
    Array.isArray(candidate.warnings)
  );
}

function extractValidation(value: unknown): ValidationResult | null {
  if (!value || typeof value !== "object") return null;

  const detail = value as { validation?: unknown };

  return isValidationResult(detail.validation) ? detail.validation : null;
}

function rulePayload(form: RuleFormState) {
  return {
    name: form.name,
    type: form.type,
    status: form.enabled ? "ACTIVE" : "DISABLED",
    scope: form.scope,
    matcher_kind: form.matcher_kind,
    matcher_value: form.matcher_value,
    reason: form.reason,
    owner: form.owner,
    enabled: form.enabled,
    description: form.description,
  };
}

export default function DetectionControlPlanePage() {
  const [inventory, setInventory] = useState<DetectionControlInventory | null>(null);
  const [managedRules, setManagedRules] = useState<ManagedRulesResponse | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("rules");
  const [form, setForm] = useState<RuleFormState>(emptyForm());
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canView =
    currentUser?.role === "ADMIN" ||
    currentUser?.role === "ANALYST" ||
    currentUser?.role === "VIEWER";
  const canWrite = currentUser?.role === "ADMIN";

  useEffect(() => {
    const storedUser = getStoredUser();
    setCurrentUser(storedUser);
    setForm(emptyForm(storedUser?.username || ""));

    fetchCurrentUser()
      .then((current) => {
        setCurrentUser(current);
        setForm((value) => ({
          ...value,
          owner: value.owner || current.username,
        }));
      })
      .catch(() => {
        // authFetch handles expired/invalid sessions globally.
      });
  }, []);

  const loadData = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const [inventoryData, rulesData] = await Promise.all([
        fetchInventory(),
        fetchManagedRules(),
      ]);

      setInventory(inventoryData);
      setManagedRules(rulesData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load detection control data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (currentUser && !canView) {
      setLoading(false);
      setError("Forbidden: Detection Control Plane is not available for this account.");
      return;
    }

    if (!currentUser) return;

    loadData();
  }, [currentUser, canView, loadData]);

  const activeInventoryItems = useMemo(() => {
    if (!inventory) return [];

    if (activeTab === "rules") return inventory.rules;
    if (activeTab === "exceptions") return inventory.exceptions;
    if (activeTab === "sources") return inventory.telemetry_sources;
    if (activeTab === "policies") return inventory.policies;

    return inventory.service_controls;
  }, [activeTab, inventory]);

  async function handleApiError(response: Response) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null;
    const detail = body?.detail;

    if (detail && typeof detail === "object") {
      const validation = extractValidation(detail);

      if (validation) {
        setValidationResult(validation);
      }

      const message = "message" in detail ? String(detail.message) : null;

      throw new Error(message || `API returned ${response.status}`);
    }

    throw new Error(typeof detail === "string" ? detail : `API returned ${response.status}`);
  }

  async function submitForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!canWrite) return;

    try {
      setSaving(true);
      setError(null);

      const response = await authFetch(
        editingRuleId
          ? `/detection-control/rules/${encodeURIComponent(editingRuleId)}`
          : "/detection-control/rules",
        {
          method: editingRuleId ? "PATCH" : "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(rulePayload(form)),
        }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as RuleMutationResponse;
      setValidationResult(result.validation || null);
      setEditingRuleId(result.rule.id);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save rule");
    } finally {
      setSaving(false);
    }
  }

  function startCreate() {
    setEditingRuleId(null);
    setValidationResult(null);
    setForm(emptyForm(currentUser?.username || ""));
  }

  function startEdit(rule: ManagedRule) {
    setEditingRuleId(rule.id);
    setValidationResult({
      valid: rule.last_validation_status !== "ERROR",
      severity: rule.last_validation_status || "OK",
      messages: rule.last_validation_status === "ERROR" && rule.last_validation_message
        ? [rule.last_validation_message]
        : [],
      warnings: rule.last_validation_status === "WARNING" && rule.last_validation_message
        ? [rule.last_validation_message]
        : [],
    });
    setForm({
      name: rule.name,
      type: rule.type,
      scope: rule.scope,
      matcher_kind: rule.matcher_kind,
      matcher_value: rule.matcher_value,
      reason: rule.reason,
      owner: rule.owner,
      enabled: rule.enabled,
      description: rule.description || "",
    });
  }

  async function validateRule(rule: ManagedRule) {
    if (!canWrite) return;

    try {
      setSaving(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/rules/${encodeURIComponent(rule.id)}/validate`,
        { method: "POST" }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as RuleMutationResponse;
      setValidationResult(result.validation || null);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to validate rule");
    } finally {
      setSaving(false);
    }
  }

  async function setRuleEnabled(rule: ManagedRule, enabled: boolean) {
    if (!canWrite) return;

    try {
      setSaving(true);
      setError(null);

      const action = enabled ? "enable" : "disable";
      const response = await authFetch(
        `/detection-control/rules/${encodeURIComponent(rule.id)}/${action}`,
        { method: "POST" }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update rule state");
    } finally {
      setSaving(false);
    }
  }

  async function archiveRule(rule: ManagedRule) {
    if (!canWrite) return;

    const confirmed = window.confirm(`Archive ${rule.name}?`);

    if (!confirmed) return;

    try {
      setSaving(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/rules/${encodeURIComponent(rule.id)}`,
        { method: "DELETE" }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      if (editingRuleId === rule.id) {
        startCreate();
      }

      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to archive rule");
    } finally {
      setSaving(false);
    }
  }

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
              Back to Dashboard
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <SlidersHorizontal className="h-3.5 w-3.5" />
              Settings
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Detection Control Plane
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Governed management for detection suppressions, exceptions, rules and
              source policies, with admin-only writes and security audit coverage.
            </p>
          </div>

          <button
            onClick={loadData}
            disabled={!canView || refreshing}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading detection control plane...
          </section>
        ) : managedRules && inventory && canView ? (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard
                title="Managed Entries"
                value={managedRules.summary.total}
                subtitle="Rules and exceptions"
                icon={<FileCog className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Active"
                value={managedRules.summary.active}
                subtitle="Enabled operational entries"
                icon={<Shield className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Disabled"
                value={managedRules.summary.disabled}
                subtitle="Inactive or archived state"
                icon={<Ban className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Failed Validation"
                value={managedRules.summary.failed_validation}
                subtitle={formatDate(managedRules.summary.generated_at)}
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
              />
            </section>

            {!canWrite && (
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 text-xs text-slate-300">
                <div className="flex items-start gap-2">
                  <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
                  <p className="leading-5">
                    {currentUser?.role} access is read-only for detection-control changes.
                    ADMIN role is required to create, edit, enable, disable, validate or archive entries.
                  </p>
                </div>
              </section>
            )}

            <section className="grid gap-3 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.55fr)]">
              <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <div className="mb-3 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-slate-100">
                      Rule / Exception Table
                    </h2>
                    <p className="mt-1 text-xs text-slate-500">
                      Changes that require apply remain staged until service orchestration is enabled.
                    </p>
                  </div>

                  {canWrite && (
                    <button
                      type="button"
                      onClick={startCreate}
                      className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      New Entry
                    </button>
                  )}
                </div>

                <ManagedRulesTable
                  canWrite={Boolean(canWrite)}
                  items={managedRules.items}
                  saving={saving}
                  onArchive={archiveRule}
                  onEdit={startEdit}
                  onToggle={setRuleEnabled}
                  onValidate={validateRule}
                />
              </div>

              <div className="min-w-0 space-y-3">
                <RuleForm
                  canWrite={Boolean(canWrite)}
                  editingRuleId={editingRuleId}
                  form={form}
                  saving={saving}
                  onChange={setForm}
                  onReset={startCreate}
                  onSubmit={submitForm}
                />

                <ValidationPanel result={validationResult} />
              </div>
            </section>

            <section className="rounded-lg border border-amber-900/70 bg-amber-950/30 p-3 text-xs text-amber-100">
              <div className="flex items-start gap-2">
                <ServerCog className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <p className="leading-5">
                  Entries may require apply or service restart depending on source policy and
                  affected service. Restart orchestration will be enabled in Step 3.
                </p>
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-2">
              <div className="mb-2 flex items-center gap-2 px-1 text-xs text-slate-400">
                <Eye className="h-3.5 w-3.5" />
                Existing Detection Control inventory
              </div>

              <div className="mb-2 flex flex-wrap gap-1.5">
                {TABS.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition ${
                      activeTab === tab.key
                        ? "border-cyan-500 bg-cyan-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-600 hover:text-cyan-200"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <InventoryTable items={activeInventoryItems} />
            </section>
          </div>
        ) : null}
      </div>
    </main>
  );
}

function MetricCard({
  title,
  value,
  subtitle,
  icon,
}: {
  title: string;
  value: ReactNode;
  subtitle: string;
  icon: ReactNode;
}) {
  return (
    <article className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="text-slate-400">{icon}</div>
      </div>
      <div className="text-lg font-semibold text-slate-100">{value}</div>
      <div className="mt-1 text-[11px] text-slate-500">{subtitle}</div>
    </article>
  );
}

function ManagedRulesTable({
  canWrite,
  items,
  saving,
  onArchive,
  onEdit,
  onToggle,
  onValidate,
}: {
  canWrite: boolean;
  items: ManagedRule[];
  saving: boolean;
  onArchive: (rule: ManagedRule) => void;
  onEdit: (rule: ManagedRule) => void;
  onToggle: (rule: ManagedRule, enabled: boolean) => void;
  onValidate: (rule: ManagedRule) => void;
}) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No managed entries have been created yet.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Scope</th>
              <th className="px-3 py-2">Enabled / Status</th>
              <th className="px-3 py-2">Owner</th>
              <th className="px-3 py-2">Last Validation</th>
              <th className="px-3 py-2">Updated</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {items.map((rule) => (
              <tr key={rule.id} className="align-top hover:bg-slate-800/40">
                <td className="px-3 py-2 text-slate-300">{rule.type}</td>
                <td className="max-w-sm px-3 py-2">
                  <div className="font-medium text-slate-100">{rule.name}</div>
                  <div className="mt-1 leading-5 text-slate-500">{rule.reason}</div>
                  {rule.requires_apply && (
                    <div className="mt-1 text-[11px] text-amber-300">
                      Apply required: {rule.affected_service || "service policy"}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2">
                  <div className="text-slate-300">{rule.scope}</div>
                  <div className="mt-1 max-w-[220px] truncate text-slate-500" title={rule.matcher_value}>
                    {rule.matcher_kind}: {rule.matcher_value}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="mb-1 text-slate-300">{rule.enabled ? "enabled" : "disabled"}</div>
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(rule.status)}`}>
                    {rule.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-300">{rule.owner}</td>
                <td className="max-w-xs px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(rule.last_validation_status || "OK")}`}>
                    {rule.last_validation_status || "OK"}
                  </span>
                  <div className="mt-1 leading-5 text-slate-500">
                    {rule.last_validation_message || "Validation not run yet."}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="text-slate-300">{formatDate(rule.updated_at)}</div>
                  <div className="mt-1 text-slate-500">{rule.updated_by || rule.created_by || "-"}</div>
                </td>
                <td className="px-3 py-2">
                  {canWrite ? (
                    <div className="flex min-w-[170px] flex-wrap gap-1.5">
                      <button
                        type="button"
                        onClick={() => onEdit(rule)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => onValidate(rule)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-emerald-700 hover:text-emerald-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Validate
                      </button>
                      <button
                        type="button"
                        onClick={() => onToggle(rule, !rule.enabled)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-amber-700 hover:text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Power className="h-3.5 w-3.5" />
                        {rule.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        onClick={() => onArchive(rule)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-red-800 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Archive
                      </button>
                    </div>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-slate-500">
                      <Lock className="h-3.5 w-3.5" />
                      Read-only
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleForm({
  canWrite,
  editingRuleId,
  form,
  saving,
  onChange,
  onReset,
  onSubmit,
}: {
  canWrite: boolean;
  editingRuleId: string | null;
  form: RuleFormState;
  saving: boolean;
  onChange: (value: RuleFormState) => void;
  onReset: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form onSubmit={onSubmit} className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-100">
          {editingRuleId ? "Edit Entry" : "Create Entry"}
        </h2>
        {editingRuleId && (
          <button
            type="button"
            onClick={onReset}
            className="text-xs text-cyan-300 hover:text-cyan-200"
          >
            Clear
          </button>
        )}
      </div>

      <div className="grid gap-2">
        <Field label="Name">
          <input
            value={form.name}
            onChange={(event) => onChange({ ...form, name: event.target.value })}
            disabled={!canWrite || saving}
            className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>

        <div className="grid gap-2 sm:grid-cols-2">
          <Field label="Type">
            <select
              value={form.type}
              onChange={(event) => onChange({ ...form, type: event.target.value as RuleType })}
              disabled={!canWrite || saving}
              className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {RULE_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </Field>

          <Field label="Scope">
            <input
              value={form.scope}
              onChange={(event) => onChange({ ...form, scope: event.target.value })}
              disabled={!canWrite || saving}
              className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
            />
          </Field>
        </div>

        <Field label="Matcher Kind">
          <select
            value={form.matcher_kind}
            onChange={(event) => onChange({ ...form, matcher_kind: event.target.value as MatcherKind })}
            disabled={!canWrite || saving}
            className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {MATCHER_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Matcher Value">
          <textarea
            value={form.matcher_value}
            onChange={(event) => onChange({ ...form, matcher_value: event.target.value })}
            disabled={!canWrite || saving}
            rows={4}
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>

        <Field label="Reason">
          <textarea
            value={form.reason}
            onChange={(event) => onChange({ ...form, reason: event.target.value })}
            disabled={!canWrite || saving}
            rows={3}
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>

        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
          <Field label="Owner">
            <input
              value={form.owner}
              onChange={(event) => onChange({ ...form, owner: event.target.value })}
              disabled={!canWrite || saving}
              className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
            />
          </Field>

          <label className="flex h-full min-h-14 items-end gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => onChange({ ...form, enabled: event.target.checked })}
              disabled={!canWrite || saving}
              className="mb-2 h-4 w-4 rounded border-slate-700 bg-slate-950"
            />
            <span className="mb-2">Enabled</span>
          </label>
        </div>

        <Field label="Description">
          <textarea
            value={form.description}
            onChange={(event) => onChange({ ...form, description: event.target.value })}
            disabled={!canWrite || saving}
            rows={2}
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="submit"
          disabled={!canWrite || saving}
          className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Save className="h-3.5 w-3.5" />
          {editingRuleId ? "Save" : "Create"}
        </button>
        <button
          type="button"
          onClick={onReset}
          disabled={saving}
          className="h-8 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Reset
        </button>
      </div>
    </form>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="grid gap-1 text-xs text-slate-400">
      <span>{label}</span>
      {children}
    </label>
  );
}

function ValidationPanel({ result }: { result: ValidationResult | null }) {
  if (!result) {
    return (
      <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 text-xs text-slate-500">
        Validation result will appear after save or validate.
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-100">Validation Result</h2>
        <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(result.severity)}`}>
          {result.valid ? "valid" : "invalid"} / {result.severity}
        </span>
      </div>

      {result.messages.length > 0 && (
        <div className="mb-2 rounded-lg border border-red-900/70 bg-red-950/30 p-2 text-xs text-red-100">
          <div className="mb-1 font-medium">Errors</div>
          <ul className="space-y-1">
            {result.messages.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        </div>
      )}

      {result.warnings.length > 0 && (
        <div className="rounded-lg border border-amber-900/70 bg-amber-950/30 p-2 text-xs text-amber-100">
          <div className="mb-1 font-medium">Warnings</div>
          <ul className="space-y-1">
            {result.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </div>
      )}

      {result.messages.length === 0 && result.warnings.length === 0 && (
        <div className="text-xs text-slate-500">No validation findings.</div>
      )}
    </section>
  );
}

function InventoryTable({ items }: { items: InventoryItem[] }) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No inventory items found for this section.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Scope / Target</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Managed</th>
              <th className="px-3 py-2">Reload</th>
              <th className="px-3 py-2">Metadata</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {items.map((item) => (
              <tr key={item.id} className="align-top hover:bg-slate-800/40">
                <td className="max-w-sm px-3 py-2">
                  <div className="font-medium text-slate-100">{item.name}</div>
                  <div className="mt-1 leading-5 text-slate-500">{item.description}</div>
                  <div className="mt-1 leading-5 text-slate-600">{item.reason}</div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${sourceTone(item.source)}`}>
                    {item.source}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-300">{item.type}</td>
                <td className="px-3 py-2">
                  <div className="text-slate-300">{item.scope}</div>
                  <div className="mt-1 max-w-xs truncate text-slate-500" title={item.target}>
                    {item.target}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(item.status)}`}>
                    {item.status}
                  </span>
                </td>
                <td className="px-3 py-2">
                  {item.managed ? (
                    <span className="inline-flex items-center gap-1 text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      yes
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-slate-500">
                      <XCircle className="h-3.5 w-3.5" />
                      no
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-300">
                  {item.requires_reload ? "required" : "no"}
                </td>
                <td className="max-w-xs px-3 py-2 text-slate-500">
                  {metadataPreview(item.metadata)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
