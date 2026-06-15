"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Eye,
  Globe2,
  ListChecks,
  LockKeyhole,
  RefreshCw,
  Save,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Users,
  Wand2,
} from "lucide-react";
import { authFetch, fetchCurrentUser, type AuthUser } from "@/lib/auth";
import AppNavigation from "../../../components/AppNavigation";

type FeaturePolicy = {
  feature_key: string;
  display_name: string;
  description: string;
  mode: string;
  allowed_provider_keys: string[];
  allowed_roles: string[];
  require_confirmation: boolean;
  payload_preview_enabled: boolean;
  store_payload_hash: boolean;
  store_redacted_preview: boolean;
  allow_raw_telemetry: boolean;
  allow_personal_data: boolean;
  audit_level: string;
  updated_at: string | null;
  updated_by: string | null;
  update_reason: string | null;
};

type PoliciesResponse = {
  global_defaults: Record<string, unknown>;
  data_classes: string[];
  policy_modes: string[];
  features: FeaturePolicy[];
};

type ProviderConfig = {
  key: string;
  display_name: string;
  external: boolean;
  enabled: boolean;
  configured: boolean;
};

type ProvidersResponse = {
  providers: ProviderConfig[];
};

type DecisionRow = {
  id: number;
  event_type: string;
  outcome: string;
  actor_username: string | null;
  actor_role: string | null;
  target_id: string | null;
  created_at: string | null;
  details: {
    feature_key?: string;
    provider_key?: string;
    mode?: string;
    allowed?: boolean;
    action?: string;
    reason?: string | null;
    redaction_applied?: boolean;
    payload_hash?: string | null;
  };
};

type EditState = {
  mode: string;
  allowed_provider_keys: string;
  allowed_roles: string;
  require_confirmation: boolean;
  payload_preview_enabled: boolean;
  store_payload_hash: boolean;
  store_redacted_preview: boolean;
  allow_raw_telemetry: boolean;
  allow_personal_data: boolean;
  audit_level: string;
  reason: string;
};

const SAMPLE_PAYLOAD = JSON.stringify(
  {
    source_ip: "10.10.42.15",
    username: "analyst@example.com",
    hostname: "workstation.internal.local",
    raw_alert: { token: "secret-token", password: "hunter2" },
    process_command_line: "/usr/bin/curl https://example.internal/api",
  },
  null,
  2
);

type ModeDetail = {
  label: string;
  summary: string;
  exposure: string;
  data: string;
  risk: "low" | "medium" | "high" | "blocked";
};

const MODE_DETAILS: Record<string, ModeDetail> = {
  EXTERNAL_AI_DISABLED: {
    label: "External disabled",
    summary: "External providers are denied for this feature.",
    exposure: "Local provider only",
    data: "No external payload",
    risk: "blocked",
  },
  LOCAL_ONLY: {
    label: "Local only",
    summary: "Requests stay on the local Ollama path.",
    exposure: "Local provider only",
    data: "Secrets still redacted before local execution",
    risk: "low",
  },
  METADATA_ONLY: {
    label: "Metadata only",
    summary: "External providers receive request metadata, not SOC content.",
    exposure: "External allowed when provider and role match",
    data: "Counts, roles and context keys only",
    risk: "low",
  },
  REDACTED_CONTEXT: {
    label: "Redacted context",
    summary: "External providers receive redacted SOC context.",
    exposure: "External allowed when provider and role match",
    data: "Sensitive fields replaced with deterministic markers",
    risk: "medium",
  },
  FULL_CONTEXT_ADMIN_ONLY: {
    label: "Full context admin-only",
    summary: "External full context is restricted to admin use.",
    exposure: "Admin-only external access",
    data: "Secrets and credentials are still redacted",
    risk: "high",
  },
  CUSTOM_ALLOWLIST: {
    label: "Custom allowlist",
    summary: "Reserved for future field-level allowlists.",
    exposure: "Depends on configured allowlist",
    data: "Custom policy surface",
    risk: "medium",
  },
  FEATURE_DISABLED: {
    label: "Feature disabled",
    summary: "AI execution is denied for this feature.",
    exposure: "No provider access",
    data: "No payload sent",
    risk: "blocked",
  },
};

const PRIMARY_MODE_ORDER = [
  "LOCAL_ONLY",
  "METADATA_ONLY",
  "REDACTED_CONTEXT",
  "FULL_CONTEXT_ADMIN_ONLY",
  "EXTERNAL_AI_DISABLED",
  "FEATURE_DISABLED",
];

const ROLE_OPTIONS = ["ADMIN", "ANALYST", "VIEWER", "SYSTEM"];

function featureGroup(policy: FeaturePolicy) {
  const key = policy.feature_key;
  if (key.startsWith("incident_")) return "Incident response";
  if (key.startsWith("case_") || key.includes("report") || key.includes("executive")) return "Cases and reporting";
  if (key.includes("detection") || key.includes("remediation") || key.includes("how_to")) return "Detection and remediation";
  return "System automation";
}

function modeDetail(mode: string | null | undefined): ModeDetail {
  return MODE_DETAILS[String(mode || "").toUpperCase()] ?? {
    label: String(mode || "Unknown"),
    summary: "Custom policy mode.",
    exposure: "Policy-defined provider access",
    data: "Policy-defined payload handling",
    risk: "medium",
  };
}

function riskClasses(mode: string | null | undefined) {
  const risk = modeDetail(mode).risk;
  if (risk === "high") return "border-rose-800 bg-rose-950/30 text-rose-100";
  if (risk === "medium") return "border-amber-800 bg-amber-950/25 text-amber-100";
  if (risk === "blocked") return "border-slate-700 bg-slate-900 text-slate-300";
  return "border-emerald-800 bg-emerald-950/25 text-emerald-100";
}

function riskBadge(mode: string | null | undefined) {
  const detail = modeDetail(mode);
  if (detail.risk === "high") return <StatusBadge value={false} label="High impact" />;
  if (detail.risk === "medium") return <StatusBadge value={null} label="Medium impact" />;
  if (detail.risk === "blocked") return <StatusBadge value={false} label="Blocked" />;
  return <StatusBadge value={true} label="Low impact" />;
}

function setCsvMembership(value: string, item: string, enabled: boolean) {
  const current = new Set(csvToList(value));
  if (enabled) current.add(item);
  else current.delete(item);
  return Array.from(current).join(", ");
}

function formatCsv(value: string) {
  const items = csvToList(value);
  if (!items.length) return "Any configured provider";
  if (items.length <= 3) return items.join(", ");
  return `${items.slice(0, 3).join(", ")} +${items.length - 3}`;
}

function ToggleChip({
  active,
  label,
  onClick,
  disabled,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex h-8 items-center justify-center rounded-sm border px-2 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${
        active
          ? "border-cyan-700 bg-cyan-950/50 text-cyan-100"
          : "border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700 hover:text-slate-200"
      }`}
    >
      {label}
    </button>
  );
}

function ModeCard({
  mode,
  selected,
  onSelect,
  disabled,
}: {
  mode: string;
  selected: boolean;
  onSelect: () => void;
  disabled?: boolean;
}) {
  const detail = modeDetail(mode);
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onSelect}
      className={`min-h-[132px] rounded-sm border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${
        selected
          ? "border-cyan-500 bg-cyan-950/25 shadow-sm"
          : "border-slate-800 bg-slate-950 hover:border-slate-700 hover:bg-slate-900/70"
      }`}
    >
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-slate-100">{detail.label}</div>
          <div className="mt-0.5 font-mono text-[10px] uppercase tracking-wide text-slate-600">{mode}</div>
        </div>
        <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 text-[10px] ${riskClasses(mode)}`}>
          {detail.risk}
        </span>
      </div>
      <div className="text-xs leading-5 text-slate-400">{detail.summary}</div>
      <div className="mt-3 grid gap-1 text-[11px] text-slate-500">
        <div className="truncate">{detail.exposure}</div>
        <div className="truncate">{detail.data}</div>
      </div>
    </button>
  );
}

function ImpactLine({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex min-h-8 items-center justify-between gap-3 border-b border-slate-800/70 py-1.5 last:border-b-0">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="max-w-[68%] text-right text-xs font-medium text-slate-200">{value}</span>
    </div>
  );
}

function statusTone(value: boolean | null | undefined) {
  if (value === true) return "border-emerald-800 bg-emerald-950/40 text-emerald-200";
  if (value === false) return "border-rose-900 bg-rose-950/40 text-rose-200";
  return "border-slate-700 bg-slate-900 text-slate-300";
}

function StatusBadge({ value, label }: { value: boolean | null | undefined; label: string }) {
  return (
    <span className={`inline-flex h-6 items-center rounded-sm border px-2 text-[11px] ${statusTone(value)}`}>
      {label}
    </span>
  );
}

function SummaryCard({
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
    <article className="flex min-h-[46px] items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-900 px-2 py-1.5 shadow-sm">
      <div className="min-w-0">
        <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-1.5">
          <span className="truncate text-base font-semibold leading-5 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[10px] leading-3 text-slate-500">
            {subtitle}
          </span>
        </div>
      </div>
      <div className="shrink-0 rounded-sm bg-slate-950 p-1 text-slate-400">
        {icon}
      </div>
    </article>
  );
}

function csvToList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function policyToEditState(policy: FeaturePolicy): EditState {
  return {
    mode: policy.mode,
    allowed_provider_keys: policy.allowed_provider_keys.join(", "),
    allowed_roles: policy.allowed_roles.join(", "),
    require_confirmation: policy.require_confirmation,
    payload_preview_enabled: policy.payload_preview_enabled,
    store_payload_hash: policy.store_payload_hash,
    store_redacted_preview: policy.store_redacted_preview,
    allow_raw_telemetry: policy.allow_raw_telemetry,
    allow_personal_data: policy.allow_personal_data,
    audit_level: policy.audit_level,
    reason: "",
  };
}

export default function AiDataControlPage() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [policies, setPolicies] = useState<PoliciesResponse | null>(null);
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [decisions, setDecisions] = useState<DecisionRow[]>([]);
  const [selectedKey, setSelectedKey] = useState<string>("incident_triage");
  const [editState, setEditState] = useState<EditState | null>(null);
  const [previewFeature, setPreviewFeature] = useState("incident_triage");
  const [previewProvider, setPreviewProvider] = useState("local_ollama");
  const [previewText, setPreviewText] = useState(SAMPLE_PAYLOAD);
  const [previewResult, setPreviewResult] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const selectedPolicy = useMemo(
    () => policies?.features.find((policy) => policy.feature_key === selectedKey) ?? null,
    [policies, selectedKey]
  );
  const selectedModeDetail = modeDetail(editState?.mode ?? selectedPolicy?.mode);
  const previewPayload = useMemo(() => {
    if (!previewResult) return null;
    try {
      return JSON.parse(previewResult);
    } catch {
      return null;
    }
  }, [previewResult]);
  const previewDecision = previewPayload?.decision ?? null;
  const policyModes = useMemo(() => {
    const available = new Set(policies?.policy_modes ?? []);
    const primary = PRIMARY_MODE_ORDER.filter((mode) => available.has(mode));
    const rest = Array.from(available)
      .filter((mode) => !PRIMARY_MODE_ORDER.includes(mode))
      .sort();
    return [...primary, ...rest];
  }, [policies]);
  const groupedFeatures = useMemo(() => {
    const groups: Record<string, FeaturePolicy[]> = {};
    for (const policy of policies?.features ?? []) {
      const group = featureGroup(policy);
      groups[group] = [...(groups[group] ?? []), policy];
    }
    return groups;
  }, [policies]);
  const selectedProviders = useMemo(
    () => new Set(csvToList(editState?.allowed_provider_keys ?? "")),
    [editState?.allowed_provider_keys]
  );
  const selectedRoles = useMemo(
    () => new Set(csvToList(editState?.allowed_roles ?? "").map((role) => role.toUpperCase())),
    [editState?.allowed_roles]
  );

  const canEdit = user?.role === "ADMIN";
  const canPreview = user?.role === "ADMIN" || user?.role === "ANALYST";

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [currentUser, policiesResponse, providersResponse, decisionsResponse] = await Promise.all([
        fetchCurrentUser(),
        authFetch("/ai-data-control/policies"),
        authFetch("/ai-providers"),
        authFetch("/ai-data-control/decisions?limit=40"),
      ]);

      if (!policiesResponse.ok) throw new Error(`Policies API error ${policiesResponse.status}`);
      if (!providersResponse.ok) throw new Error(`Providers API error ${providersResponse.status}`);
      if (!decisionsResponse.ok) throw new Error(`Decisions API error ${decisionsResponse.status}`);

      const nextPolicies: PoliciesResponse = await policiesResponse.json();
      setUser(currentUser);
      setPolicies(nextPolicies);
      setProviders(await providersResponse.json());
      const decisionPayload = await decisionsResponse.json();
      setDecisions(decisionPayload.decisions ?? []);

      const nextSelected =
        nextPolicies.features.find((policy) => policy.feature_key === selectedKey)?.feature_key ??
        nextPolicies.features[0]?.feature_key ??
        "incident_triage";
      setSelectedKey(nextSelected);
      const nextPolicy = nextPolicies.features.find((policy) => policy.feature_key === nextSelected);
      if (nextPolicy) setEditState(policyToEditState(nextPolicy));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to load AI data control.");
    } finally {
      setLoading(false);
    }
  }, [selectedKey]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (selectedPolicy) {
      setEditState(policyToEditState(selectedPolicy));
    }
  }, [selectedPolicy]);

  async function savePolicy() {
    if (!selectedPolicy || !editState || !canEdit) return;
    setSaving(true);
    setError(null);
    setNotice(null);

    try {
      const response = await authFetch(`/ai-data-control/policies/${encodeURIComponent(selectedPolicy.feature_key)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: editState.mode,
          allowed_provider_keys: csvToList(editState.allowed_provider_keys),
          allowed_roles: csvToList(editState.allowed_roles).map((role) => role.toUpperCase()),
          require_confirmation: editState.require_confirmation,
          payload_preview_enabled: editState.payload_preview_enabled,
          store_payload_hash: editState.store_payload_hash,
          store_redacted_preview: editState.store_redacted_preview,
          allow_raw_telemetry: editState.allow_raw_telemetry,
          allow_personal_data: editState.allow_personal_data,
          audit_level: editState.audit_level,
          reason: editState.reason,
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.detail || `Policy update failed ${response.status}`);
      setNotice("Policy saved.");
      await load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Policy update failed.");
    } finally {
      setSaving(false);
    }
  }

  async function runRedactionPreview() {
    if (!canPreview) return;
    setError(null);
    setNotice(null);
    try {
      const parsed = JSON.parse(previewText);
      const response = await authFetch("/ai-data-control/redaction-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: parsed, external_sensitive: true }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.detail || `Redaction preview failed ${response.status}`);
      setPreviewResult(JSON.stringify(payload, null, 2));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Redaction preview failed.");
    }
  }

  async function runEvaluationPreview() {
    if (!canPreview) return;
    setError(null);
    setNotice(null);
    try {
      const parsed = JSON.parse(previewText);
      const response = await authFetch("/ai-data-control/evaluate-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          feature_key: previewFeature,
          provider_key: previewProvider,
          prompt: JSON.stringify(parsed),
          context: parsed,
          confirmed: true,
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.detail || `Evaluation preview failed ${response.status}`);
      setPreviewResult(JSON.stringify(payload, null, 2));
      await load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Evaluation preview failed.");
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 border-b border-slate-800 pb-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="mb-2 flex flex-col items-start gap-2">
              <Link href="/" className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200">
                Back to Dashboard
              </Link>
              <div className="inline-flex items-center gap-2 rounded-sm border border-cyan-900/70 bg-cyan-950/20 px-2 py-1 text-[11px] font-medium uppercase tracking-wide text-cyan-200">
                <Shield className="h-3.5 w-3.5" strokeWidth={1.75} />
                AI Data Control
              </div>
            </div>
            <h1 className="text-xl font-semibold text-slate-50">AI Data Control Policy</h1>
            <p className="mt-1 max-w-3xl text-sm text-slate-400">
              Policy decisions, redaction preview and external AI data controls.
            </p>
          </div>

          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex h-9 items-center justify-center gap-2 rounded-sm border border-slate-700 px-3 text-xs font-medium text-slate-200 transition hover:border-cyan-800 hover:bg-slate-900"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} strokeWidth={1.75} />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 flex items-start gap-2 rounded-sm border border-rose-900 bg-rose-950/30 px-3 py-2 text-sm text-rose-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
            <span>{error}</span>
          </div>
        )}

        {notice && (
          <div className="mb-3 flex items-start gap-2 rounded-sm border border-emerald-900 bg-emerald-950/30 px-3 py-2 text-sm text-emerald-100">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
            <span>{notice}</span>
          </div>
        )}

        <section className="mb-3 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
          <SummaryCard
            title="Default mode"
            value={String(policies?.global_defaults.default_mode ?? "-")}
            subtitle="policy baseline"
            icon={<Shield className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
          <SummaryCard
            title="External default"
            value={String(policies?.global_defaults.external_default_policy ?? "-")}
            subtitle="external AI"
            icon={<ShieldAlert className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
          <SummaryCard
            title="Policy features"
            value={policies?.features.length ?? 0}
            subtitle="governed"
            icon={<Eye className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
          <SummaryCard
            title="Payload hash"
            value={policies?.global_defaults.store_payload_hash ? "Enabled" : "Disabled"}
            subtitle="audit metadata"
            icon={<CheckCircle2 className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
        </section>

        <div className="grid gap-3 xl:grid-cols-[300px_minmax(0,1fr)_360px]">
          <section className="rounded-sm border border-slate-800 bg-slate-950">
            <div className="border-b border-slate-800 px-3 py-3">
              <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
                <ListChecks className="h-3.5 w-3.5" strokeWidth={1.75} />
                Feature Library
              </div>
            </div>
            <div className="max-h-[700px] overflow-y-auto p-2">
              {Object.entries(groupedFeatures).map(([group, items]) => (
                <div key={group} className="mb-3 last:mb-0">
                  <div className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-wide text-slate-600">
                    {group}
                  </div>
                  <div className="space-y-1">
                    {items.map((policy) => {
                      const selected = policy.feature_key === selectedKey;
                      const detail = modeDetail(policy.mode);
                      return (
                        <button
                          key={policy.feature_key}
                          type="button"
                          onClick={() => setSelectedKey(policy.feature_key)}
                          className={`w-full rounded-sm border px-2 py-2 text-left transition ${
                            selected
                              ? "border-cyan-700 bg-cyan-950/35"
                              : "border-transparent bg-transparent hover:border-slate-800 hover:bg-slate-900"
                          }`}
                        >
                          <div className="flex min-w-0 items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="truncate text-xs font-semibold text-slate-100">{policy.display_name}</div>
                              <div className="mt-0.5 truncate text-[10px] text-slate-600">{policy.feature_key}</div>
                            </div>
                            <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 text-[10px] ${riskClasses(policy.mode)}`}>
                              {detail.risk}
                            </span>
                          </div>
                          <div className="mt-1 truncate text-[11px] text-slate-500">{detail.label}</div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-sm border border-slate-800 bg-slate-950">
            <div className="border-b border-slate-800 px-3 py-3">
              <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
                    <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={1.75} />
                    Policy Workbench
                  </div>
                  <h2 className="mt-1 text-lg font-semibold text-slate-100">{selectedPolicy?.display_name ?? "Policy"}</h2>
                  <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">{selectedPolicy?.description}</p>
                </div>
                <div className="flex shrink-0 gap-1">{riskBadge(editState?.mode ?? selectedPolicy?.mode)}</div>
              </div>
            </div>

            {editState && (
              <div className="space-y-4 p-3">
                <div>
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <div className="text-sm font-semibold text-slate-100">Data exposure posture</div>
                    <div className="font-mono text-[10px] uppercase tracking-wide text-slate-600">{editState.mode}</div>
                  </div>
                  <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                    {policyModes.map((mode) => (
                      <ModeCard
                        key={mode}
                        mode={mode}
                        selected={editState.mode === mode}
                        disabled={!canEdit}
                        onSelect={() => setEditState({ ...editState, mode })}
                      />
                    ))}
                  </div>
                </div>

                <div className="grid gap-3 lg:grid-cols-2">
                  <div className="rounded-sm border border-slate-800 bg-slate-900/40 p-3">
                    <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
                      <Globe2 className="h-4 w-4 text-slate-400" strokeWidth={1.75} />
                      Provider scope
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {(providers?.providers ?? []).map((provider) => (
                        <ToggleChip
                          key={provider.key}
                          active={selectedProviders.has(provider.key)}
                          label={provider.display_name}
                          disabled={!canEdit}
                          onClick={() =>
                            setEditState({
                              ...editState,
                              allowed_provider_keys: setCsvMembership(
                                editState.allowed_provider_keys,
                                provider.key,
                                !selectedProviders.has(provider.key)
                              ),
                            })
                          }
                        />
                      ))}
                    </div>
                    <div className="mt-2 truncate text-[11px] text-slate-600">{formatCsv(editState.allowed_provider_keys)}</div>
                  </div>

                  <div className="rounded-sm border border-slate-800 bg-slate-900/40 p-3">
                    <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
                      <Users className="h-4 w-4 text-slate-400" strokeWidth={1.75} />
                      Roles allowed
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {ROLE_OPTIONS.map((role) => (
                        <ToggleChip
                          key={role}
                          active={selectedRoles.has(role)}
                          label={role}
                          disabled={!canEdit}
                          onClick={() =>
                            setEditState({
                              ...editState,
                              allowed_roles: setCsvMembership(editState.allowed_roles, role, !selectedRoles.has(role)),
                            })
                          }
                        />
                      ))}
                    </div>
                    <div className="mt-2 truncate text-[11px] text-slate-600">{formatCsv(editState.allowed_roles)}</div>
                  </div>
                </div>

                <div className="rounded-sm border border-slate-800 bg-slate-900/40 p-3">
                  <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <LockKeyhole className="h-4 w-4 text-slate-400" strokeWidth={1.75} />
                    Guardrails
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                    {[
                      ["require_confirmation", "Require confirmation"],
                      ["store_payload_hash", "Store payload hash"],
                      ["store_redacted_preview", "Store redacted preview"],
                      ["allow_raw_telemetry", "Allow raw telemetry"],
                      ["allow_personal_data", "Allow personal data"],
                      ["payload_preview_enabled", "Enable preview"],
                    ].map(([key, label]) => (
                      <label
                        key={key}
                        className={`flex min-h-10 items-center gap-2 rounded-sm border px-2 py-2 text-xs transition ${
                          Boolean(editState[key as keyof EditState])
                            ? "border-cyan-800 bg-cyan-950/25 text-cyan-100"
                            : "border-slate-800 bg-slate-950 text-slate-400"
                        }`}
                      >
                        <input
                          type="checkbox"
                          disabled={!canEdit}
                          checked={Boolean(editState[key as keyof EditState])}
                          onChange={(event) => setEditState({ ...editState, [key]: event.target.checked })}
                          className="h-3.5 w-3.5"
                        />
                        <span className="min-w-0 truncate">{label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </section>

          <aside className="rounded-sm border border-slate-800 bg-slate-950">
            <div className="border-b border-slate-800 px-3 py-3">
              <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
                <Database className="h-3.5 w-3.5" strokeWidth={1.75} />
                Impact Review
              </div>
              <div className="mt-1 text-sm font-semibold text-slate-100">{selectedModeDetail.label}</div>
            </div>

            {editState && (
              <div className="space-y-3 p-3">
                <div className={`rounded-sm border p-3 ${riskClasses(editState.mode)}`}>
                  <div className="text-sm font-semibold">{selectedModeDetail.summary}</div>
                </div>

                <div className="rounded-sm border border-slate-800 bg-slate-900/40 px-3 py-2">
                  <ImpactLine label="Provider access" value={selectedModeDetail.exposure} />
                  <ImpactLine label="Data sent" value={selectedModeDetail.data} />
                  <ImpactLine label="Providers" value={formatCsv(editState.allowed_provider_keys)} />
                  <ImpactLine label="Roles" value={formatCsv(editState.allowed_roles)} />
                  <ImpactLine
                    label="Audit"
                    value={`${editState.store_payload_hash ? "Hash" : "No hash"}${
                      editState.store_redacted_preview ? " + preview" : ""
                    }`}
                  />
                  <ImpactLine
                    label="Sensitive data"
                    value={
                      editState.allow_raw_telemetry || editState.allow_personal_data
                        ? "Expanded exposure"
                        : "Restricted"
                    }
                  />
                  <ImpactLine label="Confirmation" value={editState.require_confirmation ? "Required" : "Not required"} />
                </div>

                <label className="block text-xs text-slate-400">
                  Change reason
                  <textarea
                    disabled={!canEdit}
                    value={editState.reason}
                    onChange={(event) => setEditState({ ...editState, reason: event.target.value })}
                    placeholder="Required for audit"
                    className="mt-1 h-24 w-full resize-none rounded-sm border border-slate-700 bg-slate-900 px-2 py-2 text-sm text-slate-100 outline-none focus:border-cyan-800 disabled:opacity-60"
                  />
                </label>

                <button
                  type="button"
                  disabled={!canEdit || saving || !editState.reason.trim()}
                  onClick={() => void savePolicy()}
                  className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-sm border border-cyan-800 bg-cyan-500 px-3 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Save className="h-3.5 w-3.5" strokeWidth={1.75} />
                  {saving ? "Saving" : "Save policy"}
                </button>
              </div>
            )}
          </aside>
        </div>

        <section className="mt-3 grid gap-3 xl:grid-cols-2">
          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">Pre-save Preview</h2>
                <div className="mt-1 text-xs text-slate-500">Evaluate payload exposure before enabling wider access.</div>
              </div>
              <div className="flex flex-wrap gap-2">
                <label className="text-[11px] text-slate-500">
                  Feature
                  <select
                    value={previewFeature}
                    onChange={(event) => setPreviewFeature(event.target.value)}
                    className="mt-1 h-8 rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100"
                  >
                    {(policies?.features ?? []).map((policy) => (
                      <option key={policy.feature_key} value={policy.feature_key}>{policy.feature_key}</option>
                    ))}
                  </select>
                </label>
                <label className="text-[11px] text-slate-500">
                  Provider
                  <select
                    value={previewProvider}
                    onChange={(event) => setPreviewProvider(event.target.value)}
                    className="mt-1 h-8 rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100"
                  >
                    {(providers?.providers ?? []).map((provider) => (
                      <option key={provider.key} value={provider.key}>{provider.display_name}</option>
                    ))}
                  </select>
                </label>
              </div>
            </div>
            <textarea
              value={previewText}
              onChange={(event) => setPreviewText(event.target.value)}
              className="h-56 w-full resize-y rounded-sm border border-slate-800 bg-slate-900 p-3 font-mono text-xs text-slate-100 outline-none focus:border-cyan-800"
            />
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={!canPreview}
                onClick={() => void runRedactionPreview()}
                className="inline-flex h-8 items-center justify-center gap-1.5 rounded-sm border border-slate-700 px-2 text-xs font-medium text-slate-200 transition hover:border-cyan-800 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Wand2 className="h-3.5 w-3.5" strokeWidth={1.75} />
                Redact
              </button>
              <button
                type="button"
                disabled={!canPreview}
                onClick={() => void runEvaluationPreview()}
                className="inline-flex h-8 items-center justify-center gap-1.5 rounded-sm border border-slate-700 px-2 text-xs font-medium text-slate-200 transition hover:border-cyan-800 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Eye className="h-3.5 w-3.5" strokeWidth={1.75} />
                Evaluate
              </button>
            </div>
          </div>

          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="mb-3 flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-slate-100">Preview Result</h2>
              {previewDecision && (
                <StatusBadge value={Boolean(previewDecision.allowed)} label={previewDecision.allowed ? "Allowed" : "Denied"} />
              )}
            </div>
            {previewDecision && (
              <div className="mb-3 grid gap-2 sm:grid-cols-2">
                <div className="rounded-sm border border-slate-800 bg-slate-900/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">Mode</div>
                  <div className="mt-1 truncate text-xs text-slate-200">{modeDetail(previewDecision.mode).label}</div>
                </div>
                <div className="rounded-sm border border-slate-800 bg-slate-900/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">Action</div>
                  <div className="mt-1 truncate text-xs text-slate-200">{previewDecision.action}</div>
                </div>
                <div className="rounded-sm border border-slate-800 bg-slate-900/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">Redaction</div>
                  <div className="mt-1 truncate text-xs text-slate-200">
                    {previewDecision.redaction_applied ? "Applied" : "Not needed"}
                  </div>
                </div>
                <div className="rounded-sm border border-slate-800 bg-slate-900/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">Payload hash</div>
                  <div className="mt-1 truncate font-mono text-xs text-slate-200">{previewDecision.payload_hash ?? "-"}</div>
                </div>
              </div>
            )}
            <pre className="h-[250px] overflow-auto rounded-sm border border-slate-800 bg-slate-900 p-3 text-xs text-slate-200">
              {previewResult || "No preview result yet."}
            </pre>
          </div>
        </section>

        <section className="mt-3 overflow-hidden rounded-sm border border-slate-800">
          <div className="border-b border-slate-800 bg-slate-950 px-3 py-3">
            <h2 className="text-sm font-semibold text-slate-100">Recent Policy Decisions</h2>
            <div className="mt-1 text-xs text-slate-500">Audit trail for evaluated, allowed, denied and previewed AI data policy decisions.</div>
          </div>
          <div className="grid grid-cols-12 gap-2 border-b border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
            <div className="col-span-3">Event</div>
            <div className="col-span-2">Feature</div>
            <div className="col-span-2">Provider</div>
            <div className="col-span-2">Decision</div>
            <div className="col-span-2">Actor</div>
            <div className="col-span-1 text-right">Hash</div>
          </div>
          <div className="max-h-80 divide-y divide-slate-800 overflow-y-auto bg-slate-950">
            {decisions.map((decision) => (
              <div key={decision.id} className="grid grid-cols-12 gap-2 px-3 py-2 text-xs text-slate-300">
                <div className="col-span-12 truncate md:col-span-3">{decision.event_type}</div>
                <div className="col-span-6 truncate md:col-span-2">{decision.details.feature_key ?? decision.target_id ?? "-"}</div>
                <div className="col-span-6 truncate md:col-span-2">{decision.details.provider_key ?? "-"}</div>
                <div className="col-span-6 md:col-span-2">
                  <StatusBadge
                    value={decision.outcome === "ALLOWED" || decision.outcome === "SUCCESS" || decision.outcome === "APPLIED"}
                    label={decision.details.reason ?? decision.outcome}
                  />
                </div>
                <div className="col-span-4 truncate md:col-span-2">{decision.actor_username ?? decision.actor_role ?? "-"}</div>
                <div className="col-span-2 text-right font-mono text-[11px] text-slate-500">
                  {decision.details.payload_hash ? decision.details.payload_hash.slice(0, 7) : "-"}
                </div>
              </div>
            ))}
            {!decisions.length && (
              <div className="px-3 py-6 text-center text-sm text-slate-500">No policy decisions recorded.</div>
            )}
          </div>
        </section>
      </div>
    </main>
  );
}
