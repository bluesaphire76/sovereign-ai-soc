"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  RefreshCw,
  Save,
  Shield,
  ShieldAlert,
  Wand2,
  XCircle,
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

        <div className="grid gap-3 xl:grid-cols-[minmax(0,1.4fr)_minmax(360px,0.8fr)]">
          <section className="overflow-hidden rounded-sm border border-slate-800">
            <div className="grid grid-cols-12 gap-2 border-b border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
              <div className="col-span-4">Feature</div>
              <div className="col-span-2">Mode</div>
              <div className="col-span-2">Roles</div>
              <div className="col-span-2">Providers</div>
              <div className="col-span-2">Risk</div>
            </div>
            <div className="max-h-[520px] divide-y divide-slate-800 overflow-y-auto bg-slate-950">
              {(policies?.features ?? []).map((policy) => {
                const selected = policy.feature_key === selectedKey;
                const externalMode = !["LOCAL_ONLY", "EXTERNAL_AI_DISABLED", "FEATURE_DISABLED"].includes(policy.mode);
                return (
                  <button
                    key={policy.feature_key}
                    type="button"
                    onClick={() => setSelectedKey(policy.feature_key)}
                    className={`grid w-full grid-cols-12 gap-2 px-3 py-3 text-left text-sm transition ${
                      selected ? "bg-cyan-950/30" : "hover:bg-slate-900/70"
                    }`}
                  >
                    <div className="col-span-12 min-w-0 md:col-span-4">
                      <div className="truncate font-semibold text-slate-100">{policy.display_name}</div>
                      <div className="truncate text-[11px] text-slate-500">{policy.feature_key}</div>
                    </div>
                    <div className="col-span-6 md:col-span-2">
                      <div className="text-xs font-medium text-slate-200">{policy.mode}</div>
                    </div>
                    <div className="col-span-6 md:col-span-2">
                      <div className="truncate text-xs text-slate-300">{policy.allowed_roles.join(", ")}</div>
                    </div>
                    <div className="col-span-6 md:col-span-2">
                      <div className="truncate text-xs text-slate-300">
                        {policy.allowed_provider_keys.length ? policy.allowed_provider_keys.join(", ") : "Any"}
                      </div>
                    </div>
                    <div className="col-span-6 flex gap-1 md:col-span-2">
                      <StatusBadge value={!externalMode} label={externalMode ? "External" : "Local"} />
                      {policy.require_confirmation && <StatusBadge value={null} label="Confirm" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="mb-3 flex items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">{selectedPolicy?.display_name ?? "Policy"}</h2>
                <p className="mt-1 text-xs text-slate-500">{selectedPolicy?.description}</p>
              </div>
              {selectedPolicy?.mode === "FEATURE_DISABLED" ? (
                <XCircle className="h-4 w-4 text-rose-300" strokeWidth={1.75} />
              ) : (
                <ShieldAlert className="h-4 w-4 text-cyan-300" strokeWidth={1.75} />
              )}
            </div>

            {editState && (
              <div className="space-y-3">
                <label className="block text-xs text-slate-400">
                  Mode
                  <select
                    disabled={!canEdit}
                    value={editState.mode}
                    onChange={(event) => setEditState({ ...editState, mode: event.target.value })}
                    className="mt-1 h-9 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-sm text-slate-100 disabled:opacity-60"
                  >
                    {(policies?.policy_modes ?? []).map((mode) => (
                      <option key={mode} value={mode}>{mode}</option>
                    ))}
                  </select>
                </label>

                <label className="block text-xs text-slate-400">
                  Allowed providers
                  <input
                    disabled={!canEdit}
                    value={editState.allowed_provider_keys}
                    onChange={(event) => setEditState({ ...editState, allowed_provider_keys: event.target.value })}
                    className="mt-1 h-9 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-sm text-slate-100 disabled:opacity-60"
                  />
                </label>

                <label className="block text-xs text-slate-400">
                  Allowed roles
                  <input
                    disabled={!canEdit}
                    value={editState.allowed_roles}
                    onChange={(event) => setEditState({ ...editState, allowed_roles: event.target.value })}
                    className="mt-1 h-9 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-sm text-slate-100 disabled:opacity-60"
                  />
                </label>

                <div className="grid gap-2 sm:grid-cols-2">
                  {[
                    ["require_confirmation", "Confirmation"],
                    ["store_payload_hash", "Payload hash"],
                    ["store_redacted_preview", "Redacted preview"],
                    ["allow_raw_telemetry", "Raw telemetry"],
                    ["allow_personal_data", "Personal data"],
                    ["payload_preview_enabled", "Preview"],
                  ].map(([key, label]) => (
                    <label key={key} className="flex items-center gap-2 rounded-sm border border-slate-800 bg-slate-900/50 px-2 py-2 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        disabled={!canEdit}
                        checked={Boolean(editState[key as keyof EditState])}
                        onChange={(event) => setEditState({ ...editState, [key]: event.target.checked })}
                        className="h-3.5 w-3.5"
                      />
                      {label}
                    </label>
                  ))}
                </div>

                <label className="block text-xs text-slate-400">
                  Reason
                  <input
                    disabled={!canEdit}
                    value={editState.reason}
                    onChange={(event) => setEditState({ ...editState, reason: event.target.value })}
                    className="mt-1 h-9 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-sm text-slate-100 disabled:opacity-60"
                  />
                </label>

                <button
                  type="button"
                  disabled={!canEdit || saving}
                  onClick={() => void savePolicy()}
                  className="inline-flex h-9 items-center justify-center gap-2 rounded-sm border border-cyan-800 bg-cyan-500 px-3 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Save className="h-3.5 w-3.5" strokeWidth={1.75} />
                  {saving ? "Saving" : "Save"}
                </button>
              </div>
            )}
          </section>
        </div>

        <section className="mt-3 grid gap-3 xl:grid-cols-2">
          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-slate-100">Preview</h2>
              <div className="flex flex-wrap gap-2">
                <select
                  value={previewFeature}
                  onChange={(event) => setPreviewFeature(event.target.value)}
                  className="h-8 rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100"
                >
                  {(policies?.features ?? []).map((policy) => (
                    <option key={policy.feature_key} value={policy.feature_key}>{policy.feature_key}</option>
                  ))}
                </select>
                <select
                  value={previewProvider}
                  onChange={(event) => setPreviewProvider(event.target.value)}
                  className="h-8 rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100"
                >
                  {(providers?.providers ?? []).map((provider) => (
                    <option key={provider.key} value={provider.key}>{provider.display_name}</option>
                  ))}
                </select>
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
            <h2 className="mb-3 text-sm font-semibold text-slate-100">Preview Result</h2>
            <pre className="h-[332px] overflow-auto rounded-sm border border-slate-800 bg-slate-900 p-3 text-xs text-slate-200">
              {previewResult || "No preview result yet."}
            </pre>
          </div>
        </section>

        <section className="mt-3 overflow-hidden rounded-sm border border-slate-800">
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
