"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  RefreshCw,
  Save,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { authFetch, fetchCurrentUser, type AuthUser } from "@/lib/auth";
import AppNavigation from "../../../components/AppNavigation";

type ProviderConfig = {
  key: string;
  type: string;
  display_name: string;
  enabled: boolean;
  external: boolean;
  configured: boolean;
  model: string | null;
  base_url: string | null;
  base_url_configured: boolean;
  api_key_configured: boolean | null;
  timeout_seconds: number;
  max_tokens: number | null;
  feature_allowlist: string[];
  redaction_mode: string;
};

type ProvidersResponse = {
  default_provider: string;
  external_providers_enabled: boolean;
  feature_overrides: Record<string, string>;
  providers: ProviderConfig[];
};

type ProviderHealth = {
  provider_key: string;
  provider_type: string;
  configured_model: string | null;
  configured: boolean;
  enabled: boolean;
  reachable: boolean | null;
  model_available: boolean | null;
  latency_ms: number | null;
  safe_message: string;
  safe_error: string | null;
};

type HealthResponse = {
  providers: ProviderHealth[];
};

type ProviderDraft = {
  enabled: boolean;
  base_url: string;
  model: string;
  timeout_seconds: string;
  max_tokens: string;
  feature_allowlist: string;
  redaction_mode: string;
  reason: string;
};

type LocalProfile = {
  name: string;
  model: string;
  num_ctx: number;
  temperature: number;
  timeout_seconds: number;
  keep_alive: string;
  active: boolean;
  loaded: boolean;
  last_used: boolean;
  routed_features: string[];
};

type LocalProfilesResponse = {
  mode: string;
  current_profile: string | null;
  last_call: Record<string, unknown>;
  ollama_ps_error: string | null;
  loaded_models: Record<string, unknown>[];
  profiles: LocalProfile[];
};

type TestResult = {
  provider_key: string;
  success: boolean;
  safe_message: string;
  latency_ms: number | null;
  safe_error?: string | null;
};

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

function healthIcon(health?: ProviderHealth) {
  if (!health || health.reachable === null) {
    return <Activity className="h-4 w-4 text-slate-500" strokeWidth={1.75} />;
  }

  if (health.reachable) {
    return <CheckCircle2 className="h-4 w-4 text-emerald-300" strokeWidth={1.75} />;
  }

  return <XCircle className="h-4 w-4 text-rose-300" strokeWidth={1.75} />;
}

function formatList(items: string[]) {
  if (!items.length) return "None";
  if (items.length <= 4) return items.join(", ");
  return `${items.slice(0, 4).join(", ")} +${items.length - 4}`;
}

function providerToDraft(provider: ProviderConfig): ProviderDraft {
  return {
    enabled: provider.enabled,
    base_url: provider.base_url || "",
    model: provider.model || "",
    timeout_seconds: String(provider.timeout_seconds ?? 30),
    max_tokens: provider.max_tokens === null || provider.max_tokens === undefined ? "" : String(provider.max_tokens),
    feature_allowlist: provider.feature_allowlist.join(", "),
    redaction_mode: provider.redaction_mode,
    reason: "",
  };
}

function csvToList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function AiProvidersPage() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [profiles, setProfiles] = useState<LocalProfilesResponse | null>(null);
  const [providerDrafts, setProviderDrafts] = useState<Record<string, ProviderDraft>>({});
  const [defaultProviderDraft, setDefaultProviderDraft] = useState("local_ollama");
  const [externalEnabledDraft, setExternalEnabledDraft] = useState(false);
  const [settingsReason, setSettingsReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [testingKey, setTestingKey] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});

  const healthByProvider = useMemo(() => {
    const mapped: Record<string, ProviderHealth> = {};
    for (const item of health?.providers ?? []) {
      mapped[item.provider_key] = item;
    }
    return mapped;
  }, [health]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [currentUser, providersResponse, healthResponse, profilesResponse] = await Promise.all([
        fetchCurrentUser(),
        authFetch("/ai-providers"),
        authFetch("/ai-providers/health"),
        authFetch("/ai-providers/local-profiles"),
      ]);

      if (!providersResponse.ok) {
        throw new Error(`Providers API error ${providersResponse.status}`);
      }

      if (!healthResponse.ok) {
        throw new Error(`Provider health API error ${healthResponse.status}`);
      }

      if (!profilesResponse.ok) {
        throw new Error(`Local profiles API error ${profilesResponse.status}`);
      }

      const providersPayload: ProvidersResponse = await providersResponse.json();
      const drafts: Record<string, ProviderDraft> = {};
      for (const provider of providersPayload.providers) {
        drafts[provider.key] = providerToDraft(provider);
      }

      setUser(currentUser);
      setProviders(providersPayload);
      setProviderDrafts(drafts);
      setDefaultProviderDraft(providersPayload.default_provider);
      setExternalEnabledDraft(providersPayload.external_providers_enabled);
      setHealth(await healthResponse.json());
      setProfiles(await profilesResponse.json());
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to load AI providers.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function testProvider(provider: ProviderConfig) {
    if (provider.external) {
      const confirmed = window.confirm(
        "Run a harmless provider connectivity test? No incident, case, alert or evidence data will be sent."
      );
      if (!confirmed) return;
    }

    setTestingKey(provider.key);
    setError(null);

    try {
      const response = await authFetch(`/ai-providers/${encodeURIComponent(provider.key)}/test`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ confirm: true }),
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result?.detail || `Provider test failed: ${response.status}`);
      }

      setTestResults((current) => ({
        ...current,
        [provider.key]: result,
      }));
      await load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Provider test failed safely.");
    } finally {
      setTestingKey(null);
    }
  }

  async function saveRegistrySettings() {
    setSavingKey("__registry__");
    setError(null);
    setNotice(null);

    try {
      const response = await authFetch("/ai-providers/settings", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          default_provider: defaultProviderDraft,
          external_providers_enabled: externalEnabledDraft,
          feature_overrides: providers?.feature_overrides ?? {},
          reason: settingsReason,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || `Provider settings update failed ${response.status}`);
      }
      setNotice("Provider settings saved.");
      setSettingsReason("");
      await load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Provider settings update failed.");
    } finally {
      setSavingKey(null);
    }
  }

  async function saveProviderConfig(provider: ProviderConfig) {
    const draft = providerDrafts[provider.key];
    if (!draft) return;

    setSavingKey(provider.key);
    setError(null);
    setNotice(null);

    try {
      const response = await authFetch(`/ai-providers/${encodeURIComponent(provider.key)}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: draft.enabled,
          base_url: draft.base_url,
          model: draft.model,
          timeout_seconds: Number(draft.timeout_seconds || provider.timeout_seconds || 30),
          max_tokens: draft.max_tokens ? Number(draft.max_tokens) : null,
          feature_allowlist: csvToList(draft.feature_allowlist),
          redaction_mode: draft.redaction_mode,
          reason: draft.reason,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || `Provider config update failed ${response.status}`);
      }
      setNotice(`${provider.display_name} saved.`);
      await load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Provider config update failed.");
    } finally {
      setSavingKey(null);
    }
  }

  const canTest = user?.role === "ADMIN";
  const canEdit = user?.role === "ADMIN";

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 border-b border-slate-800 pb-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="mb-2 flex flex-col items-start gap-2">
              <Link
                href="/"
                className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
              >
                Back to Dashboard
              </Link>

              <div className="inline-flex items-center gap-2 rounded-sm border border-cyan-900/70 bg-cyan-950/20 px-2 py-1 text-[11px] font-medium uppercase tracking-wide text-cyan-200">
                <Cpu className="h-3.5 w-3.5" strokeWidth={1.75} />
                AI Providers
              </div>
            </div>
            <h1 className="text-xl font-semibold text-slate-50">AI Provider Control</h1>
            <p className="mt-1 max-w-3xl text-sm text-slate-400">
              Local-first provider visibility with governed external provider controls.
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
          <div className="flex items-start gap-2 rounded-sm border border-rose-900 bg-rose-950/30 px-3 py-2 text-sm text-rose-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
            <span>{error}</span>
          </div>
        )}

        {notice && (
          <div className="flex items-start gap-2 rounded-sm border border-emerald-900 bg-emerald-950/30 px-3 py-2 text-sm text-emerald-100">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
            <span>{notice}</span>
          </div>
        )}

        <section className="mb-3 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
          <SummaryCard
            title="Default provider"
            value={providers?.default_provider ?? "Loading"}
            subtitle="selected"
            icon={<Cpu className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
          <SummaryCard
            title="External providers"
            value={providers?.external_providers_enabled ? "Enabled" : "Disabled"}
            subtitle="runtime switch"
            icon={<ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
          <SummaryCard
            title="Configured providers"
            value={providers?.providers.length ?? 0}
            subtitle="registry"
            icon={<Activity className="h-3.5 w-3.5" strokeWidth={1.75} />}
          />
        </section>

        <section className="rounded-sm border border-slate-800 bg-slate-950 p-3">
          <div className="grid gap-3 lg:grid-cols-[minmax(220px,0.8fr)_minmax(220px,0.8fr)_minmax(260px,1fr)_auto] lg:items-end">
            <label className="block text-xs text-slate-400">
              Default provider
              <select
                disabled={!canEdit}
                value={defaultProviderDraft}
                onChange={(event) => setDefaultProviderDraft(event.target.value)}
                className="mt-1 h-9 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-sm text-slate-100 disabled:opacity-60"
              >
                {(providers?.providers ?? []).map((provider) => (
                  <option key={provider.key} value={provider.key}>
                    {provider.display_name}
                  </option>
                ))}
              </select>
            </label>

            <label className="flex h-9 items-center gap-2 rounded-sm border border-slate-800 bg-slate-900/60 px-3 text-xs text-slate-300">
              <input
                type="checkbox"
                disabled={!canEdit}
                checked={externalEnabledDraft}
                onChange={(event) => setExternalEnabledDraft(event.target.checked)}
                className="h-3.5 w-3.5"
              />
              External providers enabled
            </label>

            <label className="block text-xs text-slate-400">
              Reason
              <input
                disabled={!canEdit}
                value={settingsReason}
                onChange={(event) => setSettingsReason(event.target.value)}
                className="mt-1 h-9 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-sm text-slate-100 disabled:opacity-60"
              />
            </label>

            <button
              type="button"
              disabled={!canEdit || savingKey === "__registry__"}
              onClick={() => void saveRegistrySettings()}
              className="inline-flex h-9 items-center justify-center gap-2 rounded-sm border border-cyan-800 bg-cyan-500 px-3 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Save className="h-3.5 w-3.5" strokeWidth={1.75} />
              {savingKey === "__registry__" ? "Saving" : "Save"}
            </button>
          </div>
        </section>

        <section className="overflow-hidden rounded-sm border border-slate-800">
          <div className="grid grid-cols-12 gap-2 border-b border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
            <div className="col-span-4">Provider</div>
            <div className="col-span-2">Status</div>
            <div className="col-span-2">Model</div>
            <div className="col-span-2">Data control</div>
            <div className="col-span-2 text-right">Test</div>
          </div>

          <div className="divide-y divide-slate-800 bg-slate-950">
            {(providers?.providers ?? []).map((provider) => {
              const providerHealth = healthByProvider[provider.key];
              const result = testResults[provider.key];
              const testDisabled =
                !canTest ||
                testingKey === provider.key ||
                (provider.external && (!provider.configured || !provider.enabled));

              return (
                <div key={provider.key} className="grid grid-cols-12 gap-2 px-3 py-3 text-sm">
                  <div className="col-span-12 min-w-0 md:col-span-4">
                    <div className="flex min-w-0 items-center gap-2">
                      {healthIcon(providerHealth)}
                      <div className="min-w-0">
                        <div className="truncate font-semibold text-slate-100">{provider.display_name}</div>
                        <div className="truncate text-[11px] text-slate-500">
                          {provider.key} · {provider.type}
                        </div>
                      </div>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      <StatusBadge value={!provider.external} label={provider.external ? "External" : "Local"} />
                      <StatusBadge value={provider.enabled} label={provider.enabled ? "Enabled" : "Disabled"} />
                      <StatusBadge value={provider.configured} label={provider.configured ? "Configured" : "Not configured"} />
                    </div>
                  </div>

                  <div className="col-span-6 md:col-span-2">
                    <div className="text-[11px] text-slate-500">Health</div>
                    <div className="mt-1 text-xs text-slate-200">
                      {providerHealth?.safe_message ?? "Not checked"}
                    </div>
                    {providerHealth?.latency_ms !== null && providerHealth?.latency_ms !== undefined && (
                      <div className="mt-1 text-[11px] text-slate-500">{providerHealth.latency_ms} ms</div>
                    )}
                  </div>

                  <div className="col-span-6 md:col-span-2">
                    <div className="text-[11px] text-slate-500">Model</div>
                    <div className="mt-1 truncate text-xs text-slate-200">{provider.model || "-"}</div>
                    <div className="mt-1 text-[11px] text-slate-500">
                      Base URL {provider.base_url_configured ? "configured" : "missing"}
                      {provider.api_key_configured !== null
                        ? ` · API key ${provider.api_key_configured ? "present" : "missing"}`
                        : ""}
                    </div>
                  </div>

                  <div className="col-span-8 md:col-span-2">
                    <div className="text-[11px] text-slate-500">Redaction</div>
                    <div className="mt-1 text-xs font-medium text-slate-200">{provider.redaction_mode}</div>
                    <div className="mt-1 line-clamp-2 text-[11px] text-slate-500">
                      {formatList(provider.feature_allowlist)}
                    </div>
                  </div>

                  <div className="col-span-4 flex flex-col items-end gap-1 md:col-span-2">
                    <button
                      type="button"
                      disabled={testDisabled}
                      onClick={() => void testProvider(provider)}
                      className="inline-flex h-8 items-center justify-center gap-1.5 rounded-sm border border-slate-700 px-2 text-xs font-medium text-slate-200 transition hover:border-cyan-800 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.75} />
                      {testingKey === provider.key ? "Testing" : "Test"}
                    </button>
                    {result && (
                      <div className={`text-right text-[11px] ${result.success ? "text-emerald-300" : "text-rose-300"}`}>
                        {result.safe_message}
                      </div>
                    )}
                  </div>

                  {canEdit && providerDrafts[provider.key] && (
                    <div className="col-span-12 rounded-sm border border-slate-800 bg-slate-900/50 p-3">
                      <div className="grid gap-2 lg:grid-cols-[120px_minmax(180px,1fr)_minmax(180px,1fr)_110px_110px_minmax(220px,1.2fr)_minmax(180px,0.9fr)_auto] lg:items-end">
                        <label className="flex h-9 items-center gap-2 rounded-sm border border-slate-800 bg-slate-950 px-2 text-xs text-slate-300">
                          <input
                            type="checkbox"
                            checked={providerDrafts[provider.key].enabled}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], enabled: event.target.checked },
                              }))
                            }
                            className="h-3.5 w-3.5"
                          />
                          Enabled
                        </label>

                        <label className="block text-[11px] text-slate-500">
                          Base URL
                          <input
                            value={providerDrafts[provider.key].base_url}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], base_url: event.target.value },
                              }))
                            }
                            className="mt-1 h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          />
                        </label>

                        <label className="block text-[11px] text-slate-500">
                          Model
                          <input
                            value={providerDrafts[provider.key].model}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], model: event.target.value },
                              }))
                            }
                            className="mt-1 h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          />
                        </label>

                        <label className="block text-[11px] text-slate-500">
                          Timeout
                          <input
                            value={providerDrafts[provider.key].timeout_seconds}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], timeout_seconds: event.target.value },
                              }))
                            }
                            className="mt-1 h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          />
                        </label>

                        <label className="block text-[11px] text-slate-500">
                          Max tokens
                          <input
                            value={providerDrafts[provider.key].max_tokens}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], max_tokens: event.target.value },
                              }))
                            }
                            className="mt-1 h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          />
                        </label>

                        <label className="block text-[11px] text-slate-500">
                          Feature allowlist
                          <input
                            value={providerDrafts[provider.key].feature_allowlist}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], feature_allowlist: event.target.value },
                              }))
                            }
                            className="mt-1 h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          />
                        </label>

                        <label className="block text-[11px] text-slate-500">
                          Redaction
                          <select
                            value={providerDrafts[provider.key].redaction_mode}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], redaction_mode: event.target.value },
                              }))
                            }
                            className="mt-1 h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          >
                            <option value="BLOCK_EXTERNAL">BLOCK_EXTERNAL</option>
                            <option value="LOCAL_ONLY">LOCAL_ONLY</option>
                            <option value="METADATA_ONLY">METADATA_ONLY</option>
                            <option value="REDACTED_CONTEXT">REDACTED_CONTEXT</option>
                          </select>
                        </label>

                        <div className="flex gap-2">
                          <input
                            value={providerDrafts[provider.key].reason}
                            onChange={(event) =>
                              setProviderDrafts((current) => ({
                                ...current,
                                [provider.key]: { ...current[provider.key], reason: event.target.value },
                              }))
                            }
                            placeholder="Reason"
                            className="h-8 min-w-0 flex-1 rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100"
                          />
                          <button
                            type="button"
                            disabled={savingKey === provider.key}
                            onClick={() => void saveProviderConfig(provider)}
                            className="inline-flex h-8 items-center justify-center gap-1.5 rounded-sm border border-cyan-800 bg-cyan-500 px-2 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            <Save className="h-3.5 w-3.5" strokeWidth={1.75} />
                            {savingKey === provider.key ? "Saving" : "Save"}
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        <section className="rounded-sm border border-slate-800 bg-slate-950 p-3">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Local LLM Profiles</h2>
              <div className="mt-1 text-xs text-slate-500">
                Mode {profiles?.mode ?? "-"} · Current {profiles?.current_profile ?? "none"}
                {profiles?.ollama_ps_error ? ` · Ollama ps ${profiles.ollama_ps_error}` : ""}
              </div>
            </div>
            <div className="text-xs text-slate-500">
              Loaded models: {profiles?.loaded_models.length ?? 0}
            </div>
          </div>

          <div className="grid gap-3 lg:grid-cols-3">
            {(profiles?.profiles ?? []).map((profile) => (
              <div key={profile.name} className="rounded-sm border border-slate-800 bg-slate-900/50 p-3">
                <div className="mb-2 flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-slate-100">{profile.name}</div>
                    <div className="mt-1 truncate text-xs text-slate-500">{profile.model}</div>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <StatusBadge value={profile.active} label={profile.active ? "Active" : "Idle"} />
                    <StatusBadge value={profile.loaded} label={profile.loaded ? "Loaded" : "Not loaded"} />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2 text-[11px] text-slate-400">
                  <div>
                    <div className="uppercase tracking-wide text-slate-600">Context</div>
                    <div className="mt-1 text-slate-200">{profile.num_ctx}</div>
                  </div>
                  <div>
                    <div className="uppercase tracking-wide text-slate-600">Timeout</div>
                    <div className="mt-1 text-slate-200">{profile.timeout_seconds}s</div>
                  </div>
                  <div>
                    <div className="uppercase tracking-wide text-slate-600">Keep alive</div>
                    <div className="mt-1 text-slate-200">{profile.keep_alive}</div>
                  </div>
                </div>

                <div className="mt-3 line-clamp-3 text-xs text-slate-400">
                  {formatList(profile.routed_features)}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
