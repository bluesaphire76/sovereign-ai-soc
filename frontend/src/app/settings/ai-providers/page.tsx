"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  RefreshCw,
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

export default function AiProvidersPage() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testingKey, setTestingKey] = useState<string | null>(null);
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
      const [currentUser, providersResponse, healthResponse] = await Promise.all([
        fetchCurrentUser(),
        authFetch("/ai-providers"),
        authFetch("/ai-providers/health"),
      ]);

      if (!providersResponse.ok) {
        throw new Error(`Providers API error ${providersResponse.status}`);
      }

      if (!healthResponse.ok) {
        throw new Error(`Provider health API error ${healthResponse.status}`);
      }

      setUser(currentUser);
      setProviders(await providersResponse.json());
      setHealth(await healthResponse.json());
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

  const canTest = user?.role === "ADMIN";

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 border-b border-slate-800 pb-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <Link
              href="/"
              className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              Back to Dashboard
            </Link>

            <div className="mb-2 inline-flex items-center gap-2 rounded-sm border border-cyan-900/70 bg-cyan-950/20 px-2 py-1 text-[11px] font-medium uppercase tracking-wide text-cyan-200">
              <Cpu className="h-3.5 w-3.5" strokeWidth={1.75} />
              AI Providers
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

        <section className="grid gap-3 md:grid-cols-3">
          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="text-[11px] uppercase tracking-wide text-slate-500">Default provider</div>
            <div className="mt-2 text-sm font-semibold text-slate-100">
              {providers?.default_provider ?? "Loading"}
            </div>
          </div>
          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="text-[11px] uppercase tracking-wide text-slate-500">External providers</div>
            <div className="mt-2">
              <StatusBadge
                value={providers?.external_providers_enabled ?? null}
                label={providers?.external_providers_enabled ? "Enabled" : "Disabled"}
              />
            </div>
          </div>
          <div className="rounded-sm border border-slate-800 bg-slate-950 p-3">
            <div className="text-[11px] uppercase tracking-wide text-slate-500">Configured providers</div>
            <div className="mt-2 text-sm font-semibold text-slate-100">
              {providers?.providers.length ?? 0}
            </div>
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
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </main>
  );
}
