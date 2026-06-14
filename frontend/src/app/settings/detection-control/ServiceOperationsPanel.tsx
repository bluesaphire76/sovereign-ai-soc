"use client";

import { authFetch, type AuthUser } from "@/lib/auth";
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

type RelatedConfigVersion = {
  id: number;
  version_number: number;
  requires_restart: boolean;
  affected_services: string[];
} | null;

type ServiceStatusDetails = {
  service_key: string;
  display_name: string;
  kind: string;
  status: string;
  message: string;
  checked_at: string;
  details: Record<string, unknown>;
  safe_error: string | null;
};

type ServiceOperation = {
  operation_id: number;
  service_key: string;
  display_name: string | null;
  operation_type: string;
  action: string;
  status: string;
  reason: string | null;
  requested_by_username: string | null;
  related_config_version_id: number | null;
  pre_status: string | null;
  post_status: string | null;
  safe_message: string | null;
  safe_error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string | null;
  created_by: string | null;
};

type ServiceItem = {
  key: string;
  display_name: string;
  description: string;
  kind: string;
  risk_level: "low" | "medium" | "high" | string;
  restart_allowed: boolean;
  restart_disabled_reason: string | null;
  requires_admin: boolean;
  impact: string;
  post_restart_check: string;
  command_family: string;
  unit: string | null;
  container: string | null;
  status: string;
  status_details: ServiceStatusDetails | null;
  last_operation: ServiceOperation | null;
};

type ServiceListResponse = {
  services: ServiceItem[];
  supported_statuses: string[];
};

type OperationsResponse = {
  items: ServiceOperation[];
};

type RestartPreview = {
  service_key: string;
  display_name: string;
  allowed: boolean;
  risk_level: string;
  current_status: string;
  current_status_details: ServiceStatusDetails;
  requires_confirmation: boolean;
  reason_required: boolean;
  impact: string;
  post_restart_check: string;
  command_family: string;
  warnings: string[];
  operation: ServiceOperation;
};

type RestartResult = {
  operation_id: number;
  service_key: string;
  display_name: string;
  action: string;
  status: string;
  pre_status: string | null;
  post_status: string | null;
  started_at: string | null;
  finished_at: string | null;
  message: string;
  safe_error: string | null;
  related_config_version_id: number | null;
};

async function fetchServices(): Promise<ServiceListResponse> {
  const response = await authFetch("/service-operations/services", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Service operations API returned ${response.status}`);
  }

  return (await response.json()) as ServiceListResponse;
}

async function fetchOperations(): Promise<OperationsResponse> {
  const response = await authFetch("/service-operations/operations?limit=200", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Service operations history returned ${response.status}`);
  }

  return (await response.json()) as OperationsResponse;
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

function statusTone(status: string) {
  const normalized = status.toLowerCase();

  if (normalized === "running" || normalized === "success") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if (normalized === "failed" || normalized === "unsupported") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  if (normalized === "stopped" || normalized === "not_found") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }

  return "border-amber-800 bg-amber-950/60 text-amber-200";
}

function riskTone(riskLevel: string) {
  if (riskLevel.toLowerCase() === "high") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  return "border-amber-800 bg-amber-950/60 text-amber-200";
}

function serviceMatchesAffected(service: ServiceItem, relatedConfigVersion: RelatedConfigVersion) {
  if (!relatedConfigVersion?.requires_restart) return false;

  return relatedConfigVersion.affected_services.some((item) =>
    serviceMatchesAffectedName(service, item)
  );
}

function serviceMatchesAffectedName(service: ServiceItem, affectedService: string) {
  const normalizedAffected = normalizeServiceName(affectedService);
  const names = new Set([
    normalizeServiceName(service.key),
    normalizeServiceName(service.key.replaceAll("_", "-")),
    normalizeServiceName(service.unit || ""),
    normalizeServiceName(`${service.unit || ""}.service`),
    normalizeServiceName(service.container || ""),
  ]);

  return names.has(normalizedAffected);
}

function normalizeServiceName(value: string) {
  return value.trim().toLowerCase();
}

function serviceDisplayName(service: ServiceItem | null, fallback: string) {
  return service?.display_name || fallback;
}

function latestSuccessfulRestartForConfig(
  operations: ServiceOperation[],
  service: ServiceItem,
  configVersionId: number
) {
  return operations.find(
    (operation) =>
      operation.operation_type === "restart" &&
      operation.status === "success" &&
      operation.related_config_version_id === configVersionId &&
      operation.service_key === service.key
  ) || null;
}

function restartClearance(
  relatedConfigVersion: RelatedConfigVersion,
  services: ServiceItem[],
  operations: ServiceOperation[]
) {
  if (!relatedConfigVersion?.requires_restart) return null;

  const impacted = relatedConfigVersion.affected_services.map((affectedService) => {
    const service =
      services.find((item) => serviceMatchesAffectedName(item, affectedService)) || null;
    const successfulRestart = service
      ? latestSuccessfulRestartForConfig(operations, service, relatedConfigVersion.id)
      : null;
    const running = service?.status === "running";
    const completed = Boolean(successfulRestart && running);

    return {
      affectedService,
      completed,
      displayName: serviceDisplayName(service, affectedService),
      operation: successfulRestart,
      running,
      service,
    };
  });

  const pending = impacted.filter((item) => !item.completed);
  const completed = impacted.filter((item) => item.completed);

  return {
    allCompleted: impacted.length > 0 && pending.length === 0,
    completed,
    impacted,
    pending,
  };
}

function joinNames(names: string[]) {
  if (names.length === 0) return "-";
  if (names.length === 1) return names[0];

  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

type RestartClearance = NonNullable<ReturnType<typeof restartClearance>>;

async function readApiError(response: Response) {
  const body = (await response.json().catch(() => null)) as { detail?: unknown } | null;
  const detail = body?.detail;

  if (typeof detail === "string") return detail;

  if (detail && typeof detail === "object") {
    return JSON.stringify(detail);
  }

  return `Request failed with status ${response.status}`;
}

function ConfigRestartStatusBanner({
  clearance,
  versionNumber,
}: {
  clearance: RestartClearance;
  versionNumber: number;
}) {
  if (clearance.allCompleted) {
    return (
      <div className="mb-3 rounded-lg border border-emerald-900/70 bg-emerald-950/30 p-3 text-xs text-emerald-100">
        <div className="flex items-start gap-2">
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <div>
            Config v{versionNumber} active and running for{" "}
            {joinNames(clearance.completed.map((item) => item.displayName))}.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mb-3 rounded-lg border border-amber-900/70 bg-amber-950/30 p-3 text-xs text-amber-100">
      <div className="flex items-start gap-2">
        <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <div>
          Config v{versionNumber} requires restart for{" "}
          {joinNames(clearance.pending.map((item) => item.displayName))}.
          {clearance.completed.length > 0 && (
            <> Completed: {joinNames(clearance.completed.map((item) => item.displayName))}.</>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ServiceOperationsPanel({
  currentUser,
  relatedConfigVersion,
}: {
  currentUser: AuthUser | null;
  relatedConfigVersion: RelatedConfigVersion;
}) {
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [operations, setOperations] = useState<ServiceOperation[]>([]);
  const [selectedService, setSelectedService] = useState<ServiceItem | null>(null);
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [preview, setPreview] = useState<RestartPreview | null>(null);
  const [result, setResult] = useState<RestartResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canPreview = currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";
  const canRestart = currentUser?.role === "ADMIN";

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [serviceData, operationData] = await Promise.all([
        fetchServices(),
        fetchOperations(),
      ]);

      setServices(serviceData.services);
      setOperations(operationData.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load service operations");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadData();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadData]);

  const affectedServiceKeys = useMemo(
    () =>
      new Set(
        services
          .filter((service) => serviceMatchesAffected(service, relatedConfigVersion))
          .map((service) => service.key)
      ),
    [relatedConfigVersion, services]
  );
  const configRestartClearance = useMemo(
    () => restartClearance(relatedConfigVersion, services, operations),
    [operations, relatedConfigVersion, services]
  );

  function openRestart(service: ServiceItem) {
    setSelectedService(service);
    setReason("");
    setConfirmed(false);
    setPreview(null);
    setResult(null);
    setError(null);
  }

  function closeRestart() {
    setSelectedService(null);
    setReason("");
    setConfirmed(false);
    setPreview(null);
    setResult(null);
  }

  async function checkStatus(service: ServiceItem) {
    try {
      setRunning(true);
      setError(null);

      const response = await authFetch(
        `/service-operations/services/${service.key}/status`,
        { method: "GET" }
      );

      if (!response.ok) {
        throw new Error(await readApiError(response));
      }

      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to check status");
    } finally {
      setRunning(false);
    }
  }

  async function runPreview() {
    if (!selectedService || !reason.trim() || !canPreview) return;

    try {
      setRunning(true);
      setError(null);
      setResult(null);

      const response = await authFetch(
        `/service-operations/services/${selectedService.key}/restart-preview`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            reason,
            related_config_version_id: relatedConfigId(selectedService),
          }),
        }
      );

      if (!response.ok) {
        throw new Error(await readApiError(response));
      }

      setPreview((await response.json()) as RestartPreview);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to run restart preview");
    } finally {
      setRunning(false);
    }
  }

  async function restartService() {
    if (!selectedService || !reason.trim() || !confirmed || !canRestart || !preview?.allowed) {
      return;
    }

    try {
      setRunning(true);
      setError(null);

      const response = await authFetch(
        `/service-operations/services/${selectedService.key}/restart`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            reason,
            confirm: confirmed,
            related_config_version_id: relatedConfigId(selectedService),
          }),
        }
      );

      if (!response.ok) {
        throw new Error(await readApiError(response));
      }

      setResult((await response.json()) as RestartResult);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to restart service");
    } finally {
      setRunning(false);
    }
  }

  function relatedConfigId(service: ServiceItem) {
    return serviceMatchesAffected(service, relatedConfigVersion)
      ? relatedConfigVersion?.id || null
      : null;
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-cyan-300">
            <RotateCcw className="h-3.5 w-3.5" />
            Service Operations
          </div>
          <h2 className="text-sm font-semibold text-slate-100">
            Managed Service Restart
          </h2>
        </div>

        <button
          type="button"
          onClick={loadData}
          disabled={loading || running}
          className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {relatedConfigVersion?.requires_restart && configRestartClearance && (
        <ConfigRestartStatusBanner
          clearance={configRestartClearance}
          versionNumber={relatedConfigVersion.version_number}
        />
      )}

      <div className="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5">
        {services.map((service) => (
          <ServiceCard
            key={service.key}
            affected={affectedServiceKeys.has(service.key)}
            restartCompleted={Boolean(
              configRestartClearance?.completed.some(
                (item) => item.service?.key === service.key
              )
            )}
            canRestart={canRestart}
            running={running}
            service={service}
            onCheckStatus={checkStatus}
            onRestart={openRestart}
          />
        ))}
      </div>

      {selectedService && (
        <RestartModal
          canPreview={canPreview}
          canRestart={canRestart}
          confirmed={confirmed}
          preview={preview}
          reason={reason}
          result={result}
          running={running}
          service={selectedService}
          relatedConfigVersion={
            serviceMatchesAffected(selectedService, relatedConfigVersion)
              ? relatedConfigVersion
              : null
          }
          onClose={closeRestart}
          onConfirm={setConfirmed}
          onPreview={runPreview}
          onReason={setReason}
          onRestart={restartService}
        />
      )}
    </section>
  );
}

function ServiceCard({
  affected,
  canRestart,
  restartCompleted,
  running,
  service,
  onCheckStatus,
  onRestart,
}: {
  affected: boolean;
  canRestart: boolean;
  restartCompleted: boolean;
  running: boolean;
  service: ServiceItem;
  onCheckStatus: (service: ServiceItem) => void;
  onRestart: (service: ServiceItem) => void;
}) {
  const restartDisabled = running || !canRestart || !service.restart_allowed;

  return (
    <article className="rounded-sm border border-slate-800 bg-slate-950 p-2 shadow-sm">
      <div className="mb-1.5 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-xs font-semibold leading-4 text-slate-100">
            {service.display_name}
          </div>
          <div className="mt-0.5 max-h-8 overflow-hidden text-[11px] leading-4 text-slate-500">
            {service.description}
          </div>
        </div>
        <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 text-[10px] ${riskTone(service.risk_level)}`}>
          {service.risk_level}
        </span>
      </div>

      <div className="mb-1.5 flex flex-wrap items-center gap-1 text-xs">
        <span className={`rounded-sm border px-1.5 py-0.5 text-[10px] ${statusTone(service.status)}`}>
          {service.status}
        </span>
        <span className="rounded-sm border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-400">
          {service.command_family}
        </span>
        {affected && (
          <span
            className={`rounded-sm border px-1.5 py-0.5 text-[10px] ${
              restartCompleted
                ? "border-emerald-800 bg-emerald-950/50 text-emerald-200"
                : "border-amber-800 bg-amber-950/50 text-amber-200"
            }`}
          >
            {restartCompleted ? "config running" : "restart pending"}
          </span>
        )}
      </div>

      {service.last_operation && (
        <div className="mb-2 truncate rounded-sm border border-slate-800 bg-slate-900 px-2 py-1 text-[10px] text-slate-400">
          Last {service.last_operation.operation_type}: {service.last_operation.status} /{" "}
          {formatDate(service.last_operation.created_at)}
        </div>
      )}

      <div className="flex flex-wrap gap-1">
        <button
          type="button"
          onClick={() => onCheckStatus(service)}
          disabled={running}
          className="flex h-7 items-center gap-1 rounded-sm border border-slate-700 bg-slate-900 px-2 text-[11px] text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Eye className="h-3.5 w-3.5" />
          Status
        </button>
        <button
          type="button"
          onClick={() => onRestart(service)}
          disabled={restartDisabled}
          title={
            !canRestart
              ? "ADMIN role required"
              : service.restart_disabled_reason || undefined
          }
          className="flex h-7 items-center gap-1 rounded-sm border border-slate-700 bg-slate-900 px-2 text-[11px] text-slate-200 hover:border-amber-700 hover:text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Restart
        </button>
      </div>
    </article>
  );
}

function RestartModal({
  canPreview,
  canRestart,
  confirmed,
  preview,
  reason,
  result,
  running,
  service,
  relatedConfigVersion,
  onClose,
  onConfirm,
  onPreview,
  onReason,
  onRestart,
}: {
  canPreview: boolean;
  canRestart: boolean;
  confirmed: boolean;
  preview: RestartPreview | null;
  reason: string;
  result: RestartResult | null;
  running: boolean;
  service: ServiceItem;
  relatedConfigVersion: RelatedConfigVersion;
  onClose: () => void;
  onConfirm: (value: boolean) => void;
  onPreview: () => void;
  onReason: (value: string) => void;
  onRestart: () => void;
}) {
  const previewReady = Boolean(preview?.allowed);
  const restartDisabled = running || !canRestart || !reason.trim() || !confirmed || !previewReady;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <div className="w-full max-w-2xl rounded-lg border border-slate-800 bg-slate-950 p-4 shadow-2xl">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold text-slate-100">
              Restart {service.display_name}
            </h3>
            <div className="mt-1 text-xs text-slate-500">
              Current status: {preview?.current_status || service.status}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={running}
            className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-900 px-2 text-[11px] text-slate-300 hover:text-slate-100 disabled:opacity-50"
          >
            <XCircle className="h-3.5 w-3.5" />
            Close
          </button>
        </div>

        <div className="mb-3 grid gap-2 text-xs md:grid-cols-2">
          <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div className="mb-1 font-medium text-slate-300">Impact</div>
            <div className="leading-5 text-slate-500">{service.impact}</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div className="mb-1 font-medium text-slate-300">Post-check</div>
            <div className="leading-5 text-slate-500">{service.post_restart_check}</div>
          </div>
        </div>

        {service.risk_level.toLowerCase() === "high" && (
          <div className="mb-3 rounded-lg border border-red-900/70 bg-red-950/30 p-3 text-xs text-red-100">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div>
                This is a high-impact operation. Restart may temporarily interrupt security processing.
              </div>
            </div>
          </div>
        )}

        {relatedConfigVersion && (
          <div className="mb-3 rounded-lg border border-amber-900/70 bg-amber-950/30 p-3 text-xs text-amber-100">
            Related configuration: version {relatedConfigVersion.version_number}
          </div>
        )}

        <label className="mb-3 block text-xs">
          <span className="mb-1 block font-medium text-slate-300">Reason</span>
          <textarea
            value={reason}
            onChange={(event) => onReason(event.target.value)}
            disabled={running}
            className="min-h-20 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none focus:border-cyan-500 disabled:opacity-60"
          />
        </label>

        <label className="mb-3 flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => onConfirm(event.target.checked)}
            disabled={running}
            className="mt-0.5"
          />
          <span>
            I understand the operational impact and want to restart this service.
          </span>
        </label>

        {preview && (
          <div className="mb-3 rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs">
            <div className="mb-2 flex items-center gap-2 text-slate-200">
              {preview.allowed ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" />
              ) : (
                <AlertTriangle className="h-3.5 w-3.5 text-amber-300" />
              )}
              Preview {preview.allowed ? "allowed" : "blocked"}
            </div>
            {preview.warnings.length > 0 && (
              <ul className="space-y-1 text-amber-100">
                {preview.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        {result && (
          <div className={`mb-3 rounded-lg border p-3 text-xs ${statusTone(result.status)}`}>
            <div className="font-medium">{result.message}</div>
            <div className="mt-1">
              Operation #{result.operation_id}: {result.pre_status || "-"} to{" "}
              {result.post_status || "-"}
            </div>
            {result.safe_error && <div className="mt-1">{result.safe_error}</div>}
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={running}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onPreview}
            disabled={running || !canPreview || !reason.trim()}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-slate-900 px-3 text-xs text-cyan-200 hover:bg-cyan-950/50 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Eye className="h-3.5 w-3.5" />
            Run preview
          </button>
          <button
            type="button"
            onClick={onRestart}
            disabled={restartDisabled}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-amber-700 bg-amber-500 px-3 text-xs font-medium text-slate-950 hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            Restart service
          </button>
        </div>
      </div>
    </div>
  );
}
