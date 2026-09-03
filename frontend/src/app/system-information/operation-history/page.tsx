"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  History,
  RefreshCw,
  XCircle,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import {
  EnterpriseBadge,
  EnterpriseBreadcrumbs,
  EnterpriseButton,
  EnterpriseEmptyState,
  EnterpriseErrorState,
  EnterpriseMetricCard,
  EnterpriseMetricStrip,
  EnterprisePageHeader,
  EnterprisePanel,
  EnterpriseSearchInput,
  EnterpriseSelect,
  EnterpriseSkeleton,
  EnterpriseStatusBadge,
} from "../../../components/enterprise";
import { authFetch, fetchCurrentUser, type AuthUser } from "../../../lib/auth";

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

type OperationsResponse = {
  items: ServiceOperation[];
  total?: number;
  limit?: number;
  offset?: number;
  page?: number;
  total_pages?: number;
};

type FilterOption = {
  label: string;
  value: string;
};

const DEFAULT_PAGE_SIZE = 25;
const PAGE_SIZE_OPTIONS: FilterOption[] = [
  { label: "25", value: "25" },
  { label: "50", value: "50" },
  { label: "100", value: "100" },
  { label: "200", value: "200" },
];

const SERVICE_OPTIONS: FilterOption[] = [
  { label: "All services", value: "ALL" },
  { label: "AI SOC Worker", value: "ai_soc_worker" },
  { label: "AI SOC API", value: "ai_soc_api" },
  { label: "AI SOC Frontend", value: "ai_soc_frontend" },
  { label: "Wazuh Manager", value: "wazuh_manager" },
  { label: "Suricata IDS", value: "suricata" },
];

const OPERATION_TYPE_OPTIONS: FilterOption[] = [
  { label: "All operations", value: "ALL" },
  { label: "Restart", value: "restart" },
  { label: "Restart preview", value: "restart_preview" },
  { label: "Status check", value: "status_check" },
];

const STATUS_OPTIONS: FilterOption[] = [
  { label: "All statuses", value: "ALL" },
  { label: "Success", value: "success" },
  { label: "Failed", value: "failed" },
  { label: "Denied", value: "denied" },
  { label: "Running", value: "running" },
];

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

async function fetchOperations(queryString: string): Promise<OperationsResponse> {
  const response = await authFetch(`/service-operations/operations?${queryString}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Service operations history returned ${response.status}`);
  }

  return (await response.json()) as OperationsResponse;
}

export default function OperationHistoryPage() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [data, setData] = useState<OperationsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [serviceKey, setServiceKey] = useState("ALL");
  const [operationType, setOperationType] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");

  const canView =
    currentUser?.role === "ADMIN" ||
    currentUser?.role === "ANALYST" ||
    currentUser?.role === "VIEWER";

  const queryString = useMemo(() => {
    const params = new URLSearchParams();

    params.set("limit", String(pageSize));
    params.set("offset", String((page - 1) * pageSize));

    if (serviceKey !== "ALL") params.set("service_key", serviceKey);
    if (operationType !== "ALL") params.set("operation_type", operationType);
    if (status !== "ALL") params.set("status", status);
    if (search) params.set("search", search);

    return params.toString();
  }, [operationType, page, pageSize, search, serviceKey, status]);

  const loadData = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const current = await fetchCurrentUser();
      setCurrentUser(current);

      if (!["ADMIN", "ANALYST", "VIEWER"].includes(current.role)) {
        setData(null);
        setError("Forbidden: Operation History is not available for this account.");
        return;
      }

      const result = await fetchOperations(queryString);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load operation history");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [queryString]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadData();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [loadData]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setPage(1);
      setSearch(searchInput.trim());
    }, 350);

    return () => window.clearTimeout(timeout);
  }, [searchInput]);

  function resetFilters() {
    setPage(1);
    setPageSize(DEFAULT_PAGE_SIZE);
    setServiceKey("ALL");
    setOperationType("ALL");
    setStatus("ALL");
    setSearchInput("");
    setSearch("");
  }

  const operations = data?.items ?? [];
  const total = data?.total ?? operations.length;
  const effectivePage = data?.page ?? page;
  const totalPages = data?.total_pages ?? 1;
  const currentOffset = data?.offset ?? (page - 1) * pageSize;
  const firstVisible = total === 0 ? 0 : currentOffset + 1;
  const lastVisible = currentOffset + operations.length;
  const failed = operations.filter((item) => item.status === "failed").length;
  const denied = operations.filter((item) => item.status === "denied").length;
  const restarts = operations.filter((item) => item.operation_type === "restart").length;

  return (
    <AppShell>
      <EnterprisePageHeader
        breadcrumbs={
          <EnterpriseBreadcrumbs
            items={[
              { label: "Dashboard", href: "/" },
              { label: "Operation History" },
            ]}
          />
        }
        eyebrow="Operations / Telemetry"
        title="Operation History"
        description="Review governed service status checks, restart previews and restart executions."
        icon={<History aria-hidden="true" className="h-3.5 w-3.5" />}
        density="compact"
        secondaryActions={
          <EnterpriseButton
            onClick={loadData}
            disabled={refreshing}
            tone="secondary"
            size="xs"
            icon={<RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />}
          >
            Refresh
          </EnterpriseButton>
        }
      />

      <div className="space-y-3">
        {error && (
          <EnterpriseErrorState
            title="Unable to load operation history"
            message={error}
            onRetry={loadData}
          />
        )}

        {canView && (
          <>
            <EnterpriseMetricStrip>
              <EnterpriseMetricCard title="Operations" value={total} subtitle="Matching filters" />
              <EnterpriseMetricCard title="Restarts" value={restarts} subtitle="Visible on page" />
              <EnterpriseMetricCard
                title="Failed"
                value={failed}
                subtitle="Visible on page"
                tone={failed > 0 ? "danger" : "neutral"}
              />
              <EnterpriseMetricCard
                title="Denied"
                value={denied}
                subtitle="Visible on page"
                tone={denied > 0 ? "warning" : "neutral"}
              />
            </EnterpriseMetricStrip>

            <EnterprisePanel title="Filters">
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
                <EnterpriseSelect
                  label="Service"
                  value={serviceKey}
                  onChange={(value) => {
                    setPage(1);
                    setServiceKey(value);
                  }}
                  options={SERVICE_OPTIONS}
                />

                <EnterpriseSelect
                  label="Operation"
                  value={operationType}
                  onChange={(value) => {
                    setPage(1);
                    setOperationType(value);
                  }}
                  options={OPERATION_TYPE_OPTIONS}
                />

                <EnterpriseSelect
                  label="Status"
                  value={status}
                  onChange={(value) => {
                    setPage(1);
                    setStatus(value);
                  }}
                  options={STATUS_OPTIONS}
                />

                <EnterpriseSelect
                  label="Page size"
                  value={String(pageSize)}
                  onChange={(value) => {
                    setPage(1);
                    setPageSize(Number(value));
                  }}
                  options={PAGE_SIZE_OPTIONS}
                />

                <div className="flex items-end">
                  <EnterpriseButton
                    onClick={resetFilters}
                    tone="ghost"
                    size="xs"
                    icon={<XCircle className="h-3.5 w-3.5" />}
                    className="w-full"
                  >
                    Reset
                  </EnterpriseButton>
                </div>
              </div>

              <EnterpriseSearchInput
                label="Search operation history"
                value={searchInput}
                onChange={setSearchInput}
                onClear={() => setSearchInput("")}
                hideLabel
                placeholder="Search service, operation, user, config, message or reason..."
                containerClassName="mt-2"
              />
            </EnterprisePanel>

            <EnterprisePanel
              title="Operation History"
              actions={<EnterpriseBadge tone="muted">{total}</EnterpriseBadge>}
            >
              {loading ? (
                <EnterpriseSkeleton label="Loading operation history" rows={4} />
              ) : operations.length === 0 ? (
                <EnterpriseEmptyState
                  title="No matching service operations"
                  description="No service operations match the selected filters."
                  icon={<AlertTriangle className="h-5 w-5" />}
                  action={
                    <EnterpriseButton onClick={resetFilters} tone="ghost" size="xs">
                      Reset filters
                    </EnterpriseButton>
                  }
                />
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
                    <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-3 py-2">Operation</th>
                        <th className="px-3 py-2">Service</th>
                        <th className="px-3 py-2">Status</th>
                        <th className="px-3 py-2">Pre / Post</th>
                        <th className="px-3 py-2">Config</th>
                        <th className="px-3 py-2">User</th>
                        <th className="px-3 py-2">Created</th>
                        <th className="px-3 py-2">Message</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-900">
                      {operations.map((item) => (
                        <tr key={item.operation_id} className="align-top hover:bg-slate-800/40">
                          <td className="px-3 py-2 text-slate-300">
                            #{item.operation_id} / {item.operation_type}
                          </td>
                          <td className="px-3 py-2 text-slate-300">
                            {item.display_name || item.service_key}
                          </td>
                          <td className="px-3 py-2">
                            <EnterpriseStatusBadge value={item.status} size="compact" />
                          </td>
                          <td className="px-3 py-2 text-slate-500">
                            {item.pre_status || "-"} / {item.post_status || "-"}
                          </td>
                          <td className="px-3 py-2 text-slate-500">
                            {item.related_config_version_id
                              ? `#${item.related_config_version_id}`
                              : "-"}
                          </td>
                          <td className="px-3 py-2 text-slate-500">
                            {item.requested_by_username || "-"}
                          </td>
                          <td className="px-3 py-2 text-slate-500">
                            {formatDate(item.created_at)}
                          </td>
                          <td className="max-w-sm px-3 py-2 text-slate-500">
                            {item.safe_message || item.safe_error || "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="mt-3 flex flex-col gap-2 border-t border-slate-800 pt-3 text-xs text-slate-400 sm:flex-row sm:items-center sm:justify-between">
                <EnterpriseButton
                  disabled={effectivePage <= 1}
                  onClick={() => setPage((value) => Math.max(value - 1, 1))}
                  tone="secondary"
                  size="xs"
                  icon={<ChevronLeft className="h-3.5 w-3.5" />}
                >
                  Previous
                </EnterpriseButton>

                <span className="text-center">
                  Showing {firstVisible}-{lastVisible} of {total} - Page {effectivePage} of {totalPages}
                </span>

                <EnterpriseButton
                  disabled={effectivePage >= totalPages}
                  onClick={() => setPage((value) => value + 1)}
                  tone="secondary"
                  size="xs"
                  icon={<ChevronRight className="h-3.5 w-3.5" />}
                  iconPosition="end"
                >
                  Next
                </EnterpriseButton>
              </div>
            </EnterprisePanel>
          </>
        )}
      </div>
    </AppShell>
  );
}
