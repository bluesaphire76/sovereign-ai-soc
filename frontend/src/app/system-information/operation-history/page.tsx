"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  History,
  RefreshCw,
  Search,
  XCircle,
} from "lucide-react";
import AppNavigation from "../../../components/AppNavigation";
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

function statusTone(status: string) {
  const normalized = status.toLowerCase();

  if (normalized === "running" || normalized === "success") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if (normalized === "failed" || normalized === "unsupported") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  if (normalized === "denied") {
    return "border-amber-800 bg-amber-950/60 text-amber-200";
  }

  return "border-slate-700 bg-slate-900 text-slate-300";
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
    loadData();
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
              <History className="h-3.5 w-3.5" />
              System Information
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Operation History
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Review governed service status checks, restart previews and restart executions.
            </p>
          </div>

          <button
            onClick={loadData}
            disabled={refreshing}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            {error}
          </div>
        )}

        {canView && (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Operations" value={total} description="Matching filters" />
              <MetricCard label="Restarts" value={restarts} description="Visible on page" />
              <MetricCard label="Failed" value={failed} description="Visible on page" />
              <MetricCard label="Denied" value={denied} description="Visible on page" />
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
                <FilterSelect
                  label="Service"
                  value={serviceKey}
                  onChange={(value) => {
                    setPage(1);
                    setServiceKey(value);
                  }}
                  options={SERVICE_OPTIONS}
                />

                <FilterSelect
                  label="Operation"
                  value={operationType}
                  onChange={(value) => {
                    setPage(1);
                    setOperationType(value);
                  }}
                  options={OPERATION_TYPE_OPTIONS}
                />

                <FilterSelect
                  label="Status"
                  value={status}
                  onChange={(value) => {
                    setPage(1);
                    setStatus(value);
                  }}
                  options={STATUS_OPTIONS}
                />

                <FilterSelect
                  label="Page size"
                  value={String(pageSize)}
                  onChange={(value) => {
                    setPage(1);
                    setPageSize(Number(value));
                  }}
                  options={PAGE_SIZE_OPTIONS}
                />

                <div className="flex items-end">
                  <button
                    onClick={resetFilters}
                    className="flex h-8 w-full items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    <XCircle className="h-3.5 w-3.5" />
                    Reset
                  </button>
                </div>
              </div>

              <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-2">
                <Search className="h-3.5 w-3.5 text-slate-500" />
                <input
                  value={searchInput}
                  onChange={(event) => setSearchInput(event.target.value)}
                  placeholder="Search service, operation, user, config, message or reason..."
                  className="h-9 w-full bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600"
                />
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <History className="h-3.5 w-3.5 text-cyan-300" />
                  <h2 className="text-sm font-semibold">Operation History</h2>
                </div>

                <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                  {total}
                </span>
              </div>

              {loading ? (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">
                  Loading operation history...
                </div>
              ) : operations.length === 0 ? (
                <div className="rounded-md border border-slate-800 bg-slate-950 p-6 text-center text-xs text-slate-500">
                  <AlertTriangle className="mx-auto mb-2 h-5 w-5 text-slate-600" />
                  No service operations match the selected filters.
                </div>
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
                            <span className={`rounded-md border px-2 py-1 text-[11px] ${statusTone(item.status)}`}>
                              {item.status}
                            </span>
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
                <button
                  disabled={effectivePage <= 1}
                  onClick={() => setPage((value) => Math.max(value - 1, 1))}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  Previous
                </button>

                <span className="text-center">
                  Showing {firstVisible}-{lastVisible} of {total} - Page {effectivePage} of {totalPages}
                </span>

                <button
                  disabled={effectivePage >= totalPages}
                  onClick={() => setPage((value) => value + 1)}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Next
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function MetricCard({
  label,
  value,
  description,
}: {
  label: string;
  value: number;
  description: string;
}) {
  return (
    <div className="flex min-h-[58px] items-center justify-between gap-3 rounded-sm border border-slate-800 bg-slate-900 px-2.5 py-2 text-slate-100 shadow-sm">
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {label}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
          <span className="text-xl font-semibold leading-6">{value}</span>
          <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500">
            {description}
          </span>
        </div>
      </div>
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
  options: FilterOption[];
}) {
  return (
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
      >
        {options.map((item) => (
          <option key={item.value} value={item.value}>
            {item.label}
          </option>
        ))}
      </select>
    </label>
  );
}
