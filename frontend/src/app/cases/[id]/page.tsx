"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Briefcase, ShieldAlert } from "lucide-react";

type IncidentCase = {
  id: number;
  group_key: string;
  title: string;
  status: string | null;
  severity: string | null;
  agent: string | null;
  correlation_type: string | null;
  risk_score: number | null;
  summary: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  incident_count: number;
};

type CaseIncident = {
  id: number;
  status: string | null;
  timestamp: string | null;
  timestamp_local?: string | null;
  timezone?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  risk_score: number | null;
  correlation_score: number | null;
  correlated: boolean | null;
  correlation_type: string | null;
  recommended_priority: string | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

function severityClass(value: string | null | undefined) {
  const severity = value ?? "LOW";

  if (severity === "CRITICAL") return "bg-red-100 text-red-800 border-red-200";
  if (severity === "HIGH") return "bg-orange-100 text-orange-800 border-orange-200";
  if (severity === "MEDIUM") return "bg-yellow-100 text-yellow-800 border-yellow-200";

  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function statusClass(value: string | null | undefined) {
  const status = value ?? "OPEN";

  if (status === "ESCALATED") return "bg-red-100 text-red-800 border-red-200";
  if (status === "TRIAGED") return "bg-blue-100 text-blue-800 border-blue-200";
  if (status === "CLOSED") return "bg-slate-200 text-slate-800 border-slate-300";
  if (status === "FALSE_POSITIVE") return "bg-purple-100 text-purple-800 border-purple-200";

  return "bg-cyan-100 text-cyan-800 border-cyan-200";
}

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("it-CH", {
    timeZone: "Europe/Zurich",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}

function prettyJson(value: string | null) {
  if (!value) return "";

  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

async function fetchCase(id: string): Promise<IncidentCase> {
  const response = await fetch(`${API_BASE}/cases/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchCaseIncidents(id: string): Promise<CaseIncident[]> {
  const response = await fetch(`${API_BASE}/cases/${id}/incidents`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function CaseDetailPage() {
  const params = useParams();
  const caseId = String(params.id);

  const [caseData, setCaseData] = useState<IncidentCase | null>(null);
  const [incidents, setIncidents] = useState<CaseIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadCase() {
    try {
      setError(null);

      const [caseResponse, incidentsResponse] = await Promise.all([
        fetchCase(caseId),
        fetchCaseIncidents(caseId),
      ]);

      setCaseData(caseResponse);
      setIncidents(incidentsResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadCase();
  }, [caseId]);

  const summary = useMemo(() => {
    return prettyJson(caseData?.summary ?? null);
  }, [caseData]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8">
          <Link
            href="/cases"
            className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to cases
          </Link>

          <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
            <Briefcase className="h-4 w-4" />
            Investigation case
          </div>

          <h1 className="text-3xl font-semibold tracking-tight">
            Case #{caseId}
          </h1>

          {caseData && (
            <p className="mt-2 max-w-4xl text-sm text-slate-400">
              {caseData.title}
            </p>
          )}
        </header>

        {loading && (
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-300">
            Loading case...
          </div>
        )}

        {error && (
          <div className="rounded-2xl border border-red-800 bg-red-950/60 p-4 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {caseData && (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-4">
              <InfoCard title="Host" value={caseData.agent ?? "unknown"} />
              <InfoCard title="Incidents" value={caseData.incident_count} />
              <InfoCard title="Risk score" value={caseData.risk_score ?? 0} />
              <InfoCard title="Updated" value={formatTimestamp(caseData.updated_at)} />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-lg font-medium">Case status</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Current grouped investigation status and severity.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2">
                  <span
                    className={`rounded-full border px-4 py-2 text-sm ${statusClass(
                      caseData.status
                    )}`}
                  >
                    {caseData.status ?? "OPEN"}
                  </span>

                  <span
                    className={`rounded-full border px-4 py-2 text-sm ${severityClass(
                      caseData.severity
                    )}`}
                  >
                    {caseData.severity ?? "LOW"} · {caseData.risk_score ?? 0}
                  </span>
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <DetailRow
                  label="Correlation type"
                  value={caseData.correlation_type ?? "-"}
                />
                <DetailRow label="Group key" value={caseData.group_key} />
                <DetailRow
                  label="Created"
                  value={formatTimestamp(caseData.created_at)}
                />
                <DetailRow
                  label="Created by"
                  value={caseData.created_by ?? "system"}
                />
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <h2 className="mb-4 text-lg font-medium">Case summary</h2>

              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300">
                {summary || "No case summary available."}
              </pre>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Related incidents</h2>
              </div>

              {incidents.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No incidents linked to this case.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
                      <tr>
                        <th className="py-3 pr-4">ID</th>
                        <th className="py-3 pr-4">Status</th>
                        <th className="py-3 pr-4">Time</th>
                        <th className="py-3 pr-4">Rule</th>
                        <th className="py-3 pr-4">Level</th>
                        <th className="py-3 pr-4">Risk</th>
                        <th className="py-3 pr-4">Priority</th>
                      </tr>
                    </thead>

                    <tbody>
                      {incidents.map((incident) => (
                        <tr
                          key={incident.id}
                          className="border-b border-slate-800/70"
                        >
                          <td className="py-3 pr-4">
                            <Link
                              href={`/incidents/${incident.id}`}
                              className="text-cyan-300 hover:text-cyan-200"
                            >
                              #{incident.id}
                            </Link>
                          </td>

                          <td className="py-3 pr-4">
                            <span
                              className={`rounded-full border px-3 py-1 text-xs ${statusClass(
                                incident.status
                              )}`}
                            >
                              {incident.status ?? "NEW"}
                            </span>
                          </td>

                          <td className="py-3 pr-4 text-slate-400">
                            {incident.timestamp_local ??
                              formatTimestamp(incident.timestamp)}
                          </td>

                          <td className="max-w-xl py-3 pr-4 text-slate-300">
                            {incident.rule ?? "-"}
                          </td>

                          <td className="py-3 pr-4">{incident.level ?? 0}</td>

                          <td className="py-3 pr-4">
                            {incident.risk_score ?? 0}
                          </td>

                          <td className="py-3 pr-4 text-slate-400">
                            {incident.recommended_priority ?? "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function InfoCard({
  title,
  value,
}: {
  title: string;
  value: string | number;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
      <div className="mb-3 text-sm text-slate-400">{title}</div>
      <div className="break-words text-xl font-semibold">{value}</div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
      <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="break-words text-sm text-slate-200">{value}</div>
    </div>
  );
}
