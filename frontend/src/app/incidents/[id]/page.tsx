"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  Brain,
  Database,
  FileText,
  ShieldAlert,
  Target,
} from "lucide-react";

type IncidentDetail = {
  id: number;
  wazuh_doc_id: string | null;
  timestamp: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  mitre: string | null;
  risk_score: number | null;
  ai_analysis: string | null;
  correlated: boolean | null;
  correlation_score: number | null;
  correlation_summary: string | null;
  raw_alert: string | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

function riskLabel(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "Critical";
  if (value >= 61) return "High";
  if (value >= 31) return "Medium";
  return "Low";
}

function riskClass(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 81) return "bg-red-100 text-red-800 border-red-200";
  if (value >= 61) return "bg-orange-100 text-orange-800 border-orange-200";
  if (value >= 31) return "bg-yellow-100 text-yellow-800 border-yellow-200";
  return "bg-emerald-100 text-emerald-800 border-emerald-200";
}

function prettyJson(value: string | null) {
  if (!value) return "";

  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

async function fetchIncident(id: string): Promise<IncidentDetail> {
  const response = await fetch(`${API_BASE}/incidents/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function IncidentDetailPage() {
  const params = useParams();
  const incidentId = String(params.id);

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadIncident() {
    try {
      setError(null);
      const data = await fetchIncident(incidentId);
      setIncident(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncident();
  }, [incidentId]);

  const rawAlert = useMemo(() => {
    return prettyJson(incident?.raw_alert ?? null);
  }, [incident]);

  const correlationSummary = useMemo(() => {
    return prettyJson(incident?.correlation_summary ?? null);
  }, [incident]);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8">
          <Link
            href="/"
            className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to dashboard
          </Link>

          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div>
              <div className="mb-2 flex items-center gap-2 text-sm text-cyan-300">
                <ShieldAlert className="h-4 w-4" />
                Incident detail
              </div>

              <h1 className="text-3xl font-semibold tracking-tight">
                Incident #{incidentId}
              </h1>

              <p className="mt-2 max-w-3xl text-sm text-slate-400">
                Complete AI triage, correlation data and raw Wazuh alert.
              </p>
            </div>

            {incident && (
              <span
                className={`rounded-full border px-4 py-2 text-sm ${riskClass(
                  incident.risk_score
                )}`}
              >
                {riskLabel(incident.risk_score)} risk {incident.risk_score ?? 0}
              </span>
            )}
          </div>
        </header>

        {loading && (
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-300">
            Loading incident...
          </div>
        )}

        {error && (
          <div className="rounded-2xl border border-red-800 bg-red-950/60 p-4 text-sm text-red-200">
            API error: {error}
          </div>
        )}

        {incident && (
          <div className="space-y-6">
            <section className="grid gap-4 md:grid-cols-4">
              <InfoCard title="Host" value={incident.agent ?? "unknown"} />
              <InfoCard title="Wazuh level" value={incident.level ?? 0} />
              <InfoCard
                title="Correlation"
                value={incident.correlation_score ?? 0}
              />
              <InfoCard
                title="Status"
                value={incident.correlated ? "Correlated" : "Not correlated"}
              />
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <Target className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Detection rule</h2>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <DetailRow label="Timestamp" value={incident.timestamp ?? "-"} />
                <DetailRow label="Agent" value={incident.agent ?? "-"} />
                <DetailRow label="Rule" value={incident.rule ?? "-"} />
                <DetailRow
                  label="Wazuh doc ID"
                  value={incident.wazuh_doc_id ?? "-"}
                />
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <Brain className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">AI analysis</h2>
              </div>

              <pre className="whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm leading-6 text-slate-200">
                {incident.ai_analysis ?? "No AI analysis available."}
              </pre>
            </section>

            <section className="grid gap-6 lg:grid-cols-2">
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <div className="mb-4 flex items-center gap-2">
                  <Database className="h-5 w-5 text-cyan-300" />
                  <h2 className="text-lg font-medium">MITRE / Metadata</h2>
                </div>

                <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300">
                  {incident.mitre ?? "No MITRE data available."}
                </pre>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
                <div className="mb-4 flex items-center gap-2">
                  <FileText className="h-5 w-5 text-cyan-300" />
                  <h2 className="text-lg font-medium">Correlation summary</h2>
                </div>

                <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300">
                  {correlationSummary || "No correlation summary available."}
                </pre>
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <FileText className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Raw Wazuh alert</h2>
              </div>

              <pre className="max-h-[600px] overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs leading-5 text-slate-300">
                {rawAlert || "No raw alert available."}
              </pre>
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

