"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  FileDown,
  Brain,
  Database,
  FileText,
  ShieldAlert,
  Target,
} from "lucide-react";

type IncidentDetail = {
  id: number;
  status: string | null;
  wazuh_doc_id: string | null;
  timestamp: string | null;
  timestamp_local?: string | null;
  timezone?: string | null;
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
  attack_chain: string | null;
  correlation_type: string | null;
  escalation_reason: string | null;
  recommended_priority: string | null;
};

type AuditEvent = {
  id: number;
  incident_id: number;
  event_type: string;
  old_value: string | null;
  new_value: string | null;
  comment: string | null;
  created_by: string | null;
  created_at: string | null;
};

type IncidentNote = {
  id: number;
  incident_id: number;
  note: string;
  created_by: string | null;
  created_at: string | null;
};

type CorrelationSummary = {
  agent?: string | null;
  window_minutes?: number | null;
  related_events?: number | null;
  current_incident_id?: number | null;
  base_score?: number | null;
  pattern_score?: number | null;
  volume_score?: number | null;
  chain_bonus?: number | null;
  final_correlation_score?: number | null;
  recommended_priority?: string | null;
  matched_patterns?: Record<
    string,
    {
      keywords?: string[];
      weight?: number;
    }
  >;
  matched_attack_chains?: Array<{
    name?: string;
    correlation_type?: string;
    priority?: string;
    reason?: string;
    score_bonus?: number;
  }>;
  related_event_details?: Array<{
    id?: number;
    timestamp?: string | null;
    agent?: string | null;
    rule?: string | null;
    level?: number | null;
    risk_score?: number | null;
    status?: string | null;
    correlation_score?: number | null;
  }>;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

const INCIDENT_STATUSES = [
  "NEW",
  "TRIAGED",
  "ESCALATED",
  "CLOSED",
  "FALSE_POSITIVE",
];

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

function parseCorrelationSummary(
  value: string | null | undefined
): CorrelationSummary | null {
  if (!value) return null;

  try {
    const parsed = JSON.parse(value);

    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as CorrelationSummary;
    }

    return null;
  } catch {
    return null;
  }
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

async function fetchIncident(id: string): Promise<IncidentDetail> {
  const response = await fetch(`${API_BASE}/incidents/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchIncidentAudit(id: string): Promise<AuditEvent[]> {
  const response = await fetch(`${API_BASE}/incidents/${id}/audit`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

async function fetchIncidentNotes(id: string): Promise<IncidentNote[]> {
  const response = await fetch(`${API_BASE}/incidents/${id}/notes`, {
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
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [noteDraft, setNoteDraft] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadIncident() {
    try {
      setError(null);
      const [data, auditData, notesData] = await Promise.all([
        fetchIncident(incidentId),
        fetchIncidentAudit(incidentId),
        fetchIncidentNotes(incidentId),
      ]);

      setIncident(data);
      setAuditEvents(auditData);
      setNotes(notesData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function updateStatus(status: string) {
    try {
      setError(null);

      const response = await fetch(`${API_BASE}/incidents/${incidentId}/status`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ status }),
      });

      if (!response.ok) {
        throw new Error(`API error ${response.status}`);
      }

      await loadIncident();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }

  async function addNote() {
    const note = noteDraft.trim();

    if (!note) {
      return;
    }

    try {
      setSavingNote(true);
      setError(null);

      const response = await fetch(`${API_BASE}/incidents/${incidentId}/notes`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          note,
          created_by: "local_analyst",
        }),
      });

      if (!response.ok) {
        throw new Error(`API error ${response.status}`);
      }

      setNoteDraft("");
      await loadIncident();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setSavingNote(false);
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

  const parsedCorrelationSummary = useMemo(() => {
    return parseCorrelationSummary(incident?.correlation_summary);
  }, [incident]);

  const matchedPatterns = useMemo(() => {
    return Object.entries(parsedCorrelationSummary?.matched_patterns ?? {});
  }, [parsedCorrelationSummary]);

  const matchedAttackChains = parsedCorrelationSummary?.matched_attack_chains ?? [];
  const relatedCorrelationEvents =
    parsedCorrelationSummary?.related_event_details ?? [];

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
          <div className="mt-5 flex flex-wrap gap-3">
            <a
              href={`${API_BASE}/reports/incidents/${incidentId}?format=markdown`}
              download
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-700 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 shadow-sm hover:bg-cyan-400"
            >
              <FileDown className="h-4 w-4" />
              Download Markdown report
            </a>

            <a
              href={`${API_BASE}/reports/incidents/${incidentId}?format=json`}
              download
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 shadow-sm hover:bg-slate-800"
            >
              <FileDown className="h-4 w-4" />
              Download JSON
            </a>
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
              <div className="mb-4 flex items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-medium">Incident lifecycle</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Update the operational SOC status for this incident.
                  </p>
                </div>

                <span className="rounded-full border border-cyan-200 bg-cyan-100 px-4 py-2 text-sm text-cyan-800">
                  {incident.status ?? "NEW"}
                </span>
              </div>

              <div className="flex flex-wrap gap-2">
                {INCIDENT_STATUSES.map((status) => (
                  <button
                    key={status}
                    onClick={() => updateStatus(status)}
                    className={`rounded-xl border px-4 py-2 text-sm ${
                      incident.status === status
                        ? "border-cyan-400 bg-cyan-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    {status}
                  </button>
                ))}
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4">
                <h2 className="text-lg font-medium">Audit trail</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Operational history for this incident.
                </p>
              </div>

              {auditEvents.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No audit events available.
                </div>
              ) : (
                <div className="space-y-3">
                  {auditEvents.map((event) => (
                    <div
                      key={event.id}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-4"
                    >
                      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                        <div>
                          <div className="text-sm font-medium text-slate-200">
                            {event.event_type}
                          </div>

                          <div className="mt-1 text-sm text-slate-400">
                            {event.old_value ?? "-"} → {event.new_value ?? "-"}
                          </div>
                        </div>

                        <div className="text-xs text-slate-500">
                          {formatTimestamp(event.created_at)} · {event.created_by ?? "system"}
                        </div>
                      </div>

                      {event.comment && (
                        <div className="mt-3 rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm text-slate-300">
                          {event.comment}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4">
                <h2 className="text-lg font-medium">Analyst notes</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Add investigation notes, assumptions, validation steps or closure rationale.
                </p>
              </div>

              <div className="mb-5 space-y-3">
                <textarea
                  value={noteDraft}
                  onChange={(event) => setNoteDraft(event.target.value)}
                  placeholder="Write an analyst note for this incident..."
                  className="min-h-28 w-full rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500"
                />

                <div className="flex justify-end">
                  <button
                    onClick={addNote}
                    disabled={savingNote || !noteDraft.trim()}
                    className="rounded-xl border border-cyan-500 bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {savingNote ? "Saving..." : "Add note"}
                  </button>
                </div>
              </div>

              {notes.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No analyst notes available.
                </div>
              ) : (
                <div className="space-y-3">
                  {notes.map((note) => (
                    <div
                      key={note.id}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-4"
                    >
                      <div className="mb-2 text-xs text-slate-500">
                        {formatTimestamp(note.created_at)} · {note.created_by ?? "local_analyst"}
                      </div>

                      <div className="whitespace-pre-wrap text-sm leading-6 text-slate-200">
                        {note.note}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <Target className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Detection rule</h2>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <DetailRow label="Timestamp" value={incident.timestamp_local ?? formatTimestamp(incident.timestamp)} />
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

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <Brain className="h-5 w-5 text-cyan-300" />
                <div>
                  <h2 className="text-lg font-medium">Correlation explanation</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Explainable correlation details derived from recent events, matched patterns and score components.
                  </p>
                </div>
              </div>

              {!parsedCorrelationSummary ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No structured correlation explanation available yet. Recompute correlation summaries for this incident.
                </div>
              ) : (
                <div className="space-y-5">
                  <div className="grid gap-4 md:grid-cols-4">
                    <InfoCard
                      title="Base score"
                      value={parsedCorrelationSummary.base_score ?? 0}
                    />
                    <InfoCard
                      title="Pattern score"
                      value={parsedCorrelationSummary.pattern_score ?? 0}
                    />
                    <InfoCard
                      title="Volume score"
                      value={parsedCorrelationSummary.volume_score ?? 0}
                    />
                    <InfoCard
                      title="Chain bonus"
                      value={parsedCorrelationSummary.chain_bonus ?? 0}
                    />
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                    <div className="mb-3 text-sm font-medium text-slate-200">
                      Matched patterns
                    </div>

                    {matchedPatterns.length === 0 ? (
                      <div className="text-sm text-slate-400">
                        No security patterns matched in the correlation window.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {matchedPatterns.map(([name, pattern]) => (
                          <div
                            key={name}
                            className="rounded-lg border border-slate-800 bg-slate-900 p-3"
                          >
                            <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                              <div className="text-sm font-medium text-cyan-300">
                                {name}
                              </div>
                              <div className="text-xs text-slate-500">
                                weight {pattern.weight ?? 0}
                              </div>
                            </div>

                            <div className="mt-2 text-sm text-slate-300">
                              {(pattern.keywords ?? []).join(", ")}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                    <div className="mb-3 text-sm font-medium text-slate-200">
                      Matched attack chains
                    </div>

                    {matchedAttackChains.length === 0 ? (
                      <div className="text-sm text-slate-400">
                        No multi-step attack chain matched. The incident may still be correlated by single-host patterns and volume.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {matchedAttackChains.map((chain, index) => (
                          <div
                            key={`${chain.name ?? "chain"}-${index}`}
                            className="rounded-lg border border-slate-800 bg-slate-900 p-3"
                          >
                            <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                              <div className="text-sm font-medium text-cyan-300">
                                {chain.name ?? "Unnamed chain"}
                              </div>
                              <div className="text-xs text-slate-500">
                                {chain.priority ?? "UNKNOWN"} · bonus {chain.score_bonus ?? 0}
                              </div>
                            </div>

                            <div className="mt-2 text-sm text-slate-300">
                              {chain.reason ?? "No explanation available."}
                            </div>

                            <div className="mt-2 text-xs text-slate-500">
                              {chain.correlation_type ?? "-"}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                    <div className="mb-3 text-sm font-medium text-slate-200">
                      Related events in correlation window
                    </div>

                    {relatedCorrelationEvents.length === 0 ? (
                      <div className="text-sm text-slate-400">
                        No related events available in the summary.
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                          <thead className="text-xs uppercase text-slate-500">
                            <tr>
                              <th className="px-3 py-2">ID</th>
                              <th className="px-3 py-2">Time</th>
                              <th className="px-3 py-2">Rule</th>
                              <th className="px-3 py-2">Level</th>
                              <th className="px-3 py-2">Risk</th>
                              <th className="px-3 py-2">Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {relatedCorrelationEvents.map((event) => (
                              <tr
                                key={event.id}
                                className="border-t border-slate-800 text-slate-300"
                              >
                                <td className="px-3 py-2">
                                  {event.id ? (
                                    <Link
                                      href={`/incidents/${event.id}`}
                                      className="text-cyan-300 hover:text-cyan-200"
                                    >
                                      #{event.id}
                                    </Link>
                                  ) : (
                                    "-"
                                  )}
                                </td>
                                <td className="px-3 py-2">
                                  {formatTimestamp(event.timestamp)}
                                </td>
                                <td className="px-3 py-2">
                                  {event.rule ?? "-"}
                                </td>
                                <td className="px-3 py-2">
                                  {event.level ?? 0}
                                </td>
                                <td className="px-3 py-2">
                                  {event.risk_score ?? 0}
                                </td>
                                <td className="px-3 py-2">
                                  {event.status ?? "NEW"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-lg">
              <div className="mb-4 flex items-center gap-2">
                <Brain className="h-5 w-5 text-cyan-300" />
                <h2 className="text-lg font-medium">Structured correlation</h2>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <DetailRow
                  label="Correlation type"
                  value={incident.correlation_type ?? "-"}
                />
                <DetailRow
                  label="Recommended priority"
                  value={incident.recommended_priority ?? "-"}
                />
                <DetailRow
                  label="Attack chain"
                  value={incident.attack_chain ?? "-"}
                />
                <DetailRow
                  label="Escalation reason"
                  value={incident.escalation_reason ?? "-"}
                />
              </div>
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

