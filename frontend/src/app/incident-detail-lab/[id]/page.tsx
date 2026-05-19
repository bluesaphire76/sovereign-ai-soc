"use client";

import { authFetch } from "@/lib/auth";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import AppNavigation from "../../../components/AppNavigation";
import {
  AlertTriangle,
  Brain,
  Database,
  FileText,
  RefreshCw,
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

type Tone = "neutral" | "success" | "warning" | "danger" | "cyan" | "violet";

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

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

function riskBand(score: number | null | undefined) {
  const value = score ?? 0;

  if (value >= 80) return "CRITICAL";
  if (value >= 60) return "HIGH";
  if (value >= 40) return "MEDIUM";
  return "LOW";
}

function riskTone(score: number | null | undefined): Tone {
  const band = riskBand(score);

  if (band === "CRITICAL") return "danger";
  if (band === "HIGH") return "warning";
  if (band === "MEDIUM") return "cyan";
  return "success";
}

function statusTone(status: string | null | undefined): Tone {
  const value = (status ?? "NEW").toUpperCase();

  if (value === "ESCALATED") return "danger";
  if (value === "TRIAGED" || value === "INVESTIGATING") return "cyan";
  if (value === "CONTAINED") return "warning";
  if (value === "RESOLVED" || value === "CLOSED") return "success";
  if (value === "FALSE_POSITIVE") return "violet";
  return "neutral";
}

function toneClass(tone: Tone) {
  const classes: Record<Tone, string> = {
    neutral: "border-slate-700 bg-slate-950 text-slate-300",
    success: "border-emerald-800 bg-emerald-950/50 text-emerald-300",
    warning: "border-orange-800 bg-orange-950/50 text-orange-300",
    danger: "border-red-800 bg-red-950/50 text-red-300",
    cyan: "border-cyan-800 bg-cyan-950/50 text-cyan-300",
    violet: "border-violet-800 bg-violet-950/50 text-violet-300",
  };

  return classes[tone];
}

function railClass(score: number | null | undefined) {
  const band = riskBand(score);

  if (band === "CRITICAL") return "border-l-red-500";
  if (band === "HIGH") return "border-l-orange-500";
  if (band === "MEDIUM") return "border-l-cyan-500";
  return "border-l-emerald-500";
}

function prettyJson(value: string | null | undefined) {
  if (!value) return "-";

  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function aiBullets(value: string | null | undefined) {
  if (!value) return [];

  return value
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) =>
      line
        .replace(/^[-*•]\s+/, "")
        .replace(/^\d+[.)]\s+/, "")
        .replace(/^#{1,4}\s*/, "")
        .trim()
    )
    .filter(Boolean)
    .slice(0, 8);
}

function decisionLabel(incident: IncidentDetail) {
  const risk = incident.risk_score ?? 0;
  const priority = (incident.recommended_priority ?? "").toUpperCase();

  if (risk >= 80 || priority === "CRITICAL") return "Immediate escalation review";
  if (risk >= 60 || priority === "HIGH") return "Priority analyst investigation";
  if (incident.correlated) return "Correlation review required";
  if (risk >= 40 || priority === "MEDIUM") return "Standard triage review";
  return "Monitor and classify";
}

function riskRationale(incident: IncidentDetail) {
  const risk = incident.risk_score ?? 0;
  const level = incident.level ?? 0;

  if (risk >= 80) {
    return "Risk is in the critical band. Validate evidence immediately and decide whether containment or case escalation is required.";
  }

  if (risk >= 60 && incident.correlated) {
    return "Risk is high and correlation is present. Treat this as a priority investigation candidate.";
  }

  if (risk >= 60) {
    return "Risk is high even without explicit correlation. Validate raw evidence, affected host and rule context before escalation.";
  }

  if (incident.correlated) {
    return "Correlation is present even though the score is not high. Review the pattern before classifying this as noise.";
  }

  if (level >= 8) {
    return "Wazuh level is elevated. The signal may still be benign, but it should be manually triaged before closure.";
  }

  return "Current indicators suggest a lower-priority signal. Validate context and classify as observed, benign or false positive if appropriate.";
}

async function fetchIncident(id: string): Promise<IncidentDetail> {
  const response = await authFetch(`/incidents/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: Tone;
}) {
  return (
    <span
      className={`inline-flex h-[18px] min-w-[72px] items-center justify-center whitespace-nowrap border px-1.5 text-center text-[10px] font-semibold uppercase leading-none tracking-wide ${toneClass(tone)}`}
    >
      {children}
    </span>
  );
}

function Section({
  title,
  description,
  icon,
  children,
}: {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="border border-slate-800 bg-slate-950">
      <div className="border-b border-slate-800 px-3 py-2">
        <div className="flex items-center gap-2">
          {icon && <div className="text-cyan-300">{icon}</div>}
          <h2 className="text-[12px] font-semibold uppercase tracking-[0.18em] text-slate-300">
            {title}
          </h2>
        </div>
        {description && (
          <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
            {description}
          </p>
        )}
      </div>
      <div>{children}</div>
    </section>
  );
}

function Field({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[120px_minmax(0,1fr)] gap-3 border-b border-slate-900 px-3 py-2 last:border-b-0">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
        {label}
      </dt>
      <dd className="min-w-0 break-words text-xs leading-5 text-slate-300">
        {value || "-"}
      </dd>
    </div>
  );
}

export default function IncidentDetailLabPage() {
  const params = useParams();
  const incidentId = String(params.id);

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadIncident() {
    try {
      setRefreshing(true);
      setError(null);

      const data = await fetchIncident(incidentId);
      setIncident(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void loadIncident();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId]);

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-slate-100">
        <div className="mx-auto max-w-[1800px] px-4 py-4">
          <AppNavigation />
          <div className="border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
            Loading incident detail lab...
          </div>
        </div>
      </main>
    );
  }

  if (!incident) {
    return (
      <main className="min-h-screen bg-slate-950 text-slate-100">
        <div className="mx-auto max-w-[1800px] px-4 py-4">
          <AppNavigation />
          <div className="border border-red-800 bg-red-950/40 p-4 text-xs text-red-200">
            Incident not found.
          </div>
        </div>
      </main>
    );
  }

  const aiItems = aiBullets(incident.ai_analysis);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1900px] px-4 py-4">
        <AppNavigation />

        <div className="border border-slate-800 bg-slate-950">
          <header className="border-b border-slate-800 px-4 py-3">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
              <div className="min-w-0">
                <Link
                  href="/incidents"
                  className="mb-1 inline-flex text-[11px] font-medium uppercase tracking-wide text-slate-500 hover:text-cyan-300"
                >
                  ← Back to incidents
                </Link>

                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-cyan-300" strokeWidth={1.75} />
                  <h1 className="text-xl font-semibold tracking-tight text-slate-100">
                    Incident #{incident.id} lab
                  </h1>
                  <Badge tone={riskTone(incident.risk_score)}>
                    {riskBand(incident.risk_score)} {incident.risk_score ?? 0}
                  </Badge>
                  <Badge tone={statusTone(incident.status)}>
                    {incident.status ?? "NEW"}
                  </Badge>
                </div>

                <p className="mt-2 max-w-5xl text-sm leading-6 text-slate-300">
                  {incident.rule ?? "No rule description available."}
                </p>
              </div>

              <button
                onClick={loadIncident}
                className="inline-flex h-8 items-center gap-1.5 border border-slate-700 bg-slate-950 px-3 text-xs font-medium text-slate-300 hover:bg-slate-900"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} strokeWidth={1.75} />
                Refresh
              </button>
            </div>
          </header>

          {error && (
            <div className="m-3 flex items-center gap-2 border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-200">
              <AlertTriangle className="h-3.5 w-3.5" strokeWidth={1.75} />
              {error}
            </div>
          )}

          <section className={`border-b border-slate-800 border-l-2 px-4 py-4 ${railClass(incident.risk_score)}`}>
            <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">
              Analyst decision brief
            </div>
            <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
              {decisionLabel(incident)}
            </div>
            <p className="mt-2 max-w-5xl text-sm leading-6 text-slate-300">
              {riskRationale(incident)}
            </p>
          </section>

          <section className="grid min-h-[680px] xl:grid-cols-[340px_minmax(0,1fr)_420px]">
            <aside className="border-r border-slate-800">
              <Section
                title="Evidence snapshot"
                description="Stable facts used for triage."
                icon={<Database className="h-3.5 w-3.5" strokeWidth={1.75} />}
              >
                <dl>
                  <Field label="Host" value={<span className="font-mono">{incident.agent ?? "unknown"}</span>} />
                  <Field label="Level" value={<span className="font-mono">{incident.level ?? 0}</span>} />
                  <Field label="Priority" value={incident.recommended_priority ?? "-"} />
                  <Field label="Created" value={<span className="font-mono">{incident.timestamp_local ?? formatTimestamp(incident.timestamp)}</span>} />
                  <Field label="Timezone" value={incident.timezone ?? "Europe/Zurich"} />
                  <Field label="Wazuh doc" value={<span className="font-mono">{incident.wazuh_doc_id ?? "-"}</span>} />
                </dl>
              </Section>

              <div className="mt-3">
                <Section
                  title="Correlation"
                  description="Pattern and chain context."
                  icon={<Target className="h-3.5 w-3.5" strokeWidth={1.75} />}
                >
                  <dl>
                    <Field label="Correlated" value={incident.correlated ? "Yes" : "No"} />
                    <Field label="Score" value={<span className="font-mono">{incident.correlation_score ?? 0}</span>} />
                    <Field label="Type" value={incident.correlation_type ?? "-"} />
                    <Field label="Attack chain" value={incident.attack_chain ?? "-"} />
                    <Field label="Reason" value={incident.escalation_reason ?? "-"} />
                  </dl>
                </Section>
              </div>
            </aside>

            <div className="min-w-0 border-r border-slate-800">
              <Section
                title="AI analysis"
                description="Simplified decision-oriented interpretation."
                icon={<Brain className="h-3.5 w-3.5" strokeWidth={1.75} />}
              >
                {aiItems.length === 0 ? (
                  <div className="p-3 text-xs text-slate-500">
                    No AI analysis available.
                  </div>
                ) : (
                  <div className="space-y-2 p-3">
                    {aiItems.map((item, index) => (
                      <div key={`${item}-${index}`} className="border border-slate-800 bg-slate-950 p-3">
                        <div className="flex gap-3">
                          <div className="flex h-6 w-6 shrink-0 items-center justify-center border border-cyan-800 bg-cyan-950 font-mono text-[11px] font-semibold text-cyan-200">
                            {index + 1}
                          </div>
                          <p className="text-sm leading-6 text-slate-300">{item}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              <div className="mt-3">
                <Section
                  title="Recommended analyst actions"
                  description="Minimal v0 placeholder before adding workflow."
                  icon={<Target className="h-3.5 w-3.5" strokeWidth={1.75} />}
                >
                  <ul className="list-disc space-y-2 p-3 pl-7 text-sm leading-6 text-slate-300 marker:text-slate-500">
                    <li>Validate affected host and Wazuh rule context.</li>
                    <li>Review whether the signal is correlated or isolated.</li>
                    <li>Decide whether this should become or join a case.</li>
                    <li>Document analyst rationale in the production detail page.</li>
                  </ul>
                </Section>
              </div>
            </div>

            <aside className="min-w-0">
              <Section
                title="Raw evidence"
                description="Available but not dominant."
                icon={<FileText className="h-3.5 w-3.5" strokeWidth={1.75} />}
              >
                <details>
                  <summary className="cursor-pointer border-b border-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:text-cyan-200">
                    Show raw Wazuh alert
                  </summary>
                  <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap p-3 text-xs leading-5 text-slate-300">
                    {prettyJson(incident.raw_alert)}
                  </pre>
                </details>
              </Section>

              <div className="mt-3">
                <Section
                  title="MITRE / metadata"
                  description="Parsed metadata payload."
                  icon={<Database className="h-3.5 w-3.5" strokeWidth={1.75} />}
                >
                  <details>
                    <summary className="cursor-pointer border-b border-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:text-cyan-200">
                      Show metadata
                    </summary>
                    <pre className="max-h-80 overflow-auto whitespace-pre-wrap p-3 text-xs leading-5 text-slate-300">
                      {prettyJson(incident.mitre)}
                    </pre>
                  </details>
                </Section>
              </div>
            </aside>
          </section>
        </div>
      </div>
    </main>
  );
}
