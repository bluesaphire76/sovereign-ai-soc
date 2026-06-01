"use client";

import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import AppNavigation from "../../components/AppNavigation";
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  RefreshCw,
  ShieldCheck,
  Target,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Incident = {
  id: number;
  status: string | null;
  timestamp: string | null;
  timestamp_local?: string | null;
  timezone?: string | null;
  agent: string | null;
  rule: string | null;
  level: number | null;
  mitre?: string[] | string | Record<string, unknown> | null;
  risk_score: number | null;
  correlation_score: number | null;
  correlated: boolean | null;
  correlation_type: string | null;
  recommended_priority: string | null;
  mitre_ids?: string[] | string | null;
  mitre_techniques?: string[] | string | null;
  raw_alert?: Record<string, unknown> | string | null;
};

type IncidentsResponse = {
  items: Incident[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
};

type ScenarioSummary = {
  scenario: string;
  incidents: number;
  correlated: number;
  priority_validated: number;
  mitre_tagged: number;
  max_risk: number;
  avg_risk: number;
};

type Tone = "success" | "warning" | "danger" | "primary" | "neutral";

type BriefItem = {
  label: string;
  value: string;
  tone: Tone;
};

type SyntheticScenario = {
  id: string;
  title: string;
  rule: string;
  recommended_priority: string;
  risk_score: number;
  correlation_type: string;
  mitre: string[];
};

type SyntheticScenariosResponse = {
  items: SyntheticScenario[];
};

type SyntheticRunResponse = {
  status: string;
  scenario: string;
  host: string;
  count_per_scenario: number;
  created: number;
  incidents: Array<{
    id: number;
    scenario: string | null;
    rule: string | null;
    risk_score: number | null;
    recommended_priority: string | null;
    correlation_score: number | null;
  }>;
};

type DetectionQualityActionGuidance = {
  source: string;
  model: string | null;
  llm_profile?: string | null;
  llm_fallback_used?: boolean;
  llm_latency_ms?: number | null;
  generated_at: string | null;
  error_type: string | null;
  cache_hit?: boolean;
  cached_at?: string | null;
  how_to_execute: string[];
  validation_notes: string;
  recommended_action?: string | null;
};

const KNOWN_SCENARIOS = [
  "ssh_bruteforce",
  "privilege_escalation",
  "malware_indicator",
  "suspicious_package_activity",
  "noisy_operational_baseline",
  "false_positive",
  "real_incident",
  "case_ready",
];

const CHART_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  primary: "#22d3ee",
  secondary: "#60a5fa",
  ai: "#a78bfa",
  success: "#10b981",
  warning: "#f59e0b",
  failed: "#ef4444",
  partial: "#f97316",
  muted: "#64748b",
  grid: "rgba(148, 163, 184, 0.14)",
  axis: "#94a3b8",
  panel: "#020617",
  tooltip: "#0f172a",
  border: "#334155",
  text: "#e2e8f0",
  cursor: "rgba(15, 23, 42, 0.42)",
};

const TABLE_BADGE_BASE =
  "inline-flex h-5 w-fit items-center justify-center whitespace-nowrap rounded-sm border px-1.5 text-[10px] font-medium leading-none";
const ACTION_GUIDANCE_STORAGE_KEY =
  "ai-soc:detection-quality-action-guidance:v1";

function isActionGuidance(
  value: unknown
): value is DetectionQualityActionGuidance {
  if (!value || typeof value !== "object") return false;

  const candidate = value as Partial<DetectionQualityActionGuidance>;

  return (
    Array.isArray(candidate.how_to_execute) &&
    candidate.how_to_execute.every((step) => typeof step === "string") &&
    typeof candidate.validation_notes === "string"
  );
}

function formatLlmProfile(profile?: string | null) {
  const normalized = String(profile ?? "").toLowerCase();

  if (normalized === "fast") return "Fast";
  if (normalized === "standard") return "Standard";
  if (normalized === "quality") return "High quality";

  return "Unknown";
}

function formatGuidanceModelLabel(guidance: DetectionQualityActionGuidance) {
  const profileLabel = formatLlmProfile(guidance.llm_profile);
  const fallbackSuffix = guidance.llm_fallback_used ? " fallback" : "";

  if (guidance.llm_profile) {
    return `${profileLabel}${fallbackSuffix}`;
  }

  return guidance.source === "local_ai" ? "LLM" : "Fallback";
}

function loadStoredActionGuidance(): Record<
  string,
  DetectionQualityActionGuidance
> {
  if (typeof window === "undefined") return {};

  try {
    const rawValue = window.localStorage.getItem(ACTION_GUIDANCE_STORAGE_KEY);
    if (!rawValue) return {};

    const parsed = JSON.parse(rawValue);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }

    return Object.fromEntries(
      Object.entries(parsed).filter((entry): entry is [
        string,
        DetectionQualityActionGuidance,
      ] => typeof entry[0] === "string" && isActionGuidance(entry[1]))
    );
  } catch {
    return {};
  }
}

function storeActionGuidance(
  guidanceByKey: Record<string, DetectionQualityActionGuidance>
) {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.setItem(
      ACTION_GUIDANCE_STORAGE_KEY,
      JSON.stringify(guidanceByKey)
    );
  } catch {
    // localStorage persistence is a convenience; generation state still works in memory.
  }
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await authFetch(path, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}


async function fetchSyntheticScenarios(): Promise<SyntheticScenariosResponse> {
  const currentUser = getStoredUser();

  if (currentUser?.role === "VIEWER") {
    return Promise.resolve({ items: [] });
  }

  return fetchJson<SyntheticScenariosResponse>("/synthetic-tests/scenarios");
}

async function runSyntheticTest(payload: {
  scenario: string;
  count: number;
  host: string;
  created_by: string;
}): Promise<SyntheticRunResponse> {
  const response = await authFetch(`/synthetic-tests/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let detail = `API error ${response.status}`;

    try {
      const body = await response.json();
      detail = body?.detail?.message ?? body?.detail ?? detail;
    } catch {
      // keep default error
    }

    throw new Error(String(detail));
  }

  return response.json();
}

async function fetchDetectionQualityActionGuidance(payload: {
  summary: string;
  recommended_action: string;
  quality_score: number;
  total_synthetic: number;
  scenario_name?: string | null;
  force_refresh?: boolean;
  weakest_scenario: Record<string, unknown> | null;
  signals: Array<Record<string, unknown>>;
  gaps: Record<string, unknown>;
}): Promise<DetectionQualityActionGuidance> {
  const response = await authFetch(`/detection-quality/action-guidance`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let detail = `API error ${response.status}`;

    try {
      const body = await response.json();
      detail = body?.detail?.message ?? body?.detail ?? detail;
    } catch {
      // keep default error
    }

    throw new Error(String(detail));
  }

  return response.json();
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

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value ?? {});
  } catch {
    return "";
  }
}

function incidentText(incident: Incident): string {
  return [
    incident.rule,
    incident.agent,
    incident.status,
    incident.correlation_type,
    incident.recommended_priority,
    safeStringify(incident.raw_alert),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function isSyntheticIncident(incident: Incident): boolean {
  const text = incidentText(incident);

  return (
    text.includes("synthetic") ||
    text.includes("sovereign-ai-soc-synthetic") ||
    KNOWN_SCENARIOS.some((scenario) => text.includes(scenario))
  );
}

function extractScenario(incident: Incident): string {
  const text = incidentText(incident);

  for (const scenario of KNOWN_SCENARIOS) {
    if (text.includes(scenario)) {
      return scenario;
    }
  }

  const rawText = safeStringify(incident.raw_alert);
  const match = rawText.match(/"scenario"\s*:\s*"([^"]+)"/i);

  if (match?.[1]) {
    return match[1];
  }

  return "unknown_synthetic";
}

function extractMitreIds(incident: Incident): string[] {
  const values: string[] = [];
  const addMitreValue = (value: unknown) => {
    if (!value) return;

    if (Array.isArray(value)) {
      for (const item of value) {
        addMitreValue(item);
      }
      return;
    }

    if (typeof value === "object") {
      for (const item of Object.values(value as Record<string, unknown>)) {
        addMitreValue(item);
      }
      return;
    }

    const text = String(value).trim();
    if (!text || text === "[]" || text === "{}") return;

    try {
      addMitreValue(JSON.parse(text));
      return;
    } catch {
      // Keep parsing as plain text below.
    }

    const matches = text.toUpperCase().match(/T\d{4}(?:\.\d{3})?/g);
    if (matches?.length) {
      values.push(...matches);
      return;
    }

    values.push(text);
  };

  addMitreValue(incident.mitre);

  addMitreValue(incident.mitre_ids);
  addMitreValue(incident.mitre_techniques);

  const text = incidentText(incident).toUpperCase();
  const matches = text.match(/T\d{4}(?:\.\d{3})?/g) ?? [];
  values.push(...matches);

  return Array.from(new Set(values.filter(Boolean)));
}

function extractExpectedPriority(incident: Incident): string | null {
  const rawAlert = incident.raw_alert;

  if (rawAlert && typeof rawAlert === "object" && !Array.isArray(rawAlert)) {
    const data = rawAlert.data;

    if (data && typeof data === "object" && !Array.isArray(data)) {
      const value = (data as Record<string, unknown>).expected_priority;

      if (typeof value === "string" && value.trim()) {
        return value.trim().toUpperCase();
      }
    }
  }

  if (typeof rawAlert === "string") {
    try {
      const parsed = JSON.parse(rawAlert);

      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const data = (parsed as Record<string, unknown>).data;

        if (data && typeof data === "object" && !Array.isArray(data)) {
          const value = (data as Record<string, unknown>).expected_priority;

          if (typeof value === "string" && value.trim()) {
            return value.trim().toUpperCase();
          }
        }
      }
    } catch {
      // fall back to regex extraction below
    }
  }

  const match = safeStringify(rawAlert).match(
    /"expected_priority"\s*:\s*"([^"]+)"/i
  );

  return match?.[1]?.trim().toUpperCase() ?? null;
}

function priorityIsHighOrCritical(priority: string | null | undefined): boolean {
  const value = (priority ?? "").toUpperCase();
  return value === "HIGH" || value === "CRITICAL";
}

function priorityMatchesSyntheticExpectation(incident: Incident): boolean {
  const expectedPriority = extractExpectedPriority(incident);
  const actualPriority = (incident.recommended_priority ?? "").toUpperCase();

  if (expectedPriority) {
    return actualPriority === expectedPriority;
  }

  return priorityIsHighOrCritical(actualPriority);
}

function toneForPriority(priority: string | null | undefined): Tone {
  const value = (priority ?? "").toUpperCase();

  if (value === "CRITICAL") return "danger";
  if (value === "HIGH") return "warning";
  if (value === "MEDIUM") return "primary";
  if (value === "LOW") return "success";
  return "neutral";
}

function pct(value: number, total: number): number {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}

function toneForScore(score: number): Tone {
  if (score >= 81) return "danger";
  if (score >= 61) return "warning";
  if (score >= 31) return "primary";
  return "success";
}

function toneForCoverage(percent: number, hasData: boolean): Tone {
  if (!hasData) return "neutral";
  if (percent >= 90) return "success";
  if (percent >= 70) return "primary";
  if (percent >= 40) return "warning";
  return "danger";
}

function scenarioQualityScore(row: ScenarioSummary) {
  if (!row.incidents) return 0;

  return Math.round(
    (pct(row.correlated, row.incidents) +
      pct(row.priority_validated, row.incidents) +
      pct(row.mitre_tagged, row.incidents)) /
      3
  );
}

function scenarioGapCount(row: ScenarioSummary) {
  return (
    Math.max(row.incidents - row.correlated, 0) +
    Math.max(row.incidents - row.priority_validated, 0) +
    Math.max(row.incidents - row.mitre_tagged, 0)
  );
}

function toneClasses(tone: Tone) {
  const classes: Record<Tone, { card: string; badge: string; text: string }> = {
    success: {
      card: "border-emerald-900/70 bg-emerald-950/20",
      badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
      text: "text-emerald-300",
    },
    warning: {
      card: "border-orange-900/70 bg-orange-950/20",
      badge: "border-orange-700 bg-orange-950 text-orange-200",
      text: "text-orange-300",
    },
    danger: {
      card: "border-red-900/70 bg-red-950/25",
      badge: "border-red-800 bg-red-950 text-red-200",
      text: "text-red-300",
    },
    primary: {
      card: "border-cyan-900/70 bg-cyan-950/20",
      badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
      text: "text-cyan-300",
    },
    neutral: {
      card: "border-slate-800 bg-slate-900",
      badge: "border-slate-700 bg-slate-950 text-slate-300",
      text: "text-slate-300",
    },
  };

  return classes[tone];
}

function toneDotClass(tone: Tone) {
  const classes: Record<Tone, string> = {
    success: "bg-emerald-400",
    warning: "bg-orange-400",
    danger: "bg-red-400",
    primary: "bg-cyan-400",
    neutral: "bg-slate-500",
  };

  return classes[tone];
}

function shortText(value: string | null | undefined, max = 96) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

function scenarioLabel(value: string) {
  return value.replaceAll("_", " ");
}

function topGapLabel({
  correlationGap,
  priorityGap,
  mitreGap,
}: {
  correlationGap: number;
  priorityGap: number;
  mitreGap: number;
}) {
  const gaps = [
    ["correlation", correlationGap],
    ["priority assignment", priorityGap],
    ["MITRE mapping", mitreGap],
  ] as const;

  return [...gaps].sort((a, b) => b[1] - a[1])[0];
}

export default function DetectionQualityPage() {
  const [incidentsData, setIncidentsData] = useState<IncidentsResponse | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [syntheticScenarios, setSyntheticScenarios] = useState<SyntheticScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("all");
  const [syntheticCount, setSyntheticCount] = useState(1);
  const [syntheticHost, setSyntheticHost] = useState("synthetic-sensor-01");
  const [syntheticCreatedBy, setSyntheticCreatedBy] = useState("local_analyst");
  const [runningSynthetic, setRunningSynthetic] = useState(false);
  const [syntheticResult, setSyntheticResult] = useState<SyntheticRunResponse | null>(null);
  const [syntheticError, setSyntheticError] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [actionGuidanceByKey, setActionGuidanceByKey] =
    useState<Record<string, DetectionQualityActionGuidance>>({});
  const [guidanceLoadingByKey, setGuidanceLoadingByKey] =
    useState<Record<string, boolean>>({});
  const [guidanceErrorByKey, setGuidanceErrorByKey] =
    useState<Record<string, string>>({});
  const guidanceInFlightRef = useRef<Record<string, boolean>>({});

  const canOperate =
    currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";
  const isViewer = currentUser?.role === "VIEWER";

  useEffect(() => {
    setActionGuidanceByKey(loadStoredActionGuidance());
  }, []);

  useEffect(() => {
    setCurrentUser(getStoredUser());

    fetchCurrentUser()
      .then((current) => setCurrentUser(current))
      .catch(() => {
        // authFetch handles expired/invalid sessions globally
      });
  }, []);

  const loadDetectionQuality = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const params = new URLSearchParams({
        page: "1",
        limit: "20",
        search: "SYNTHETIC",
      });

      const response = await fetchJson<IncidentsResponse>(
        `/incidents?${params.toString()}`
      );

      setIncidentsData(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadDetectionQuality();

    const interval = window.setInterval(() => {
      loadDetectionQuality();
    }, 30000);

    return () => window.clearInterval(interval);
  }, [loadDetectionQuality]);


  useEffect(() => {
    if (!currentUser) return;

    if (!canOperate) {
      setSyntheticScenarios([]);
      setSyntheticError(null);
      return;
    }

    fetchSyntheticScenarios()
      .then((response) => setSyntheticScenarios(response.items))
      .catch((err) =>
        setSyntheticError(
          err instanceof Error ? err.message : "Unable to load synthetic scenarios"
        )
      );
  }, [currentUser, canOperate]);

  async function handleRunSyntheticTest() {
    if (!canOperate) {
      setSyntheticError("Read-only access: synthetic test execution is available only to ADMIN and ANALYST roles.");
      return;
    }
    try {
      setRunningSynthetic(true);
      setSyntheticError(null);
      setSyntheticResult(null);

      const response = await runSyntheticTest({
        scenario: selectedScenario,
        count: syntheticCount,
        host: syntheticHost,
        created_by: syntheticCreatedBy,
      });

      setSyntheticResult(response);
      await loadDetectionQuality();
    } catch (err) {
      setSyntheticError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setRunningSynthetic(false);
    }
  }

  const syntheticIncidents = useMemo(() => {
    const items = incidentsData?.items ?? [];
    return items.filter(isSyntheticIncident);
  }, [incidentsData]);

  const totalSynthetic = syntheticIncidents.length;

  const correlatedSynthetic = syntheticIncidents.filter(
    (incident) => incident.correlated
  ).length;

  const priorityValidatedSynthetic = syntheticIncidents.filter((incident) =>
    priorityMatchesSyntheticExpectation(incident)
  ).length;

  const mitreTaggedSynthetic = syntheticIncidents.filter(
    (incident) => extractMitreIds(incident).length > 0
  ).length;

  const maxRisk = syntheticIncidents.reduce(
    (max, incident) => Math.max(max, incident.risk_score ?? 0),
    0
  );

  const averageRisk =
    totalSynthetic > 0
      ? Math.round(
          syntheticIncidents.reduce(
            (sum, incident) => sum + (incident.risk_score ?? 0),
            0
          ) / totalSynthetic
        )
      : 0;

  const detectionQualityScore = useMemo(() => {
    if (!totalSynthetic) return 0;

    const correlationScore = pct(correlatedSynthetic, totalSynthetic);
    const priorityScore = pct(priorityValidatedSynthetic, totalSynthetic);
    const mitreScore = pct(mitreTaggedSynthetic, totalSynthetic);

    return Math.round((correlationScore + priorityScore + mitreScore) / 3);
  }, [
    totalSynthetic,
    correlatedSynthetic,
    priorityValidatedSynthetic,
    mitreTaggedSynthetic,
  ]);

  const scenarioRows = useMemo<ScenarioSummary[]>(() => {
    const grouped = new Map<string, Incident[]>();

    for (const incident of syntheticIncidents) {
      const scenario = extractScenario(incident);
      const current = grouped.get(scenario) ?? [];
      current.push(incident);
      grouped.set(scenario, current);
    }

    return Array.from(grouped.entries())
      .map(([scenario, incidents]) => {
        const riskValues = incidents.map((incident) => incident.risk_score ?? 0);
        const riskSum = riskValues.reduce((sum, value) => sum + value, 0);

        return {
          scenario,
          incidents: incidents.length,
          correlated: incidents.filter((incident) => incident.correlated)
            .length,
          priority_validated: incidents.filter((incident) =>
            priorityMatchesSyntheticExpectation(incident)
          ).length,
          mitre_tagged: incidents.filter(
            (incident) => extractMitreIds(incident).length > 0
          ).length,
          max_risk: Math.max(...riskValues, 0),
          avg_risk: incidents.length ? Math.round(riskSum / incidents.length) : 0,
        };
      })
      .sort((a, b) => b.incidents - a.incidents);
  }, [syntheticIncidents]);

  const scenarioChartData = useMemo(() => {
    return scenarioRows.map((row) => ({
      key: row.scenario,
      name: scenarioLabel(row.scenario),
      incidents: row.incidents,
      correlated: row.correlated,
      correlation_gap: Math.max(row.incidents - row.correlated, 0),
      coverage_percent: pct(row.correlated, row.incidents),
      quality_score: scenarioQualityScore(row),
    }));
  }, [scenarioRows]);

  const correlationGap = Math.max(totalSynthetic - correlatedSynthetic, 0);
  const priorityGap = Math.max(totalSynthetic - priorityValidatedSynthetic, 0);
  const mitreGap = Math.max(totalSynthetic - mitreTaggedSynthetic, 0);
  const weakestScenario = useMemo(() => {
    if (scenarioRows.length === 0) return null;

    return [...scenarioRows]
      .sort((a, b) => {
        const qualityDelta = scenarioQualityScore(a) - scenarioQualityScore(b);
        if (qualityDelta !== 0) return qualityDelta;
        return scenarioGapCount(b) - scenarioGapCount(a);
      })[0];
  }, [scenarioRows]);
  const [dominantGapLabel, dominantGapCount] = topGapLabel({
    correlationGap,
    priorityGap,
    mitreGap,
  });
  const detectionBriefItems: BriefItem[] = [
    {
      label: "Correlation coverage",
      value: `${pct(correlatedSynthetic, totalSynthetic)}%`,
      tone: toneForCoverage(pct(correlatedSynthetic, totalSynthetic), totalSynthetic > 0),
    },
    {
      label: "Priority validation",
      value: `${pct(priorityValidatedSynthetic, totalSynthetic)}%`,
      tone: toneForCoverage(pct(priorityValidatedSynthetic, totalSynthetic), totalSynthetic > 0),
    },
    {
      label: "MITRE coverage",
      value: `${pct(mitreTaggedSynthetic, totalSynthetic)}%`,
      tone: toneForCoverage(pct(mitreTaggedSynthetic, totalSynthetic), totalSynthetic > 0),
    },
  ];
  const detectionBriefSummary =
    totalSynthetic === 0
      ? "No synthetic validation data is loaded yet. Run or ingest synthetic scenarios before assessing detection quality."
      : detectionQualityScore >= 85
        ? "Synthetic validation posture is strong across correlation, priority assignment and MITRE mapping."
        : detectionQualityScore >= 60
          ? "Synthetic validation is partially covered. Review the weakest scenario and close remaining mapping gaps."
          : "Synthetic validation requires attention. Correlation, priority or MITRE signals are missing from the loaded sample.";
  const detectionBriefNextAction =
    totalSynthetic === 0
      ? "Run all synthetic scenarios, wait for ingestion, then refresh this page."
      : dominantGapCount > 0
        ? `Prioritize ${dominantGapLabel} review across ${dominantGapCount} loaded synthetic signal(s).`
        : "Validate the latest synthetic incidents with a human analyst and document tuning evidence before release.";

  const guidanceScenarioName =
    weakestScenario?.scenario ?? "overall_detection_quality";
  const buildGuidanceKey = useCallback(
    (scenarioName: string, recommendedAction: string) =>
      `${scenarioName}::${recommendedAction}`,
    []
  );
  const guidanceKey = buildGuidanceKey(
    guidanceScenarioName,
    detectionBriefNextAction
  );
  const currentActionGuidance = actionGuidanceByKey[guidanceKey] ?? null;
  const currentGuidanceLoading = Boolean(guidanceLoadingByKey[guidanceKey]);
  const currentGuidanceError = guidanceErrorByKey[guidanceKey] ?? null;

  const generateActionGuidance = useCallback(async () => {
    if (actionGuidanceByKey[guidanceKey]) return;
    if (guidanceLoadingByKey[guidanceKey]) return;
    if (guidanceInFlightRef.current[guidanceKey]) return;

    const weakestScenarioPayload = weakestScenario
      ? {
          scenario: weakestScenario.scenario,
          incidents: weakestScenario.incidents,
          correlated: weakestScenario.correlated,
          priority_validated: weakestScenario.priority_validated,
          mitre_tagged: weakestScenario.mitre_tagged,
          avg_risk: weakestScenario.avg_risk,
          max_risk: weakestScenario.max_risk,
          quality_score: scenarioQualityScore(weakestScenario),
        }
      : null;

    guidanceInFlightRef.current[guidanceKey] = true;
    setGuidanceLoadingByKey((previous) => ({
      ...previous,
      [guidanceKey]: true,
    }));
    setGuidanceErrorByKey((previous) => {
      const next = { ...previous };
      delete next[guidanceKey];
      return next;
    });

    try {
      const response = await fetchDetectionQualityActionGuidance({
        summary: detectionBriefSummary,
        recommended_action: detectionBriefNextAction,
        quality_score: detectionQualityScore,
        total_synthetic: totalSynthetic,
        scenario_name: guidanceScenarioName,
        weakest_scenario: weakestScenarioPayload,
        signals: [
          {
            label: "Correlation coverage",
            value: pct(correlatedSynthetic, totalSynthetic),
            covered: correlatedSynthetic,
            total: totalSynthetic,
          },
          {
            label: "Priority validation",
            value: pct(priorityValidatedSynthetic, totalSynthetic),
            covered: priorityValidatedSynthetic,
            total: totalSynthetic,
          },
          {
            label: "MITRE coverage",
            value: pct(mitreTaggedSynthetic, totalSynthetic),
            covered: mitreTaggedSynthetic,
            total: totalSynthetic,
          },
        ],
        gaps: {
          correlation: correlationGap,
          priority_assignment: priorityGap,
          mitre_mapping: mitreGap,
          dominant_gap: dominantGapLabel,
          dominant_gap_count: dominantGapCount,
        },
      });

      setActionGuidanceByKey((previous) => {
        const next = {
          ...previous,
          [guidanceKey]: response,
        };
        storeActionGuidance(next);
        return next;
      });
    } catch (err) {
      setGuidanceErrorByKey((previous) => ({
        ...previous,
        [guidanceKey]:
          err instanceof Error ? err.message : "Unable to generate LLM guidance",
      }));
    } finally {
      guidanceInFlightRef.current[guidanceKey] = false;
      setGuidanceLoadingByKey((previous) => ({
        ...previous,
        [guidanceKey]: false,
      }));
    }
  }, [
    actionGuidanceByKey,
    guidanceLoadingByKey,
    guidanceKey,
    guidanceScenarioName,
    detectionBriefSummary,
    detectionBriefNextAction,
    detectionQualityScore,
    totalSynthetic,
    correlatedSynthetic,
    priorityValidatedSynthetic,
    mitreTaggedSynthetic,
    correlationGap,
    priorityGap,
    mitreGap,
    dominantGapLabel,
    dominantGapCount,
    weakestScenario,
  ]);

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
              ← Dashboard
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <Target className="h-3.5 w-3.5" />
              Detection Engineering
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Detection Quality Dashboard
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Compact view of synthetic scenario visibility, AI correlation,
              priority assignment and MITRE coverage across the AI SOC pipeline.
            </p>
          </div>

          <button
            onClick={loadDetectionQuality}
            className="flex h-8 items-center gap-1.5 rounded-sm border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-sm border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading detection quality data...
          </section>
        ) : (
          <div className="space-y-3">
            {canOperate ? (
            <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Synthetic test runner</h2>
                  <p className="mt-0.5 text-[11px] leading-4 text-slate-500">
                    Generate controlled synthetic incidents to validate detection, correlation, priority and MITRE coverage from the GUI.
                  </p>
                </div>

                <button
                  onClick={handleRunSyntheticTest}
                  disabled={runningSynthetic}
                  className="h-8 rounded-sm border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 shadow-sm hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {runningSynthetic ? "Running..." : "Run synthetic test"}
                </button>
              </div>

              <div className="grid gap-2 md:grid-cols-4">
                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Scenario
                  </span>
                  <select
                    value={selectedScenario}
                    onChange={(event) => setSelectedScenario(event.target.value)}
                    className="h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="all">All scenarios</option>
                    {syntheticScenarios.map((scenario) => (
                      <option key={scenario.id} value={scenario.id}>
                        {scenario.id.replaceAll("_", " ")}
                      </option>
                    ))}
                  </select>
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Count per scenario
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={10}
                    value={syntheticCount}
                    onChange={(event) =>
                      setSyntheticCount(
                        Math.max(1, Math.min(Number(event.target.value || 1), 10))
                      )
                    }
                    className="h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Host
                  </span>
                  <input
                    value={syntheticHost}
                    onChange={(event) => setSyntheticHost(event.target.value)}
                    className="h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Created by
                  </span>
                  <input
                    value={syntheticCreatedBy}
                    onChange={(event) => setSyntheticCreatedBy(event.target.value)}
                    className="h-8 w-full rounded-sm border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                  />
                </label>
              </div>

              {syntheticError && (
                <div className="mt-2 rounded-sm border border-red-800 bg-red-950/60 p-2 text-xs text-red-200">
                  Synthetic test error: {syntheticError}
                </div>
              )}

              {syntheticResult && (
                <div className="mt-2 rounded-sm border border-emerald-800 bg-emerald-950/30 p-2 text-xs text-emerald-200">
                  Created {syntheticResult.created} synthetic incident(s) on host{" "}
                  <strong>{syntheticResult.host}</strong>. Latest IDs:{" "}
                  {syntheticResult.incidents.slice(0, 6).map((item) => `#${item.id}`).join(", ")}
                  {syntheticResult.incidents.length > 6 ? "…" : ""}
                </div>
              )}
            </section>
            ) : isViewer ? (
            <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <h2 className="text-sm font-semibold">Synthetic test runner</h2>
              <p className="mt-2 text-xs text-slate-500">
                Read-only access: synthetic test execution is available only to ADMIN and ANALYST roles.
              </p>
            </section>
            ) : null}

            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-5">
              <QualityMetric
                title="Synthetic incidents"
                value={totalSynthetic}
                subtitle={`${incidentsData?.total ?? 0} matching loaded`}
                icon={<ShieldCheck className="h-3.5 w-3.5" />}
                tone="primary"
              />

              <QualityMetric
                title="Correlated"
                value={`${pct(correlatedSynthetic, totalSynthetic)}%`}
                subtitle={`${correlatedSynthetic}/${totalSynthetic}`}
                icon={<Brain className="h-3.5 w-3.5" />}
                tone={toneForCoverage(pct(correlatedSynthetic, totalSynthetic), totalSynthetic > 0)}
              />

              <QualityMetric
                title="Priority valid"
                value={`${pct(priorityValidatedSynthetic, totalSynthetic)}%`}
                subtitle={`${priorityValidatedSynthetic}/${totalSynthetic}`}
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
                tone={toneForCoverage(pct(priorityValidatedSynthetic, totalSynthetic), totalSynthetic > 0)}
              />

              <QualityMetric
                title="MITRE signal"
                value={`${pct(mitreTaggedSynthetic, totalSynthetic)}%`}
                subtitle={`${mitreTaggedSynthetic}/${totalSynthetic}`}
                icon={<Target className="h-3.5 w-3.5" />}
                tone={toneForCoverage(pct(mitreTaggedSynthetic, totalSynthetic), totalSynthetic > 0)}
              />

              <QualityMetric
                title="Quality score"
                value={`${detectionQualityScore}%`}
                subtitle="Correlation + priority + MITRE"
                icon={<CheckCircle2 className="h-3.5 w-3.5" />}
                tone={toneForCoverage(detectionQualityScore, totalSynthetic > 0)}
              />
            </section>

            <DetectionQualityBrief
              summary={detectionBriefSummary}
              nextAction={detectionBriefNextAction}
              qualityScore={detectionQualityScore}
              totalSynthetic={totalSynthetic}
              weakestScenario={weakestScenario}
              items={detectionBriefItems}
              actionGuidance={currentActionGuidance}
              guidanceLoading={currentGuidanceLoading}
              guidanceError={currentGuidanceError}
              onGenerateGuidance={generateActionGuidance}
            />

            <section className="grid gap-2 xl:grid-cols-[440px_1fr]">
              <div className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold">
                      Synthetic scenario coverage
                    </h2>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      Stacked view of correlated detections and correlation gaps by scenario.
                    </p>
                  </div>

                  <span
                    className={`shrink-0 rounded-sm border px-2 py-1 text-[11px] ${
                      toneClasses(toneForScore(maxRisk)).badge
                    }`}
                  >
                    Max {maxRisk} · Avg {averageRisk}
                  </span>
                </div>

                {totalSynthetic === 0 ? (
                  <div className="rounded-sm border border-orange-800 bg-orange-950/40 p-3 text-xs text-orange-100">
                    No synthetic incidents found. Run a synthetic scenario, wait
                    for ingestion, then refresh.
                  </div>
                ) : (
                  <div className="h-40">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={scenarioChartData}
                        layout="vertical"
                        barCategoryGap="28%"
                        margin={{ top: 4, right: 12, left: 4, bottom: 4 }}
                      >
                        <CartesianGrid
                          horizontal={false}
                          strokeDasharray="2 4"
                          stroke={CHART_COLORS.grid}
                        />
                        <XAxis
                          type="number"
                          allowDecimals={false}
                          tick={{ fill: CHART_COLORS.axis, fontSize: 10 }}
                          axisLine={{ stroke: CHART_COLORS.grid }}
                          tickLine={false}
                        />
                        <YAxis
                          type="category"
                          dataKey="name"
                          width={115}
                          tick={{ fill: CHART_COLORS.axis, fontSize: 10 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          cursor={{ fill: CHART_COLORS.cursor }}
                          contentStyle={{
                            backgroundColor: CHART_COLORS.tooltip,
                            border: `1px solid ${CHART_COLORS.border}`,
                            borderRadius: "3px",
                            color: CHART_COLORS.text,
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: CHART_COLORS.primary }}
                          itemStyle={{ color: CHART_COLORS.text }}
                          formatter={(value, name) => [
                            value,
                            String(name).toLowerCase().includes("gap")
                              ? "Correlation gap"
                              : "Correlated detections",
                          ]}
                        />
                        <Legend
                          verticalAlign="top"
                          align="right"
                          iconType="square"
                          wrapperStyle={{
                            color: CHART_COLORS.axis,
                            fontSize: "11px",
                            lineHeight: "16px",
                          }}
                        />
                        <Bar
                          dataKey="correlated"
                          name="Correlated detections"
                          stackId="coverage"
                          fill={CHART_COLORS.success}
                          radius={[0, 0, 0, 0]}
                          barSize={11}
                        />
                        <Bar
                          dataKey="correlation_gap"
                          name="Correlation gap"
                          stackId="coverage"
                          fill={CHART_COLORS.failed}
                          radius={[0, 2, 2, 0]}
                          barSize={11}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>

              <div className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
                <div className="mb-2 flex items-center justify-between">
                  <h2 className="text-sm font-semibold">
                    Scenario quality breakdown
                  </h2>

                  <span className="rounded-sm border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                    {scenarioRows.length} scenario(s)
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="min-w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-2 py-1.5">Scenario</th>
                        <th className="px-2 py-1.5">Inc</th>
                        <th className="px-2 py-1.5">Corr</th>
                        <th className="px-2 py-1.5">Prio</th>
                        <th className="px-2 py-1.5">MITRE</th>
                        <th className="px-2 py-1.5">Avg</th>
                        <th className="px-2 py-1.5">Max</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/80">
                      {scenarioRows.map((row) => (
                        <tr key={row.scenario} className="hover:bg-slate-800/40">
                          <td className="max-w-[220px] truncate px-2 py-1.5 font-medium text-slate-100">
                            {scenarioLabel(row.scenario)}
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {row.incidents}
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {pct(row.correlated, row.incidents)}%
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {pct(row.priority_validated, row.incidents)}%
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {pct(row.mitre_tagged, row.incidents)}%
                          </td>
                          <td className="px-2 py-1.5 text-slate-300">
                            {row.avg_risk}
                          </td>
                          <td className="px-2 py-1.5">
                            <span
                              className={`${TABLE_BADGE_BASE} ${
                                toneClasses(toneForScore(row.max_risk)).badge
                              }`}
                            >
                              {row.max_risk}
                            </span>
                          </td>
                        </tr>
                      ))}

                      {scenarioRows.length === 0 && (
                        <tr>
                          <td
                            colSpan={7}
                            className="px-2 py-4 text-center text-slate-500"
                          >
                            No synthetic scenario data available yet.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>

            <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
              <div className="mb-2 flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">
                    Latest synthetic incidents
                  </h2>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Most recent synthetic detections loaded from the incident stream.
                  </p>
                </div>

                <span className="rounded-sm border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                  Showing {Math.min(syntheticIncidents.length, 25)}
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="px-2 py-1.5">ID</th>
                      <th className="px-2 py-1.5">Time</th>
                      <th className="px-2 py-1.5">Host</th>
                      <th className="px-2 py-1.5">Rule</th>
                      <th className="px-2 py-1.5">Priority</th>
                      <th className="px-2 py-1.5">Risk</th>
                      <th className="px-2 py-1.5">Correlation</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/80">
                    {syntheticIncidents.slice(0, 25).map((incident) => (
                      <tr key={incident.id} className="hover:bg-slate-800/40">
                        <td className="px-2 py-1.5">
                          <Link
                            href={`/incidents/${incident.id}`}
                            className="text-cyan-300 hover:text-cyan-200"
                          >
                            #{incident.id}
                          </Link>
                        </td>
                        <td className="whitespace-nowrap px-2 py-1.5 text-slate-300">
                          {formatTimestamp(
                            incident.timestamp_local ?? incident.timestamp
                          )}
                        </td>
                        <td className="max-w-[140px] truncate px-2 py-1.5 text-slate-300">
                          {incident.agent ?? "-"}
                        </td>
                        <td
                          className="max-w-xl truncate px-2 py-1.5 text-slate-300"
                          title={incident.rule ?? "-"}
                        >
                          {shortText(incident.rule, 120)}
                        </td>
                        <td className="px-2 py-1.5 text-slate-300">
                          <span
                            className={`${TABLE_BADGE_BASE} ${
                              toneClasses(toneForPriority(incident.recommended_priority)).badge
                            }`}
                          >
                            {incident.recommended_priority ?? "UNKNOWN"}
                          </span>
                        </td>
                        <td className="px-2 py-1.5">
                          <span
                            className={`${TABLE_BADGE_BASE} ${
                              toneClasses(
                                toneForScore(incident.risk_score ?? 0)
                              ).badge
                            }`}
                          >
                            {incident.risk_score ?? 0}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-slate-300">
                          {incident.correlated ? "Yes" : "No"}
                          {incident.correlation_score !== null &&
                          incident.correlation_score !== undefined
                            ? ` · ${incident.correlation_score}`
                            : ""}
                        </td>
                      </tr>
                    ))}

                    {syntheticIncidents.length === 0 && (
                      <tr>
                        <td
                          colSpan={7}
                          className="px-2 py-4 text-center text-slate-500"
                        >
                          No synthetic incidents found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function DetectionQualityBrief({
  summary,
  nextAction,
  qualityScore,
  totalSynthetic,
  weakestScenario,
  items,
  actionGuidance,
  guidanceLoading,
  guidanceError,
  onGenerateGuidance,
}: {
  summary: string;
  nextAction: string;
  qualityScore: number;
  totalSynthetic: number;
  weakestScenario: ScenarioSummary | null;
  items: BriefItem[];
  actionGuidance: DetectionQualityActionGuidance | null;
  guidanceLoading: boolean;
  guidanceError: string | null;
  onGenerateGuidance: () => void;
}) {
  const scoreTone = toneForCoverage(qualityScore, totalSynthetic > 0);
  const weakestQuality = weakestScenario ? scenarioQualityScore(weakestScenario) : 0;
  const alignedBriefItems: BriefItem[] = [
    ...items,
    {
      label: "Quality score",
      value: `${qualityScore}%`,
      tone: scoreTone,
    },
    {
      label: "Weakest scenario",
      value: weakestScenario
        ? `${scenarioLabel(weakestScenario.scenario)} · ${weakestQuality}%`
        : "Not available",
      tone: weakestScenario ? toneForCoverage(weakestQuality, true) : "neutral",
    },
  ];

  return (
    <section className="rounded-sm border border-slate-800 bg-slate-900 p-3 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-wide text-violet-300">
            <Brain className="h-3.5 w-3.5" />
            Detection quality brief
          </div>
          <h2 className="mt-1 text-sm font-semibold">
            Synthetic validation posture
          </h2>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={`${TABLE_BADGE_BASE} ${
              toneClasses(scoreTone).badge
            }`}
          >
            Quality {qualityScore}%
          </span>
          <span className="rounded-sm border border-slate-700 bg-slate-950 px-2 py-1 text-[10px] uppercase tracking-wide text-slate-500">
            Human review
          </span>
        </div>
      </div>

      <div className="mt-3">
        <p className="text-xs leading-5 text-slate-400">
          {summary}
        </p>

        <div className="mt-3 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-5">
          {alignedBriefItems.map((item) => (
            <div
              key={item.label}
              className="rounded-sm border border-slate-800 bg-slate-950 px-2 py-1.5"
            >
              <div className="truncate text-[10px] uppercase tracking-wide text-slate-500">
                {item.label}
              </div>
              <div className="mt-1 flex items-center justify-between gap-2">
                <span
                  className="truncate text-sm font-semibold text-slate-100"
                  title={item.value}
                >
                  {item.value}
                </span>
                <span
                  className={`h-2 w-2 shrink-0 rounded-full ${toneDotClass(item.tone)}`}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 grid gap-2 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <div className="rounded-sm border border-slate-800 bg-slate-950 px-2.5 py-2">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[10px] uppercase tracking-wide text-slate-500">
                Recommended next action
              </div>
              <div className="mt-1 text-xs leading-5 text-slate-300">
                {nextAction}
              </div>
            </div>
            <span className="shrink-0 rounded-sm border border-amber-900/70 bg-amber-950/30 px-1.5 py-0.5 text-[10px] leading-none text-amber-200">
              Analyst decision
            </span>
          </div>
          <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-600">
            Human validation required before tuning or release decisions
          </div>
        </div>

        <div className="rounded-sm border border-violet-900/70 bg-violet-950/20 px-2.5 py-2">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div className="text-[10px] uppercase leading-4 tracking-wide text-violet-300">
                AI suggestion
              </div>
              <div className="mt-0.5 text-[11px] text-slate-500">
                LLM-assisted execution guidance
              </div>
            </div>
            {actionGuidance ? (
              <span
                className="inline-flex h-4 items-center rounded-sm border border-violet-800 bg-violet-950 px-1.5 py-0 text-[10px] leading-4 text-violet-200"
                title={`${formatGuidanceModelLabel(actionGuidance)}${
                  actionGuidance.model ? ` · ${actionGuidance.model}` : ""
                }${actionGuidance.cache_hit ? " · cache" : ""}`}
              >
                {formatGuidanceModelLabel(actionGuidance)}
              </span>
            ) : (
              <button
                type="button"
                onClick={onGenerateGuidance}
                disabled={guidanceLoading}
                className="inline-flex h-4 items-center rounded-sm border border-violet-800 bg-violet-950 px-2 py-0 text-[10px] font-medium leading-4 text-violet-200 hover:bg-violet-900 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {guidanceLoading ? "Generating..." : "Generate AI suggestion"}
              </button>
            )}
          </div>

          {guidanceLoading ? (
            <div className="mt-2 rounded-sm border border-violet-900/50 bg-slate-950 px-2 py-1.5 text-[11px] leading-4 text-slate-400">
              Generating AI suggestion...
            </div>
          ) : guidanceError ? (
            <div className="mt-2 rounded-sm border border-orange-900/60 bg-orange-950/20 px-2 py-1.5 text-[11px] leading-4 text-orange-200">
              LLM guidance unavailable: {guidanceError}
            </div>
          ) : actionGuidance ? (
            <>
              <ol className="mt-2 space-y-1 text-[11px] leading-4 text-slate-300">
                {actionGuidance.how_to_execute.map((step, index) => (
                  <li key={`${step}-${index}`} className="flex gap-1.5">
                    <span className="mt-0.5 h-4 min-w-4 rounded-sm border border-violet-800 bg-violet-950 text-center text-[10px] leading-4 text-violet-200">
                      {index + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
              <div className="mt-2 border-t border-violet-900/50 pt-1.5 text-[10px] leading-4 text-slate-500">
                {actionGuidance.validation_notes}
              </div>
              <div className="mt-1 text-[10px] leading-4 text-slate-600">
                Model: {formatGuidanceModelLabel(actionGuidance)}
                {actionGuidance.model ? ` (${actionGuidance.model})` : ""}
                {typeof actionGuidance.llm_latency_ms === "number"
                  ? ` · ${actionGuidance.llm_latency_ms} ms`
                  : ""}
              </div>
            </>
          ) : (
            <div className="mt-2 rounded-sm border border-violet-900/40 bg-slate-950 px-2 py-1.5 text-[11px] leading-4 text-slate-500">
              Click Generate AI suggestion to generate LLM execution guidance for this recommended action.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function QualityMetric({
  title,
  value,
  subtitle,
  icon,
  tone,
}: {
  title: string;
  value: string | number;
  subtitle: string;
  icon: ReactNode;
  tone: Tone;
}) {
  const classes = toneClasses(tone);

  return (
    <div
      className={`flex min-h-[58px] items-center justify-between gap-3 rounded-sm border px-2.5 py-2 shadow-sm ${classes.card}`}
    >
        <div className="min-w-0">
          <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
            {title}
          </div>
          <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
            <span className="text-xl font-semibold leading-6 text-slate-100">
              {value}
            </span>
            <span className="min-w-0 truncate text-[11px] leading-4 text-slate-500">
              {subtitle}
            </span>
          </div>
        </div>

        <div className={`shrink-0 rounded-sm bg-slate-950 p-1.5 ${classes.text}`}>
          {icon}
        </div>
    </div>
  );
}
