"use client";

import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";
import {
  SOC_CONTROL_CLASSES,
  SOC_TONE_CLASSES,
  cx,
  type SocTone,
} from "@/lib/semantic-styles";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import AppShell from "@/components/AppShell";
import {
  EnterpriseBadge,
  EnterpriseBreadcrumbs,
  EnterpriseButton,
  EnterpriseChartCard,
  EnterpriseEmptyState,
  EnterpriseErrorState,
  EnterpriseMetricCard,
  EnterpriseMetricStrip,
  EnterprisePageHeader,
  EnterprisePanel,
  EnterpriseSection,
  EnterpriseSelect,
  EnterpriseSeverityBadge,
  EnterpriseSkeleton,
} from "@/components/enterprise";
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

type Tone = SocTone;

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
  provider_key?: string | null;
  provider_type?: string | null;
  used_external_provider?: boolean;
  redaction_applied?: boolean;
  redaction_mode?: string | null;
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
  low: "#2563eb",
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

function pct(value: number, total: number): number {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}

function toneForScore(score: number): Tone {
  if (score >= 81) return "danger";
  if (score >= 61) return "high";
  if (score >= 31) return "medium";
  return "low";
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

function toneDotClass(tone: Tone) {
  return SOC_TONE_CLASSES[tone].dot;
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
    <AppShell>
      <EnterprisePageHeader
        breadcrumbs={
          <EnterpriseBreadcrumbs
            items={[{ label: "Dashboard", href: "/" }, { label: "Detection Quality" }]}
          />
        }
        eyebrow="Detection Engineering"
        title="Detection Quality Dashboard"
        description="Compact view of synthetic scenario visibility, AI correlation, priority assignment and MITRE coverage across the AI SOC pipeline."
        icon={<Target aria-hidden="true" className="h-3.5 w-3.5" />}
        secondaryActions={
          <EnterpriseButton
            onClick={loadDetectionQuality}
            tone="secondary"
            size="xs"
            icon={
              <RefreshCw
                aria-hidden="true"
                className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
              />
            }
          >
            Refresh
          </EnterpriseButton>
        }
        density="compact"
      />

        {error && (
          <EnterpriseErrorState
            title="Unable to load detection quality data"
            message={`API error: ${error}${incidentsData ? ". Last loaded data remains visible." : ""}`}
            onRetry={loadDetectionQuality}
            className="mb-3"
          />
        )}

        {loading ? (
          <EnterprisePanel>
            <EnterpriseSkeleton label="Loading detection quality data" rows={5} />
          </EnterprisePanel>
        ) : incidentsData ? (
          <div className="space-y-3">
            {canOperate ? (
            <EnterpriseSection
              title="Synthetic test runner"
              description="Generate controlled synthetic incidents to validate detection, correlation, priority and MITRE coverage from the GUI."
              actions={
                <EnterpriseButton
                  onClick={handleRunSyntheticTest}
                  disabled={runningSynthetic}
                  tone="primary"
                  size="xs"
                >
                  {runningSynthetic ? "Running..." : "Run synthetic test"}
                </EnterpriseButton>
              }
            >

              <div className="grid gap-2 md:grid-cols-4">
                <EnterpriseSelect
                  label="Scenario"
                  value={selectedScenario}
                  onChange={setSelectedScenario}
                  options={[
                    { label: "All scenarios", value: "all" },
                    ...syntheticScenarios.map((scenario) => ({
                      label: scenario.id.replaceAll("_", " "),
                      value: scenario.id,
                    })),
                  ]}
                />

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
                    className={cx(SOC_CONTROL_CLASSES.input, SOC_CONTROL_CLASSES.focus, "h-8 w-full px-2 text-xs")}
                  />
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Host
                  </span>
                  <input
                    value={syntheticHost}
                    onChange={(event) => setSyntheticHost(event.target.value)}
                    className={cx(SOC_CONTROL_CLASSES.input, SOC_CONTROL_CLASSES.focus, "h-8 w-full px-2 text-xs")}
                  />
                </label>

                <label>
                  <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                    Created by
                  </span>
                  <input
                    value={syntheticCreatedBy}
                    onChange={(event) => setSyntheticCreatedBy(event.target.value)}
                    className={cx(SOC_CONTROL_CLASSES.input, SOC_CONTROL_CLASSES.focus, "h-8 w-full px-2 text-xs")}
                  />
                </label>
              </div>

              {syntheticError && (
                <EnterpriseErrorState
                  title="Synthetic test error"
                  message={syntheticError}
                  className="mt-2"
                />
              )}

              {syntheticResult && (
                <div
                  role="status"
                  className={cx(
                    "mt-2 rounded-sm border p-2 text-xs",
                    SOC_TONE_CLASSES.success.panel,
                    SOC_TONE_CLASSES.success.text
                  )}
                >
                  Created {syntheticResult.created} synthetic incident(s) on host{" "}
                  <strong>{syntheticResult.host}</strong>. Latest IDs:{" "}
                  {syntheticResult.incidents.slice(0, 6).map((item) => `#${item.id}`).join(", ")}
                  {syntheticResult.incidents.length > 6 ? "…" : ""}
                </div>
              )}
            </EnterpriseSection>
            ) : isViewer ? (
            <EnterprisePanel title="Synthetic test runner">
              <p className="text-xs text-slate-500">
                Read-only access: synthetic test execution is available only to ADMIN and ANALYST roles.
              </p>
            </EnterprisePanel>
            ) : null}

            <EnterpriseMetricStrip className="lg:grid-cols-5">
              <EnterpriseMetricCard
                stacked
                title="Synthetic incidents"
                value={totalSynthetic}
                subtitle={`${incidentsData?.total ?? 0} matching loaded`}
                icon={<ShieldCheck className="h-3.5 w-3.5" />}
                tone="primary"
              />

              <EnterpriseMetricCard
                stacked
                title="Correlated"
                value={`${pct(correlatedSynthetic, totalSynthetic)}%`}
                subtitle={`${correlatedSynthetic}/${totalSynthetic}`}
                icon={<Brain className="h-3.5 w-3.5" />}
                tone={toneForCoverage(pct(correlatedSynthetic, totalSynthetic), totalSynthetic > 0)}
              />

              <EnterpriseMetricCard
                stacked
                title="Priority valid"
                value={`${pct(priorityValidatedSynthetic, totalSynthetic)}%`}
                subtitle={`${priorityValidatedSynthetic}/${totalSynthetic}`}
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
                tone={toneForCoverage(pct(priorityValidatedSynthetic, totalSynthetic), totalSynthetic > 0)}
              />

              <EnterpriseMetricCard
                stacked
                title="MITRE signal"
                value={`${pct(mitreTaggedSynthetic, totalSynthetic)}%`}
                subtitle={`${mitreTaggedSynthetic}/${totalSynthetic}`}
                icon={<Target className="h-3.5 w-3.5" />}
                tone={toneForCoverage(pct(mitreTaggedSynthetic, totalSynthetic), totalSynthetic > 0)}
              />

              <EnterpriseMetricCard
                stacked
                title="Quality score"
                value={`${detectionQualityScore}%`}
                subtitle="Correlation + priority + MITRE"
                icon={<CheckCircle2 className="h-3.5 w-3.5" />}
                tone={toneForCoverage(detectionQualityScore, totalSynthetic > 0)}
              />
            </EnterpriseMetricStrip>

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
              <EnterpriseChartCard
                title="Synthetic scenario coverage"
                description="Stacked view of correlated detections and correlation gaps by scenario."
                height="h-40"
                actions={
                  <EnterpriseBadge tone={toneForScore(maxRisk)} size="compact">
                    Max {maxRisk} · Avg {averageRisk}
                  </EnterpriseBadge>
                }
              >

                {totalSynthetic === 0 ? (
                  <EnterpriseEmptyState
                    title="No synthetic incidents found"
                    description="Run a synthetic scenario, wait for ingestion, then refresh."
                    className="h-full py-3"
                  />
                ) : (
                  <div className="h-full">
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
              </EnterpriseChartCard>

              <EnterprisePanel
                title="Scenario quality breakdown"
                actions={
                  <EnterpriseBadge tone="muted" size="compact">
                    {scenarioRows.length} scenario(s)
                  </EnterpriseBadge>
                }
                className="bg-slate-900"
              >

                <div className="overflow-x-auto" role="region" aria-label="Scenario quality data" tabIndex={0}>
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
                            <EnterpriseBadge tone={toneForScore(row.max_risk)} size="compact">
                              {row.max_risk}
                            </EnterpriseBadge>
                          </td>
                        </tr>
                      ))}

                      {scenarioRows.length === 0 && (
                        <tr>
                          <td
                            colSpan={7}
                            className="px-2 py-4 text-center text-slate-500"
                          >
                            <EnterpriseEmptyState
                              title="No synthetic scenario data"
                              description="Run or ingest a synthetic scenario to populate this breakdown."
                              className="py-3"
                            />
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </EnterprisePanel>
            </section>

            <EnterprisePanel
              title="Latest synthetic incidents"
              description="Most recent synthetic detections loaded from the incident stream."
              actions={
                <EnterpriseBadge tone="muted" size="compact">
                  Showing {Math.min(syntheticIncidents.length, 25)}
                </EnterpriseBadge>
              }
              className="bg-slate-900"
            >

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
                          <EnterpriseSeverityBadge
                            value={incident.recommended_priority}
                            size="compact"
                          />
                        </td>
                        <td className="px-2 py-1.5">
                          <EnterpriseBadge
                            tone={incident.risk_score == null ? "neutral" : toneForScore(incident.risk_score)}
                            size="compact"
                          >
                            {incident.risk_score ?? "-"}
                          </EnterpriseBadge>
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
                          <EnterpriseEmptyState
                            title="No synthetic incidents found"
                            description="Run or ingest a synthetic scenario, then refresh this page."
                            className="py-3"
                          />
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </EnterprisePanel>
          </div>
        ) : null}
    </AppShell>
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
    <EnterpriseSection
      title="Synthetic validation posture"
      description="Detection quality brief with deterministic metrics and analyst-controlled guidance."
      actions={
        <>
          <EnterpriseBadge tone={scoreTone} size="compact">
            Quality {qualityScore}%
          </EnterpriseBadge>
          <EnterpriseBadge tone="neutral" size="compact">
            Human review
          </EnterpriseBadge>
        </>
      }
    >

      <div>
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
            <EnterpriseBadge tone="medium" size="compact" className="shrink-0">
              Analyst decision
            </EnterpriseBadge>
          </div>
          <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-600">
            Human validation required before tuning or release decisions
          </div>
        </div>

        <div className="rounded-sm border border-violet-900/70 bg-violet-950/20 px-2.5 py-2">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div className="text-[10px] uppercase leading-4 tracking-wide text-violet-300">
                AI suggestion · advisory
              </div>
              <div className="mt-0.5 text-[11px] text-slate-500">
                Non-authoritative LLM-assisted execution guidance
              </div>
            </div>
            {actionGuidance ? (
              <EnterpriseBadge
                tone="executive"
                size="compact"
                title={`${formatGuidanceModelLabel(actionGuidance)}${
                  actionGuidance.model ? ` · ${actionGuidance.model}` : ""
                }${actionGuidance.cache_hit ? " · cache" : ""}`}
              >
                {formatGuidanceModelLabel(actionGuidance)}
              </EnterpriseBadge>
            ) : (
              <EnterpriseButton
                onClick={onGenerateGuidance}
                disabled={guidanceLoading}
                tone="executive"
                size="xs"
              >
                {guidanceLoading ? "Generating..." : "Generate AI suggestion"}
              </EnterpriseButton>
            )}
          </div>

          {guidanceLoading ? (
            <EnterpriseSkeleton label="Generating AI suggestion" rows={2} className="mt-2" />
          ) : guidanceError ? (
            <EnterpriseErrorState
              title="LLM guidance unavailable"
              message={guidanceError}
              onRetry={onGenerateGuidance}
              className="mt-2"
            />
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
                {` · Provider: ${actionGuidance.provider_key || "local_ollama"}`}
                {` · External AI: ${actionGuidance.used_external_provider ? "yes" : "no"}`}
                {actionGuidance.redaction_applied
                  ? ` · Redaction: ${actionGuidance.redaction_mode || "applied"}`
                  : ""}
              </div>
            </>
          ) : (
            <div className="mt-2 rounded-sm border border-violet-900/40 bg-slate-950 px-2 py-1.5 text-[11px] leading-4 text-slate-500">
              Generate an advisory AI suggestion for this recommended action. Deterministic metrics and analyst review remain authoritative.
            </div>
          )}
        </div>
      </div>
    </EnterpriseSection>
  );
}
