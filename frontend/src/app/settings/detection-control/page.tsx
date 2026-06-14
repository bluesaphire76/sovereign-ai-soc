"use client";

import { authFetch, fetchCurrentUser, getStoredUser, type AuthUser } from "@/lib/auth";

import dynamic from "next/dynamic";
import {
  Component,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ErrorInfo,
  type FormEvent,
  type ReactNode,
} from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import ServiceOperationsPanel from "./ServiceOperationsPanel";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Eye,
  FileCog,
  Lock,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Save,
  ServerCog,
  Shield,
  SlidersHorizontal,
  Trash2,
  XCircle,
} from "lucide-react";

type InventoryItem = {
  id: string;
  name: string;
  type: string;
  source: string;
  scope: string;
  target: string;
  status: string;
  managed: boolean;
  requires_reload: boolean;
  last_seen: string | null;
  description: string;
  reason: string;
  metadata?: Record<string, unknown>;
};

type DetectionControlInventory = {
  summary: {
    total_items: number;
    total_rules: number;
    active_rules: number;
    disabled_rules: number;
    exceptions: number;
    telemetry_sources: number;
    policies: number;
    service_controls: number;
    managed_items: number;
    unmanaged_items: number;
    pending_review: number;
    read_only: boolean;
    generated_at: string;
  };
  rules: InventoryItem[];
  exceptions: InventoryItem[];
  telemetry_sources: InventoryItem[];
  policies: InventoryItem[];
  service_controls: InventoryItem[];
};

type ManagedRule = {
  id: string;
  name: string;
  type: RuleType;
  status: string;
  scope: string;
  matcher_kind: MatcherKind;
  matcher_value: string;
  reason: string;
  owner: string;
  enabled: boolean;
  description: string | null;
  created_at: string | null;
  updated_at: string | null;
  created_by: string | null;
  updated_by: string | null;
  last_validation_status: string | null;
  last_validation_message: string | null;
  metadata?: Record<string, unknown>;
  requires_apply: boolean;
  affected_service: string | null;
  restart_note: string;
};

type ManagedRulesResponse = {
  items: ManagedRule[];
  summary: {
    total: number;
    active: number;
    disabled: number;
    failed_validation: number;
    generated_at: string;
    restart_orchestration: string;
  };
  rbac: {
    role: string;
    can_write: boolean;
  };
};

type ConfigDomain =
  | "noise_suppression"
  | "exceptions"
  | "detection_rules"
  | "source_controls";

type ConfigVersion = {
  id: number;
  config_domain: ConfigDomain;
  version_number: number;
  status: string;
  config_checksum: string;
  checksum_short: string | null;
  created_at: string | null;
  created_by: string | null;
  created_reason: string | null;
  activated_at: string | null;
  activated_by: string | null;
  validation_status: string | null;
  validation_errors: string[];
  validation_warnings: string[];
  diff_summary: ConfigDiff | null;
  rollback_of_version_id: number | null;
  source_identifier: string | null;
  requires_restart: boolean;
  affected_services: string[];
  config_payload?: { items: ManagedRule[] };
};

type ConfigVersionsResponse = {
  items: ConfigVersion[];
  domains: ConfigDomain[];
};

type ValidationResult = {
  valid: boolean;
  severity: "OK" | "WARNING" | "ERROR" | string;
  messages: string[];
  warnings: string[];
};

type RuleMutationResponse = {
  rule: ManagedRule;
  validation?: ValidationResult;
};

type ConfigValidationResult = ValidationResult & {
  requires_restart: boolean;
  affected_services: string[];
};

type ConfigDiff = {
  added: Array<Record<string, unknown>>;
  removed: Array<Record<string, unknown>>;
  modified: Array<{
    rule_id: string;
    name?: string;
    type?: string;
    changes: Record<string, { from: unknown; to: unknown }>;
  }>;
  unchanged_count: number;
  summary: {
    added_count: number;
    removed_count: number;
    modified_count: number;
  };
};

type RuleType =
  | "NOISE_SUPPRESSION"
  | "EXCEPTION"
  | "DETECTION_RULE"
  | "SOURCE_POLICY"
  | "TELEMETRY_SOURCE"
  | "SERVICE_CONTROL";
type MatcherKind = "CONTAINS" | "EXACT" | "REGEX" | "JSON" | "YAML";
type TabKey = "rules" | "exceptions" | "sources" | "policies" | "services";
type InventoryCategory = TabKey;

type RuleFormState = {
  name: string;
  type: RuleType;
  scope: string;
  matcher_kind: MatcherKind;
  matcher_value: string;
  reason: string;
  owner: string;
  enabled: boolean;
  description: string;
  metadata: Record<string, unknown>;
};

type LifecyclePanelProps = {
  currentUser: AuthUser | null;
  onConfigChanged: () => Promise<void>;
};

const RULE_TYPES: RuleType[] = [
  "NOISE_SUPPRESSION",
  "EXCEPTION",
  "DETECTION_RULE",
  "SOURCE_POLICY",
  "TELEMETRY_SOURCE",
  "SERVICE_CONTROL",
];

const MATCHER_KINDS: MatcherKind[] = ["CONTAINS", "EXACT", "REGEX", "JSON", "YAML"];

const CONFIG_DOMAINS: ConfigDomain[] = [
  "noise_suppression",
  "exceptions",
  "detection_rules",
  "source_controls",
];

const CONFIG_DOMAIN_LABELS: Record<ConfigDomain, string> = {
  noise_suppression: "Noise suppression",
  exceptions: "Exceptions",
  detection_rules: "Detection rules",
  source_controls: "Source controls",
};

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "rules", label: "Rules" },
  { key: "exceptions", label: "Exceptions" },
  { key: "sources", label: "Sources" },
  { key: "policies", label: "Policies" },
  { key: "services", label: "Service Control" },
];

const LifecyclePanel = dynamic<LifecyclePanelProps>(() => import("./LifecyclePanel"), {
  ssr: false,
  loading: () => (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 text-xs text-slate-400">
      Loading detection lifecycle...
    </section>
  ),
});

class LifecyclePanelBoundary extends Component<
  { children: ReactNode },
  { errorMessage: string | null; retryKey: number }
> {
  state = {
    errorMessage: null,
    retryKey: 0,
  };

  static getDerivedStateFromError(error: Error) {
    return {
      errorMessage: error.message || "Detection lifecycle panel failed to load.",
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Detection lifecycle panel failed", error, errorInfo);
  }

  retry = () => {
    this.setState((state) => ({
      errorMessage: null,
      retryKey: state.retryKey + 1,
    }));
  };

  render() {
    if (this.state.errorMessage) {
      return (
        <section className="rounded-lg border border-amber-900/70 bg-amber-950/30 p-3 text-xs text-amber-100">
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-2">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div>
                <div className="font-medium">Detection lifecycle is temporarily unavailable.</div>
                <div className="mt-1 text-amber-200/80">{this.state.errorMessage}</div>
              </div>
            </div>
            <button
              type="button"
              onClick={this.retry}
              className="flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-amber-800 bg-amber-950 px-3 text-xs text-amber-100 hover:bg-amber-900"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Retry
            </button>
          </div>
        </section>
      );
    }

    return <div key={this.state.retryKey}>{this.props.children}</div>;
  }
}

function emptyForm(owner = ""): RuleFormState {
  return {
    name: "",
    type: "NOISE_SUPPRESSION",
    scope: "",
    matcher_kind: "CONTAINS",
    matcher_value: "",
    reason: "",
    owner,
    enabled: true,
    description: "",
    metadata: {},
  };
}

async function fetchInventory(): Promise<DetectionControlInventory> {
  const response = await authFetch("/settings/detection-control", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Inventory API returned ${response.status}`);
  }

  return (await response.json()) as DetectionControlInventory;
}

async function fetchManagedRules(): Promise<ManagedRulesResponse> {
  const response = await authFetch("/detection-control/rules", {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Rules API returned ${response.status}`);
  }

  return (await response.json()) as ManagedRulesResponse;
}

async function fetchConfigVersions(domain: ConfigDomain): Promise<ConfigVersionsResponse> {
  const response = await authFetch(`/detection-control/config-versions/${domain}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Config versions API returned ${response.status}`);
  }

  return (await response.json()) as ConfigVersionsResponse;
}

async function fetchActiveConfigVersion(domain: ConfigDomain): Promise<ConfigVersion | null> {
  const response = await authFetch(`/detection-control/config-versions/${domain}/active`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Active config API returned ${response.status}`);
  }

  return (await response.json()) as ConfigVersion | null;
}

async function fetchConfigVersion(
  domain: ConfigDomain,
  versionNumber: number
): Promise<ConfigVersion> {
  const response = await authFetch(
    `/detection-control/config-versions/${domain}/${versionNumber}`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error(`Config version detail API returned ${response.status}`);
  }

  return (await response.json()) as ConfigVersion;
}

function statusTone(status: string) {
  const normalized = status.toUpperCase();

  if (normalized === "ACTIVE" || normalized === "OK") {
    return "border-emerald-800 bg-emerald-950/60 text-emerald-200";
  }

  if (normalized === "DISABLED" || normalized === "READ_ONLY" || normalized === "EMPTY") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }

  if (normalized === "ERROR" || normalized === "FAILED_VALIDATION") {
    return "border-red-800 bg-red-950/60 text-red-200";
  }

  return "border-amber-800 bg-amber-950/60 text-amber-200";
}

function sourceTone(source: string) {
  const normalized = source.toLowerCase();

  if (normalized.includes("wazuh")) {
    return "border-cyan-900/80 bg-cyan-950/40 text-cyan-200";
  }

  if (normalized.includes("suricata")) {
    return "border-violet-900/80 bg-violet-950/40 text-violet-200";
  }

  if (normalized.includes("dns")) {
    return "border-sky-900/80 bg-sky-950/40 text-sky-200";
  }

  return "border-slate-700 bg-slate-900 text-slate-300";
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

function metadataPreview(metadata?: Record<string, unknown>) {
  if (!metadata) return "-";

  const entries = Object.entries(metadata)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 4);

  if (entries.length === 0) return "-";

  return entries
    .map(([key, value]) => {
      if (Array.isArray(value)) {
        return `${key}: ${value.length}`;
      }

      if (typeof value === "object") {
        return `${key}: object`;
      }

      return `${key}: ${String(value)}`;
    })
    .join(" / ");
}

function isValidationResult(value: unknown): value is ValidationResult {
  if (!value || typeof value !== "object") return false;

  const candidate = value as Partial<ValidationResult>;

  return (
    typeof candidate.valid === "boolean" &&
    typeof candidate.severity === "string" &&
    Array.isArray(candidate.messages) &&
    Array.isArray(candidate.warnings)
  );
}

function extractValidation(value: unknown): ValidationResult | null {
  if (!value || typeof value !== "object") return null;

  const detail = value as { validation?: unknown };

  return isValidationResult(detail.validation) ? detail.validation : null;
}

function rulePayload(form: RuleFormState) {
  return {
    name: form.name,
    type: form.type,
    status: form.enabled ? "ACTIVE" : "DISABLED",
    scope: form.scope,
    matcher_kind: form.matcher_kind,
    matcher_value: form.matcher_value,
    reason: form.reason,
    owner: form.owner,
    enabled: form.enabled,
    description: form.description,
    metadata: form.metadata,
  };
}

function allInventoryItems(inventory: DetectionControlInventory | null) {
  if (!inventory) return [];

  return [
    ...inventory.rules.map((item) => ({ item, category: "rules" as const })),
    ...inventory.exceptions.map((item) => ({ item, category: "exceptions" as const })),
    ...inventory.telemetry_sources.map((item) => ({ item, category: "sources" as const })),
    ...inventory.policies.map((item) => ({ item, category: "policies" as const })),
    ...inventory.service_controls.map((item) => ({ item, category: "services" as const })),
  ];
}

function managedInventoryId(rule: ManagedRule) {
  const value = rule.metadata?.inventory_id;

  return typeof value === "string" ? value : null;
}

function categoryForManagedRule(rule: ManagedRule): InventoryCategory {
  const metadataCategory = rule.metadata?.inventory_category;

  if (
    metadataCategory === "rules" ||
    metadataCategory === "exceptions" ||
    metadataCategory === "sources" ||
    metadataCategory === "policies" ||
    metadataCategory === "services"
  ) {
    return metadataCategory;
  }

  if (rule.type === "DETECTION_RULE") return "rules";
  if (rule.type === "EXCEPTION" || rule.type === "NOISE_SUPPRESSION") return "exceptions";
  if (rule.type === "TELEMETRY_SOURCE") return "sources";
  if (rule.type === "SERVICE_CONTROL") return "services";

  return "policies";
}

function domainForManagedRule(rule: ManagedRule): ConfigDomain {
  if (rule.type === "NOISE_SUPPRESSION") return "noise_suppression";
  if (rule.type === "EXCEPTION") return "exceptions";
  if (rule.type === "DETECTION_RULE") return "detection_rules";

  return "source_controls";
}

function versionPayloadItem(rule: ManagedRule) {
  return {
    id: rule.id,
    name: rule.name,
    type: rule.type,
    status: rule.status,
    scope: rule.scope,
    matcher_kind: rule.matcher_kind,
    matcher_value: rule.matcher_value,
    reason: rule.reason,
    owner: rule.owner,
    enabled: rule.enabled,
    description: rule.description,
    metadata: rule.metadata || {},
  };
}

function proposedConfigItems(domain: ConfigDomain, rules: ManagedRule[]) {
  return rules
    .filter((rule) => domainForManagedRule(rule) === domain)
    .map(versionPayloadItem);
}

function typeForInventoryItem(item: InventoryItem, category: InventoryCategory): RuleType {
  if (category === "rules") return "DETECTION_RULE";
  if (category === "exceptions") return "EXCEPTION";
  if (category === "sources") return "TELEMETRY_SOURCE";
  if (category === "services") return "SERVICE_CONTROL";

  if (item.type.includes("NOISE_SUPPRESSION")) return "NOISE_SUPPRESSION";

  return "SOURCE_POLICY";
}

function enabledForInventoryItem(item: InventoryItem) {
  return ["ACTIVE", "OK"].includes(item.status.toUpperCase());
}

function inventoryItemForm(
  item: InventoryItem,
  category: InventoryCategory,
  owner: string
): RuleFormState {
  return {
    name: item.name,
    type: typeForInventoryItem(item, category),
    scope: item.scope || "global",
    matcher_kind: "EXACT",
    matcher_value: item.target || item.id,
    reason: item.reason || item.description || "Managed from Detection Control inventory.",
    owner,
    enabled: enabledForInventoryItem(item),
    description: item.description || "",
    metadata: {
      inventory_id: item.id,
      inventory_category: category,
      inventory_type: item.type,
      inventory_source: item.source,
      inventory_target: item.target,
    },
  };
}

function buildManagedByInventoryId(items: ManagedRule[]) {
  const map = new Map<string, ManagedRule>();

  for (const rule of items) {
    const inventoryId = managedInventoryId(rule);

    if (inventoryId) {
      map.set(inventoryId, rule);
    }
  }

  return map;
}

function isActiveStatus(status: string, enabled: boolean) {
  const normalized = status.toUpperCase();

  return enabled && (normalized === "ACTIVE" || normalized === "OK");
}

function isDisabledStatus(status: string, enabled: boolean) {
  const normalized = status.toUpperCase();

  return (
    !enabled ||
    normalized === "DISABLED" ||
    normalized === "READ_ONLY" ||
    normalized === "EMPTY"
  );
}

function isFailedStatus(status: string, validationStatus?: string | null) {
  const normalized = status.toUpperCase();
  const validation = (validationStatus || "").toUpperCase();

  return normalized === "ERROR" || normalized === "FAILED_VALIDATION" || validation === "ERROR";
}

export default function DetectionControlPlanePage() {
  const [inventory, setInventory] = useState<DetectionControlInventory | null>(null);
  const [managedRules, setManagedRules] = useState<ManagedRulesResponse | null>(null);
  const [versionHistory, setVersionHistory] = useState<ConfigVersion[]>([]);
  const [activeVersion, setActiveVersion] = useState<ConfigVersion | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("rules");
  const [selectedDomain, setSelectedDomain] = useState<ConfigDomain>("noise_suppression");
  const [form, setForm] = useState<RuleFormState>(emptyForm());
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [configValidation, setConfigValidation] = useState<ConfigValidationResult | null>(null);
  const [configDiff, setConfigDiff] = useState<ConfigDiff | null>(null);
  const [selectedVersionDetails, setSelectedVersionDetails] = useState<ConfigVersion | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [versionActionRunning, setVersionActionRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canView =
    currentUser?.role === "ADMIN" ||
    currentUser?.role === "ANALYST" ||
    currentUser?.role === "VIEWER";
  const canWrite = currentUser?.role === "ADMIN";
  const canValidateConfig = currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST";
  const canApplyConfig = currentUser?.role === "ADMIN";

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const storedUser = getStoredUser();
      setCurrentUser(storedUser);
      setForm(emptyForm(storedUser?.username || ""));

      fetchCurrentUser()
        .then((current) => {
          setCurrentUser(current);
          setForm((value) => ({
            ...value,
            owner: value.owner || current.username,
          }));
        })
        .catch(() => {
          // authFetch handles expired/invalid sessions globally.
        });
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  const loadData = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const [inventoryData, rulesData, versionsData, activeVersionData] = await Promise.all([
        fetchInventory(),
        fetchManagedRules(),
        fetchConfigVersions(selectedDomain),
        fetchActiveConfigVersion(selectedDomain),
      ]);

      setInventory(inventoryData);
      setManagedRules(rulesData);
      setVersionHistory(versionsData.items);
      setActiveVersion(activeVersionData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load detection control data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedDomain]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (currentUser && !canView) {
        setLoading(false);
        setError("Forbidden: Detection Control Plane is not available for this account.");
        return;
      }

      if (!currentUser) return;

      void loadData();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [currentUser, canView, loadData]);

  const activeInventoryItems = useMemo(() => {
    if (!inventory) return [];

    if (activeTab === "rules") {
      return inventory.rules.map((item) => ({ item, category: "rules" as const }));
    }
    if (activeTab === "exceptions") {
      return inventory.exceptions.map((item) => ({ item, category: "exceptions" as const }));
    }
    if (activeTab === "sources") {
      return inventory.telemetry_sources.map((item) => ({ item, category: "sources" as const }));
    }
    if (activeTab === "policies") {
      return inventory.policies.map((item) => ({ item, category: "policies" as const }));
    }

    return inventory.service_controls.map((item) => ({ item, category: "services" as const }));
  }, [activeTab, inventory]);

  const managedByInventoryId = useMemo(
    () => buildManagedByInventoryId(managedRules?.items || []),
    [managedRules]
  );

  const unifiedSummary = useMemo(() => {
    const rows = allInventoryItems(inventory);
    const standaloneManaged = (managedRules?.items || []).filter(
      (rule) => !managedInventoryId(rule)
    );
    const categoryCounts = {
      rules: 0,
      exceptions: 0,
      sources: 0,
      policies: 0,
      services: 0,
    };
    let active = 0;
    let disabled = 0;
    let failedValidation = 0;

    for (const { item, category } of rows) {
      categoryCounts[category] += 1;
      const managed = managedByInventoryId.get(item.id);
      const status = managed?.status || item.status;
      const enabled = managed ? managed.enabled : enabledForInventoryItem(item);

      if (isActiveStatus(status, enabled)) active += 1;
      if (isDisabledStatus(status, enabled)) disabled += 1;
      if (isFailedStatus(status, managed?.last_validation_status)) failedValidation += 1;
    }

    for (const rule of standaloneManaged) {
      categoryCounts[categoryForManagedRule(rule)] += 1;

      if (isActiveStatus(rule.status, rule.enabled)) active += 1;
      if (isDisabledStatus(rule.status, rule.enabled)) disabled += 1;
      if (isFailedStatus(rule.status, rule.last_validation_status)) failedValidation += 1;
    }

    return {
      total: rows.length + standaloneManaged.length,
      active,
      disabled,
      failed_validation: failedValidation,
      managed_overlays: managedByInventoryId.size,
      managed_standalone: standaloneManaged.length,
      ...categoryCounts,
    };
  }, [inventory, managedByInventoryId, managedRules]);

  const proposedItems = useMemo(
    () => proposedConfigItems(selectedDomain, managedRules?.items || []),
    [managedRules, selectedDomain]
  );
  const proposedConfigSignature = useMemo(
    () => JSON.stringify(proposedItems),
    [proposedItems]
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setConfigValidation(null);
      setConfigDiff(null);
      setSelectedVersionDetails(null);
    }, 0);

    return () => window.clearTimeout(timer);
  }, [selectedDomain, proposedConfigSignature]);

  async function handleApiError(response: Response) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null;
    const detail = body?.detail;

    if (detail && typeof detail === "object") {
      const validation = extractValidation(detail);

      if (validation) {
        setValidationResult(validation);
      }

      const message = "message" in detail ? String(detail.message) : null;

      throw new Error(message || `API returned ${response.status}`);
    }

    throw new Error(typeof detail === "string" ? detail : `API returned ${response.status}`);
  }

  async function submitForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!canWrite) return;

    try {
      setSaving(true);
      setError(null);

      const response = await authFetch(
        editingRuleId
          ? `/detection-control/rules/${encodeURIComponent(editingRuleId)}`
          : "/detection-control/rules",
        {
          method: editingRuleId ? "PATCH" : "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(rulePayload(form)),
        }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as RuleMutationResponse;
      setValidationResult(result.validation || null);
      setEditingRuleId(result.rule.id);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save rule");
    } finally {
      setSaving(false);
    }
  }

  function startCreate() {
    setEditingRuleId(null);
    setValidationResult(null);
    setForm(emptyForm(currentUser?.username || ""));
  }

  function startEdit(rule: ManagedRule) {
    setEditingRuleId(rule.id);
    setValidationResult({
      valid: rule.last_validation_status !== "ERROR",
      severity: rule.last_validation_status || "OK",
      messages: rule.last_validation_status === "ERROR" && rule.last_validation_message
        ? [rule.last_validation_message]
        : [],
      warnings: rule.last_validation_status === "WARNING" && rule.last_validation_message
        ? [rule.last_validation_message]
        : [],
    });
    setForm({
      name: rule.name,
      type: rule.type,
      scope: rule.scope,
      matcher_kind: rule.matcher_kind,
      matcher_value: rule.matcher_value,
      reason: rule.reason,
      owner: rule.owner,
      enabled: rule.enabled,
      description: rule.description || "",
      metadata: rule.metadata || {},
    });
  }

  function startManageInventoryItem(item: InventoryItem, category: InventoryCategory) {
    const existingRule = managedByInventoryId.get(item.id);

    if (existingRule) {
      startEdit(existingRule);
      return;
    }

    setEditingRuleId(null);
    setValidationResult(null);
    setForm(inventoryItemForm(item, category, currentUser?.username || ""));
  }

  async function validateRule(rule: ManagedRule) {
    if (!canWrite) return;

    try {
      setSaving(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/rules/${encodeURIComponent(rule.id)}/validate`,
        { method: "POST" }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as RuleMutationResponse;
      setValidationResult(result.validation || null);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to validate rule");
    } finally {
      setSaving(false);
    }
  }

  async function setRuleEnabled(rule: ManagedRule, enabled: boolean) {
    if (!canWrite) return;

    try {
      setSaving(true);
      setError(null);

      const action = enabled ? "enable" : "disable";
      const response = await authFetch(
        `/detection-control/rules/${encodeURIComponent(rule.id)}/${action}`,
        { method: "POST" }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update rule state");
    } finally {
      setSaving(false);
    }
  }

  async function archiveRule(rule: ManagedRule) {
    if (!canWrite) return;

    const confirmed = window.confirm(`Archive ${rule.name}?`);

    if (!confirmed) return;

    try {
      setSaving(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/rules/${encodeURIComponent(rule.id)}`,
        { method: "DELETE" }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      if (editingRuleId === rule.id) {
        startCreate();
      }

      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to archive rule");
    } finally {
      setSaving(false);
    }
  }

  async function validateSelectedConfig() {
    if (!canValidateConfig) return;

    try {
      setVersionActionRunning(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/config-versions/${selectedDomain}/validate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ items: proposedItems }),
        }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as ConfigValidationResult;
      setConfigValidation(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to validate config");
    } finally {
      setVersionActionRunning(false);
    }
  }

  async function previewSelectedDiff() {
    if (!canValidateConfig) return;

    try {
      setVersionActionRunning(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/config-versions/${selectedDomain}/diff`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ items: proposedItems }),
        }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as ConfigDiff;
      setConfigDiff(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to preview diff");
    } finally {
      setVersionActionRunning(false);
    }
  }

  async function viewVersionDetails(version: ConfigVersion) {
    try {
      setVersionActionRunning(true);
      setError(null);

      const result = await fetchConfigVersion(selectedDomain, version.version_number);
      setSelectedVersionDetails(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load version details");
    } finally {
      setVersionActionRunning(false);
    }
  }

  async function applySelectedConfig() {
    if (!canApplyConfig || !configValidation?.valid) return;

    const reason = window.prompt("Reason for applying this detection configuration version:");

    if (!reason) return;

    const confirmed = window.confirm(
      `Apply ${CONFIG_DOMAIN_LABELS[selectedDomain]} as a new active version?`
    );

    if (!confirmed) return;

    try {
      setVersionActionRunning(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/config-versions/${selectedDomain}/apply`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            items: proposedItems,
            reason,
          }),
        }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as {
        validation: ConfigValidationResult;
        diff: ConfigDiff;
      };
      setConfigValidation(result.validation);
      setConfigDiff(result.diff);
      setSelectedVersionDetails(null);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to apply config");
    } finally {
      setVersionActionRunning(false);
    }
  }

  async function rollbackToVersion(version: ConfigVersion) {
    if (!canApplyConfig) return;

    const reason = window.prompt(
      `Reason for rollback to version ${version.version_number}:`
    );

    if (!reason) return;

    const confirmed = window.confirm(
      `You are about to restore version ${version.version_number} as a new active version. This may require service restart to take effect.`
    );

    if (!confirmed) return;

    try {
      setVersionActionRunning(true);
      setError(null);

      const response = await authFetch(
        `/detection-control/config-versions/${selectedDomain}/rollback`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            version_number: version.version_number,
            reason,
          }),
        }
      );

      if (!response.ok) {
        await handleApiError(response);
      }

      const result = (await response.json()) as {
        validation: ConfigValidationResult;
        diff: ConfigDiff;
      };
      setConfigValidation(result.validation);
      setConfigDiff(result.diff);
      setSelectedVersionDetails(null);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to rollback config");
    } finally {
      setVersionActionRunning(false);
    }
  }

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
              <SlidersHorizontal className="h-3.5 w-3.5" />
              Settings
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              Detection Control Plane
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Governed management for detection suppressions, exceptions, rules and
              source policies, with admin-only writes and security audit coverage.
            </p>
          </div>

          <button
            onClick={loadData}
            disabled={!canView || refreshing}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            API error: {error}
          </div>
        )}

        {loading ? (
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
            Loading detection control plane...
          </section>
        ) : managedRules && inventory && canView ? (
          <div className="space-y-3">
            <section className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-6">
              <MetricCard
                title="Unified Inventory"
                value={unifiedSummary.total}
                subtitle={`${unifiedSummary.active} active / ${unifiedSummary.disabled} disabled`}
                icon={<FileCog className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Rules"
                value={unifiedSummary.rules}
                subtitle="Detected and managed"
                icon={<Shield className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Exceptions"
                value={unifiedSummary.exceptions}
                subtitle="Suppressions and exceptions"
                icon={<Ban className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Sources"
                value={unifiedSummary.sources}
                subtitle="Telemetry inputs"
                icon={<ServerCog className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Policies"
                value={unifiedSummary.policies}
                subtitle={`${unifiedSummary.services} service controls`}
                icon={<SlidersHorizontal className="h-3.5 w-3.5" />}
              />
              <MetricCard
                title="Failed Validation"
                value={unifiedSummary.failed_validation}
                subtitle={formatDate(managedRules.summary.generated_at)}
                icon={<AlertTriangle className="h-3.5 w-3.5" />}
              />
            </section>

            {!canWrite && (
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 text-xs text-slate-300">
                <div className="flex items-start gap-2">
                  <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
                  <p className="leading-5">
                    {currentUser?.role} access is read-only for detection-control changes.
                    ADMIN role is required to create, edit, enable, disable, validate or archive entries.
                  </p>
                </div>
              </section>
            )}

            <VersionGovernancePanel
              activeVersion={activeVersion}
              canApply={Boolean(canApplyConfig)}
              canValidate={Boolean(canValidateConfig)}
              diff={configDiff}
              domain={selectedDomain}
              history={versionHistory}
              proposedCount={proposedItems.length}
              running={versionActionRunning}
              selectedVersion={selectedVersionDetails}
              validation={configValidation}
              onApply={applySelectedConfig}
              onChangeDomain={setSelectedDomain}
              onCloseVersionDetails={() => setSelectedVersionDetails(null)}
              onDiff={previewSelectedDiff}
              onRollback={rollbackToVersion}
              onValidate={validateSelectedConfig}
              onViewVersion={viewVersionDetails}
            />

            <LifecyclePanelBoundary>
              <LifecyclePanel currentUser={currentUser} onConfigChanged={loadData} />
            </LifecyclePanelBoundary>

            <section id="service-operations" className="scroll-mt-4">
              <ServiceOperationsPanel
                currentUser={currentUser}
                relatedConfigVersion={
                  activeVersion
                    ? {
                        id: activeVersion.id,
                        version_number: activeVersion.version_number,
                        requires_restart: activeVersion.requires_restart,
                        affected_services: activeVersion.affected_services,
                      }
                    : null
                }
              />
            </section>

            <section className="grid gap-3 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.55fr)]">
              <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <div className="mb-3 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-slate-100">
                      Managed Control Entries
                    </h2>
                    <p className="mt-1 text-xs text-slate-500">
                      Entries created directly or linked from inventory share the same validation, RBAC and audit path.
                    </p>
                  </div>

                  {canWrite && (
                    <button
                      type="button"
                      onClick={startCreate}
                      className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      New Entry
                    </button>
                  )}
                </div>

                <ManagedRulesTable
                  canWrite={Boolean(canWrite)}
                  items={managedRules.items}
                  saving={saving}
                  onArchive={archiveRule}
                  onEdit={startEdit}
                  onToggle={setRuleEnabled}
                  onValidate={validateRule}
                />
              </div>

              <div className="min-w-0 space-y-3">
                <RuleForm
                  canWrite={Boolean(canWrite)}
                  editingRuleId={editingRuleId}
                  form={form}
                  saving={saving}
                  onChange={setForm}
                  onReset={startCreate}
                  onSubmit={submitForm}
                />

                <ValidationPanel result={validationResult} />
              </div>
            </section>

            <section className="rounded-lg border border-amber-900/70 bg-amber-950/30 p-3 text-xs text-amber-100">
              <div className="flex items-start gap-2">
                <ServerCog className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <p className="leading-5">
                  Entries may require apply or service restart depending on source policy and
                  affected service. Use Service Operations for governed restart after applying configuration changes.
                </p>
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-2">
              <div className="mb-2 flex items-center gap-2 px-1 text-xs text-slate-400">
                <Eye className="h-3.5 w-3.5" />
                Existing Detection Control inventory
              </div>

              <div className="mb-2 flex flex-wrap gap-1.5">
                {TABS.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition ${
                      activeTab === tab.key
                        ? "border-cyan-500 bg-cyan-500 text-slate-950"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-600 hover:text-cyan-200"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <InventoryTable
                canWrite={Boolean(canWrite)}
                items={activeInventoryItems}
                managedByInventoryId={managedByInventoryId}
                saving={saving}
                onEditManaged={startEdit}
                onManageInventory={startManageInventoryItem}
              />
            </section>
          </div>
        ) : null}
      </div>
    </main>
  );
}

function VersionGovernancePanel({
  activeVersion,
  canApply,
  canValidate,
  diff,
  domain,
  history,
  proposedCount,
  running,
  selectedVersion,
  validation,
  onApply,
  onChangeDomain,
  onCloseVersionDetails,
  onDiff,
  onRollback,
  onValidate,
  onViewVersion,
}: {
  activeVersion: ConfigVersion | null;
  canApply: boolean;
  canValidate: boolean;
  diff: ConfigDiff | null;
  domain: ConfigDomain;
  history: ConfigVersion[];
  proposedCount: number;
  running: boolean;
  selectedVersion: ConfigVersion | null;
  validation: ConfigValidationResult | null;
  onApply: () => void;
  onChangeDomain: (domain: ConfigDomain) => void;
  onCloseVersionDetails: () => void;
  onDiff: () => void;
  onRollback: (version: ConfigVersion) => void;
  onValidate: () => void;
  onViewVersion: (version: ConfigVersion) => void;
}) {
  const applyEnabled = Boolean(canApply && validation?.valid && diff);

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Configuration Versioning
          </h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            Validate and preview changes before creating a new active configuration version.
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {CONFIG_DOMAINS.map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => onChangeDomain(item)}
              className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition ${
                domain === item
                  ? "border-cyan-500 bg-cyan-500 text-slate-950"
                  : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-600 hover:text-cyan-200"
              }`}
            >
              {CONFIG_DOMAIN_LABELS[item]}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,0.75fr)_minmax(0,1.25fr)]">
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
            Active Configuration
          </div>

          {activeVersion ? (
            <div className="grid gap-2 text-xs">
              <InfoRow label="Domain" value={CONFIG_DOMAIN_LABELS[domain]} />
              <InfoRow label="Version" value={`v${activeVersion.version_number}`} />
              <InfoRow label="Checksum" value={activeVersion.checksum_short || "-"} />
              <InfoRow label="Activated" value={formatDate(activeVersion.activated_at)} />
              <InfoRow label="Activated by" value={activeVersion.activated_by || "-"} />
              <InfoRow label="Validation" value={activeVersion.validation_status || "-"} />
              <InfoRow
                label="Restart"
                value={activeVersion.requires_restart ? "required" : "not required"}
              />
            </div>
          ) : (
            <div className="text-xs text-slate-500">No active version yet.</div>
          )}

          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onValidate}
              disabled={!canValidate || running}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 hover:border-emerald-700 hover:text-emerald-200 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              Validate
            </button>
            <button
              type="button"
              onClick={onDiff}
              disabled={!canValidate || running}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Eye className="h-3.5 w-3.5" />
              Preview diff
            </button>
            <button
              type="button"
              onClick={onApply}
              disabled={!applyEnabled || running}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              Apply version
            </button>
          </div>

          <div className="mt-2 text-[11px] text-slate-500">
            Proposed entries in this domain: {proposedCount}
          </div>
        </div>

        <div className="grid gap-3 lg:grid-cols-2">
          <ConfigValidationPanel result={validation} />
          <ConfigDiffPanel diff={diff} />
        </div>
      </div>

      <VersionHistoryTable
        canApply={canApply}
        history={history}
        running={running}
        onRollback={onRollback}
        onViewVersion={onViewVersion}
      />

      {selectedVersion && (
        <VersionDetailsPanel
          version={selectedVersion}
          onClose={onCloseVersionDetails}
        />
      )}
    </section>
  );
}

function InfoRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-2">
      <span className="text-slate-500">{label}</span>
      <span className="min-w-0 truncate text-slate-200">{value}</span>
    </div>
  );
}

function ConfigValidationPanel({ result }: { result: ConfigValidationResult | null }) {
  if (!result) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
        Run validation before applying a version.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
          Validation
        </div>
        <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(result.severity)}`}>
          {result.valid ? "valid" : "blocked"} / {result.severity}
        </span>
      </div>

      <div className="mb-2 text-[11px] text-slate-500">
        {result.requires_restart
          ? `Restart required: ${result.affected_services.join(", ")}`
          : "No restart flagged"}
      </div>

      {result.messages.length > 0 && (
        <FindingList title="Blocking errors" tone="red" items={result.messages} />
      )}

      {result.warnings.length > 0 && (
        <FindingList title="Warnings" tone="amber" items={result.warnings} />
      )}

      {result.messages.length === 0 && result.warnings.length === 0 && (
        <div className="text-xs text-slate-500">No validation findings.</div>
      )}
    </div>
  );
}

function ConfigDiffPanel({ diff }: { diff: ConfigDiff | null }) {
  if (!diff) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
        Preview diff to compare proposed config against the active version.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
        Diff Preview
      </div>

      <div className="mb-2 grid grid-cols-3 gap-1.5 text-xs">
        <DiffCount label="Added" value={diff.summary.added_count} />
        <DiffCount label="Removed" value={diff.summary.removed_count} />
        <DiffCount label="Modified" value={diff.summary.modified_count} />
      </div>

      <div className="max-h-40 overflow-auto rounded-md border border-slate-800 bg-slate-900 p-2 text-[11px] text-slate-400">
        {diff.summary.added_count + diff.summary.removed_count + diff.summary.modified_count > 0 ? (
          <div className="space-y-2.5">
            {diff.added.length > 0 && (
              <DiffItemList title="Added" items={diff.added} />
            )}
            {diff.removed.length > 0 && (
              <DiffItemList title="Removed" items={diff.removed} />
            )}
            {diff.modified.slice(0, 6).map((item) => (
              <div key={item.rule_id}>
                <div className="font-medium text-slate-200">
                  {item.name || item.rule_id}
                </div>
                <div className="mt-1 text-slate-500">
                  {Object.keys(item.changes).join(", ")}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div>No field-level changes.</div>
        )}
      </div>
    </div>
  );
}

function DiffItemList({
  title,
  items,
}: {
  title: string;
  items: Array<Record<string, unknown>>;
}) {
  return (
    <div>
      <div className="font-medium text-slate-200">{title}</div>
      <div className="mt-1 text-slate-500">
        {items.slice(0, 6).map(diffItemLabel).join(", ")}
        {items.length > 6 ? ` +${items.length - 6} more` : ""}
      </div>
    </div>
  );
}

function diffItemLabel(item: Record<string, unknown>) {
  return String(item.name || item.id || item.type || "unnamed");
}

function DiffCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-900 p-2">
      <div className="text-[11px] text-slate-500">{label}</div>
      <div className="mt-1 text-sm font-semibold text-slate-100">{value}</div>
    </div>
  );
}

function FindingList({
  title,
  tone,
  items,
}: {
  title: string;
  tone: "red" | "amber";
  items: string[];
}) {
  const className =
    tone === "red"
      ? "border-red-900/70 bg-red-950/30 text-red-100"
      : "border-amber-900/70 bg-amber-950/30 text-amber-100";

  return (
    <div className={`mb-2 rounded-lg border p-2 text-xs ${className}`}>
      <div className="mb-1 font-medium">{title}</div>
      <ul className="space-y-1">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function VersionDetailsPanel({
  version,
  onClose,
}: {
  version: ConfigVersion;
  onClose: () => void;
}) {
  const payloadItems = version.config_payload?.items || [];
  const diffSummary = version.diff_summary?.summary;

  return (
    <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">
            Version v{version.version_number} Details
          </h3>
          <div className="mt-1 text-xs text-slate-500">
            {CONFIG_DOMAIN_LABELS[version.config_domain]} / {version.checksum_short || "-"}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-900 px-2 text-[11px] text-slate-300 hover:text-slate-100"
        >
          <XCircle className="h-3.5 w-3.5" />
          Close
        </button>
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <div className="rounded-md border border-slate-800 bg-slate-900 p-2 text-xs">
          <InfoRow label="Status" value={version.status} />
          <InfoRow label="Created" value={formatDate(version.created_at)} />
          <InfoRow label="Created by" value={version.created_by || "-"} />
          <InfoRow label="Activated" value={formatDate(version.activated_at)} />
          <InfoRow label="Activated by" value={version.activated_by || "-"} />
          <InfoRow
            label="Rollback of"
            value={version.rollback_of_version_id ? `#${version.rollback_of_version_id}` : "-"}
          />
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-900 p-2 text-xs">
          <div className="mb-2 font-medium text-slate-300">Validation</div>
          <InfoRow label="Status" value={version.validation_status || "-"} />
          <InfoRow label="Errors" value={version.validation_errors.length} />
          <InfoRow label="Warnings" value={version.validation_warnings.length} />
          <InfoRow
            label="Restart"
            value={version.requires_restart ? version.affected_services.join(", ") : "not required"}
          />
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-900 p-2 text-xs">
          <div className="mb-2 font-medium text-slate-300">Diff</div>
          {diffSummary ? (
            <div className="grid grid-cols-3 gap-1.5">
              <DiffCount label="Added" value={diffSummary.added_count} />
              <DiffCount label="Removed" value={diffSummary.removed_count} />
              <DiffCount label="Modified" value={diffSummary.modified_count} />
            </div>
          ) : (
            <div className="text-slate-500">Baseline or no diff recorded.</div>
          )}
        </div>
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div className="rounded-md border border-slate-800 bg-slate-900 p-2 text-xs">
          <div className="mb-2 font-medium text-slate-300">Reason</div>
          <div className="leading-5 text-slate-500">{version.created_reason || "-"}</div>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-900 p-2 text-xs">
          <div className="mb-2 font-medium text-slate-300">
            Payload Entries ({payloadItems.length})
          </div>
          {payloadItems.length > 0 ? (
            <div className="max-h-28 overflow-auto text-slate-500">
              {payloadItems.slice(0, 10).map((item) => (
                <div key={item.id} className="truncate">
                  {item.name} / {item.type}
                </div>
              ))}
              {payloadItems.length > 10 && (
                <div>+{payloadItems.length - 10} more</div>
              )}
            </div>
          ) : (
            <div className="text-slate-500">No entries in payload.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function VersionHistoryTable({
  canApply,
  history,
  running,
  onRollback,
  onViewVersion,
}: {
  canApply: boolean;
  history: ConfigVersion[];
  running: boolean;
  onRollback: (version: ConfigVersion) => void;
  onViewVersion: (version: ConfigVersion) => void;
}) {
  return (
    <div className="mt-3 overflow-hidden rounded-lg border border-slate-800">
      <div className="border-b border-slate-800 bg-slate-950 px-3 py-2 text-xs font-medium uppercase tracking-wide text-slate-500">
        Version History
      </div>
      <div className="max-h-[220px] overflow-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="sticky top-0 z-10 bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Version</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Created</th>
              <th className="px-3 py-2">Activated</th>
              <th className="px-3 py-2">Reason</th>
              <th className="px-3 py-2">Validation</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {history.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-3 py-3 text-slate-500">
                  No version history found.
                </td>
              </tr>
            ) : (
              history.map((version) => (
                <tr key={version.id} className="align-top hover:bg-slate-800/40">
                  <td className="px-3 py-2 text-slate-200">v{version.version_number}</td>
                  <td className="px-3 py-2">
                    <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(version.status)}`}>
                      {version.status}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-slate-300">{formatDate(version.created_at)}</div>
                    <div className="mt-1 text-slate-500">{version.created_by || "-"}</div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-slate-300">{formatDate(version.activated_at)}</div>
                    <div className="mt-1 text-slate-500">{version.activated_by || "-"}</div>
                  </td>
                  <td className="max-w-xs px-3 py-2 text-slate-500">
                    {version.created_reason || "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-300">
                    {version.validation_status || "-"}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex min-w-[160px] flex-wrap gap-1.5">
                      <button
                        type="button"
                        onClick={() => onViewVersion(version)}
                        disabled={running}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        Details
                      </button>
                      {canApply && version.status !== "ACTIVE" && (
                        <button
                          type="button"
                          onClick={() => onRollback(version)}
                          disabled={running}
                          className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-amber-700 hover:text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <RefreshCw className="h-3.5 w-3.5" />
                          Rollback
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  subtitle,
  icon,
}: {
  title: string;
  value: ReactNode;
  subtitle: string;
  icon: ReactNode;
}) {
  return (
    <article className="flex min-h-[46px] items-center justify-between gap-2 rounded-sm border border-slate-800 bg-slate-900 px-2 py-1.5 shadow-sm">
      <div className="min-w-0">
        <div className="truncate text-[9px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className="mt-0.5 flex min-w-0 items-baseline gap-1.5">
          <span className="text-base font-semibold leading-5 text-slate-100">
            {value}
          </span>
          <span className="min-w-0 truncate text-[10px] leading-3 text-slate-500">
            {subtitle}
          </span>
        </div>
      </div>
      <div className="shrink-0 rounded-sm bg-slate-950 p-1 text-slate-400">
        {icon}
      </div>
    </article>
  );
}

function ManagedRulesTable({
  canWrite,
  items,
  saving,
  onArchive,
  onEdit,
  onToggle,
  onValidate,
}: {
  canWrite: boolean;
  items: ManagedRule[];
  saving: boolean;
  onArchive: (rule: ManagedRule) => void;
  onEdit: (rule: ManagedRule) => void;
  onToggle: (rule: ManagedRule, enabled: boolean) => void;
  onValidate: (rule: ManagedRule) => void;
}) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No managed entries have been created yet.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Scope</th>
              <th className="px-3 py-2">Enabled / Status</th>
              <th className="px-3 py-2">Owner</th>
              <th className="px-3 py-2">Last Validation</th>
              <th className="px-3 py-2">Updated</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {items.map((rule) => (
              <tr key={rule.id} className="align-top hover:bg-slate-800/40">
                <td className="px-3 py-2 text-slate-300">{rule.type}</td>
                <td className="max-w-sm px-3 py-2">
                  <div className="font-medium text-slate-100">{rule.name}</div>
                  <div className="mt-1 leading-5 text-slate-500">{rule.reason}</div>
                  {rule.requires_apply && (
                    <div className="mt-1 text-[11px] text-amber-300">
                      Apply required: {rule.affected_service || "service policy"}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2">
                  <div className="text-slate-300">{rule.scope}</div>
                  <div className="mt-1 max-w-[220px] truncate text-slate-500" title={rule.matcher_value}>
                    {rule.matcher_kind}: {rule.matcher_value}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="mb-1 text-slate-300">{rule.enabled ? "enabled" : "disabled"}</div>
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(rule.status)}`}>
                    {rule.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-300">{rule.owner}</td>
                <td className="max-w-xs px-3 py-2">
                  <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(rule.last_validation_status || "OK")}`}>
                    {rule.last_validation_status || "OK"}
                  </span>
                  <div className="mt-1 leading-5 text-slate-500">
                    {rule.last_validation_message || "Validation not run yet."}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="text-slate-300">{formatDate(rule.updated_at)}</div>
                  <div className="mt-1 text-slate-500">{rule.updated_by || rule.created_by || "-"}</div>
                </td>
                <td className="px-3 py-2">
                  {canWrite ? (
                    <div className="flex min-w-[170px] flex-wrap gap-1.5">
                      <button
                        type="button"
                        onClick={() => onEdit(rule)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => onValidate(rule)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-emerald-700 hover:text-emerald-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Validate
                      </button>
                      <button
                        type="button"
                        onClick={() => onToggle(rule, !rule.enabled)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-amber-700 hover:text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Power className="h-3.5 w-3.5" />
                        {rule.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        onClick={() => onArchive(rule)}
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-red-800 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Archive
                      </button>
                    </div>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-slate-500">
                      <Lock className="h-3.5 w-3.5" />
                      Read-only
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleForm({
  canWrite,
  editingRuleId,
  form,
  saving,
  onChange,
  onReset,
  onSubmit,
}: {
  canWrite: boolean;
  editingRuleId: string | null;
  form: RuleFormState;
  saving: boolean;
  onChange: (value: RuleFormState) => void;
  onReset: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form onSubmit={onSubmit} className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-100">
          {editingRuleId ? "Edit Entry" : "Create Entry"}
        </h2>
        {editingRuleId && (
          <button
            type="button"
            onClick={onReset}
            className="text-xs text-cyan-300 hover:text-cyan-200"
          >
            Clear
          </button>
        )}
      </div>

      <div className="grid gap-2">
        <Field label="Name">
          <input
            value={form.name}
            onChange={(event) => onChange({ ...form, name: event.target.value })}
            disabled={!canWrite || saving}
            className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>

        <div className="grid gap-2 sm:grid-cols-2">
          <Field label="Type">
            <select
              value={form.type}
              onChange={(event) => onChange({ ...form, type: event.target.value as RuleType })}
              disabled={!canWrite || saving}
              className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {RULE_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </Field>

          <Field label="Scope">
            <input
              value={form.scope}
              onChange={(event) => onChange({ ...form, scope: event.target.value })}
              disabled={!canWrite || saving}
              className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
            />
          </Field>
        </div>

        <Field label="Matcher Kind">
          <select
            value={form.matcher_kind}
            onChange={(event) => onChange({ ...form, matcher_kind: event.target.value as MatcherKind })}
            disabled={!canWrite || saving}
            className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {MATCHER_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Matcher Value">
          <textarea
            value={form.matcher_value}
            onChange={(event) => onChange({ ...form, matcher_value: event.target.value })}
            disabled={!canWrite || saving}
            rows={4}
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>

        <Field label="Reason">
          <textarea
            value={form.reason}
            onChange={(event) => onChange({ ...form, reason: event.target.value })}
            disabled={!canWrite || saving}
            rows={3}
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>

        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
          <Field label="Owner">
            <input
              value={form.owner}
              onChange={(event) => onChange({ ...form, owner: event.target.value })}
              disabled={!canWrite || saving}
              className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
            />
          </Field>

          <label className="flex h-full min-h-14 items-end gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => onChange({ ...form, enabled: event.target.checked })}
              disabled={!canWrite || saving}
              className="mb-2 h-4 w-4 rounded border-slate-700 bg-slate-950"
            />
            <span className="mb-2">Enabled</span>
          </label>
        </div>

        <Field label="Description">
          <textarea
            value={form.description}
            onChange={(event) => onChange({ ...form, description: event.target.value })}
            disabled={!canWrite || saving}
            rows={2}
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs leading-5 text-slate-100 outline-none focus:border-cyan-600 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </Field>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="submit"
          disabled={!canWrite || saving}
          className="flex h-8 items-center gap-1.5 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Save className="h-3.5 w-3.5" />
          {editingRuleId ? "Save" : "Create"}
        </button>
        <button
          type="button"
          onClick={onReset}
          disabled={saving}
          className="h-8 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Reset
        </button>
      </div>
    </form>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="grid gap-1 text-xs text-slate-400">
      <span>{label}</span>
      {children}
    </label>
  );
}

function ValidationPanel({ result }: { result: ValidationResult | null }) {
  if (!result) {
    return (
      <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 text-xs text-slate-500">
        Validation result will appear after save or validate.
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-100">Validation Result</h2>
        <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(result.severity)}`}>
          {result.valid ? "valid" : "invalid"} / {result.severity}
        </span>
      </div>

      {result.messages.length > 0 && (
        <div className="mb-2 rounded-lg border border-red-900/70 bg-red-950/30 p-2 text-xs text-red-100">
          <div className="mb-1 font-medium">Errors</div>
          <ul className="space-y-1">
            {result.messages.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        </div>
      )}

      {result.warnings.length > 0 && (
        <div className="rounded-lg border border-amber-900/70 bg-amber-950/30 p-2 text-xs text-amber-100">
          <div className="mb-1 font-medium">Warnings</div>
          <ul className="space-y-1">
            {result.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </div>
      )}

      {result.messages.length === 0 && result.warnings.length === 0 && (
        <div className="text-xs text-slate-500">No validation findings.</div>
      )}
    </section>
  );
}

function InventoryTable({
  canWrite,
  items,
  managedByInventoryId,
  saving,
  onEditManaged,
  onManageInventory,
}: {
  canWrite: boolean;
  items: Array<{ item: InventoryItem; category: InventoryCategory }>;
  managedByInventoryId: Map<string, ManagedRule>;
  saving: boolean;
  onEditManaged: (rule: ManagedRule) => void;
  onManageInventory: (item: InventoryItem, category: InventoryCategory) => void;
}) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-500">
        No inventory items found for this section.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
          <thead className="bg-slate-950 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Scope / Target</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Governed</th>
              <th className="px-3 py-2">Reload</th>
              <th className="px-3 py-2">Metadata</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900">
            {items.map(({ item, category }) => {
              const managedRule = managedByInventoryId.get(item.id);
              const status = managedRule?.status || item.status;
              const validationStatus = managedRule?.last_validation_status;

              return (
                <tr key={item.id} className="align-top hover:bg-slate-800/40">
                  <td className="max-w-sm px-3 py-2">
                    <div className="font-medium text-slate-100">{item.name}</div>
                    <div className="mt-1 leading-5 text-slate-500">{item.description}</div>
                    <div className="mt-1 leading-5 text-slate-600">{item.reason}</div>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${sourceTone(item.source)}`}>
                      {item.source}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-slate-300">{item.type}</div>
                    <div className="mt-1 text-slate-500">{category}</div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-slate-300">{item.scope}</div>
                    <div className="mt-1 max-w-xs truncate text-slate-500" title={item.target}>
                      {item.target}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] ${statusTone(status)}`}>
                      {status}
                    </span>
                    {validationStatus && (
                      <div className="mt-1 text-[11px] text-slate-500">
                        validation: {validationStatus}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {managedRule ? (
                      <span className="inline-flex items-center gap-1 text-emerald-300">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        linked
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-slate-500">
                        <XCircle className="h-3.5 w-3.5" />
                        inventory
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-300">
                    {item.requires_reload || managedRule?.requires_apply ? "required" : "no"}
                  </td>
                  <td className="max-w-xs px-3 py-2 text-slate-500">
                    {metadataPreview(managedRule?.metadata || item.metadata)}
                  </td>
                  <td className="px-3 py-2">
                    {canWrite ? (
                      <button
                        type="button"
                        onClick={() =>
                          managedRule
                            ? onEditManaged(managedRule)
                            : onManageInventory(item, category)
                        }
                        disabled={saving}
                        className="flex h-7 items-center gap-1 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 hover:border-cyan-700 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                        {managedRule ? "Edit" : "Manage"}
                      </button>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-slate-500">
                        <Lock className="h-3.5 w-3.5" />
                        Read-only
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
