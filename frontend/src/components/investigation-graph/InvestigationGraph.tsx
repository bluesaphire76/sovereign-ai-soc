"use client";

import { authFetch } from "@/lib/auth";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  Brain,
  Database,
  Filter,
  GitBranch,
  Network,
  RefreshCw,
  Search,
  Shield,
  X,
} from "lucide-react";

type GraphScope = "incident" | "case";

type EvidenceRef = {
  type: string;
  id: string;
  summary: string;
};

type GraphNode = {
  id: string;
  type: string;
  label: string;
  subtitle?: string | null;
  severity?: string | null;
  confidence: string;
  source: string;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  count: number;
  metadata: Record<string, unknown>;
  evidence_refs?: EvidenceRef[];
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  confidence: string;
  weight: number;
  evidence_count: number;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  evidence_refs: EvidenceRef[];
};

type GraphPayload = {
  scope: GraphScope;
  scope_id: number;
  generated_at: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: {
    node_count: number;
    edge_count: number;
    entity_count: number;
    highest_severity?: string | null;
    primary_entities: string[];
    warnings: string[];
    graph_quality?: string;
    hosts?: number;
    users?: number;
    ips?: number;
    mitre_techniques?: number;
    alerts?: number;
    raw_events?: number;
    ai_hypotheses?: number;
  };
  filters: {
    available_node_types: string[];
    available_edge_types: string[];
  };
  redaction: {
    applied: boolean;
    reason?: string | null;
  };
};

type InvestigationGraphProps = {
  scope: GraphScope;
  scopeId: number | string;
};

type LaneKey = "scope" | "evidence" | "entities" | "context";

type Lane = {
  key: LaneKey;
  title: string;
  description: string;
};

const LANES: Lane[] = [
  {
    key: "scope",
    title: "Scope",
    description: "Incident or case anchor.",
  },
  {
    key: "evidence",
    title: "Evidence",
    description: "Alerts, raw events and aggregates.",
  },
  {
    key: "entities",
    title: "Entities",
    description: "Hosts, users, IPs and artifacts.",
  },
  {
    key: "context",
    title: "Context",
    description: "MITRE, rules, timeline and AI.",
  },
];

const NODE_TYPE_LANE: Record<string, LaneKey> = {
  INCIDENT: "scope",
  CASE: "scope",
  SECURITY_ALERT: "evidence",
  RAW_EVENT: "evidence",
  EVENT_AGGREGATE: "evidence",
  HOST: "entities",
  USER: "entities",
  SOURCE_IP: "entities",
  DESTINATION_IP: "entities",
  PROCESS: "entities",
  FILE: "entities",
  PACKAGE: "entities",
  MITRE_TECHNIQUE: "context",
  DETECTION_RULE: "context",
  NOISE_SUPPRESSION: "context",
  EXCEPTION: "context",
  AI_HYPOTHESIS: "context",
  AI_ANALYSIS: "context",
  TIMELINE_EVENT: "context",
};

const NODE_STYLES: Record<string, { border: string; badge: string; marker: string }> = {
  INCIDENT: {
    border: "border-blue-800 bg-blue-950/25",
    badge: "border-blue-700 bg-blue-950 text-blue-200",
    marker: "bg-blue-500",
  },
  CASE: {
    border: "border-violet-800 bg-violet-950/25",
    badge: "border-violet-700 bg-violet-950 text-violet-200",
    marker: "bg-violet-500",
  },
  SECURITY_ALERT: {
    border: "border-amber-800 bg-amber-950/20",
    badge: "border-amber-700 bg-amber-950 text-amber-200",
    marker: "bg-amber-500",
  },
  RAW_EVENT: {
    border: "border-slate-700 bg-slate-950",
    badge: "border-slate-700 bg-slate-900 text-slate-300",
    marker: "bg-slate-500",
  },
  EVENT_AGGREGATE: {
    border: "border-teal-800 bg-teal-950/20",
    badge: "border-teal-700 bg-teal-950 text-teal-200",
    marker: "bg-teal-500",
  },
  HOST: {
    border: "border-teal-800 bg-teal-950/20",
    badge: "border-teal-700 bg-teal-950 text-teal-200",
    marker: "bg-teal-500",
  },
  USER: {
    border: "border-indigo-800 bg-indigo-950/20",
    badge: "border-indigo-700 bg-indigo-950 text-indigo-200",
    marker: "bg-indigo-500",
  },
  SOURCE_IP: {
    border: "border-emerald-800 bg-emerald-950/20",
    badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
    marker: "bg-emerald-500",
  },
  DESTINATION_IP: {
    border: "border-emerald-800 bg-emerald-950/20",
    badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
    marker: "bg-emerald-500",
  },
  MITRE_TECHNIQUE: {
    border: "border-red-900 bg-red-950/20",
    badge: "border-red-800 bg-red-950 text-red-200",
    marker: "bg-red-500",
  },
  DETECTION_RULE: {
    border: "border-sky-800 bg-sky-950/20",
    badge: "border-sky-700 bg-sky-950 text-sky-200",
    marker: "bg-sky-500",
  },
  AI_ANALYSIS: {
    border: "border-violet-800 bg-violet-950/20",
    badge: "border-violet-700 bg-violet-950 text-violet-200",
    marker: "bg-violet-500",
  },
  AI_HYPOTHESIS: {
    border: "border-violet-800 bg-violet-950/20",
    badge: "border-violet-700 bg-violet-950 text-violet-200",
    marker: "bg-violet-500",
  },
  TIMELINE_EVENT: {
    border: "border-slate-700 bg-slate-950",
    badge: "border-slate-700 bg-slate-900 text-slate-300",
    marker: "bg-slate-500",
  },
};

const DEFAULT_NODE_STYLE = {
  border: "border-slate-700 bg-slate-950",
  badge: "border-slate-700 bg-slate-900 text-slate-300",
  marker: "bg-slate-500",
};

const EDGE_STYLES: Record<string, string> = {
  HAS_ALERT: "border-amber-800 bg-amber-950/20 text-amber-200",
  HAS_RAW_EVENT: "border-slate-700 bg-slate-900 text-slate-300",
  PART_OF_CASE: "border-violet-800 bg-violet-950/20 text-violet-200",
  OBSERVED_ON: "border-teal-800 bg-teal-950/20 text-teal-200",
  AUTHENTICATED_AS: "border-indigo-800 bg-indigo-950/20 text-indigo-200",
  SOURCE_OF: "border-emerald-800 bg-emerald-950/20 text-emerald-200",
  TARGETS: "border-emerald-800 bg-emerald-950/20 text-emerald-200",
  MAPS_TO_MITRE: "border-red-900 bg-red-950/20 text-red-200",
  TRIGGERED_BY_RULE: "border-sky-800 bg-sky-950/20 text-sky-200",
  AI_EXPLAINS: "border-violet-800 bg-violet-950/20 text-violet-200",
  AI_SUGGESTS: "border-violet-800 bg-violet-950/20 text-violet-200",
};

function prettyType(value: string) {
  return value.replaceAll("_", " ");
}

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "-";

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;

  return parsed.toLocaleString("it-CH", {
    timeZone: "Europe/Zurich",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function nodeLink(node: GraphNode) {
  if (node.type === "INCIDENT") {
    return { href: `/incidents/${node.id.split(":")[1]}`, label: "Open incident" };
  }

  if (node.type === "CASE") {
    return { href: `/cases/${node.id.split(":")[1]}`, label: "Open case" };
  }

  if (node.type === "DETECTION_RULE") {
    return { href: "/settings/detection-control", label: "Open detection control" };
  }

  return null;
}

function metricLabel(value: number | undefined) {
  return String(value ?? 0);
}

async function fetchGraph(
  scope: GraphScope,
  scopeId: number | string,
  options: {
    includeRawEvents: boolean;
    includeTimeline: boolean;
    includeAi: boolean;
    includeDetectionRules: boolean;
  }
): Promise<GraphPayload> {
  const params = new URLSearchParams({
    depth: "2",
    include_raw_events: String(options.includeRawEvents),
    include_timeline: String(options.includeTimeline),
    include_ai: String(options.includeAi),
    include_detection_rules: String(options.includeDetectionRules),
    limit_nodes: "120",
    limit_edges: "240",
  });

  const response = await authFetch(
    `/investigation-graph/${scope}s/${scopeId}?${params.toString()}`,
    { cache: "no-store" }
  );

  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }

  return response.json();
}

export default function InvestigationGraph({ scope, scopeId }: InvestigationGraphProps) {
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [includeRawEvents, setIncludeRawEvents] = useState(false);
  const [includeTimeline, setIncludeTimeline] = useState(false);
  const [includeAi, setIncludeAi] = useState(true);
  const [includeDetectionRules, setIncludeDetectionRules] = useState(true);
  const [nodeTypeFilter, setNodeTypeFilter] = useState("ALL");
  const [edgeTypeFilter, setEdgeTypeFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  const loadGraph = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);
      const payload = await fetchGraph(scope, scopeId, {
        includeRawEvents,
        includeTimeline,
        includeAi,
        includeDetectionRules,
      });
      setGraph(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown graph error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [includeAi, includeDetectionRules, includeRawEvents, includeTimeline, scope, scopeId]);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadGraph();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [loadGraph]);

  const visibleNodes = useMemo(() => {
    const searchText = search.trim().toLowerCase();
    const nodes = graph?.nodes ?? [];

    return nodes.filter((node) => {
      if (nodeTypeFilter !== "ALL" && node.type !== nodeTypeFilter) return false;
      if (!searchText) return true;

      return (
        node.id.toLowerCase().includes(searchText) ||
        node.label.toLowerCase().includes(searchText) ||
        String(node.subtitle ?? "").toLowerCase().includes(searchText)
      );
    });
  }, [graph?.nodes, nodeTypeFilter, search]);

  const visibleNodeIds = useMemo(
    () => new Set(visibleNodes.map((node) => node.id)),
    [visibleNodes]
  );

  const visibleEdges = useMemo(() => {
    return (graph?.edges ?? [])
      .filter((edge) => {
        if (edgeTypeFilter !== "ALL" && edge.type !== edgeTypeFilter) return false;
        return visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target);
      })
      .sort((left, right) => right.evidence_count - left.evidence_count);
  }, [edgeTypeFilter, graph?.edges, visibleNodeIds]);

  const nodeById = useMemo(
    () => new Map((graph?.nodes ?? []).map((node) => [node.id, node])),
    [graph?.nodes]
  );

  const lanes = useMemo(() => {
    const grouped = new Map<LaneKey, GraphNode[]>();
    for (const lane of LANES) {
      grouped.set(lane.key, []);
    }

    for (const node of visibleNodes) {
      const lane = NODE_TYPE_LANE[node.type] ?? "entities";
      grouped.get(lane)?.push(node);
    }

    return LANES.map((lane) => ({
      ...lane,
      nodes: (grouped.get(lane.key) ?? []).sort((left, right) => {
        const severityDelta =
          severityRank(right.severity) - severityRank(left.severity);
        if (severityDelta !== 0) return severityDelta;
        return right.count - left.count;
      }),
    }));
  }, [visibleNodes]);

  const selectedNode = selectedNodeId ? nodeById.get(selectedNodeId) ?? null : null;
  const selectedEdge = selectedEdgeId
    ? graph?.edges.find((edge) => edge.id === selectedEdgeId) ?? null
    : null;

  const nodeTypes = graph?.filters.available_node_types ?? [];
  const edgeTypes = graph?.filters.available_edge_types ?? [];
  const operationalWarnings =
    graph?.summary.warnings.filter(
      (warning) =>
        !warning.toLowerCase().includes("investigation memory") &&
        !warning.toLowerCase().includes("ai hypothesis")
    ) ?? [];

  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-6">
        <GraphMetric title="Nodes" value={graph?.summary.node_count} />
        <GraphMetric title="Edges" value={graph?.summary.edge_count} />
        <GraphMetric title="Hosts" value={graph?.summary.hosts} />
        <GraphMetric title="IPs" value={graph?.summary.ips} />
        <GraphMetric title="Alerts" value={graph?.summary.alerts} />
        <GraphMetric title="MITRE" value={graph?.summary.mitre_techniques} />
      </div>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-3">
          <GraphToolbar
            search={search}
            onSearchChange={setSearch}
            nodeTypeFilter={nodeTypeFilter}
            onNodeTypeFilterChange={setNodeTypeFilter}
            nodeTypes={nodeTypes}
            edgeTypeFilter={edgeTypeFilter}
            onEdgeTypeFilterChange={setEdgeTypeFilter}
            edgeTypes={edgeTypes}
            includeRawEvents={includeRawEvents}
            onIncludeRawEventsChange={setIncludeRawEvents}
            includeTimeline={includeTimeline}
            onIncludeTimelineChange={setIncludeTimeline}
            includeAi={includeAi}
            onIncludeAiChange={setIncludeAi}
            includeDetectionRules={includeDetectionRules}
            onIncludeDetectionRulesChange={setIncludeDetectionRules}
            refreshing={refreshing}
            onRefresh={loadGraph}
          />

          {error && (
            <div className="rounded-md border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
              Graph error: {error}
            </div>
          )}

          {graph?.redaction.applied && (
            <div className="rounded-md border border-amber-800 bg-amber-950/30 p-3 text-xs text-amber-200">
              Raw event metadata is redacted for the current role.
            </div>
          )}

          {operationalWarnings.map((warning) => (
            <div
              key={warning}
              className="rounded-md border border-amber-800 bg-amber-950/30 p-3 text-xs text-amber-200"
            >
              {warning}
            </div>
          ))}

          <div className="rounded-md border border-slate-800 bg-slate-950 p-3">
            <div className="mb-3 flex flex-col gap-1 md:flex-row md:items-start md:justify-between">
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-300">
                  <GitBranch className="h-3.5 w-3.5 text-cyan-300" />
                  Relationship map
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Evidence-backed entities grouped by investigation role.
                </p>
              </div>
              <span className="w-fit rounded-sm border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] text-slate-400">
                {visibleNodes.length} nodes · {visibleEdges.length} relationships
              </span>
            </div>

            {loading ? (
              <div className="flex h-64 items-center justify-center text-xs text-slate-400">
                Loading graph...
              </div>
            ) : visibleNodes.length === 0 ? (
              <div className="flex h-64 items-center justify-center text-xs text-slate-500">
                No graph relationships found with the current filters.
              </div>
            ) : (
              <div className="grid gap-3 xl:grid-cols-4">
                {lanes.map((lane) => (
                  <GraphLane
                    key={lane.key}
                    lane={lane}
                    selectedNodeId={selectedNodeId}
                    onSelectNode={(nodeId) => {
                      setSelectedNodeId(nodeId);
                      setSelectedEdgeId(null);
                    }}
                  />
                ))}
              </div>
            )}
          </div>

          <RelationshipTable
            edges={visibleEdges}
            nodeById={nodeById}
            selectedEdgeId={selectedEdgeId}
            onSelectEdge={(edgeId) => {
              setSelectedEdgeId(edgeId);
              setSelectedNodeId(null);
            }}
          />

          <GraphLegend nodeTypes={nodeTypes} edgeTypes={edgeTypes.slice(0, 12)} />
        </div>

        <GraphDetailDrawer
          selectedNode={selectedNode}
          selectedEdge={selectedEdge}
          onClose={() => {
            setSelectedNodeId(null);
            setSelectedEdgeId(null);
          }}
        />
      </div>
    </div>
  );
}

function severityRank(value: string | null | undefined) {
  const ranks: Record<string, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
  };
  return ranks[String(value ?? "").toUpperCase()] ?? 0;
}

function GraphMetric({ title, value }: { title: string; value: number | undefined }) {
  return (
    <div className="rounded-sm border border-slate-800 bg-slate-950 p-2">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </div>
      <div className="mt-1 text-lg font-semibold text-slate-100">{metricLabel(value)}</div>
    </div>
  );
}

function GraphToolbar({
  search,
  onSearchChange,
  nodeTypeFilter,
  onNodeTypeFilterChange,
  nodeTypes,
  edgeTypeFilter,
  onEdgeTypeFilterChange,
  edgeTypes,
  includeRawEvents,
  onIncludeRawEventsChange,
  includeTimeline,
  onIncludeTimelineChange,
  includeAi,
  onIncludeAiChange,
  includeDetectionRules,
  onIncludeDetectionRulesChange,
  refreshing,
  onRefresh,
}: {
  search: string;
  onSearchChange: (value: string) => void;
  nodeTypeFilter: string;
  onNodeTypeFilterChange: (value: string) => void;
  nodeTypes: string[];
  edgeTypeFilter: string;
  onEdgeTypeFilterChange: (value: string) => void;
  edgeTypes: string[];
  includeRawEvents: boolean;
  onIncludeRawEventsChange: (value: boolean) => void;
  includeTimeline: boolean;
  onIncludeTimelineChange: (value: boolean) => void;
  includeAi: boolean;
  onIncludeAiChange: (value: boolean) => void;
  includeDetectionRules: boolean;
  onIncludeDetectionRulesChange: (value: boolean) => void;
  refreshing: boolean;
  onRefresh: () => void;
}) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-3">
      <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-300">
          <Network className="h-3.5 w-3.5 text-cyan-300" />
          Investigation controls
        </div>
        <button
          onClick={onRefresh}
          className="inline-flex h-8 w-fit items-center gap-2 rounded-sm border border-slate-700 bg-slate-900 px-2.5 text-xs text-slate-200 hover:bg-slate-800"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        <label className="block">
          <span className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
            <Search className="h-3 w-3" />
            Search
          </span>
          <input
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="host, user, T1110"
            className="h-8 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-700"
          />
        </label>

        <GraphSelect
          icon={<Filter className="h-3 w-3" />}
          label="Node type"
          value={nodeTypeFilter}
          onChange={onNodeTypeFilterChange}
          options={["ALL", ...nodeTypes]}
        />

        <GraphSelect
          icon={<GitBranch className="h-3 w-3" />}
          label="Edge type"
          value={edgeTypeFilter}
          onChange={onEdgeTypeFilterChange}
          options={["ALL", ...edgeTypes]}
        />

        <div className="flex flex-wrap items-end gap-2">
          <GraphToggle label="Raw" value={includeRawEvents} onChange={onIncludeRawEventsChange} />
          <GraphToggle label="AI" value={includeAi} onChange={onIncludeAiChange} />
          <GraphToggle label="Rules" value={includeDetectionRules} onChange={onIncludeDetectionRulesChange} />
          <GraphToggle label="Timeline" value={includeTimeline} onChange={onIncludeTimelineChange} />
        </div>
      </div>
    </div>
  );
}

function GraphSelect({
  icon,
  label,
  value,
  onChange,
  options,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
}) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {icon}
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-100 outline-none focus:border-cyan-700"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {prettyType(option)}
          </option>
        ))}
      </select>
    </label>
  );
}

function GraphToggle({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className="inline-flex h-8 items-center gap-1.5 rounded-sm border border-slate-700 bg-slate-900 px-2 text-xs text-slate-200">
      <input
        type="checkbox"
        checked={value}
        onChange={(event) => onChange(event.target.checked)}
        className="h-3.5 w-3.5 accent-cyan-500"
      />
      {label}
    </label>
  );
}

function GraphLane({
  lane,
  selectedNodeId,
  onSelectNode,
}: {
  lane: Lane & { nodes: GraphNode[] };
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  return (
    <section className="min-h-[220px] rounded-md border border-slate-800 bg-slate-900/70 p-2">
      <div className="mb-2">
        <div className="flex items-center justify-between gap-2">
          <h4 className="text-xs font-semibold text-slate-200">{lane.title}</h4>
          <span className="rounded-sm border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[10px] text-slate-400">
            {lane.nodes.length}
          </span>
        </div>
        <p className="mt-0.5 text-[11px] leading-4 text-slate-500">{lane.description}</p>
      </div>

      <div className="max-h-[420px] space-y-2 overflow-auto pr-1">
        {lane.nodes.length === 0 ? (
          <div className="rounded-sm border border-dashed border-slate-800 bg-slate-950 p-3 text-center text-[11px] text-slate-600">
            No nodes
          </div>
        ) : (
          lane.nodes.map((node) => (
            <NodeCard
              key={node.id}
              node={node}
              selected={selectedNodeId === node.id}
              onClick={() => onSelectNode(node.id)}
            />
          ))
        )}
      </div>
    </section>
  );
}

function NodeCard({
  node,
  selected,
  onClick,
}: {
  node: GraphNode;
  selected: boolean;
  onClick: () => void;
}) {
  const style = NODE_STYLES[node.type] ?? DEFAULT_NODE_STYLE;

  return (
    <button
      type="button"
      onClick={onClick}
      className={`block w-full rounded-sm border p-2 text-left shadow-sm transition hover:border-cyan-700 ${
        style.border
      } ${selected ? "ring-1 ring-cyan-300" : ""}`}
    >
      <div className="flex items-start gap-2">
        <span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${style.marker}`} />
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 items-center gap-1.5">
            <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 text-[9px] font-semibold uppercase ${style.badge}`}>
              {prettyType(node.type)}
            </span>
            {node.severity && (
              <span className="shrink-0 rounded-sm border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[9px] text-slate-300">
                {node.severity}
              </span>
            )}
          </div>
          <div className="mt-1 truncate text-xs font-semibold text-slate-100">{node.label}</div>
          {node.subtitle && (
            <div className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-slate-400">
              {node.subtitle}
            </div>
          )}
          <div className="mt-1.5 flex flex-wrap gap-1 text-[10px] text-slate-500">
            <span>{node.confidence}</span>
            <span>source {node.source}</span>
            <span>count {node.count}</span>
          </div>
        </div>
      </div>
    </button>
  );
}

function RelationshipTable({
  edges,
  nodeById,
  selectedEdgeId,
  onSelectEdge,
}: {
  edges: GraphEdge[];
  nodeById: Map<string, GraphNode>;
  selectedEdgeId: string | null;
  onSelectEdge: (edgeId: string) => void;
}) {
  return (
    <section className="rounded-md border border-slate-800 bg-slate-950 p-3">
      <div className="mb-2 flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-300">
            <GitBranch className="h-3.5 w-3.5 text-cyan-300" />
            Relationships
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Evidence-backed edges between visible nodes.
          </p>
        </div>
        <span className="w-fit rounded-sm border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] text-slate-400">
          {edges.length} shown
        </span>
      </div>

      {edges.length === 0 ? (
        <div className="rounded-sm border border-dashed border-slate-800 bg-slate-900 p-3 text-center text-xs text-slate-500">
          No relationships match the current filters.
        </div>
      ) : (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-950 text-[10px] uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-1.5 pr-2">Source</th>
                <th className="py-1.5 pr-2">Relationship</th>
                <th className="py-1.5 pr-2">Target</th>
                <th className="py-1.5 pr-2">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {edges.map((edge) => {
                const source = nodeById.get(edge.source);
                const target = nodeById.get(edge.target);
                const selected = selectedEdgeId === edge.id;

                return (
                  <tr
                    key={edge.id}
                    onClick={() => onSelectEdge(edge.id)}
                    className={`cursor-pointer hover:bg-slate-900/80 ${selected ? "bg-cyan-950/30" : ""}`}
                  >
                    <td className="max-w-[220px] truncate py-2 pr-2 text-slate-300">
                      {source?.label ?? edge.source}
                    </td>
                    <td className="py-2 pr-2">
                      <span className={`rounded-sm border px-1.5 py-0.5 text-[10px] ${EDGE_STYLES[edge.type] ?? "border-slate-700 bg-slate-900 text-slate-300"}`}>
                        {edge.label}
                      </span>
                    </td>
                    <td className="max-w-[220px] truncate py-2 pr-2 text-slate-300">
                      {target?.label ?? edge.target}
                    </td>
                    <td className="whitespace-nowrap py-2 pr-2 text-slate-500">
                      {edge.evidence_count} ref(s)
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function GraphLegend({ nodeTypes, edgeTypes }: { nodeTypes: string[]; edgeTypes: string[] }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950 p-3">
      <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        <Shield className="h-3 w-3" />
        Legend
      </div>
      <div className="flex flex-wrap gap-2">
        {nodeTypes.map((type) => {
          const style = NODE_STYLES[type] ?? DEFAULT_NODE_STYLE;
          return (
            <span
              key={type}
              className="inline-flex items-center gap-1.5 rounded-sm border border-slate-800 bg-slate-900 px-2 py-1 text-[11px] text-slate-300"
            >
              <span className={`h-2 w-2 rounded-full ${style.marker}`} />
              {prettyType(type)}
            </span>
          );
        })}
        {edgeTypes.map((type) => (
          <span
            key={type}
            className={`inline-flex items-center rounded-sm border px-2 py-1 text-[11px] ${
              EDGE_STYLES[type] ?? "border-slate-700 bg-slate-900 text-slate-300"
            }`}
          >
            {prettyType(type)}
          </span>
        ))}
      </div>
    </div>
  );
}

function GraphDetailDrawer({
  selectedNode,
  selectedEdge,
  onClose,
}: {
  selectedNode: GraphNode | null;
  selectedEdge: GraphEdge | null;
  onClose: () => void;
}) {
  if (!selectedNode && !selectedEdge) {
    return (
      <aside className="rounded-md border border-slate-800 bg-slate-950 p-3">
        <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-200">
          <Database className="h-3.5 w-3.5 text-cyan-300" />
          Graph details
        </div>
        <p className="text-xs leading-5 text-slate-500">
          Select a node or relationship to inspect evidence, metadata and linked records.
        </p>
      </aside>
    );
  }

  return (
    <aside className="rounded-md border border-slate-800 bg-slate-950 p-3">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
            {selectedNode ? prettyType(selectedNode.type) : prettyType(selectedEdge?.type ?? "Relationship")}
          </div>
          <h3 className="mt-1 truncate text-sm font-semibold text-slate-100">
            {selectedNode?.label ?? selectedEdge?.label}
          </h3>
        </div>
        <button
          onClick={onClose}
          className="rounded-sm border border-slate-700 bg-slate-900 p-1 text-slate-400 hover:text-slate-100"
          aria-label="Close graph details"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {selectedNode ? <NodeDetails node={selectedNode} /> : null}
      {selectedEdge ? <EdgeDetails edge={selectedEdge} /> : null}
    </aside>
  );
}

function NodeDetails({ node }: { node: GraphNode }) {
  const link = nodeLink(node);

  return (
    <div className="space-y-3 text-xs">
      <DetailGrid
        rows={[
          ["ID", node.id],
          ["Confidence", node.confidence],
          ["Source", node.source],
          ["Severity", node.severity ?? "-"],
          ["First seen", formatTimestamp(node.first_seen_at)],
          ["Last seen", formatTimestamp(node.last_seen_at)],
          ["Count", String(node.count)],
        ]}
      />

      {link && (
        <Link
          href={link.href}
          className="inline-flex h-8 items-center gap-2 rounded-sm border border-cyan-800 bg-cyan-950/40 px-2.5 text-xs text-cyan-200 hover:bg-cyan-900/40"
        >
          <GitBranch className="h-3.5 w-3.5" />
          {link.label}
        </Link>
      )}

      <MetadataBlock metadata={node.metadata} />
      <EvidenceBlock evidenceRefs={node.evidence_refs ?? []} />
    </div>
  );
}

function EdgeDetails({ edge }: { edge: GraphEdge }) {
  return (
    <div className="space-y-3 text-xs">
      <DetailGrid
        rows={[
          ["ID", edge.id],
          ["Type", prettyType(edge.type)],
          ["Confidence", edge.confidence],
          ["Weight", String(edge.weight)],
          ["Evidence", String(edge.evidence_count)],
          ["First seen", formatTimestamp(edge.first_seen_at)],
          ["Last seen", formatTimestamp(edge.last_seen_at)],
        ]}
      />
      <EvidenceBlock evidenceRefs={edge.evidence_refs} />
    </div>
  );
}

function DetailGrid({ rows }: { rows: Array<[string, string]> }) {
  return (
    <div className="grid gap-px overflow-hidden rounded-sm border border-slate-800 bg-slate-800">
      {rows.map(([label, value]) => (
        <div key={label} className="grid grid-cols-[92px_minmax(0,1fr)] gap-2 bg-slate-950 px-2 py-1.5">
          <span className="text-slate-500">{label}</span>
          <span className="truncate text-slate-200">{value}</span>
        </div>
      ))}
    </div>
  );
}

function MetadataBlock({ metadata }: { metadata: Record<string, unknown> }) {
  const entries = Object.entries(metadata || {});

  if (entries.length === 0) {
    return (
      <div className="rounded-sm border border-slate-800 bg-slate-900 p-2 text-xs text-slate-500">
        No sanitized metadata available.
      </div>
    );
  }

  return (
    <div>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        Metadata
      </div>
      <div className="max-h-52 overflow-auto rounded-sm border border-slate-800 bg-slate-900 p-2">
        <pre className="whitespace-pre-wrap break-words text-[11px] leading-5 text-slate-300">
          {JSON.stringify(metadata, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function EvidenceBlock({ evidenceRefs }: { evidenceRefs: EvidenceRef[] }) {
  if (evidenceRefs.length === 0) {
    return (
      <div className="rounded-sm border border-slate-800 bg-slate-900 p-2 text-xs text-slate-500">
        No evidence references available.
      </div>
    );
  }

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        <Brain className="h-3 w-3" />
        Evidence
      </div>
      <div className="space-y-1.5">
        {evidenceRefs.map((ref) => (
          <div key={`${ref.type}-${ref.id}-${ref.summary}`} className="rounded-sm border border-slate-800 bg-slate-900 p-2">
            <div className="font-medium text-slate-200">
              {ref.type} #{ref.id}
            </div>
            <div className="mt-0.5 text-slate-500">{ref.summary}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
