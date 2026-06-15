from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import inspect, or_
from sqlalchemy.exc import SQLAlchemyError

from case_timeline import build_case_timeline_payload
from incident_timeline import TimelineQuery, build_incident_timeline_payload
from models import (
    CaseAIAnalysis,
    CaseIncident,
    EventAggregate,
    Incident,
    IncidentCase,
    InvestigationHypothesisHistoryRecord,
    InvestigationSessionRecord,
    InvestigationSnapshotRecord,
    RawEvent,
    SecurityAlert,
)


DEFAULT_MAX_NODES = 80
HARD_MAX_NODES = 200
DEFAULT_MAX_EDGES = 160
HARD_MAX_EDGES = 400
MAX_DEPTH = 2
INTERNAL_ROW_LIMIT = 200
MAX_EVIDENCE_REFS = 5
MAX_TIMELINE_NODES = 12
MAX_AI_RECORDS = 8

ENTITY_NODE_TYPES = {
    "HOST",
    "USER",
    "SOURCE_IP",
    "DESTINATION_IP",
    "PROCESS",
    "FILE",
    "PACKAGE",
    "MITRE_TECHNIQUE",
    "DETECTION_RULE",
    "NOISE_SUPPRESSION",
    "EXCEPTION",
    "AI_HYPOTHESIS",
    "AI_ANALYSIS",
}

SEVERITY_ORDER = {
    None: 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SENSITIVE_METADATA_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "payload",
    "raw",
    "env",
)

MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True)
class InvestigationGraphOptions:
    depth: int = 1
    include_raw_events: bool = False
    include_timeline: bool = True
    include_ai: bool = True
    include_detection_rules: bool = True
    include_suppression: bool = True
    limit_nodes: int = DEFAULT_MAX_NODES
    limit_edges: int = DEFAULT_MAX_EDGES


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_graph_options(
    *,
    depth: int | None = None,
    include_raw_events: bool = False,
    include_timeline: bool = True,
    include_ai: bool = True,
    include_detection_rules: bool = True,
    include_suppression: bool = True,
    limit_nodes: int | None = None,
    limit_edges: int | None = None,
) -> InvestigationGraphOptions:
    return InvestigationGraphOptions(
        depth=max(1, min(int(depth or 1), MAX_DEPTH)),
        include_raw_events=bool(include_raw_events),
        include_timeline=bool(include_timeline),
        include_ai=bool(include_ai),
        include_detection_rules=bool(include_detection_rules),
        include_suppression=bool(include_suppression),
        limit_nodes=max(1, min(int(limit_nodes or DEFAULT_MAX_NODES), HARD_MAX_NODES)),
        limit_edges=max(1, min(int(limit_edges or DEFAULT_MAX_EDGES), HARD_MAX_EDGES)),
    )


def current_user_role(current_user: Mapping[str, Any] | None) -> str:
    return str((current_user or {}).get("role") or "").upper().strip()


def is_viewer(current_user: Mapping[str, Any] | None) -> bool:
    return current_user_role(current_user) == "VIEWER"


def _iso(value: Any) -> str | None:
    if not value:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    return str(value)


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _first_timestamp(left: str | None, right: str | None) -> str | None:
    left_dt = _parse_datetime(left)
    right_dt = _parse_datetime(right)

    if not left_dt:
        return right
    if not right_dt:
        return left

    return left if left_dt <= right_dt else right


def _last_timestamp(left: str | None, right: str | None) -> str | None:
    left_dt = _parse_datetime(left)
    right_dt = _parse_datetime(right)

    if not left_dt:
        return right
    if not right_dt:
        return left

    return left if left_dt >= right_dt else right


def _json_loads(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return None


def _table_exists(db, table_name: str) -> bool:
    try:
        return inspect(db.bind).has_table(table_name)
    except SQLAlchemyError:
        return False


def _safe_rollback(db) -> None:
    try:
        db.rollback()
    except Exception:
        pass


def _short(value: Any, limit: int = 160) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}..."


def _stable_value(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text or text in {"-", "unknown", "UNKNOWN", "null", "None"}:
        return None
    if len(text) > 180:
        return None

    return text


def _slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^a-z0-9._:/-]+", "", text)
    return text[:120] or "unknown"


def _severity_from_risk(value: Any) -> str | None:
    try:
        risk = int(value or 0)
    except (TypeError, ValueError):
        return None

    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    return "LOW"


def _severity_from_alert(alert: SecurityAlert) -> str | None:
    bucket = str(alert.severity_bucket or "").upper().strip()
    if bucket in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return bucket
    return _severity_from_risk((alert.level or 0) * 10)


def _confidence_from_score(value: Any) -> str:
    try:
        score = int(value or 0)
    except (TypeError, ValueError):
        return "medium"

    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _sanitize_metadata(
    metadata: Mapping[str, Any] | None,
    *,
    current_user: Mapping[str, Any] | None,
    sensitive: bool = False,
) -> dict[str, Any]:
    if not metadata:
        return {}

    if sensitive and is_viewer(current_user):
        return {"redacted": True, "reason": "viewer_role_limited_metadata"}

    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = str(key)
        key_lower = key_text.lower()
        if any(marker in key_lower for marker in SENSITIVE_METADATA_KEYS):
            continue
        if value is None:
            continue

        if isinstance(value, (str, int, float, bool)):
            sanitized[key_text] = _short(value)
        elif isinstance(value, list):
            sanitized[key_text] = [_short(item, 80) for item in value[:8]]
        elif isinstance(value, dict):
            nested = {}
            for nested_key, nested_value in list(value.items())[:8]:
                nested_key_text = str(nested_key)
                if any(marker in nested_key_text.lower() for marker in SENSITIVE_METADATA_KEYS):
                    continue
                if isinstance(nested_value, (str, int, float, bool)):
                    nested[nested_key_text] = _short(nested_value, 80)
            if nested:
                sanitized[key_text] = nested

        if len(sanitized) >= 12:
            break

    return sanitized


def _evidence_ref(ref_type: str, ref_id: Any, summary: str | None = None) -> dict[str, str]:
    return {
        "type": ref_type,
        "id": str(ref_id),
        "summary": _short(summary or f"{ref_type} {ref_id}", 120),
    }


class GraphBuilder:
    def __init__(self, *, current_user: Mapping[str, Any] | None, options: InvestigationGraphOptions):
        self.current_user = current_user or {}
        self.options = options
        self.nodes: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.edges: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.warnings: list[str] = []

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        *,
        subtitle: str | None = None,
        severity: str | None = None,
        confidence: str = "unknown",
        source: str = "unknown",
        first_seen_at: Any = None,
        last_seen_at: Any = None,
        count: int = 1,
        metadata: Mapping[str, Any] | None = None,
        sensitive_metadata: bool = False,
        evidence_refs: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        clean_metadata = _sanitize_metadata(
            metadata,
            current_user=self.current_user,
            sensitive=sensitive_metadata,
        )
        first = _iso(first_seen_at)
        last = _iso(last_seen_at) or first
        normalized_severity = severity if severity in SEVERITY_ORDER else None

        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": _short(label, 96),
                "subtitle": subtitle or node_type.replace("_", " ").title(),
                "severity": normalized_severity,
                "confidence": confidence,
                "source": source,
                "first_seen_at": first,
                "last_seen_at": last,
                "count": max(int(count or 1), 1),
                "metadata": clean_metadata,
                "evidence_refs": (evidence_refs or [])[:MAX_EVIDENCE_REFS],
            }
            return self.nodes[node_id]

        node = self.nodes[node_id]
        node["count"] = int(node.get("count") or 0) + max(int(count or 1), 1)
        node["first_seen_at"] = _first_timestamp(node.get("first_seen_at"), first)
        node["last_seen_at"] = _last_timestamp(node.get("last_seen_at"), last)

        existing_severity = node.get("severity")
        if SEVERITY_ORDER.get(normalized_severity, 0) > SEVERITY_ORDER.get(existing_severity, 0):
            node["severity"] = normalized_severity

        if node.get("confidence") in {"unknown", "low"} and confidence in {"medium", "high"}:
            node["confidence"] = confidence

        node["metadata"].update(
            {
                key: value
                for key, value in clean_metadata.items()
                if key not in node["metadata"]
            }
        )

        for evidence_ref in evidence_refs or []:
            if evidence_ref not in node["evidence_refs"] and len(node["evidence_refs"]) < MAX_EVIDENCE_REFS:
                node["evidence_refs"].append(evidence_ref)

        return node

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        *,
        label: str,
        confidence: str = "unknown",
        weight: int = 1,
        first_seen_at: Any = None,
        last_seen_at: Any = None,
        evidence_refs: list[dict[str, str]] | None = None,
    ) -> None:
        if source not in self.nodes or target not in self.nodes:
            return

        edge_id = f"edge:{source}:{edge_type}:{target}"
        first = _iso(first_seen_at)
        last = _iso(last_seen_at) or first
        refs = (evidence_refs or [])[:MAX_EVIDENCE_REFS]

        if edge_id not in self.edges:
            self.edges[edge_id] = {
                "id": edge_id,
                "source": source,
                "target": target,
                "type": edge_type,
                "label": label,
                "confidence": confidence,
                "weight": max(int(weight or 1), 1),
                "evidence_count": max(len(refs), 1),
                "first_seen_at": first,
                "last_seen_at": last,
                "evidence_refs": refs,
            }
            return

        edge = self.edges[edge_id]
        edge["weight"] = int(edge.get("weight") or 0) + max(int(weight or 1), 1)
        edge["evidence_count"] = int(edge.get("evidence_count") or 0) + max(len(refs), 1)
        edge["first_seen_at"] = _first_timestamp(edge.get("first_seen_at"), first)
        edge["last_seen_at"] = _last_timestamp(edge.get("last_seen_at"), last)

        if edge.get("confidence") in {"unknown", "low"} and confidence in {"medium", "high"}:
            edge["confidence"] = confidence

        for ref in refs:
            if ref not in edge["evidence_refs"] and len(edge["evidence_refs"]) < MAX_EVIDENCE_REFS:
                edge["evidence_refs"].append(ref)

    def finalize(self, *, scope: str, scope_id: int, redaction_applied: bool = False, redaction_reason: str | None = None) -> dict[str, Any]:
        all_nodes = list(self.nodes.values())
        all_edges = list(self.edges.values())

        limited_nodes = all_nodes[: self.options.limit_nodes]
        if len(all_nodes) > len(limited_nodes):
            self.warnings.append(
                f"Graph truncated to {len(limited_nodes)} nodes. Use filters to narrow the result."
            )

        allowed_node_ids = {node["id"] for node in limited_nodes}
        limited_edges = [
            edge
            for edge in all_edges
            if edge["source"] in allowed_node_ids and edge["target"] in allowed_node_ids
        ][: self.options.limit_edges]

        if len(all_edges) > len(limited_edges):
            self.warnings.append(
                f"Graph truncated to {len(limited_edges)} edges. Use filters to narrow the result."
            )

        summary = summarize_graph(limited_nodes, limited_edges, self.warnings)

        return {
            "scope": scope,
            "scope_id": scope_id,
            "generated_at": _iso(utc_now()),
            "nodes": limited_nodes,
            "edges": limited_edges,
            "summary": summary,
            "filters": {
                "available_node_types": sorted({node["type"] for node in limited_nodes}),
                "available_edge_types": sorted({edge["type"] for edge in limited_edges}),
            },
            "redaction": {
                "applied": redaction_applied,
                "reason": redaction_reason,
            },
        }


def summarize_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], warnings: list[str]) -> dict[str, Any]:
    node_types = {node["type"] for node in nodes}
    highest = None
    for node in nodes:
        severity = node.get("severity")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity

    primary_entities = [
        node["id"]
        for node in nodes
        if node["type"] in {"HOST", "USER", "SOURCE_IP", "DESTINATION_IP"}
    ][:8]

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "entity_count": sum(1 for node in nodes if node["type"] in ENTITY_NODE_TYPES),
        "highest_severity": highest,
        "primary_entities": primary_entities,
        "warnings": warnings,
        "graph_quality": "limited" if warnings else ("good" if edges else "sparse"),
        "hosts": sum(1 for node in nodes if node["type"] == "HOST"),
        "users": sum(1 for node in nodes if node["type"] == "USER"),
        "ips": sum(1 for node in nodes if node["type"] in {"SOURCE_IP", "DESTINATION_IP"}),
        "mitre_techniques": sum(1 for node in nodes if node["type"] == "MITRE_TECHNIQUE"),
        "alerts": sum(1 for node in nodes if node["type"] == "SECURITY_ALERT"),
        "raw_events": sum(1 for node in nodes if node["type"] == "RAW_EVENT"),
        "ai_hypotheses": sum(1 for node in nodes if node["type"] == "AI_HYPOTHESIS"),
    }


def graph_summary_payload(graph: dict[str, Any]) -> dict[str, Any]:
    summary = graph["summary"]
    return {
        "scope": graph["scope"],
        "scope_id": graph["scope_id"],
        "node_count": summary["node_count"],
        "edge_count": summary["edge_count"],
        "hosts": summary["hosts"],
        "users": summary["users"],
        "ips": summary["ips"],
        "mitre_techniques": summary["mitre_techniques"],
        "alerts": summary["alerts"],
        "raw_events": summary["raw_events"],
        "ai_hypotheses": summary["ai_hypotheses"],
        "graph_quality": summary["graph_quality"],
        "warnings": summary["warnings"],
    }


def investigation_graph_capabilities() -> dict[str, Any]:
    return {
        "incident_graph": True,
        "case_graph": True,
        "raw_events_supported": True,
        "ai_nodes_supported": True,
        "timeline_nodes_supported": True,
        "max_depth": MAX_DEPTH,
        "max_nodes": HARD_MAX_NODES,
        "max_edges": HARD_MAX_EDGES,
    }


def _load_incident(db, incident_id: int) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")
    return incident


def _load_case(db, case_id: int) -> IncidentCase:
    case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
    if not case:
        raise ValueError(f"Case {case_id} not found")
    return case


def _collect_security_alerts(db, incident: Incident) -> list[SecurityAlert]:
    filters = [SecurityAlert.incident_id == incident.id]
    if incident.security_alert_id:
        filters.append(SecurityAlert.id == incident.security_alert_id)

    rows = (
        db.query(SecurityAlert)
        .filter(or_(*filters))
        .order_by(SecurityAlert.event_timestamp.asc(), SecurityAlert.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )

    seen: set[int] = set()
    result: list[SecurityAlert] = []
    for row in rows:
        if row.id in seen:
            continue
        seen.add(row.id)
        result.append(row)

    return result


def _collect_raw_events(db, incident: Incident, alerts: list[SecurityAlert]) -> list[RawEvent]:
    raw_event_ids = {alert.raw_event_id for alert in alerts if alert.raw_event_id}
    if incident.raw_event_id:
        raw_event_ids.add(incident.raw_event_id)

    if not raw_event_ids:
        return []

    return (
        db.query(RawEvent)
        .filter(RawEvent.id.in_(sorted(raw_event_ids)))
        .order_by(RawEvent.event_timestamp.asc(), RawEvent.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )


def _collect_cases_for_incident(db, incident_id: int) -> list[IncidentCase]:
    case_ids = [
        row.case_id
        for row in db.query(CaseIncident)
        .filter(CaseIncident.incident_id == incident_id)
        .order_by(CaseIncident.created_at.asc(), CaseIncident.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    ]
    if not case_ids:
        return []
    return (
        db.query(IncidentCase)
        .filter(IncidentCase.id.in_(case_ids))
        .order_by(IncidentCase.created_at.asc(), IncidentCase.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )


def _collect_incidents_for_case(db, case_id: int) -> list[Incident]:
    return (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )


def _add_host(builder: GraphBuilder, source_node_id: str, host: Any, *, timestamp: Any, evidence: dict[str, str]) -> None:
    value = _stable_value(host)
    if not value:
        return

    node_id = f"host:{_slug(value)}"
    builder.add_node(
        node_id,
        "HOST",
        value,
        subtitle="Host",
        confidence="high",
        source="wazuh",
        first_seen_at=timestamp,
        last_seen_at=timestamp,
        metadata={"host": value},
        evidence_refs=[evidence],
    )
    builder.add_edge(
        source_node_id,
        node_id,
        "OBSERVED_ON",
        label="observed on",
        confidence="high",
        first_seen_at=timestamp,
        last_seen_at=timestamp,
        evidence_refs=[evidence],
    )


def _add_rule(
    builder: GraphBuilder,
    source_node_id: str,
    rule_id: Any,
    *,
    description: Any = None,
    timestamp: Any = None,
    evidence: dict[str, str],
) -> None:
    if not builder.options.include_detection_rules:
        return

    value = _stable_value(rule_id)
    if not value:
        return

    node_id = f"detection_rule:{_slug(value)}"
    builder.add_node(
        node_id,
        "DETECTION_RULE",
        f"Rule {value}",
        subtitle="Detection rule",
        confidence="high",
        source="wazuh",
        first_seen_at=timestamp,
        last_seen_at=timestamp,
        metadata={"rule_id": value, "description": _short(description, 120)},
        sensitive_metadata=is_viewer(builder.current_user),
        evidence_refs=[evidence],
    )
    builder.add_edge(
        source_node_id,
        node_id,
        "TRIGGERED_BY_RULE",
        label="triggered by",
        confidence="high",
        first_seen_at=timestamp,
        last_seen_at=timestamp,
        evidence_refs=[evidence],
    )


def _add_mitre(builder: GraphBuilder, source_node_id: str, values: list[str], *, timestamp: Any, evidence: dict[str, str]) -> None:
    for value in sorted(set(values)):
        node_id = f"mitre:{value.upper()}"
        builder.add_node(
            node_id,
            "MITRE_TECHNIQUE",
            value.upper(),
            subtitle="MITRE technique",
            confidence="high",
            source="ai_soc",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            metadata={"technique": value.upper()},
            evidence_refs=[evidence],
        )
        builder.add_edge(
            source_node_id,
            node_id,
            "MAPS_TO_MITRE",
            label="maps to MITRE",
            confidence="high",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            evidence_refs=[evidence],
        )


def _mitre_values(*values: Any) -> list[str]:
    matches: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            text = json.dumps(value, default=str)
        else:
            text = str(value)

        parsed = _json_loads(text)
        if parsed is not None and not isinstance(parsed, str):
            text = json.dumps(parsed, default=str)
        matches.extend(match.upper() for match in MITRE_RE.findall(text))

    return sorted(set(matches))


def _iter_json_values(value: Any, prefix: str = ""):
    if isinstance(value, Mapping):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_json_values(item, path)
    elif isinstance(value, list):
        for index, item in enumerate(value[:30]):
            path = f"{prefix}.{index}" if prefix else str(index)
            yield from _iter_json_values(item, path)
    else:
        yield prefix, value


def _entity_from_path(path: str, value: Any) -> tuple[str, str, str] | None:
    text = _stable_value(value)
    if not text:
        return None

    path_lower = path.lower()
    key = path_lower.rsplit(".", 1)[-1]

    if key in {"srcip", "src_ip", "source_ip", "client_ip"} or path_lower.endswith(".source.ip"):
        if IP_RE.match(text):
            return "SOURCE_IP", text, "source of"

    if key in {"dstip", "dst_ip", "dest_ip", "destination_ip", "resolver_ip"} or path_lower.endswith(".destination.ip"):
        if IP_RE.match(text):
            return "DESTINATION_IP", text, "targets"

    if key in {"user", "username", "srcuser", "dstuser", "targetusername", "subjectusername"} and "agent" not in path_lower:
        if "user_agent" not in path_lower and "user-agent" not in path_lower:
            return "USER", text, "authenticated as"

    if (
        key in {"process", "process_name", "processname", "command", "exe", "executable"}
        or "process.name" in path_lower
        or path_lower.endswith(".audit.exe")
    ):
        return "PROCESS", text, "executes"

    if key in {"path", "filepath", "file_path", "filename"} or "syscheck.path" in path_lower or "file.path" in path_lower:
        if "/" in text or "\\" in text:
            return "FILE", text, "touches file"

    if key in {"package", "package_name", "packagename"} or "package.name" in path_lower:
        return "PACKAGE", text, "installs package"

    return None


def _add_entities_from_payload(
    builder: GraphBuilder,
    source_node_id: str,
    payload: Any,
    *,
    timestamp: Any,
    evidence: dict[str, str],
) -> None:
    parsed = _json_loads(payload)
    if parsed is None:
        return

    seen: set[str] = set()
    for path, value in _iter_json_values(parsed):
        entity = _entity_from_path(path, value)
        if not entity:
            continue

        node_type, label, edge_label = entity
        node_id = f"{node_type.lower()}:{_slug(label)}"
        if node_id in seen:
            continue
        seen.add(node_id)

        edge_type = {
            "USER": "AUTHENTICATED_AS",
            "SOURCE_IP": "SOURCE_OF",
            "DESTINATION_IP": "TARGETS",
            "PROCESS": "EXECUTES",
            "FILE": "TOUCHES_FILE",
            "PACKAGE": "INSTALLS_PACKAGE",
        }.get(node_type, "RELATED_TO")

        builder.add_node(
            node_id,
            node_type,
            label,
            subtitle=node_type.replace("_", " ").title(),
            confidence="medium",
            source="wazuh",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            metadata={"field": path},
            sensitive_metadata=node_type == "USER",
            evidence_refs=[evidence],
        )
        builder.add_edge(
            source_node_id,
            node_id,
            edge_type,
            label=edge_label,
            confidence="medium",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            evidence_refs=[evidence],
        )

    _add_mitre(builder, source_node_id, _mitre_values(parsed), timestamp=timestamp, evidence=evidence)


def _add_suppression_node(builder: GraphBuilder, source_node_id: str, alert: SecurityAlert, evidence: dict[str, str]) -> None:
    if not builder.options.include_suppression:
        return

    status = str(alert.status or "").upper()
    if "SUPPRESS" not in status and "NOISE" not in status:
        return

    node_id = f"noise_suppression:{_slug(status)}"
    builder.add_node(
        node_id,
        "NOISE_SUPPRESSION",
        status.replace("_", " ").title(),
        subtitle="Noise suppression",
        confidence="high",
        source="ai_soc",
        first_seen_at=alert.event_timestamp or alert.created_at,
        last_seen_at=alert.updated_at,
        metadata={"alert_status": status},
        evidence_refs=[evidence],
    )
    builder.add_edge(
        source_node_id,
        node_id,
        "SUPPRESSED_BY",
        label="suppressed by",
        confidence="high",
        first_seen_at=alert.event_timestamp or alert.created_at,
        last_seen_at=alert.updated_at,
        evidence_refs=[evidence],
    )


def _add_incident_core(builder: GraphBuilder, incident: Incident) -> str:
    node_id = f"incident:{incident.id}"
    timestamp = incident.timestamp
    builder.add_node(
        node_id,
        "INCIDENT",
        f"Incident #{incident.id}",
        subtitle=incident.rule or "Incident",
        severity=_severity_from_risk(incident.risk_score),
        confidence="high",
        source="ai_soc",
        first_seen_at=timestamp,
        last_seen_at=timestamp,
        metadata={
            "status": incident.status,
            "risk_score": incident.risk_score,
            "level": incident.level,
            "correlation_score": incident.correlation_score,
            "correlation_type": incident.correlation_type,
            "recommended_priority": incident.recommended_priority,
            "rule": incident.rule,
        },
        evidence_refs=[_evidence_ref("incident", incident.id, incident.rule)],
    )

    incident_evidence = _evidence_ref("incident", incident.id, incident.rule)
    _add_host(builder, node_id, incident.agent, timestamp=timestamp, evidence=incident_evidence)
    _add_mitre(
        builder,
        node_id,
        _mitre_values(incident.mitre, incident.attack_chain, incident.correlation_summary),
        timestamp=timestamp,
        evidence=incident_evidence,
    )
    _add_entities_from_payload(
        builder,
        node_id,
        incident.raw_alert,
        timestamp=timestamp,
        evidence=incident_evidence,
    )

    return node_id


def _add_alert_context(
    builder: GraphBuilder,
    incident_node_id: str,
    alert: SecurityAlert,
    raw_events_by_id: Mapping[int, RawEvent],
) -> None:
    node_id = f"security_alert:{alert.id}"
    timestamp = alert.event_timestamp or alert.created_at
    evidence = _evidence_ref("security_alert", alert.id, alert.rule_description or f"Wazuh alert level {alert.level}")

    builder.add_node(
        node_id,
        "SECURITY_ALERT",
        f"Alert #{alert.id}",
        subtitle=alert.rule_description or "Security alert",
        severity=_severity_from_alert(alert),
        confidence="high",
        source=alert.source or "wazuh",
        first_seen_at=timestamp,
        last_seen_at=alert.updated_at,
        metadata={
            "status": alert.status,
            "rule_id": alert.rule_id,
            "level": alert.level,
            "severity_bucket": alert.severity_bucket,
            "fingerprint": alert.fingerprint,
        },
        evidence_refs=[evidence],
    )
    builder.add_edge(
        incident_node_id,
        node_id,
        "HAS_ALERT",
        label="has alert",
        confidence="high",
        first_seen_at=timestamp,
        last_seen_at=alert.updated_at,
        evidence_refs=[evidence],
    )

    _add_host(builder, node_id, alert.agent, timestamp=timestamp, evidence=evidence)
    _add_rule(builder, node_id, alert.rule_id, description=alert.rule_description, timestamp=timestamp, evidence=evidence)
    _add_suppression_node(builder, node_id, alert, evidence)

    raw_event = raw_events_by_id.get(alert.raw_event_id)
    if builder.options.include_raw_events and raw_event:
        raw_node_id = _add_raw_event_context(builder, raw_event)
        builder.add_edge(
            node_id,
            raw_node_id,
            "HAS_RAW_EVENT",
            label="has raw event",
            confidence="high",
            first_seen_at=timestamp,
            last_seen_at=raw_event.updated_at,
            evidence_refs=[evidence, _evidence_ref("raw_event", raw_event.id, raw_event.rule_description)],
        )


def _add_raw_event_context(builder: GraphBuilder, raw_event: RawEvent) -> str:
    node_id = f"raw_event:{raw_event.id}"
    timestamp = raw_event.event_timestamp or raw_event.created_at
    evidence = _evidence_ref("raw_event", raw_event.id, raw_event.rule_description)
    viewer_limited = is_viewer(builder.current_user)

    builder.add_node(
        node_id,
        "RAW_EVENT",
        f"Raw event #{raw_event.id}",
        subtitle=raw_event.rule_description or raw_event.source_event_id or "Raw event",
        severity=_severity_from_risk((raw_event.level or 0) * 10),
        confidence="high",
        source=raw_event.source or "wazuh",
        first_seen_at=timestamp,
        last_seen_at=raw_event.updated_at,
        metadata={
            "source_event_id": raw_event.source_event_id,
            "source_index": raw_event.source_index,
            "rule_id": raw_event.rule_id,
            "level": raw_event.level,
            "agent": raw_event.agent,
        },
        sensitive_metadata=viewer_limited,
        evidence_refs=[evidence],
    )
    _add_host(builder, node_id, raw_event.agent, timestamp=timestamp, evidence=evidence)
    _add_rule(builder, node_id, raw_event.rule_id, description=raw_event.rule_description, timestamp=timestamp, evidence=evidence)

    if not viewer_limited:
        _add_entities_from_payload(
            builder,
            node_id,
            raw_event.payload_json,
            timestamp=timestamp,
            evidence=evidence,
        )

    return node_id


def _add_case_context(builder: GraphBuilder, case: IncidentCase, *, scope_node_id: str | None = None) -> str:
    node_id = f"case:{case.id}"
    evidence = _evidence_ref("case", case.id, case.title)
    owner_metadata = {}
    if not is_viewer(builder.current_user):
        owner_metadata = {
            "owner": case.owner,
            "assignee": case.assignee,
            "created_by": case.created_by,
        }

    builder.add_node(
        node_id,
        "CASE",
        f"Case #{case.id}",
        subtitle=case.title,
        severity=(case.severity_review or case.severity or "").upper() or _severity_from_risk(case.risk_score),
        confidence="high",
        source="case",
        first_seen_at=case.created_at,
        last_seen_at=case.updated_at,
        metadata={
            "status": case.status,
            "risk_score": case.risk_score,
            "correlation_type": case.correlation_type,
            "sla_due_at": _iso(case.sla_due_at),
            **owner_metadata,
        },
        sensitive_metadata=is_viewer(builder.current_user),
        evidence_refs=[evidence],
    )
    _add_host(builder, node_id, case.agent, timestamp=case.created_at, evidence=evidence)

    if scope_node_id and scope_node_id != node_id:
        builder.add_edge(
            scope_node_id,
            node_id,
            "PART_OF_CASE",
            label="part of case",
            confidence="high",
            first_seen_at=case.created_at,
            last_seen_at=case.updated_at,
            evidence_refs=[evidence],
        )

    return node_id


def _add_event_aggregates(builder: GraphBuilder, db, incident_node_id: str, incident: Incident) -> None:
    if not _table_exists(db, EventAggregate.__tablename__):
        return

    try:
        rows = (
            db.query(EventAggregate)
            .filter(EventAggregate.last_incident_id == incident.id)
            .order_by(EventAggregate.last_seen.asc(), EventAggregate.id.asc())
            .limit(INTERNAL_ROW_LIMIT)
            .all()
        )
    except SQLAlchemyError:
        _safe_rollback(db)
        return

    for row in rows:
        node_id = f"event_aggregate:{row.id}"
        evidence = _evidence_ref("event_aggregate", row.id, row.rule_description)
        builder.add_node(
            node_id,
            "EVENT_AGGREGATE",
            f"Aggregate #{row.id}",
            subtitle=row.rule_description or row.fingerprint,
            severity=(row.severity_bucket or "").upper() or _severity_from_risk((row.level or 0) * 10),
            confidence="medium",
            source=row.source or "wazuh",
            first_seen_at=row.first_seen,
            last_seen_at=row.last_seen,
            count=row.count or 1,
            metadata={
                "fingerprint": row.fingerprint,
                "rule_id": row.rule_id,
                "level": row.level,
                "decoder": row.decoder,
                "location": row.location,
            },
            sensitive_metadata=is_viewer(builder.current_user),
            evidence_refs=[evidence],
        )
        builder.add_edge(
            incident_node_id,
            node_id,
            "RELATED_TO",
            label="related aggregate",
            confidence="medium",
            first_seen_at=row.first_seen,
            last_seen_at=row.last_seen,
            evidence_refs=[evidence],
        )
        _add_host(builder, node_id, row.agent, timestamp=row.last_seen, evidence=evidence)
        _add_rule(builder, node_id, row.rule_id, description=row.rule_description, timestamp=row.last_seen, evidence=evidence)
        _add_mitre(builder, node_id, _mitre_values(row.sample_event_json, row.last_event_json), timestamp=row.last_seen, evidence=evidence)


def _add_ai_incident_nodes(builder: GraphBuilder, db, incident_node_id: str, incident: Incident) -> None:
    if not builder.options.include_ai:
        return

    if incident.ai_analysis:
        node_id = f"ai_analysis:incident:{incident.id}"
        evidence = _evidence_ref("incident_ai_analysis", incident.id, "Persisted incident AI analysis")
        builder.add_node(
            node_id,
            "AI_ANALYSIS",
            "Incident AI analysis",
            subtitle="AI-generated analysis",
            severity=None,
            confidence="medium",
            source="ai_analysis",
            first_seen_at=incident.timestamp,
            last_seen_at=incident.timestamp,
            metadata={"summary": _short(incident.ai_analysis, 220)},
            evidence_refs=[evidence],
        )
        builder.add_edge(
            node_id,
            incident_node_id,
            "AI_EXPLAINS",
            label="AI explains",
            confidence="medium",
            first_seen_at=incident.timestamp,
            last_seen_at=incident.timestamp,
            evidence_refs=[evidence],
        )

    if not _table_exists(db, InvestigationSessionRecord.__tablename__):
        return

    try:
        sessions = (
            db.query(InvestigationSessionRecord)
            .filter(InvestigationSessionRecord.incident_id == incident.id)
            .order_by(InvestigationSessionRecord.created_at.desc(), InvestigationSessionRecord.id.desc())
            .limit(MAX_AI_RECORDS)
            .all()
        )
    except SQLAlchemyError:
        _safe_rollback(db)
        return
    session_ids = [session.session_id for session in sessions]
    if not session_ids:
        return

    snapshots = []
    if _table_exists(db, InvestigationSnapshotRecord.__tablename__):
        try:
            snapshots = (
                db.query(InvestigationSnapshotRecord)
                .filter(InvestigationSnapshotRecord.session_id.in_(session_ids))
                .order_by(InvestigationSnapshotRecord.created_at.desc(), InvestigationSnapshotRecord.id.desc())
                .limit(MAX_AI_RECORDS)
                .all()
            )
        except SQLAlchemyError:
            _safe_rollback(db)
            snapshots = []
    for snapshot in snapshots:
        node_id = f"ai_analysis:snapshot:{_slug(snapshot.snapshot_id)}"
        evidence = _evidence_ref("investigation_snapshot", snapshot.snapshot_id, snapshot.snapshot_type)
        builder.add_node(
            node_id,
            "AI_ANALYSIS",
            snapshot.snapshot_type.replace("_", " ").title(),
            subtitle="Investigation snapshot",
            confidence="medium",
            source="ai_analysis",
            first_seen_at=snapshot.created_at,
            last_seen_at=snapshot.created_at,
            metadata={
                "snapshot_id": snapshot.snapshot_id,
                "session_id": snapshot.session_id,
                "evidence_count": snapshot.evidence_count,
                "hypothesis_count": snapshot.hypothesis_count,
            },
            evidence_refs=[evidence],
        )
        builder.add_edge(
            node_id,
            incident_node_id,
            "AI_EXPLAINS",
            label="AI explains",
            confidence="medium",
            first_seen_at=snapshot.created_at,
            last_seen_at=snapshot.created_at,
            evidence_refs=[evidence],
        )

    hypotheses = []
    if _table_exists(db, InvestigationHypothesisHistoryRecord.__tablename__):
        try:
            hypotheses = (
                db.query(InvestigationHypothesisHistoryRecord)
                .filter(InvestigationHypothesisHistoryRecord.session_id.in_(session_ids))
                .order_by(InvestigationHypothesisHistoryRecord.created_at.desc(), InvestigationHypothesisHistoryRecord.id.desc())
                .limit(MAX_AI_RECORDS)
                .all()
            )
        except SQLAlchemyError:
            _safe_rollback(db)
            hypotheses = []
    for hypothesis in hypotheses:
        node_id = f"ai_hypothesis:{_slug(hypothesis.session_id)}:{_slug(hypothesis.hypothesis_id)}"
        evidence = _evidence_ref("investigation_hypothesis", hypothesis.hypothesis_id, hypothesis.hypothesis_status)
        confidence = _confidence_from_score(hypothesis.confidence_score)
        builder.add_node(
            node_id,
            "AI_HYPOTHESIS",
            hypothesis.hypothesis_id.replace("-", " ").title(),
            subtitle="AI hypothesis",
            confidence=confidence,
            source="ai_analysis",
            first_seen_at=hypothesis.created_at,
            last_seen_at=hypothesis.created_at,
            metadata={
                "status": hypothesis.hypothesis_status,
                "confidence_score": hypothesis.confidence_score,
                "claim_classification": hypothesis.claim_classification,
                "supporting_evidence_count": hypothesis.supporting_evidence_count,
                "contradictory_evidence_count": hypothesis.contradictory_evidence_count,
                "missing_evidence_count": hypothesis.missing_evidence_count,
            },
            evidence_refs=[evidence],
        )
        builder.add_edge(
            node_id,
            incident_node_id,
            "AI_SUGGESTS",
            label="AI suggests",
            confidence=confidence,
            first_seen_at=hypothesis.created_at,
            last_seen_at=hypothesis.created_at,
            evidence_refs=[evidence],
        )


def _add_case_ai_nodes(builder: GraphBuilder, db, case_node_id: str, case: IncidentCase) -> None:
    if not builder.options.include_ai:
        return

    if not _table_exists(db, CaseAIAnalysis.__tablename__):
        return

    try:
        analyses = (
            db.query(CaseAIAnalysis)
            .filter(CaseAIAnalysis.case_id == case.id)
            .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
            .limit(MAX_AI_RECORDS)
            .all()
        )
    except SQLAlchemyError:
        _safe_rollback(db)
        return
    for analysis in analyses:
        node_id = f"ai_analysis:case:{analysis.id}"
        evidence = _evidence_ref("case_ai_analysis", analysis.id, analysis.recommended_status)
        builder.add_node(
            node_id,
            "AI_ANALYSIS",
            "Case AI analysis",
            subtitle="AI-generated case analysis",
            confidence="medium",
            source="ai_analysis",
            first_seen_at=analysis.created_at,
            last_seen_at=analysis.created_at,
            metadata={
                "model": analysis.model,
                "recommended_status": analysis.recommended_status,
                "recommended_severity": analysis.recommended_severity,
                "summary": _short(analysis.analysis, 220),
            },
            evidence_refs=[evidence],
        )
        builder.add_edge(
            node_id,
            case_node_id,
            "AI_EXPLAINS",
            label="AI explains",
            confidence="medium",
            first_seen_at=analysis.created_at,
            last_seen_at=analysis.created_at,
            evidence_refs=[evidence],
        )


def _add_timeline_nodes(builder: GraphBuilder, scope_node_id: str, items: list[dict[str, Any]], *, scope_label: str) -> None:
    if not builder.options.include_timeline:
        return

    previous_node_id: str | None = None
    for item in items[:MAX_TIMELINE_NODES]:
        item_id = item.get("id") or item.get("item_id") or f"{scope_label}:{item.get('event_type') or item.get('category')}:{item.get('reference_id')}"
        node_id = f"timeline_event:{_slug(item_id)}"
        timestamp = item.get("timestamp")
        evidence = _evidence_ref("timeline_event", item_id, item.get("title"))
        builder.add_node(
            node_id,
            "TIMELINE_EVENT",
            item.get("title") or item.get("event_type") or item.get("category") or "Timeline event",
            subtitle=item.get("category") or item.get("event_type") or "Timeline event",
            severity=(item.get("severity") or "").upper() or None,
            confidence="medium",
            source=item.get("source_system") or item.get("source") or "timeline",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            metadata={
                "status": item.get("status"),
                "actor": item.get("actor"),
                "source": item.get("source_system") or item.get("source"),
            },
            sensitive_metadata=is_viewer(builder.current_user),
            evidence_refs=[evidence],
        )
        builder.add_edge(
            scope_node_id,
            node_id,
            "RELATED_TO",
            label="has timeline event",
            confidence="medium",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            evidence_refs=[evidence],
        )

        if previous_node_id:
            builder.add_edge(
                previous_node_id,
                node_id,
                "TIMELINE_PRECEDES",
                label="precedes",
                confidence="medium",
                first_seen_at=timestamp,
                last_seen_at=timestamp,
                evidence_refs=[evidence],
            )
        previous_node_id = node_id


def _add_related_incidents_from_correlation(builder: GraphBuilder, db, incident_node_id: str, incident: Incident) -> None:
    if builder.options.depth < 2:
        return

    summary = _json_loads(incident.correlation_summary)
    if not isinstance(summary, Mapping):
        return

    related_ids = []
    for item in summary.get("related_event_details") or []:
        if not isinstance(item, Mapping):
            continue
        try:
            related_id = int(item.get("id"))
        except (TypeError, ValueError):
            continue
        if related_id != incident.id:
            related_ids.append(related_id)

    if not related_ids:
        return

    rows = (
        db.query(Incident)
        .filter(Incident.id.in_(sorted(set(related_ids))))
        .order_by(Incident.id.asc())
        .limit(20)
        .all()
    )
    for row in rows:
        related_node_id = _add_incident_core(builder, row)
        evidence = _evidence_ref("correlation_summary", incident.id, "Related incident from correlation metadata")
        builder.add_edge(
            incident_node_id,
            related_node_id,
            "CORRELATED_WITH",
            label="correlated with",
            confidence="medium",
            first_seen_at=incident.timestamp,
            last_seen_at=row.timestamp,
            evidence_refs=[evidence],
        )


def _add_incident_context(builder: GraphBuilder, db, incident: Incident) -> str:
    incident_node_id = _add_incident_core(builder, incident)
    alerts = _collect_security_alerts(db, incident)
    raw_events = _collect_raw_events(db, incident, alerts)
    raw_events_by_id = {raw_event.id: raw_event for raw_event in raw_events}

    for alert in alerts:
        _add_alert_context(builder, incident_node_id, alert, raw_events_by_id)

    if builder.options.include_raw_events:
        for raw_event in raw_events:
            raw_node_id = f"raw_event:{raw_event.id}"
            if raw_node_id not in builder.nodes:
                raw_node_id = _add_raw_event_context(builder, raw_event)
            builder.add_edge(
                incident_node_id,
                raw_node_id,
                "HAS_RAW_EVENT",
                label="has raw event",
                confidence="high",
                first_seen_at=raw_event.event_timestamp or raw_event.created_at,
                last_seen_at=raw_event.updated_at,
                evidence_refs=[_evidence_ref("raw_event", raw_event.id, raw_event.rule_description)],
            )

    _add_event_aggregates(builder, db, incident_node_id, incident)
    _add_ai_incident_nodes(builder, db, incident_node_id, incident)
    _add_related_incidents_from_correlation(builder, db, incident_node_id, incident)

    return incident_node_id


def build_incident_graph(
    db,
    incident_id: int,
    options: InvestigationGraphOptions | None = None,
    current_user: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    options = options or InvestigationGraphOptions()
    builder = GraphBuilder(current_user=current_user, options=options)
    incident = _load_incident(db, incident_id)
    incident_node_id = _add_incident_context(builder, db, incident)

    for case in _collect_cases_for_incident(db, incident.id):
        _add_case_context(builder, case, scope_node_id=incident_node_id)
        _add_case_ai_nodes(builder, db, f"case:{case.id}", case)

    if options.include_timeline:
        try:
            timeline_payload = build_incident_timeline_payload(
                db,
                incident.id,
                TimelineQuery(limit=MAX_TIMELINE_NODES, sort="asc", include_raw_payload=False),
                current_user=current_user,
            )
            _add_timeline_nodes(builder, incident_node_id, timeline_payload.get("items") or [], scope_label=f"incident:{incident.id}")
        except Exception:
            _safe_rollback(db)
            builder.warnings.append("Incident timeline nodes could not be included.")

    redaction_applied = is_viewer(current_user) and options.include_raw_events
    redaction_reason = "viewer_role_limited_raw_event_metadata" if redaction_applied else None
    if is_viewer(current_user) and options.include_raw_events:
        builder.warnings.append("Raw event metadata is redacted for VIEWER role.")

    return builder.finalize(
        scope="incident",
        scope_id=incident.id,
        redaction_applied=redaction_applied,
        redaction_reason=redaction_reason,
    )


def build_case_graph(
    db,
    case_id: int,
    options: InvestigationGraphOptions | None = None,
    current_user: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    options = options or InvestigationGraphOptions()
    builder = GraphBuilder(current_user=current_user, options=options)
    case = _load_case(db, case_id)
    case_node_id = _add_case_context(builder, case)
    _add_case_ai_nodes(builder, db, case_node_id, case)

    for incident in _collect_incidents_for_case(db, case.id):
        incident_node_id = _add_incident_context(builder, db, incident)
        evidence = _evidence_ref("case_incident", f"{case.id}:{incident.id}", "Incident linked to case")
        builder.add_edge(
            incident_node_id,
            case_node_id,
            "PART_OF_CASE",
            label="part of case",
            confidence="high",
            first_seen_at=incident.timestamp,
            last_seen_at=case.updated_at,
            evidence_refs=[evidence],
        )

    if options.include_timeline:
        try:
            timeline_payload = build_case_timeline_payload(db, case.id)
            _add_timeline_nodes(builder, case_node_id, timeline_payload.get("items") or [], scope_label=f"case:{case.id}")
        except Exception:
            _safe_rollback(db)
            builder.warnings.append("Case timeline nodes could not be included.")

    redaction_applied = is_viewer(current_user) and options.include_raw_events
    redaction_reason = "viewer_role_limited_raw_event_metadata" if redaction_applied else None
    if is_viewer(current_user) and options.include_raw_events:
        builder.warnings.append("Raw event metadata is redacted for VIEWER role.")

    return builder.finalize(
        scope="case",
        scope_id=case.id,
        redaction_applied=redaction_applied,
        redaction_reason=redaction_reason,
    )
