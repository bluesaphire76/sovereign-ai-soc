from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from database import SessionLocal


DNS_CONTEXT_LIMITATION = (
    "DNS context is matched by host/client IP and selected time window only. "
    "It does not imply causal correlation with the incident."
)

EMPTY_DNS_CONTEXT = {
    "available": False,
    "reason": "not_available",
    "source": "dns_events",
    "matching_logic": "same host/client IP and selected time window only",
    "causal_correlation_inferred": False,
    "window_minutes": 120,
    "matched_agents": [],
    "matched_client_ips": [],
    "summary": {
        "total": 0,
        "unique_domains": 0,
        "query_types": [],
        "top_domains": [],
    },
    "items": [],
    "limitations": [
        DNS_CONTEXT_LIMITATION,
    ],
}


def empty_dns_context(reason: str = "not_available") -> dict[str, Any]:
    context = dict(EMPTY_DNS_CONTEXT)
    context["summary"] = dict(EMPTY_DNS_CONTEXT["summary"])
    context["summary"]["query_types"] = []
    context["summary"]["top_domains"] = []
    context["matched_agents"] = []
    context["matched_client_ips"] = []
    context["items"] = []
    context["limitations"] = list(EMPTY_DNS_CONTEXT["limitations"])
    context["reason"] = reason
    return context


def parse_timestamp_utc(value: Any) -> datetime | None:
    if not value:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    normalized = raw.replace("Z", "+00:00")

    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def parse_raw_alert(value: Any) -> dict[str, Any]:
    if not value:
        return {}

    if isinstance(value, dict):
        return value

    try:
        parsed = json.loads(value)
    except Exception:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def deep_get(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


def iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    return value


def row_to_dict(row: Any) -> dict[str, Any]:
    item = dict(row)

    for key in ["event_timestamp", "created_at"]:
        if key in item:
            item[key] = iso(item[key])

    return item


def _incident_payload_from_db(db, incident_id: int) -> dict[str, Any] | None:
    incident = (
        db.execute(
            text("""
                SELECT id, timestamp, agent, raw_alert
                FROM incidents
                WHERE id = :incident_id
            """),
            {"incident_id": incident_id},
        )
        .mappings()
        .fetchone()
    )

    if not incident:
        return None

    return dict(incident)


def _dns_candidates(incident_payload: dict[str, Any]) -> tuple[set[str], set[str]]:
    raw_alert = parse_raw_alert(incident_payload.get("raw_alert"))

    candidate_agents = {
        str(incident_payload.get("agent") or "").strip(),
        str(deep_get(raw_alert, "agent", "name") or "").strip(),
        str(deep_get(raw_alert, "host", "name") or "").strip(),
    }

    candidate_ips = {
        str(deep_get(raw_alert, "agent", "ip") or "").strip(),
        str(deep_get(raw_alert, "data", "srcip") or "").strip(),
        str(deep_get(raw_alert, "data", "dstip") or "").strip(),
        str(deep_get(raw_alert, "data", "src_ip") or "").strip(),
        str(deep_get(raw_alert, "data", "dst_ip") or "").strip(),
    }

    entities = incident_payload.get("extracted_entities")
    if isinstance(entities, dict):
        for ip in entities.get("ips") or []:
            candidate_ips.add(str(ip).strip())

    candidate_agents = {
        value for value in candidate_agents if value and value != "-"
    }
    candidate_ips = {
        value for value in candidate_ips if value and value != "-"
    }

    return candidate_agents, candidate_ips


def load_incident_dns_context_from_payload(
    incident_payload: dict[str, Any],
    window_minutes: int = 120,
    limit: int = 25,
) -> dict[str, Any]:
    """Load contextual DNS telemetry for report enrichment.

    This is read-only and intentionally conservative: DNS is matched only by
    host/client IP candidates and a selected time window. It must never be
    represented as causal evidence in reports.
    """

    try:
        incident_ts = parse_timestamp_utc(incident_payload.get("timestamp"))

        if not incident_ts:
            return empty_dns_context("incident_timestamp_unavailable")

        candidate_agents, candidate_ips = _dns_candidates(incident_payload)

        if not candidate_agents and not candidate_ips:
            return empty_dns_context("no_agent_or_client_ip_candidates")

        start_ts = incident_ts - timedelta(minutes=window_minutes)
        end_ts = incident_ts + timedelta(minutes=window_minutes)

        match_clauses: list[str] = []
        params: dict[str, Any] = {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "limit": limit,
        }

        for index, agent in enumerate(sorted(candidate_agents)[:20]):
            key = f"agent_{index}"
            params[key] = agent
            match_clauses.append(f"agent_name = :{key}")

        for index, ip in enumerate(sorted(candidate_ips)[:20]):
            key = f"ip_{index}"
            params[key] = ip
            match_clauses.append(f"client_ip = :{key}")

        if not match_clauses:
            return empty_dns_context("no_valid_match_candidates")

        where_clause = (
            "event_timestamp BETWEEN :start_ts AND :end_ts "
            "AND (" + " OR ".join(match_clauses) + ")"
        )

        with SessionLocal() as db:
            rows = (
                db.execute(
                    text(f"""
                        SELECT
                            id,
                            source,
                            raw_event_id,
                            source_event_id,
                            event_timestamp,
                            agent_name,
                            agent_ip,
                            client_ip,
                            client_port,
                            resolver_ip,
                            resolver_port,
                            query_name,
                            query_type,
                            query_status,
                            collector,
                            raw_line,
                            created_at
                        FROM dns_events
                        WHERE {where_clause}
                        ORDER BY event_timestamp DESC NULLS LAST, id DESC
                        LIMIT :limit
                    """),
                    params,
                )
                .mappings()
                .all()
            )

            total = db.execute(
                text(f"""
                    SELECT count(*)
                    FROM dns_events
                    WHERE {where_clause}
                """),
                params,
            ).scalar()

            unique_domains = db.execute(
                text(f"""
                    SELECT count(DISTINCT query_name)
                    FROM dns_events
                    WHERE {where_clause}
                """),
                params,
            ).scalar()

            query_types = (
                db.execute(
                    text(f"""
                        SELECT query_type, count(*) AS count
                        FROM dns_events
                        WHERE {where_clause}
                        GROUP BY query_type
                        ORDER BY count DESC
                        LIMIT 10
                    """),
                    params,
                )
                .mappings()
                .all()
            )

            top_domains = (
                db.execute(
                    text(f"""
                        SELECT query_name, count(*) AS count
                        FROM dns_events
                        WHERE {where_clause}
                          AND query_name IS NOT NULL
                        GROUP BY query_name
                        ORDER BY count DESC
                        LIMIT 10
                    """),
                    params,
                )
                .mappings()
                .all()
            )

        items = [row_to_dict(row) for row in rows]
        total_count = int(total or 0)

        return {
            "available": total_count > 0,
            "reason": "matched_dns_context" if total_count else "no_contextual_dns_events_found",
            "source": "dns_events",
            "matching_logic": "same host/client IP and selected time window only",
            "causal_correlation_inferred": False,
            "window_minutes": window_minutes,
            "matched_agents": sorted(candidate_agents),
            "matched_client_ips": sorted(candidate_ips),
            "summary": {
                "total": total_count,
                "unique_domains": int(unique_domains or 0),
                "query_types": [dict(row) for row in query_types],
                "top_domains": [dict(row) for row in top_domains],
            },
            "items": items,
            "limitations": [DNS_CONTEXT_LIMITATION],
        }

    except Exception as exc:
        context = empty_dns_context("dns_context_lookup_failed")
        context["lookup_error_handled"] = True
        context["error_type"] = type(exc).__name__
        return context


def load_incident_dns_context(
    incident_id: int,
    window_minutes: int = 120,
    limit: int = 25,
) -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            incident_payload = _incident_payload_from_db(db, incident_id)

        if not incident_payload:
            return empty_dns_context("incident_not_found")

        return load_incident_dns_context_from_payload(
            incident_payload,
            window_minutes=window_minutes,
            limit=limit,
        )

    except Exception as exc:
        context = empty_dns_context("dns_context_lookup_failed")
        context["lookup_error_handled"] = True
        context["error_type"] = type(exc).__name__
        return context


def attach_incident_dns_context(payload: dict[str, Any]) -> dict[str, Any]:
    incident = payload.get("incident")

    if not isinstance(incident, dict):
        payload["dns_context"] = empty_dns_context("incident_payload_missing")
        return payload

    incident_id = incident.get("id")

    if not incident_id:
        payload["dns_context"] = empty_dns_context("incident_id_missing")
        return payload

    incident_payload = {
        "id": incident_id,
        "timestamp": incident.get("timestamp"),
        "agent": incident.get("agent"),
        "raw_alert": incident.get("raw_alert"),
    }

    payload["dns_context"] = load_incident_dns_context_from_payload(incident_payload)
    return payload


def attach_case_dns_context(
    payload: dict[str, Any],
    max_incidents: int = 20,
) -> dict[str, Any]:
    incidents = payload.get("incidents")

    if not isinstance(incidents, list):
        payload["dns_context_summary"] = {
            "source": "dns_events",
            "incidents_checked": 0,
            "incidents_with_dns_context": 0,
            "total_dns_observations": 0,
            "reason": "case_payload_has_no_incidents_list",
            "causal_correlation_inferred": False,
            "limitations": [DNS_CONTEXT_LIMITATION],
        }
        return payload

    checked = 0
    with_context = 0
    total_observations = 0

    for incident in incidents[:max_incidents]:
        if not isinstance(incident, dict):
            continue

        incident_id = incident.get("id")
        if not incident_id:
            continue

        checked += 1
        context = load_incident_dns_context(int(incident_id))
        incident["dns_context"] = context

        summary = context.get("summary") if isinstance(context, dict) else {}
        total = int((summary or {}).get("total") or 0)
        total_observations += total

        if total > 0:
            with_context += 1

    payload["dns_context_summary"] = {
        "source": "dns_events",
        "incidents_checked": checked,
        "incidents_with_dns_context": with_context,
        "total_dns_observations": total_observations,
        "max_incidents_checked": max_incidents,
        "causal_correlation_inferred": False,
        "limitations": [DNS_CONTEXT_LIMITATION],
    }

    return payload


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return "-"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    return str(value)


def _escape_table(value: Any) -> str:
    return _format_value(value).replace("|", "\\|").replace("\n", "<br/>")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]

    for row in rows:
        lines.append("| " + " | ".join(_escape_table(item) for item in row) + " |")

    return "\n".join(lines)


def _query_type_rows(context: dict[str, Any]) -> list[list[Any]]:
    summary = context.get("summary") or {}
    rows = []

    for item in summary.get("query_types") or []:
        if isinstance(item, dict):
            rows.append([item.get("query_type") or "UNKNOWN", item.get("count")])

    return rows


def _top_domain_rows(context: dict[str, Any]) -> list[list[Any]]:
    summary = context.get("summary") or {}
    rows = []

    for item in summary.get("top_domains") or []:
        if isinstance(item, dict):
            rows.append([item.get("query_name") or "unknown", item.get("count")])

    return rows


def build_incident_dns_context_markdown(
    context: dict[str, Any] | None,
    heading_level: int = 2,
    technical: bool = False,
    title: str = "DNS Context",
    seen_item_keys: set[str] | None = None,
) -> str:
    heading = "#" * heading_level
    context = context if isinstance(context, dict) else empty_dns_context("not_available")
    summary = context.get("summary") or {}
    items = context.get("items") or []
    total = int(summary.get("total") or 0)

    lines: list[str] = [
        f"{heading} {title}",
        "",
        DNS_CONTEXT_LIMITATION,
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Available", "Yes" if context.get("available") else "No"],
                ["Reason", context.get("reason")],
                ["Source", context.get("source")],
                ["Matching logic", context.get("matching_logic")],
                ["Causal correlation inferred", context.get("causal_correlation_inferred")],
                ["Selected time window", f"±{context.get('window_minutes', 120)} minutes"],
                ["Total DNS observations", total],
                ["Unique queried domains", summary.get("unique_domains", 0)],
            ],
        ),
        "",
        "Matched entities:",
        "",
        _table(
            ["Type", "Values"],
            [
                ["Agents", ", ".join(context.get("matched_agents") or []) or "-"],
                ["Client IPs", ", ".join(context.get("matched_client_ips") or []) or "-"],
            ],
        ),
        "",
    ]

    if total == 0:
        lines.extend(
            [
                "No contextual DNS telemetry was found for the same host/client IP in the selected time window.",
                "",
            ]
        )
        return "\n".join(lines)

    query_type_rows = _query_type_rows(context)
    if query_type_rows:
        lines.extend(["Query type distribution:", "", _table(["Query type", "Count"], query_type_rows), ""])

    top_domain_rows = _top_domain_rows(context)
    if top_domain_rows:
        lines.extend(["Top queried domains:", "", _table(["Query name", "Count"], top_domain_rows), ""])

    rows = []

    for item in items:
        if not isinstance(item, dict):
            continue

        item_key = str(
            item.get("raw_event_id")
            or item.get("source_event_id")
            or item.get("id")
            or f"{item.get('event_timestamp')}:{item.get('query_name')}"
        )

        if seen_item_keys is not None and item_key in seen_item_keys:
            continue

        if seen_item_keys is not None:
            seen_item_keys.add(item_key)

        if technical:
            rows.append(
                [
                    item.get("raw_event_id"),
                    item.get("source_event_id"),
                    item.get("event_timestamp"),
                    item.get("query_name"),
                    item.get("query_type"),
                    item.get("client_ip"),
                    item.get("resolver_ip"),
                    item.get("collector"),
                    item.get("source"),
                ]
            )
        else:
            rows.append(
                [
                    item.get("event_timestamp"),
                    item.get("agent_name") or item.get("client_ip"),
                    item.get("resolver_ip"),
                    item.get("query_name"),
                    item.get("query_type"),
                    f"{_format_value(item.get('source'))} / {_format_value(item.get('collector'))}",
                ]
            )

    if rows:
        if technical:
            lines.extend(
                [
                    "Recent contextual DNS observations:",
                    "",
                    _table(
                        [
                            "Raw event ID",
                            "Source event ID",
                            "Time",
                            "Query",
                            "Type",
                            "Client IP",
                            "Resolver IP",
                            "Collector",
                            "Source",
                        ],
                        rows,
                    ),
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "Recent DNS observations:",
                    "",
                    _table(
                        ["Time", "Agent / client IP", "Resolver", "Query", "Type", "Source / collector"],
                        rows,
                    ),
                    "",
                ]
            )
    elif seen_item_keys is not None:
        lines.extend(["DNS observations for this incident were already listed earlier in the evidence pack.", ""])

    return "\n".join(lines)


def append_incident_dns_context_markdown(
    markdown: str,
    payload: dict[str, Any],
) -> str:
    section = build_incident_dns_context_markdown(
        payload.get("dns_context"),
        heading_level=2,
        technical=False,
        title="DNS Context",
    )

    return markdown.rstrip() + "\n\n" + section


def append_case_dns_context_markdown(
    markdown: str,
    payload: dict[str, Any],
    technical: bool = False,
) -> str:
    incidents = payload.get("incidents")
    summary = payload.get("dns_context_summary") or {}
    title = "Contextual DNS Telemetry" if technical else "DNS Context"

    lines: list[str] = [
        f"## {title}",
        "",
        DNS_CONTEXT_LIMITATION,
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Incidents checked", summary.get("incidents_checked", 0)],
                ["Incidents with DNS context", summary.get("incidents_with_dns_context", 0)],
                ["Total DNS observations", summary.get("total_dns_observations", 0)],
                ["Causal correlation inferred", summary.get("causal_correlation_inferred", False)],
            ],
        ),
        "",
    ]

    if not isinstance(incidents, list) or not incidents:
        lines.extend(["No linked incidents were available for DNS context enrichment.", ""])
        return markdown.rstrip() + "\n\n" + "\n".join(lines)

    if not technical:
        rows = []

        for incident in incidents[:20]:
            if not isinstance(incident, dict):
                continue

            context = incident.get("dns_context")
            if not isinstance(context, dict):
                context = empty_dns_context("not_available")

            dns_summary = context.get("summary") or {}
            top_domains = dns_summary.get("top_domains") or []
            top_domain = "-"

            if top_domains and isinstance(top_domains[0], dict):
                top_domain = top_domains[0].get("query_name") or "-"

            rows.append(
                [
                    incident.get("id"),
                    incident.get("agent"),
                    incident.get("rule"),
                    dns_summary.get("total", 0),
                    dns_summary.get("unique_domains", 0),
                    top_domain,
                    context.get("reason"),
                ]
            )

        if rows:
            lines.extend(
                [
                    "DNS context observed around linked incidents:",
                    "",
                    _table(
                        ["Incident", "Host", "Rule", "DNS observations", "Unique domains", "Top domain", "Reason"],
                        rows,
                    ),
                    "",
                ]
            )

        return markdown.rstrip() + "\n\n" + "\n".join(lines)

    seen_item_keys: set[str] = set()

    for incident in incidents[:20]:
        if not isinstance(incident, dict):
            continue

        lines.extend(
            [
                f"### Incident {incident.get('id', '-')}: {_format_value(incident.get('rule'))}",
                "",
                build_incident_dns_context_markdown(
                    incident.get("dns_context"),
                    heading_level=4,
                    technical=True,
                    title="Endpoint DNS Context",
                    seen_item_keys=seen_item_keys,
                ),
                "",
            ]
        )

    return markdown.rstrip() + "\n\n" + "\n".join(lines)
