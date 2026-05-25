from __future__ import annotations

from typing import Any

from database import SessionLocal


EMPTY_NETWORK_EVIDENCE = {
    "source": "suricata",
    "available": False,
    "reason": "not_available",
    "correlation_window_minutes": 120,
    "matched_ips": [],
    "matched_hostnames": [],
    "summary": {
        "total": 0,
        "alert": 0,
        "dns": 0,
        "http": 0,
        "tls": 0,
        "flow": 0,
    },
    "items": [],
}


def empty_network_evidence(reason: str = "not_available") -> dict[str, Any]:
    payload = dict(EMPTY_NETWORK_EVIDENCE)
    payload["summary"] = dict(EMPTY_NETWORK_EVIDENCE["summary"])
    payload["matched_ips"] = []
    payload["matched_hostnames"] = []
    payload["items"] = []
    payload["reason"] = reason
    return payload


def load_incident_network_evidence(incident_id: int) -> dict[str, Any]:
    """Load read-only Suricata network evidence for report enrichment.

    This intentionally reuses the incident AI brief payload builder so report
    enrichment stays aligned with the Incident Detail Network Evidence logic.
    Failure to load network telemetry must never break report export.
    """
    try:
        from incident_ai_brief import load_incident_payload

        db = SessionLocal()

        try:
            incident_payload = load_incident_payload(db, incident_id)
        finally:
            db.close()

        evidence = incident_payload.get("network_evidence")

        if isinstance(evidence, dict):
            return evidence

        return empty_network_evidence("network_evidence_missing_from_incident_payload")

    except Exception as exc:
        evidence = empty_network_evidence("network_evidence_lookup_failed")
        evidence["error_type"] = type(exc).__name__
        return evidence


def attach_incident_network_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    incident = payload.get("incident")

    if not isinstance(incident, dict):
        payload["network_evidence"] = empty_network_evidence("incident_payload_missing")
        return payload

    incident_id = incident.get("id")

    if not incident_id:
        payload["network_evidence"] = empty_network_evidence("incident_id_missing")
        return payload

    payload["network_evidence"] = load_incident_network_evidence(int(incident_id))
    return payload


def attach_case_network_evidence(
    payload: dict[str, Any],
    max_incidents: int = 20,
) -> dict[str, Any]:
    incidents = payload.get("incidents")

    if not isinstance(incidents, list):
        payload["network_evidence_summary"] = {
            "source": "suricata",
            "total_related_events": 0,
            "incidents_with_network_evidence": 0,
            "incidents_checked": 0,
            "reason": "case_payload_has_no_incidents_list",
        }
        return payload

    total_related = 0
    with_evidence = 0
    checked = 0

    for incident in incidents[:max_incidents]:
        if not isinstance(incident, dict):
            continue

        incident_id = incident.get("id")
        if not incident_id:
            continue

        checked += 1
        evidence = load_incident_network_evidence(int(incident_id))
        incident["network_evidence"] = evidence

        summary = evidence.get("summary") if isinstance(evidence, dict) else {}
        related = int((summary or {}).get("total") or 0)
        total_related += related

        if related > 0:
            with_evidence += 1

    payload["network_evidence_summary"] = {
        "source": "suricata",
        "total_related_events": total_related,
        "incidents_with_network_evidence": with_evidence,
        "incidents_checked": checked,
        "max_incidents_checked": max_incidents,
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


def build_incident_network_evidence_markdown(
    evidence: dict[str, Any] | None,
    heading_level: int = 2,
) -> str:
    heading = "#" * heading_level
    evidence = evidence if isinstance(evidence, dict) else empty_network_evidence("not_available")
    summary = evidence.get("summary") or {}
    items = evidence.get("items") or []

    total = int(summary.get("total") or 0)
    alerts = int(summary.get("alert") or 0)

    lines: list[str] = [
        f"{heading} Network Evidence",
        "",
        "Source: Suricata network telemetry.",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Available", "Yes" if evidence.get("available") else "No"],
                ["Reason", evidence.get("reason")],
                ["Correlation window", f"±{evidence.get('correlation_window_minutes', 120)} minutes"],
                ["Related network events", total],
                ["IDS alert events", alerts],
                ["DNS events", summary.get("dns", 0)],
                ["HTTP events", summary.get("http", 0)],
                ["TLS events", summary.get("tls", 0)],
                ["Flow events", summary.get("flow", 0)],
            ],
        ),
        "",
        "Matched entities:",
        "",
        _table(
            ["Type", "Values"],
            [
                ["IPs", ", ".join(evidence.get("matched_ips") or []) or "-"],
                ["Hostnames", ", ".join(evidence.get("matched_hostnames") or []) or "-"],
            ],
        ),
        "",
    ]

    if total == 0:
        lines.extend(
            [
                "No related Suricata network telemetry was found in the selected correlation window.",
                "",
                "Note: absence of matching network telemetry does not prove benign activity; it only means no matching Suricata evidence was available for this report window.",
                "",
            ]
        )
        return "\n".join(lines)

    rows = []

    for item in items[:12]:
        if not isinstance(item, dict):
            continue

        rows.append(
            [
                item.get("event_timestamp"),
                item.get("event_type"),
                f"{_format_value(item.get('src_ip'))}:{_format_value(item.get('src_port'))}",
                f"{_format_value(item.get('dest_ip'))}:{_format_value(item.get('dest_port'))}",
                item.get("hostname") or item.get("tls_sni") or "-",
                item.get("app_proto") or item.get("proto") or "-",
                item.get("alert_signature") or "No IDS alert",
            ]
        )

    lines.extend(
        [
            "Latest related network events:",
            "",
            _table(
                ["Time", "Type", "Source", "Destination", "Host / SNI", "Protocol", "Alert"],
                rows,
            ),
            "",
            "Analyst note: Suricata network telemetry is supporting evidence. It should be interpreted together with Wazuh, correlation context and analyst validation.",
            "",
        ]
    )

    return "\n".join(lines)


def append_incident_network_evidence_markdown(
    markdown: str,
    payload: dict[str, Any],
) -> str:
    section = build_incident_network_evidence_markdown(
        payload.get("network_evidence"),
        heading_level=2,
    )

    return markdown.rstrip() + "\n\n" + section


def append_case_network_evidence_markdown(
    markdown: str,
    payload: dict[str, Any],
) -> str:
    incidents = payload.get("incidents")
    summary = payload.get("network_evidence_summary") or {}

    lines: list[str] = [
        "## Network Evidence Summary",
        "",
        "Source: Suricata network telemetry.",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Incidents checked", summary.get("incidents_checked", 0)],
                ["Incidents with network evidence", summary.get("incidents_with_network_evidence", 0)],
                ["Total related network events", summary.get("total_related_events", 0)],
            ],
        ),
        "",
    ]

    if not isinstance(incidents, list) or not incidents:
        lines.extend(["No linked incidents were available for network evidence enrichment.", ""])
        return markdown.rstrip() + "\n\n" + "\n".join(lines)

    for incident in incidents[:20]:
        if not isinstance(incident, dict):
            continue

        evidence = incident.get("network_evidence")

        lines.extend(
            [
                f"### Incident {incident.get('id', '-')}: {_format_value(incident.get('rule'))}",
                "",
                build_incident_network_evidence_markdown(evidence, heading_level=4),
                "",
            ]
        )

    return markdown.rstrip() + "\n\n" + "\n".join(lines)
