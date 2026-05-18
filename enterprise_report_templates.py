from __future__ import annotations

import json
from typing import Any


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return "-"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)

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


def _json_block(value: Any) -> str:
    if value is None:
        value = None

    return "```json\n" + json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n```"


def _text_block(value: Any, fallback: str = "Not documented.") -> str:
    text = _format_value(value)

    if text == "-":
        return fallback

    return text


def _ai_line(ai_text: str | None, label: str) -> str | None:
    if not ai_text:
        return None

    needle = label.lower()

    for raw_line in ai_text.splitlines():
        line = raw_line.strip()
        if needle in line.lower() and ":" in line:
            return line.split(":", 1)[1].strip()

    return None


def _compact_correlation_summary(summary: Any, max_related_events: int = 10) -> Any:
    if not isinstance(summary, dict):
        return summary

    compact = dict(summary)

    details = compact.get("related_event_details")
    if isinstance(details, list) and len(details) > max_related_events:
        compact["related_event_details_sample"] = details[:max_related_events]
        compact["related_event_details_total"] = len(details)
        compact["related_event_details_truncated"] = True
        compact.pop("related_event_details", None)

    return compact


def _risk_review_note(current: str | None, reviewed: str | None) -> str:
    current_value = (current or "").upper()
    reviewed_value = (reviewed or "").upper()

    if not current_value or not reviewed_value or current_value == reviewed_value:
        return "No severity review discrepancy detected."

    return (
        "Severity review differs from the current case severity. "
        "Analyst validation is required before external distribution."
    )


def _status_decision(status: str | None) -> str:
    normalized = (status or "").upper()

    if normalized in {"CLOSED", "FALSE_POSITIVE"}:
        return "Terminal workflow status reached."

    if normalized in {"ESCALATED", "INVESTIGATING"}:
        return "Active investigation or escalation in progress."

    if normalized in {"TRIAGED", "OPEN", "NEW"}:
        return "Human review and follow-up remain required."

    return "Workflow status requires analyst review."


def _append_audit_trail(lines: list[str], audit_events: list[dict[str, Any]], title: str) -> None:
    lines.extend([f"## {title}", ""])

    if not audit_events:
        lines.extend(["No audit events available.", ""])
        return

    rows = []

    for event in audit_events:
        rows.append(
            [
                event.get("id"),
                event.get("event_type") or event.get("type"),
                event.get("old_value"),
                event.get("new_value"),
                event.get("created_by"),
                event.get("created_at"),
            ]
        )

    lines.extend(
        [
            _table(
                ["ID", "Type", "Old value", "New value", "Actor", "Timestamp"],
                rows,
            ),
            "",
        ]
    )


def _append_notes(lines: list[str], notes: list[dict[str, Any]]) -> None:
    lines.extend(["## Analyst Notes", ""])

    if not notes:
        lines.extend(["No analyst notes available.", ""])
        return

    for note in notes:
        lines.extend(
            [
                f"### Note #{_format_value(note.get('id'))}",
                "",
                f"- **Created by:** {_format_value(note.get('created_by'))}",
                f"- **Created at:** {_format_value(note.get('created_at'))}",
                "",
                _text_block(note.get("note") or note.get("content")),
                "",
            ]
        )


def build_enterprise_incident_markdown(payload: dict[str, Any]) -> str:
    incident = payload["incident"]
    ai_analysis = incident.get("ai_analysis")
    correlation_summary = incident.get("correlation_summary")
    compact_correlation = _compact_correlation_summary(correlation_summary)

    risk_normalization = {}
    if isinstance(correlation_summary, dict):
        risk_normalization = correlation_summary.get("risk_normalization") or {}

    executive_ai_summary = _ai_line(ai_analysis, "short executive summary")
    recommended_checks = _ai_line(ai_analysis, "recommended checks")
    suggested_remediation = _ai_line(ai_analysis, "suggested remediation")
    business_risk = _ai_line(ai_analysis, "business risk")

    lines: list[str] = [
        f"# Enterprise Incident Report #{incident['id']}",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## 1. Executive Snapshot",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Status", incident.get("status")],
                ["Host", incident.get("agent")],
                ["Rule", incident.get("rule")],
                ["Risk score", incident.get("risk_score")],
                ["Recommended priority", incident.get("recommended_priority")],
                ["Correlation score", incident.get("correlation_score")],
                ["Correlation type", incident.get("correlation_type")],
                ["Workflow decision", _status_decision(incident.get("status"))],
            ],
        ),
        "",
        "## 2. Business Impact & Triage Assessment",
        "",
        f"- **Business risk:** {_format_value(business_risk)}",
        f"- **Executive summary:** {_format_value(executive_ai_summary)}",
        f"- **Current triage state:** {_status_decision(incident.get('status'))}",
        f"- **Escalation reason:** {_format_value(incident.get('escalation_reason'))}",
        "",
        "## 3. Recommended Analyst Actions",
        "",
        f"1. **Validate the event:** {_format_value(recommended_checks)}",
        f"2. **Apply remediation or acceptance decision:** {_format_value(suggested_remediation)}",
        "3. **Document the human decision:** confirm whether the event is authorized, operational noise, or a security-relevant signal.",
        "4. **Update workflow status:** close, triage, or escalate based on evidence and business impact.",
        "",
        "## 4. Technical Incident Details",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Timestamp", incident.get("timestamp")],
                ["Wazuh document ID", incident.get("wazuh_doc_id")],
                ["Wazuh level", incident.get("level")],
                ["Correlated", incident.get("correlated")],
                ["Risk policy", risk_normalization.get("policy")],
                ["Risk cap", risk_normalization.get("cap")],
                ["Raw score before cap", risk_normalization.get("raw_score_before_cap")],
                ["Matched attack chains", risk_normalization.get("matched_chain_count")],
            ],
        ),
        "",
        "## 5. AI-Assisted Analysis",
        "",
        _text_block(ai_analysis, "No AI analysis available."),
        "",
        "## 6. MITRE ATT&CK Mapping",
        "",
        _json_block(incident.get("mitre")),
        "",
        "## 7. Risk & Correlation Rationale",
        "",
        _json_block(compact_correlation),
        "",
        "## 8. Attack Chain Assessment",
        "",
        _json_block(incident.get("attack_chain")),
        "",
    ]

    _append_notes(lines, payload.get("notes", []))
    _append_audit_trail(lines, payload.get("audit_trail", []), "Audit Trail")

    lines.extend(
        [
            "## Appendix A — Raw Alert Evidence",
            "",
            _json_block(incident.get("raw_alert")),
            "",
        ]
    )

    return "\n".join(lines).strip() + "\n"


def build_enterprise_case_markdown(payload: dict[str, Any]) -> str:
    case = payload["case"]
    analysis = payload.get("case_ai_analysis") or {}
    actions = payload.get("case_actions", [])
    incidents = payload.get("incidents", [])
    readiness = payload.get("case_closure_readiness") or {}
    checklist = payload.get("case_closure_checklist") or {}

    open_actions = [
        action
        for action in actions
        if (action.get("status") or "").upper() in {"OPEN", "IN_PROGRESS"}
    ]

    blocking_items = readiness.get("blocking_items") or []

    lines: list[str] = [
        f"# Enterprise Investigation Case Report #{case['id']}",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## 1. Executive Snapshot",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Title", case.get("title")],
                ["Status", case.get("status")],
                ["Severity", case.get("severity")],
                ["Severity review", case.get("severity_review")],
                ["Risk score", case.get("risk_score")],
                ["Owner", case.get("owner")],
                ["Host", case.get("agent")],
                ["SLA status", case.get("sla_status")],
                ["Linked incidents", len(incidents)],
                ["Open / in-progress actions", len(open_actions)],
                ["Closure readiness", "READY" if readiness.get("ready_to_close") else "BLOCKED"],
            ],
        ),
        "",
        "## 2. Management Assessment",
        "",
        f"- **Workflow decision:** {_status_decision(case.get('status'))}",
        f"- **Severity governance:** {_risk_review_note(case.get('severity'), case.get('severity_review'))}",
        f"- **Closure readiness:** {'Ready for closure review.' if readiness.get('ready_to_close') else 'Closure is blocked pending mandatory evidence and decision fields.'}",
        f"- **SLA posture:** {_format_value(case.get('sla_status'))}",
        "",
        "## 3. Case Narrative",
        "",
        _text_block(case.get("summary"), "No case summary available."),
        "",
        "## 4. AI Case Analysis",
        "",
    ]

    if analysis:
        lines.extend(
            [
                _table(
                    ["Field", "Value"],
                    [
                        ["Recommended severity", analysis.get("recommended_severity")],
                        ["Recommended status", analysis.get("recommended_status")],
                        ["Confidence", analysis.get("confidence")],
                        ["Created at", analysis.get("created_at")],
                    ],
                ),
                "",
                _text_block(analysis.get("analysis"), "No AI case analysis text available."),
                "",
            ]
        )
    else:
        lines.extend(["No case AI analysis available.", ""])

    lines.extend(["## 5. Action Plan & Ownership", ""])

    if actions:
        action_rows = []
        for action in actions:
            action_rows.append(
                [
                    action.get("id"),
                    action.get("title"),
                    action.get("status"),
                    action.get("priority"),
                    action.get("owner"),
                    action.get("due_at"),
                ]
            )

        lines.extend(
            [
                _table(
                    ["ID", "Action", "Status", "Priority", "Owner", "Due at"],
                    action_rows,
                ),
                "",
            ]
        )
    else:
        lines.extend(
            [
                "No case actions available.",
                "",
                "Recommended minimum follow-up:",
                "",
                "1. Confirm business ownership for the affected asset.",
                "2. Validate whether the linked incident represents authorized operational activity or a security-relevant signal.",
                "3. Document evidence reviewed, root cause, residual risk and closure decision.",
                "4. Close or escalate the case only after human review.",
                "",
            ]
        )

    lines.extend(
        [
            "## 6. Closure Readiness & Governance",
            "",
            _table(
                ["Field", "Value"],
                [
                    ["Ready to close", readiness.get("ready_to_close")],
                    ["Open action count", readiness.get("open_action_count")],
                    ["Closure decision", checklist.get("closure_decision")],
                    ["Final severity", checklist.get("final_severity")],
                    ["Reviewed by", checklist.get("reviewed_by")],
                    ["Reviewed at", checklist.get("reviewed_at")],
                    ["Residual risk", checklist.get("residual_risk")],
                ],
            ),
            "",
        ]
    )

    if blocking_items:
        lines.extend(["### Blocking Items", ""])
        lines.extend([f"- {item}" for item in blocking_items])
        lines.append("")

    lines.extend(
        [
            "## 7. Linked Incident Overview",
            "",
        ]
    )

    if incidents:
        incident_rows = []
        for incident in incidents:
            incident_rows.append(
                [
                    incident.get("id"),
                    incident.get("status"),
                    incident.get("timestamp"),
                    incident.get("agent"),
                    incident.get("rule"),
                    incident.get("risk_score"),
                    incident.get("recommended_priority"),
                    incident.get("correlation_score"),
                ]
            )

        lines.extend(
            [
                _table(
                    [
                        "ID",
                        "Status",
                        "Timestamp",
                        "Host",
                        "Rule",
                        "Risk",
                        "Priority",
                        "Correlation",
                    ],
                    incident_rows,
                ),
                "",
            ]
        )
    else:
        lines.extend(["No linked incidents available.", ""])

    _append_audit_trail(lines, payload.get("case_audit_trail", []), "8. Case Workflow Audit Trail")

    lines.extend(
        [
            "## Appendix A — Closure Checklist Details",
            "",
            "### Root Cause / Conclusion",
            "",
            _text_block(checklist.get("root_cause"), "Not documented."),
            "",
            "### Evidence Reviewed",
            "",
            _text_block(checklist.get("evidence_reviewed"), "Not documented."),
            "",
            "### Actions Summary",
            "",
            _text_block(checklist.get("actions_summary"), "Not documented."),
            "",
            "### Closure Reason",
            "",
            _text_block(checklist.get("closure_reason"), "Not documented."),
            "",
            "### Residual Risk",
            "",
            _text_block(checklist.get("residual_risk"), "Not documented."),
            "",
            "## Appendix B — Linked Incident Evidence",
            "",
        ]
    )

    for incident in incidents:
        compact_correlation = _compact_correlation_summary(
            incident.get("correlation_summary"),
            max_related_events=5,
        )

        lines.extend(
            [
                f"### Incident #{incident.get('id')}",
                "",
                _table(
                    ["Field", "Value"],
                    [
                        ["Status", incident.get("status")],
                        ["Timestamp", incident.get("timestamp")],
                        ["Host", incident.get("agent")],
                        ["Rule", incident.get("rule")],
                        ["Level", incident.get("level")],
                        ["Risk score", incident.get("risk_score")],
                        ["Recommended priority", incident.get("recommended_priority")],
                        ["Correlation score", incident.get("correlation_score")],
                        ["Correlation type", incident.get("correlation_type")],
                    ],
                ),
                "",
                "#### AI Analysis",
                "",
                _text_block(incident.get("ai_analysis"), "No incident AI analysis available."),
                "",
                "#### MITRE ATT&CK",
                "",
                _json_block(incident.get("mitre")),
                "",
                "#### Compact Correlation Summary",
                "",
                _json_block(compact_correlation),
                "",
            ]
        )

    return "\n".join(lines).strip() + "\n"
