from __future__ import annotations

import json
import re
from typing import Any


NOT_AVAILABLE = "Not available"
AI_SECTION_HEADINGS = {
    "executive summary",
    "summary",
    "risk assessment",
    "risk rationale",
    "key evidence",
    "soc hypothesis",
    "open gaps",
    "recommended immediate actions",
    "recommended actions",
    "suggested remediation",
    "operational recommendation",
}


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return NOT_AVAILABLE

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)

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
    return "```json\n" + json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n```"


def _text_block(value: Any, fallback: str = NOT_AVAILABLE) -> str:
    if value is None or value == "":
        return fallback

    if isinstance(value, (dict, list)):
        return _json_block(value)

    text = str(value).strip()
    return text or fallback


def _plain_text(value: Any, fallback: str = NOT_AVAILABLE) -> str:
    if value is None or value == "":
        return fallback

    if isinstance(value, (dict, list)):
        return fallback

    text = str(value).strip()
    return text or fallback


def _first_available(*values: Any, fallback: str = NOT_AVAILABLE) -> str:
    for value in values:
        if value is None or value == "":
            continue

        if isinstance(value, str) and not value.strip():
            continue

        return _plain_text(value, fallback=fallback)

    return fallback


def _ai_line(ai_text: str | None, label: str) -> str | None:
    if not ai_text:
        return None

    needle = label.lower()

    for raw_line in ai_text.splitlines():
        line = raw_line.strip().strip("-* ")
        if needle in line.lower() and ":" in line:
            return line.split(":", 1)[1].strip()

    return None


def _clean_heading(value: str) -> str:
    cleaned = value.strip().strip("#").strip()
    cleaned = cleaned.replace("**", "").replace("__", "")
    cleaned = re.sub(r"^\d+[.)]\s*", "", cleaned)
    return cleaned.strip().rstrip(":")


def _ai_section(ai_text: str | None, labels: list[str]) -> str | None:
    if not ai_text:
        return None

    targets = [label.lower() for label in labels]
    collected: list[str] = []
    active = False

    for raw_line in ai_text.splitlines():
        line = raw_line.rstrip()
        heading = _clean_heading(line).lower()
        is_heading = bool(
            heading
            and (
                raw_line.lstrip().startswith("#")
                or re.match(r"^\s*(?:\*\*)?\d+[.)]\s+", raw_line)
                or heading in AI_SECTION_HEADINGS
                or heading in targets
            )
        )

        if any(heading.startswith(target) for target in targets):
            active = True
            remainder = _clean_heading(line)
            if ":" in remainder:
                remainder = remainder.split(":", 1)[1].strip()
                if remainder:
                    collected.append(remainder)
            continue

        if active and is_heading:
            break

        if active:
            collected.append(line)

    text = "\n".join(collected).strip()
    return text or None


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


def _risk_band(score: Any) -> str:
    try:
        value = int(score or 0)
    except (TypeError, ValueError):
        return NOT_AVAILABLE

    if value >= 80:
        return "Critical"
    if value >= 60:
        return "High"
    if value >= 40:
        return "Medium"
    return "Low"


def _status_decision(status: str | None) -> str:
    normalized = (status or "").upper()

    if normalized in {"CLOSED", "FALSE_POSITIVE"}:
        return "Terminal workflow status reached."

    if normalized in {"ESCALATED", "INVESTIGATING"}:
        return "Active investigation or escalation in progress."

    if normalized in {"TRIAGED", "OPEN", "NEW"}:
        return "Human review and follow-up remain required."

    return "Workflow status requires analyst review."


def _risk_review_note(current: str | None, reviewed: str | None) -> str:
    current_value = (current or "").upper()
    reviewed_value = (reviewed or "").upper()

    if not current_value or not reviewed_value or current_value == reviewed_value:
        return "No severity review discrepancy detected."

    return (
        "Severity review differs from the current case severity. "
        "Analyst validation is required before external distribution."
    )


def _correlation_state(incident: dict[str, Any]) -> str:
    if incident.get("correlated"):
        return (
            "Correlated"
            f" ({_format_value(incident.get('correlation_type'))}, "
            f"score {_format_value(incident.get('correlation_score'))})"
        )

    return "Not correlated"


def _related_evidence_summary(correlation_summary: Any) -> str:
    if not isinstance(correlation_summary, dict):
        return NOT_AVAILABLE

    details = correlation_summary.get("related_event_details")
    if isinstance(details, list) and details:
        return f"{len(details)} related event(s) available in the technical appendix."

    related_count = correlation_summary.get("related_event_count")
    if related_count:
        return f"{related_count} related event(s) referenced by correlation metadata."

    return "No related event details available."


def _metadata_summary(value: Any) -> str:
    if not value:
        return NOT_AVAILABLE

    if isinstance(value, dict):
        for key in ("technique", "techniques", "tactic", "tactics", "id", "name"):
            item = value.get(key)
            if item:
                return _format_value(item)
        return f"Metadata object with {len(value)} field(s)."

    if isinstance(value, list):
        return f"{len(value)} metadata item(s)."

    return str(value)


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
                event.get("comment"),
            ]
        )

    lines.extend(
        [
            _table(
                ["ID", "Type", "Old value", "New value", "Actor", "Timestamp", "Comment"],
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


def _append_evidence_used(lines: list[str], evidence_used: list[dict[str, Any]]) -> None:
    lines.extend(["### Evidence Used", ""])

    if not evidence_used:
        lines.extend(["No structured evidence list available.", ""])
        return

    for item in evidence_used:
        lines.append(
            "- "
            f"**{_format_value(item.get('label'))}:** "
            f"{_format_value(item.get('description'))} "
            f"(count: {_format_value(item.get('count'))})"
        )

    lines.append("")


def _append_hypotheses(lines: list[str], hypotheses: list[dict[str, Any]]) -> None:
    lines.extend(["### Investigation Hypotheses", ""])

    if not hypotheses:
        lines.extend(["No investigation hypotheses available.", ""])
        return

    for item in hypotheses:
        lines.append(
            "- "
            f"**{_format_value(item.get('label'))} "
            f"({_format_value(item.get('likelihood'))}):** "
            f"{_format_value(item.get('rationale'))}"
        )

    lines.append("")


def _append_recommended_actions(lines: list[str], actions: list[dict[str, Any]]) -> None:
    lines.extend(["### Recommended Checks / Actions", ""])

    if not actions:
        lines.extend(["No structured recommended actions available.", ""])
        return

    for index, item in enumerate(actions, start=1):
        approval = (
            "human approval required"
            if item.get("requires_approval") or item.get("requires_human_approval")
            else "no approval flag provided"
        )
        lines.append(
            f"{index}. **{_format_value(item.get('action') or item.get('title'))}** - "
            f"Impact: {_format_value(item.get('impact'))}; {approval}."
        )

    lines.append("")


def _incident_brief(payload: dict[str, Any]) -> dict[str, Any]:
    ai_brief = payload.get("ai_brief")
    if not isinstance(ai_brief, dict):
        return {}

    brief = ai_brief.get("brief")
    if isinstance(brief, dict):
        return brief

    return {}


def build_enterprise_incident_markdown(payload: dict[str, Any]) -> str:
    incident = payload["incident"]
    ai_analysis = incident.get("ai_analysis")
    brief = _incident_brief(payload)
    correlation_summary = incident.get("correlation_summary")
    compact_correlation = _compact_correlation_summary(correlation_summary)

    executive_summary = _first_available(
        brief.get("executive_summary"),
        brief.get("situation_summary"),
        _ai_line(ai_analysis, "short executive summary"),
        _ai_line(ai_analysis, "executive summary"),
        fallback="No executive summary available.",
    )

    risk_rationale = _first_available(
        brief.get("risk_rationale"),
        _ai_line(ai_analysis, "risk rationale"),
        _ai_line(ai_analysis, "business risk"),
        fallback="No risk rationale available.",
    )

    recommended_actions = brief.get("recommended_actions") or []
    if not recommended_actions:
        recommended_checks = _ai_line(ai_analysis, "recommended checks")
        suggested_remediation = _ai_line(ai_analysis, "suggested remediation")
        for value in (recommended_checks, suggested_remediation):
            if value:
                recommended_actions.append(
                    {
                        "action": value,
                        "impact": NOT_AVAILABLE,
                        "requires_approval": True,
                    }
                )

    lines: list[str] = [
        "# Incident Report",
        "",
        f"Incident ID: **{incident['id']}**",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "## Incident Overview",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Incident ID", incident.get("id")],
                ["Severity / risk score", f"{_risk_band(incident.get('risk_score'))} / {_format_value(incident.get('risk_score'))}"],
                ["Status", incident.get("status")],
                ["Host / agent", incident.get("agent")],
                ["First seen", incident.get("timestamp")],
                ["Generated at", payload.get("generated_at")],
                ["Correlation state", _correlation_state(incident)],
                ["Recommended priority", incident.get("recommended_priority")],
            ],
        ),
        "",
        "## AI Analysis / Incident AI Brief",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Brief source", (payload.get("ai_brief") or {}).get("source")],
                ["Situation summary", brief.get("situation_summary")],
                ["Risk rationale", risk_rationale],
                ["Confidence", brief.get("confidence")],
                ["Impact", brief.get("impact")],
                ["Likelihood", brief.get("likelihood")],
                ["Human validation required", brief.get("human_validation_required", True)],
            ],
        ),
        "",
        "### Confidence / Limitations",
        "",
    ]

    limitations = brief.get("limitations") or []
    if limitations:
        lines.extend([f"- {item}" for item in limitations])
        lines.append("")
    else:
        lines.extend(["No explicit limitations available.", ""])

    _append_evidence_used(lines, brief.get("evidence_used") or [])
    _append_hypotheses(lines, brief.get("investigation_hypotheses") or [])
    _append_recommended_actions(lines, recommended_actions)

    lines.extend(
        [
            "### Original AI Analysis",
            "",
            _text_block(ai_analysis, "No original incident AI analysis available."),
            "",
            "## Evidence Overview",
            "",
            _table(
                ["Field", "Value"],
                [
                    ["Wazuh rule", incident.get("rule")],
                    ["Wazuh level", incident.get("level")],
                    ["MITRE / attack chain", _metadata_summary(incident.get("mitre"))],
                    ["Attack chain metadata", _metadata_summary(incident.get("attack_chain"))],
                    ["Correlation score", incident.get("correlation_score")],
                    ["Correlation type", incident.get("correlation_type")],
                    ["Escalation reason", incident.get("escalation_reason")],
                    ["Related evidence", _related_evidence_summary(correlation_summary)],
                ],
            ),
            "",
        ]
    )

    _append_notes(lines, payload.get("notes", []))
    _append_audit_trail(lines, payload.get("audit_trail", []), "Audit Trail")

    lines.extend(
        [
            "## Technical Appendix",
            "",
            "### Raw Alert",
            "",
            _json_block(incident.get("raw_alert")),
            "",
            "### Correlation JSON",
            "",
            _json_block(compact_correlation),
            "",
            "### MITRE Metadata",
            "",
            _json_block(incident.get("mitre")),
            "",
            "### Attack Chain Metadata",
            "",
            _json_block(incident.get("attack_chain")),
            "",
        ]
    )

    return "\n".join(lines).strip() + "\n"


def _case_summary(case: dict[str, Any]) -> str:
    summary = case.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()

    return "Structured case summary is available in the Technical Appendix."


def _case_action_rows(actions: list[dict[str, Any]], statuses: set[str]) -> list[list[Any]]:
    rows = []

    for action in actions:
        if (action.get("status") or "").upper() not in statuses:
            continue

        rows.append(
            [
                action.get("id"),
                action.get("title"),
                action.get("status"),
                action.get("priority"),
                action.get("created_by"),
                action.get("due_at"),
                action.get("completed_at"),
            ]
        )

    return rows


def _append_action_table(
    lines: list[str],
    title: str,
    rows: list[list[Any]],
    fallback: str,
) -> None:
    lines.extend([f"### {title}", ""])

    if not rows:
        lines.extend([fallback, ""])
        return

    lines.extend(
        [
            _table(
                ["ID", "Action", "Status", "Priority", "Owner", "Due at", "Completed at"],
                rows,
            ),
            "",
        ]
    )


def build_enterprise_case_markdown(payload: dict[str, Any]) -> str:
    case = payload["case"]
    analysis = payload.get("case_ai_analysis") or {}
    analysis_text = analysis.get("analysis")
    actions = payload.get("case_actions", [])
    incidents = payload.get("incidents", [])
    readiness = payload.get("case_closure_readiness") or {}
    checklist = payload.get("case_closure_checklist") or {}

    open_action_rows = _case_action_rows(actions, {"OPEN", "IN_PROGRESS"})
    completed_action_rows = _case_action_rows(actions, {"DONE", "CANCELLED"})
    blocking_items = readiness.get("blocking_items") or readiness.get("missing_items") or []
    closure_ready = "READY" if readiness.get("ready_to_close") else "BLOCKED"
    approval_state = "Approved" if checklist.get("closure_approved") else "Not approved"

    executive_summary = (
        f"Case #{case['id']} is currently {_format_value(case.get('status'))} "
        f"with {_format_value(case.get('severity'))} severity, "
        f"{_format_value(case.get('risk_score'))} risk score and {len(incidents)} linked incident(s). "
        f"Closure readiness is {closure_ready}. {_status_decision(case.get('status'))}"
    )

    lines: list[str] = [
        "# Case Report",
        "",
        f"Case ID: **{case['id']}**",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## Executive Case Summary",
        "",
        executive_summary,
        "",
        _case_summary(case),
        "",
        "## Case Overview",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Case ID", case.get("id")],
                ["Title", case.get("title")],
                ["Severity", case.get("severity")],
                ["Status", case.get("status")],
                ["Owner / assignee", f"{_format_value(case.get('owner'))} / {_format_value(case.get('assignee'))}"],
                ["SLA target", case.get("sla_due_at")],
                ["SLA status", case.get("sla_status")],
                ["Closure readiness", closure_ready],
            ],
        ),
        "",
        "## Linked Incidents",
        "",
    ]

    if incidents:
        incident_rows = []
        for incident in incidents:
            incident_rows.append(
                [
                    incident.get("id"),
                    _risk_band(incident.get("risk_score")),
                    incident.get("risk_score"),
                    incident.get("status"),
                    incident.get("agent"),
                    incident.get("rule"),
                    incident.get("correlation_score"),
                ]
            )

        lines.extend(
            [
                _table(
                    ["ID", "Severity", "Risk", "Status", "Host", "Rule", "Correlation"],
                    incident_rows,
                ),
                "",
            ]
        )
    else:
        lines.extend(["No linked incidents available.", ""])

    lines.extend(["## AI Case Analysis", ""])

    if analysis:
        lines.extend(
            [
                _table(
                    ["Field", "Value"],
                    [
                        ["Recommended severity", analysis.get("recommended_severity")],
                        ["Recommended status", analysis.get("recommended_status")],
                        ["Model", analysis.get("model")],
                        ["Created by", analysis.get("created_by")],
                        ["Created at", analysis.get("created_at")],
                    ],
                ),
                "",
                "### Summary",
                "",
                _text_block(
                    _ai_section(analysis_text, ["Executive summary", "Summary"]),
                    "No AI summary section available.",
                ),
                "",
                "### Risk Rationale",
                "",
                _text_block(
                    _ai_section(analysis_text, ["Risk assessment", "Risk rationale"]),
                    "No AI risk rationale section available.",
                ),
                "",
                "### Recommended Actions",
                "",
                _text_block(
                    _ai_section(
                        analysis_text,
                        [
                            "Recommended immediate actions",
                            "Suggested remediation",
                            "Operational recommendation",
                        ],
                    ),
                    "No AI recommended actions section available.",
                ),
                "",
                "### Open Gaps",
                "",
                _text_block(
                    _ai_section(analysis_text, ["SOC hypothesis", "Open gaps"]),
                    "No AI open gaps section available.",
                ),
                "",
                "### Human Decision Points",
                "",
                f"- **Workflow decision:** {_status_decision(case.get('status'))}",
                f"- **Severity governance:** {_risk_review_note(case.get('severity'), case.get('severity_review'))}",
                f"- **Closure readiness:** {closure_ready}",
                f"- **Approval state:** {approval_state}",
                "",
                "### Full AI Analysis",
                "",
                _text_block(analysis_text, "No AI case analysis text available."),
                "",
            ]
        )
    else:
        lines.extend(["No case AI analysis available.", ""])

    lines.extend(["## Action Plan", ""])
    _append_action_table(
        lines,
        "Open Actions",
        open_action_rows,
        "No open or in-progress actions available.",
    )
    _append_action_table(
        lines,
        "Completed Actions",
        completed_action_rows,
        "No completed or cancelled actions available.",
    )

    if not actions:
        lines.extend(
            [
                "Recommended minimum follow-up:",
                "",
                "1. Confirm business ownership for the affected asset.",
                "2. Validate whether linked incidents represent authorized activity or a security-relevant signal.",
                "3. Document evidence reviewed, root cause, residual risk and closure decision.",
                "4. Close or escalate the case only after human review.",
                "",
            ]
        )

    lines.extend(
        [
            "## Closure Governance",
            "",
            _table(
                ["Field", "Value"],
                [
                    ["Closure readiness", closure_ready],
                    ["Open action count", readiness.get("open_action_count")],
                    ["Closure checklist", "Available" if checklist else "Not available"],
                    ["Approval state", approval_state],
                    ["Approved by", checklist.get("closure_approved_by")],
                    ["Approved at", checklist.get("closure_approved_at")],
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
        lines.extend(["### Remaining Blockers", ""])
        lines.extend([f"- {item}" for item in blocking_items])
        lines.append("")
    else:
        lines.extend(["No closure blockers reported by the readiness check.", ""])

    lines.extend(
        [
            "## Notes and Audit",
            "",
            "### Analyst Notes",
            "",
            _text_block(checklist.get("evidence_reviewed"), "No standalone case notes available."),
            "",
        ]
    )

    _append_audit_trail(lines, payload.get("case_audit_trail", []), "Audit Trail")

    lines.extend(
        [
            "## Technical Appendix",
            "",
            "### Case Summary Payload",
            "",
            _json_block(case.get("summary")),
            "",
            "### Closure Checklist Details",
            "",
            "#### Root Cause / Conclusion",
            "",
            _text_block(checklist.get("root_cause"), "Not documented."),
            "",
            "#### Evidence Reviewed",
            "",
            _text_block(checklist.get("evidence_reviewed"), "Not documented."),
            "",
            "#### Actions Summary",
            "",
            _text_block(checklist.get("actions_summary"), "Not documented."),
            "",
            "#### Closure Reason",
            "",
            _text_block(checklist.get("closure_reason"), "Not documented."),
            "",
            "#### Residual Risk",
            "",
            _text_block(checklist.get("residual_risk"), "Not documented."),
            "",
            "### Linked Incident Technical Evidence",
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
                f"#### Incident #{incident.get('id')}",
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
                "##### Incident AI Analysis",
                "",
                _text_block(incident.get("ai_analysis"), "No incident AI analysis available."),
                "",
                "##### MITRE Metadata",
                "",
                _json_block(incident.get("mitre")),
                "",
                "##### Correlation Summary",
                "",
                _json_block(compact_correlation),
                "",
            ]
        )

    return "\n".join(lines).strip() + "\n"
