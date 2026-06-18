from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable

from ai_model_config import get_profile
from ai_model_policy import AiTask
from investigation_ai.adapters import safe_text
from llm_client import generate_ai_response
from llm_output import is_invalid_llm_output, sanitize_llm_output


logger = logging.getLogger(__name__)

RECOMMENDED_PLAYBOOKS_SYSTEM_PROMPT = """
You are the local AI analyst assistant for Sovereign AI SOC.

Your task is to generate incident-specific Recommended Playbooks for a human SOC analyst.

You must use:
- current incident facts as the primary source of truth;
- retrieved playbook context as operational guidance;
- similar historical incidents only when they are provided;
- governance constraints and human approval rules.

You must not:
- invent playbooks that were not retrieved;
- claim that containment, remediation, severity changes, exceptions, false-positive
  classifications, or closure are approved;
- treat Qdrant retrieval or historical similarity as a decision engine;
- replace analyst judgment;
- produce generic recommendations that could apply to any incident;
- include hidden reasoning, chain-of-thought, or <think> tags.

For every recommended playbook, connect the recommendation to current incident facts,
identify concrete evidence and false-positive checks, define escalation criteria, and
phrase containment or remediation as approval-required options.

If retrieved context is insufficient, state the limitation and provide conservative,
specific next steps.

Return valid JSON only and use only exact playbook titles supplied in the retrieved
context.
""".strip()

GOVERNANCE_CONSTRAINTS = [
    "Recommendations require analyst review.",
    "Containment and remediation actions are not automatically approved.",
    "Severity changes require deterministic evidence and authorized human review.",
    "False-positive classification requires evidence and documentation.",
    "Incident or case closure requires the applicable closure criteria and approval.",
    "Historical similarity is a validation pattern, not proof of the same outcome.",
]

OUTPUT_SCHEMA = {
    "selection_summary": "Concise explanation of why these playbooks were selected.",
    "playbooks": [
        {
            "title": "Exact retrieved playbook title",
            "why_applies": "Specific current incident facts supporting the selection.",
            "supporting_incident_facts": ["Concrete current incident fact"],
            "immediate_analyst_checks": ["Concrete analyst check"],
            "evidence_to_collect": ["Specific evidence item"],
            "false_positive_checks": ["Specific benign explanation to validate"],
            "escalation_criteria": ["Condition that justifies escalation"],
            "containment_remediation_guidance": [
                "Approval-required defensive option"
            ],
            "closure_considerations": ["Evidence or documentation required before closure"],
        }
    ],
    "limitations": ["Missing or weak context limitation, when applicable"],
}


def _env_float(name: str, default: float) -> float:
    try:
        return float(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        return default


RECOMMENDED_PLAYBOOKS_LLM_TIMEOUT_SECONDS = _env_float(
    "RECOMMENDED_PLAYBOOKS_LLM_TIMEOUT_SECONDS",
    45.0,
)


def _short_text(value: Any, *, max_chars: int = 700) -> str:
    text = " ".join(safe_text(value).split())
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _safe_list(value: Any, *, limit: int = 8, max_chars: int = 360) -> list[str]:
    if isinstance(value, list | tuple | set):
        values = value
    elif value in (None, ""):
        values = []
    else:
        values = [value]

    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _short_text(item, max_chars=max_chars)
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _json_safe_facts(facts: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in facts.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list | tuple | set):
            values = list(value)[:12]
            if values and all(isinstance(item, dict) for item in values):
                result[key] = [_json_safe_facts(item) for item in values]
            else:
                result[key] = _safe_list(values, limit=12, max_chars=240)
        elif isinstance(value, dict):
            result[key] = _json_safe_facts(value)
        else:
            result[key] = _short_text(value, max_chars=900)
    return result


def build_incident_generation_facts(incident: Any) -> dict[str, Any]:
    return _json_safe_facts(
        {
            "incident_id": getattr(incident, "id", None),
            "status": getattr(incident, "status", None),
            "rule_name": getattr(incident, "rule", None),
            "severity_level": getattr(incident, "level", None),
            "risk_score": getattr(incident, "risk_score", None),
            "recommended_priority": getattr(incident, "recommended_priority", None),
            "source_or_agent": getattr(incident, "agent", None),
            "mitre": getattr(incident, "mitre", None),
            "correlation_type": getattr(incident, "correlation_type", None),
            "correlation_summary": getattr(incident, "correlation_summary", None),
            "attack_chain": getattr(incident, "attack_chain", None),
            "escalation_reason": getattr(incident, "escalation_reason", None),
            "existing_ai_analysis": getattr(incident, "ai_analysis", None),
            "raw_alert_excerpt": _short_text(
                getattr(incident, "raw_alert", None),
                max_chars=900,
            ),
        }
    )


def build_case_generation_facts(
    case: Any,
    *,
    incidents: list[Any],
    actions: list[Any],
    closure: Any | None,
    latest_analysis: Any | None,
) -> dict[str, Any]:
    incident_facts = [
        build_incident_generation_facts(incident)
        for incident in incidents[:8]
    ]
    action_facts = [
        _json_safe_facts(
            {
                "title": getattr(action, "title", None),
                "category": getattr(action, "category", None),
                "priority": getattr(action, "priority", None),
                "status": getattr(action, "status", None),
                "description": getattr(action, "description", None),
            }
        )
        for action in actions[:8]
    ]
    return _json_safe_facts(
        {
            "case_id": getattr(case, "id", None),
            "title": getattr(case, "title", None),
            "status": getattr(case, "status", None),
            "severity": getattr(case, "severity_review", None)
            or getattr(case, "severity", None),
            "risk_score": getattr(case, "risk_score", None),
            "correlation_type": getattr(case, "correlation_type", None),
            "summary": getattr(case, "summary", None),
            "linked_incidents": incident_facts,
            "existing_actions": action_facts,
            "closure_decision": getattr(closure, "closure_decision", None),
            "residual_risk": getattr(closure, "residual_risk", None),
            "latest_ai_analysis": getattr(latest_analysis, "analysis", None),
        }
    )


def _playbook_prompt_item(item: dict[str, Any]) -> dict[str, Any]:
    sections: list[dict[str, Any]] = []
    for chunk in (item.get("supporting_chunks") or [])[:4]:
        if not isinstance(chunk, dict):
            continue
        sections.append(
            {
                "section": _short_text(chunk.get("section"), max_chars=120),
                "excerpt": _short_text(chunk.get("excerpt"), max_chars=700),
                "relevance_score": chunk.get("relevance_score"),
            }
        )

    if not sections and safe_text(item.get("excerpt")):
        sections.append(
            {
                "section": safe_text(item.get("section")) or "Document",
                "excerpt": _short_text(item.get("excerpt"), max_chars=700),
                "relevance_score": item.get("relevance_score"),
            }
        )

    return {
        "title": _short_text(item.get("title"), max_chars=220),
        "file_path": _short_text(
            item.get("file_path") or item.get("source"),
            max_chars=320,
        ),
        "domain": _short_text(item.get("domain"), max_chars=100),
        "source": _short_text(item.get("playbook_source"), max_chars=100),
        "incident_types": _safe_list(item.get("incident_types"), limit=8, max_chars=100),
        "mitre_tactics": _safe_list(item.get("mitre_tactics"), limit=8, max_chars=100),
        "mitre_techniques": _safe_list(
            item.get("mitre_techniques"),
            limit=8,
            max_chars=100,
        ),
        "matched_metadata": _safe_list(
            item.get("matched_metadata"),
            limit=8,
            max_chars=100,
        ),
        "retrieval_stage": _short_text(item.get("retrieval_stage"), max_chars=100),
        "sections": sections,
    }


def _similar_incident_prompt_item(item: dict[str, Any]) -> dict[str, Any]:
    return _json_safe_facts(
        {
            "incident_id": item.get("incident_id"),
            "similarity_score": item.get("score"),
            "status": item.get("status"),
            "risk_score": item.get("risk_score"),
            "rule": item.get("rule"),
            "mitre": item.get("mitre"),
            "correlation_type": item.get("correlation_type"),
            "historical_observation": item.get("excerpt"),
        }
    )


def build_recommended_playbooks_prompt(
    *,
    target_type: str,
    current_facts: dict[str, Any],
    recommendations: list[dict[str, Any]],
    similar_incidents: list[dict[str, Any]] | None = None,
) -> str:
    playbook_context = [
        _playbook_prompt_item(item)
        for item in recommendations[:5]
        if safe_text(item.get("title"))
    ]
    historical_context = [
        _similar_incident_prompt_item(item)
        for item in (similar_incidents or [])[:3]
    ]
    historical_payload: Any = historical_context or (
        "No similar historical incident context was provided. Do not infer a "
        "historical outcome."
    )

    return f"""
/no_think

Generate specific Recommended Playbooks for the current {target_type}.

CURRENT INCIDENT FACTS
{json.dumps(_json_safe_facts(current_facts), ensure_ascii=False, indent=2)}

RETRIEVED PLAYBOOK CONTEXT
{json.dumps(playbook_context, ensure_ascii=False, indent=2)}

SIMILAR HISTORICAL INCIDENTS
{json.dumps(historical_payload, ensure_ascii=False, indent=2)}

GOVERNANCE AND HUMAN-IN-THE-LOOP CONSTRAINTS
{json.dumps(GOVERNANCE_CONSTRAINTS, ensure_ascii=False, indent=2)}

OUTPUT REQUIREMENTS
- Current incident facts are authoritative.
- Retrieved playbooks are advisory operational guidance.
- Historical incidents are supporting validation patterns only.
- Use only exact titles present in RETRIEVED PLAYBOOK CONTEXT.
- Connect each playbook to specific current facts.
- Avoid vague actions such as "check logs", "investigate further", or "take action".
- Use concrete SOC checks and identify the evidence source to review.
- Phrase containment and remediation as options requiring analyst approval.
- If retrieval_stage is broad_playbook or broad_knowledge_base, explicitly state
  that the match is broad or weak.
- Return valid JSON only, matching this schema:
{json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2)}
""".strip()


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = sanitize_llm_output(text)
    cleaned = cleaned.replace("```json", "").replace("```", "").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("LLM output does not contain a JSON object")
    value = json.loads(cleaned[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("LLM output JSON must be an object")
    return value


def _category_defaults(category: str) -> dict[str, list[str]]:
    if category == "authentication":
        return {
            "evidence": [
                "Review failed and successful authentication events for the affected user, source and host.",
                "Collect source ownership, VPN, bastion, scanner and administrator context.",
                "Correlate successful access with sudo, process, package, service and outbound network activity.",
            ],
            "false_positive": [
                "Confirm whether the source belongs to an approved scanner, VPN, administrator or monitoring platform.",
                "Validate maintenance, penetration-test and administrative activity with the responsible owner.",
            ],
            "escalation": [
                "Escalate when a successful login follows repeated failures or privileged activity is unauthorized.",
                "Escalate when the same source targets multiple hosts or sensitive accounts.",
            ],
            "guidance": [
                "Consider session revocation, credential rotation or source blocking only after analyst validation and approval.",
            ],
        }
    if category == "network":
        return {
            "evidence": [
                "Collect the relevant DNS, Suricata, firewall or flow records with timestamps and endpoints.",
                "Validate source and destination ownership, protocol, ports, query patterns and follow-on connections.",
                "Correlate network activity with endpoint, authentication and process telemetry.",
            ],
            "false_positive": [
                "Confirm whether the source is an approved scanner, monitoring platform, update service or business application.",
                "Compare the activity with approved scan windows and the normal host or domain baseline.",
            ],
            "escalation": [
                "Escalate when reconnaissance is followed by exploit or authentication attempts.",
                "Escalate when DNS or network patterns correlate with host compromise or data-exfiltration indicators.",
            ],
            "guidance": [
                "Consider blocking or isolation only when deterministic evidence supports the action and an analyst approves it.",
            ],
        }
    if category == "linux_host":
        return {
            "evidence": [
                "Collect process, package, service, file and authentication events around the detection window.",
                "Identify the user, parent process, command, package or service definition responsible for the change.",
                "Correlate the host change with outbound network activity and prior authentication anomalies.",
            ],
            "false_positive": [
                "Validate deployment, patching, configuration-management and maintenance records.",
                "Confirm the change owner, expected command and approved time window.",
            ],
            "escalation": [
                "Escalate unauthorized persistence, privileged execution or software installation.",
                "Escalate when the change correlates with suspicious login or network activity.",
            ],
            "guidance": [
                "Consider disabling the service, removing the package or isolating the host only after evidence review and approval.",
            ],
        }
    if category == "windows_host":
        return {
            "evidence": [
                "Collect the relevant Windows Event IDs with account, Logon ID, source workstation, logon type and affected host.",
                "Review process, service, scheduled task, registry, Defender and SMB activity around the detection window.",
                "Use Sysmon process, network, file or registry events as optional enrichment when available.",
            ],
            "false_positive": [
                "Validate endpoint-management, Group Policy, software deployment, support and approved administrator activity.",
                "Confirm the expected account, source device, change ticket and affected-host ownership.",
            ],
            "escalation": [
                "Escalate when Windows evidence supports account compromise, persistence, defense evasion or lateral movement.",
                "Escalate when privileged identities or critical Windows assets are affected without authorization.",
            ],
            "guidance": [
                "Consider session revocation, account restriction, service or task disablement, or host isolation only after evidence review and approval.",
            ],
        }
    if category == "malware":
        return {
            "evidence": [
                "Preserve the process tree, command line, artifact hash, origin, user context and network activity.",
                "Collect downloaded files, scripts, child processes, persistence and endpoint security detections.",
                "Correlate the artifact with DNS, proxy, firewall and Suricata command-and-control evidence.",
            ],
            "false_positive": [
                "Validate approved software, administration, deployment and security-testing explanations.",
                "Confirm artifact signature, trusted source, responsible owner and expected execution path.",
            ],
            "escalation": [
                "Escalate confirmed malicious execution, reverse-shell access, persistence or command-and-control.",
                "Escalate when the artifact executes with privilege or appears on additional endpoints.",
            ],
            "guidance": [
                "Consider process termination, quarantine, infrastructure blocking or endpoint isolation only after evidence capture and approval.",
            ],
        }
    if category == "data_exfiltration":
        return {
            "evidence": [
                "Collect outbound bytes, destination, protocol, duration, process, user and data-access evidence.",
                "Review staging, archive, encryption, DNS, proxy, firewall and Suricata activity against the expected baseline.",
                "Identify the data classification, business owner and authorization for the transfer.",
            ],
            "false_positive": [
                "Validate approved backup, replication, migration, SaaS, partner and telemetry transfers.",
                "Confirm destination ownership, expected volume, source data, schedule and responsible user or application.",
            ],
            "escalation": [
                "Escalate unauthorized transfer of sensitive data or traffic linked to compromised identities or endpoints.",
                "Escalate when transfer volume, destination or protocol is unexplained and activity remains active.",
            ],
            "guidance": [
                "Consider pausing the transfer, restricting credentials, blocking the destination or isolating the host only after analyst approval.",
            ],
        }
    if category == "governance":
        return {
            "evidence": [
                "Document the decision, supporting and contradictory evidence, affected scope, owner and unresolved uncertainty.",
                "Record business impact, alternatives, residual risk, required authority and applicable workflow.",
                "Preserve the requester, reviewer, approver, timestamps, conditions and audit references.",
            ],
            "false_positive": [
                "Confirm the request is not a duplicate of an existing authoritative case, approval or review.",
                "Validate whether a lower-impact, reversible or monitoring-only option satisfies the decision objective.",
            ],
            "escalation": [
                "Escalate when approval authority is unclear, evidence integrity is insufficient or critical impact is possible.",
                "Escalate unresolved legal, privacy, regulatory, safety or executive decision requirements.",
            ],
            "guidance": [
                "Do not change severity, open or close a case, approve containment or accept residual risk without authorized human review.",
            ],
        }
    return {
        "evidence": [
            "Collect the deterministic evidence referenced by the selected playbook.",
            "Document the source, timestamps, affected entities and analyst validation.",
        ],
        "false_positive": [
            "Validate expected business, administrative, maintenance and testing explanations.",
        ],
        "escalation": [
            "Escalate only when current evidence supports malicious or unauthorized activity.",
        ],
        "guidance": [
            "Any containment, remediation, severity or closure change requires analyst approval.",
        ],
    }


def _fallback_playbook(item: dict[str, Any]) -> dict[str, Any]:
    defaults = _category_defaults(safe_text(item.get("category")))
    matched = _safe_list(item.get("matched_metadata"), limit=8, max_chars=100)
    retrieval_stage = safe_text(item.get("retrieval_stage"))
    match_text = ", ".join(matched) if matched else "semantic retrieval context"
    if retrieval_stage in {"broad_playbook", "broad_knowledge_base"}:
        why_applies = (
            f"This is a broad guidance match selected from {retrieval_stage}; "
            "validate applicability against current evidence."
        )
    else:
        why_applies = f"Selected because the current context matched: {match_text}."

    return {
        "title": safe_text(item.get("title")) or "Retrieved SOC Playbook",
        "why_applies": why_applies,
        "supporting_incident_facts": _safe_list(
            item.get("why_suggested"),
            limit=3,
            max_chars=300,
        ),
        "immediate_analyst_checks": _safe_list(
            item.get("recommended_checks"),
            limit=5,
            max_chars=360,
        )
        or ["Review the retrieved playbook against the current incident evidence."],
        "evidence_to_collect": defaults["evidence"],
        "false_positive_checks": defaults["false_positive"],
        "escalation_criteria": defaults["escalation"],
        "containment_remediation_guidance": defaults["guidance"],
        "closure_considerations": [
            "Document evidence, analyst rationale, residual risk and any approval before closure.",
            "Do not close as false positive until the benign explanation is confirmed.",
        ],
    }


def build_deterministic_playbooks_generation(
    *,
    recommendations: list[dict[str, Any]],
    reason: str,
) -> dict[str, Any]:
    playbooks = [_fallback_playbook(item) for item in recommendations[:5]]
    selection_summary = (
        "The local AI model was unavailable or returned invalid output. "
        "These playbooks were selected deterministically from Qdrant retrieval "
        "context and require analyst review."
    )
    if reason == "llm_not_requested":
        selection_summary = (
            "These playbooks were selected deterministically from Qdrant retrieval "
            "context and require analyst review."
        )
    return {
        "selection_summary": selection_summary,
        "playbooks": playbooks,
        "limitations": [f"LLM synthesis fallback reason: {reason}."],
    }


def _normalize_playbook(
    raw_item: dict[str, Any],
    fallback_item: dict[str, Any],
) -> dict[str, Any]:
    return {
        "title": fallback_item["title"],
        "why_applies": _short_text(
            raw_item.get("why_applies") or fallback_item["why_applies"],
            max_chars=700,
        ),
        "supporting_incident_facts": _safe_list(
            raw_item.get("supporting_incident_facts")
            or fallback_item["supporting_incident_facts"],
            limit=5,
            max_chars=360,
        ),
        "immediate_analyst_checks": _safe_list(
            raw_item.get("immediate_analyst_checks")
            or fallback_item["immediate_analyst_checks"],
            limit=6,
            max_chars=420,
        ),
        "evidence_to_collect": _safe_list(
            raw_item.get("evidence_to_collect")
            or fallback_item["evidence_to_collect"],
            limit=6,
            max_chars=420,
        ),
        "false_positive_checks": _safe_list(
            raw_item.get("false_positive_checks")
            or fallback_item["false_positive_checks"],
            limit=6,
            max_chars=420,
        ),
        "escalation_criteria": _safe_list(
            raw_item.get("escalation_criteria")
            or fallback_item["escalation_criteria"],
            limit=6,
            max_chars=420,
        ),
        "containment_remediation_guidance": _safe_list(
            raw_item.get("containment_remediation_guidance")
            or fallback_item["containment_remediation_guidance"],
            limit=6,
            max_chars=420,
        ),
        "closure_considerations": _safe_list(
            raw_item.get("closure_considerations")
            or fallback_item["closure_considerations"],
            limit=5,
            max_chars=420,
        ),
    }


def normalize_recommended_playbooks_output(
    raw_payload: dict[str, Any],
    *,
    recommendations: list[dict[str, Any]],
) -> dict[str, Any]:
    fallback = build_deterministic_playbooks_generation(
        recommendations=recommendations,
        reason="partial_llm_output",
    )
    allowed = {
        safe_text(item.get("title")).lower(): fallback_item
        for item, fallback_item in zip(recommendations[:5], fallback["playbooks"])
        if safe_text(item.get("title"))
    }
    raw_playbooks = raw_payload.get("playbooks")
    if not isinstance(raw_playbooks, list):
        raise ValueError("LLM JSON does not contain a playbooks list")

    raw_by_title = {
        safe_text(item.get("title")).lower(): item
        for item in raw_playbooks
        if isinstance(item, dict) and safe_text(item.get("title")).lower() in allowed
    }
    if not raw_by_title:
        raise ValueError("LLM JSON did not use any retrieved playbook title")

    playbooks = [
        _normalize_playbook(raw_by_title.get(title_key, {}), fallback_item)
        for title_key, fallback_item in allowed.items()
    ]
    return {
        "selection_summary": _short_text(
            raw_payload.get("selection_summary") or fallback["selection_summary"],
            max_chars=900,
        ),
        "playbooks": playbooks,
        "limitations": _safe_list(
            raw_payload.get("limitations"),
            limit=5,
            max_chars=420,
        ),
    }


def render_recommended_playbooks_markdown(generation: dict[str, Any]) -> str:
    lines = [
        "# Recommended Playbooks",
        "",
        "## Selection Summary",
        "",
        safe_text(generation.get("selection_summary")),
        "",
    ]
    for index, item in enumerate(generation.get("playbooks") or [], start=1):
        lines.extend(
            [
                f"## {index}. {safe_text(item.get('title'))}",
                "",
                "### Why this playbook applies",
                "",
                safe_text(item.get("why_applies")),
                "",
            ]
        )
        for heading, field_name in (
            ("Supporting incident facts", "supporting_incident_facts"),
            ("Immediate analyst checks", "immediate_analyst_checks"),
            ("Evidence to collect", "evidence_to_collect"),
            ("False positive checks", "false_positive_checks"),
            ("Escalation criteria", "escalation_criteria"),
            (
                "Containment and remediation guidance",
                "containment_remediation_guidance",
            ),
            ("Closure considerations", "closure_considerations"),
        ):
            lines.extend([f"### {heading}", ""])
            values = _safe_list(item.get(field_name), limit=8, max_chars=500)
            lines.extend(f"- {value}" for value in values)
            lines.append("")

    limitations = _safe_list(generation.get("limitations"), limit=5, max_chars=500)
    if limitations:
        lines.extend(["## Limitations", ""])
        lines.extend(f"- {item}" for item in limitations)
        lines.append("")

    lines.extend(
        [
            "## Human Decision Required",
            "",
            (
                "Containment, remediation, severity changes, false-positive "
                "classification, and closure require analyst review and approval."
            ),
        ]
    )
    return "\n".join(lines).strip()


def _llm_metadata(
    llm_result: dict[str, Any] | None,
    *,
    source: str,
    error_type: str | None,
    similar_incidents_included: int,
) -> dict[str, Any]:
    result = llm_result or {}
    return {
        "source": source,
        "model": result.get("model") or get_profile("standard").model,
        "llm_profile": result.get("profile"),
        "llm_fallback_used": bool(result.get("fallback_used", False)),
        "llm_latency_ms": result.get("latency_ms"),
        "provider_key": result.get("provider_key") or "local_ollama",
        "provider_type": result.get("provider_type") or "LOCAL_OLLAMA",
        "used_external_provider": bool(result.get("used_external_provider", False)),
        "redaction_applied": bool(result.get("redaction_applied", False)),
        "redaction_mode": result.get("redaction_mode") or "LOCAL_ONLY",
        "error_type": error_type,
        "similar_incidents_included": similar_incidents_included,
    }


def generate_recommended_playbooks(
    *,
    target_type: str,
    current_facts: dict[str, Any],
    recommendations: list[dict[str, Any]],
    similar_incidents: list[dict[str, Any]] | None = None,
    severity: str | None = None,
    llm_generator: Callable[..., dict[str, Any]] = generate_ai_response,
) -> dict[str, Any]:
    historical_context = list(similar_incidents or [])[:3]
    prompt = build_recommended_playbooks_prompt(
        target_type=target_type,
        current_facts=current_facts,
        recommendations=recommendations,
        similar_incidents=historical_context,
    )
    llm_result: dict[str, Any] | None = None

    try:
        llm_result = llm_generator(
            messages=[
                {"role": "system", "content": RECOMMENDED_PLAYBOOKS_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            task=(
                AiTask.CASE_ANALYSIS
                if target_type == "case"
                else AiTask.INCIDENT_ANALYSIS
            ),
            severity=severity,
            requested_mode="standard",
            user_triggered=True,
            timeout_seconds=RECOMMENDED_PLAYBOOKS_LLM_TIMEOUT_SECONDS,
        )
        raw_output = safe_text(llm_result.get("text"))
        cleaned = sanitize_llm_output(raw_output)
        if not raw_output:
            raise ValueError(safe_text(llm_result.get("error_type")) or "EmptyLlmResponse")
        if is_invalid_llm_output(raw_output) or is_invalid_llm_output(cleaned):
            raise ValueError("InvalidLlmOutput")
        generation = normalize_recommended_playbooks_output(
            _extract_json_object(cleaned),
            recommendations=recommendations,
        )
        metadata = _llm_metadata(
            llm_result,
            source=(
                "external_ai"
                if bool(llm_result.get("used_external_provider"))
                else "local_ai"
            ),
            error_type=safe_text(llm_result.get("error_type")) or None,
            similar_incidents_included=len(historical_context),
        )
    except Exception as exc:
        provider_error = safe_text((llm_result or {}).get("error_type"))
        exception_text = safe_text(exc)
        reason = provider_error or exc.__class__.__name__
        if exception_text in {"EmptyLlmResponse", "InvalidLlmOutput"}:
            reason = exception_text
        generation = build_deterministic_playbooks_generation(
            recommendations=recommendations,
            reason=reason,
        )
        metadata = _llm_metadata(
            llm_result,
            source="deterministic_fallback",
            error_type=reason,
            similar_incidents_included=len(historical_context),
        )

    generation["generated_markdown"] = render_recommended_playbooks_markdown(generation)
    generation["generation"] = metadata
    logger.info(
        "recommended_playbooks_generation",
        extra={
            "target_type": target_type,
            "playbook_count": len(recommendations),
            "playbook_titles": [
                safe_text(item.get("title"))
                for item in recommendations[:5]
            ],
            "similar_incidents_included": len(historical_context),
            "fallback_used": metadata["source"] == "deterministic_fallback",
            "latency_ms": metadata.get("llm_latency_ms"),
            "error_type": metadata.get("error_type"),
        },
    )
    return generation


def apply_generation_to_recommendations(
    recommendations: list[dict[str, Any]],
    generation: dict[str, Any],
) -> list[dict[str, Any]]:
    generated_by_title = {
        safe_text(item.get("title")).lower(): item
        for item in generation.get("playbooks") or []
        if safe_text(item.get("title"))
    }
    source = safe_text((generation.get("generation") or {}).get("source"))
    result: list[dict[str, Any]] = []
    for item in recommendations:
        enriched = dict(item)
        generated = generated_by_title.get(safe_text(item.get("title")).lower())
        if generated:
            enriched.update(
                {
                    "why_suggested": [
                        safe_text(generated.get("why_applies")),
                        *_safe_list(
                            generated.get("supporting_incident_facts"),
                            limit=3,
                            max_chars=360,
                        ),
                    ],
                    "recommended_checks": _safe_list(
                        generated.get("immediate_analyst_checks"),
                        limit=6,
                        max_chars=420,
                    ),
                    "evidence_to_collect": _safe_list(
                        generated.get("evidence_to_collect"),
                        limit=6,
                        max_chars=420,
                    ),
                    "false_positive_checks": _safe_list(
                        generated.get("false_positive_checks"),
                        limit=6,
                        max_chars=420,
                    ),
                    "escalation_criteria": _safe_list(
                        generated.get("escalation_criteria"),
                        limit=6,
                        max_chars=420,
                    ),
                    "containment_remediation_guidance": _safe_list(
                        generated.get("containment_remediation_guidance"),
                        limit=6,
                        max_chars=420,
                    ),
                    "closure_considerations": _safe_list(
                        generated.get("closure_considerations"),
                        limit=5,
                        max_chars=420,
                    ),
                    "generation_source": source,
                }
            )
        result.append(enriched)
    return result
