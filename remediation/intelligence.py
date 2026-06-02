from __future__ import annotations

import copy
import json
import os
import time
from typing import Any

from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError

from ai_governance.policy import assess_remediation_output_governance
from ai_model_policy import AiTask
from ai_triage_hardening import call_ollama_chat, get_last_llm_call_metadata
from database import SessionLocal
from llm_output import is_invalid_llm_output, sanitize_llm_output
from models import Incident, IncidentAudit, utc_now


load_dotenv()

REMEDIATION_INTELLIGENCE_TIMEOUT_SECONDS = float(
    os.getenv("REMEDIATION_INTELLIGENCE_TIMEOUT_SECONDS", "60")
)
REMEDIATION_INTELLIGENCE_CACHE_TTL_SECONDS = float(
    os.getenv("REMEDIATION_INTELLIGENCE_CACHE_TTL_SECONDS", "120")
)
_REMEDIATION_INTELLIGENCE_CACHE: dict[int, tuple[float, dict[str, Any]]] = {}
REMEDIATION_PLAN_SNAPSHOT_EVENT_TYPE = "REMEDIATION_PLAN_SNAPSHOT"


def _cache_get(incident_id: int) -> dict[str, Any] | None:
    cached = _REMEDIATION_INTELLIGENCE_CACHE.get(incident_id)
    if not cached:
        return None

    cached_at, payload = cached
    if time.monotonic() - cached_at > REMEDIATION_INTELLIGENCE_CACHE_TTL_SECONDS:
        _REMEDIATION_INTELLIGENCE_CACHE.pop(incident_id, None)
        return None

    return copy.deepcopy(payload)


def _cache_set(incident_id: int, payload: dict[str, Any]) -> None:
    _REMEDIATION_INTELLIGENCE_CACHE[incident_id] = (time.monotonic(), copy.deepcopy(payload))


def _persistent_snapshot_get(db, incident_id: int) -> dict[str, Any] | None:
    row = (
        db.query(IncidentAudit)
        .filter(
            IncidentAudit.incident_id == incident_id,
            IncidentAudit.event_type == REMEDIATION_PLAN_SNAPSHOT_EVENT_TYPE,
        )
        .order_by(IncidentAudit.created_at.desc(), IncidentAudit.id.desc())
        .first()
    )
    if row is None or not row.new_value:
        return None

    try:
        payload = json.loads(row.new_value)
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    payload.setdefault("incident_id", incident_id)
    payload["history_source"] = "incident_audit_snapshot"
    payload["snapshot_event_id"] = row.id
    payload["snapshot_created_at"] = (
        row.created_at.isoformat()
        if hasattr(row.created_at, "isoformat")
        else str(row.created_at)
    )
    return payload


def _persistent_snapshot_set(db, incident_id: int, payload: dict[str, Any]) -> None:
    row = IncidentAudit(
        incident_id=incident_id,
        event_type=REMEDIATION_PLAN_SNAPSHOT_EVENT_TYPE,
        old_value=None,
        new_value=json.dumps(payload, ensure_ascii=False, default=str, sort_keys=True),
        comment=(
            "Persistent remediation intelligence snapshot. "
            "Used to keep Incident Command Room history stable across page refreshes."
        ),
        created_by="remediation_intelligence",
    )
    db.add(row)
    db.commit()


def _safe_json_loads(value: str | None) -> Any:
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return None


def _extract_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None

    cleaned = text.strip()

    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _compact_text(value: Any, max_chars: int) -> str | None:
    if value is None:
        return None

    text = str(value).strip()

    if len(text) <= max_chars:
        return text

    return text[:max_chars] + "... [truncated]"


def _compact_value(value: Any, max_chars: int) -> Any:
    parsed = _safe_json_loads(value) if isinstance(value, str) else value

    if isinstance(parsed, dict):
        result: dict[str, Any] = {}

        for key, item in parsed.items():
            if len(result) >= 24:
                break

            if isinstance(item, (dict, list)):
                result[key] = _compact_text(
                    json.dumps(item, ensure_ascii=False, default=str),
                    max_chars // 4,
                )
            else:
                result[key] = item

        return result

    if isinstance(parsed, list):
        return parsed[:12]

    return _compact_text(parsed, max_chars)


def _incident_payload(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "status": incident.status,
        "wazuh_doc_id": incident.wazuh_doc_id,
        "timestamp": (
            incident.timestamp.isoformat()
            if hasattr(incident.timestamp, "isoformat")
            else incident.timestamp
        ),
        "agent": incident.agent,
        "rule": incident.rule,
        "level": incident.level,
        "mitre": _safe_json_loads(incident.mitre) or incident.mitre,
        "risk_score": incident.risk_score,
        "ai_analysis_summary": _compact_text(incident.ai_analysis, 1200),
        "correlated": incident.correlated,
        "correlation_score": incident.correlation_score,
        "correlation_summary": _compact_value(incident.correlation_summary, 2000),
        "raw_alert_summary": _compact_value(incident.raw_alert, 2000),
        "attack_chain": incident.attack_chain,
        "correlation_type": incident.correlation_type,
        "escalation_reason": incident.escalation_reason,
        "recommended_priority": incident.recommended_priority,
    }


def _minimal_incident_payload(incident_id: int) -> dict[str, Any]:
    return {
        "id": incident_id,
        "status": None,
        "wazuh_doc_id": None,
        "timestamp": None,
        "agent": "affected host",
        "rule": "incident lookup unavailable",
        "level": None,
        "mitre": None,
        "risk_score": 0,
        "ai_analysis_summary": None,
        "correlated": None,
        "correlation_score": None,
        "correlation_summary": None,
        "raw_alert_summary": None,
        "attack_chain": None,
        "correlation_type": None,
        "escalation_reason": None,
        "recommended_priority": "UNSET",
    }


def _required_schema() -> dict[str, Any]:
    return {
        "executive_summary": "string",
        "remediation_objective": "string",
        "containment_strategy": [
            {
                "title": "string",
                "priority": "LOW|MEDIUM|HIGH|CRITICAL",
                "description": "string",
                "requires_approval": True,
                "business_risk": "string",
                "operational_precautions": "string",
            }
        ],
        "investigation_validation_steps": [
            {
                "title": "string",
                "reason": "string",
                "expected_signal": "string",
            }
        ],
        "recommended_actions": [
            {
                "action_type": "CREATE_TICKET|NOTIFY_OWNER|ESCALATE_CASE|COLLECT_FORENSIC_EVIDENCE|ISOLATE_HOST|DISABLE_USER|BLOCK_IP",
                "title": "string",
                "description": "string",
                "approval_requirement": "ANALYST_APPROVAL|ADMIN_APPROVAL|SECURITY_LEAD_APPROVAL|FORBIDDEN_BY_DEFAULT",
                "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
                "rollback_possible": True,
                "evidence_basis": ["string"],
            }
        ],
        "rollback_considerations": ["string"],
        "business_impact_considerations": ["string"],
        "approval_requirements": ["string"],
        "assumptions": ["string"],
        "unsupported_claims": ["string"],
        "human_validation_required": True,
        "limitations": ["string"],
    }


def _build_prompt(incident_payload: dict[str, Any]) -> str:
    compact_payload = {
        "id": incident_payload.get("id"),
        "status": incident_payload.get("status"),
        "agent": incident_payload.get("agent"),
        "rule": incident_payload.get("rule"),
        "level": incident_payload.get("level"),
        "risk_score": incident_payload.get("risk_score"),
        "recommended_priority": incident_payload.get("recommended_priority"),
        "correlated": incident_payload.get("correlated"),
        "correlation_score": incident_payload.get("correlation_score"),
        "correlation_type": incident_payload.get("correlation_type"),
        "attack_chain": incident_payload.get("attack_chain"),
        "escalation_reason": incident_payload.get("escalation_reason"),
        "mitre": incident_payload.get("mitre"),
        "ai_analysis_summary": incident_payload.get("ai_analysis_summary"),
    }

    schema = {
        "executive_summary": "string",
        "remediation_objective": "string",
        "containment_strategy": [
            {
                "title": "string",
                "priority": "LOW|MEDIUM|HIGH|CRITICAL",
                "description": "string",
                "requires_approval": True,
                "business_risk": "string",
                "operational_precautions": "string",
            }
        ],
        "investigation_validation_steps": [
            {
                "title": "string",
                "reason": "string",
                "expected_signal": "string",
            }
        ],
        "recommended_actions": [
            {
                "action_type": "CREATE_TICKET|NOTIFY_OWNER|ESCALATE_CASE|COLLECT_FORENSIC_EVIDENCE|ISOLATE_HOST|DISABLE_USER|BLOCK_IP",
                "title": "string",
                "description": "string",
                "approval_requirement": "ANALYST_APPROVAL|ADMIN_APPROVAL|SECURITY_LEAD_APPROVAL|FORBIDDEN_BY_DEFAULT",
                "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
                "rollback_possible": True,
                "evidence_basis": ["string"],
            }
        ],
        "rollback_considerations": ["string"],
        "business_impact_considerations": ["string"],
        "approval_requirements": ["string"],
        "assumptions": ["string"],
        "unsupported_claims": ["string"],
        "human_validation_required": True,
        "limitations": ["string"],
    }

    return (
        "/no_think\n"
        "You are a defensive SOC remediation advisor. Produce one concise incident-specific remediation plan. "
        "No commands. No automatic execution. No offensive actions. Human approval is mandatory. "
        "Every recommended action must include evidence_basis. Include assumptions and limitations. "
        "Do not claim remediation, containment, rollback or response was performed. "
        "Return only valid JSON, no markdown, no chain-of-thought, no prose outside JSON.\n\n"
        f"Incident:\n{json.dumps(compact_payload, ensure_ascii=False, default=str)}\n\n"
        f"JSON schema:\n{json.dumps(schema, ensure_ascii=False)}"
    )


def _fallback_plan(incident_payload: dict[str, Any], reason: str) -> dict[str, Any]:
    host = incident_payload.get("agent") or "affected host"
    rule = incident_payload.get("rule") or "the triggering rule"
    risk_score = incident_payload.get("risk_score") or 0
    priority = incident_payload.get("recommended_priority") or "UNSET"

    return {
        "executive_summary": (
            "Local AI remediation intelligence was unavailable. "
            "A conservative human-supervised fallback plan was generated."
        ),
        "remediation_objective": (
            f"Validate incident evidence for {host}, rule {rule}, risk score {risk_score}, "
            f"priority {priority}, then decide whether containment is justified."
        ),
        "containment_strategy": [
            {
                "title": "Prepare containment decision only after evidence validation",
                "priority": "MEDIUM",
                "description": (
                    "Review host, identity and network context before deciding whether containment is required."
                ),
                "requires_approval": True,
                "business_risk": "Containment may affect service availability or user productivity.",
                "operational_precautions": "Confirm asset ownership and business criticality before any action.",
            }
        ],
        "investigation_validation_steps": [
            {
                "title": "Validate source alert and host context",
                "reason": "The fallback plan cannot infer additional context beyond structured incident fields.",
                "expected_signal": "Analyst confirms whether alert context supports containment or closure.",
            }
        ],
        "recommended_actions": [
            {
                "action_type": "COLLECT_FORENSIC_EVIDENCE",
                "title": "Collect evidence before remediation",
                "description": "Collect host, identity and network evidence before selecting any operational remediation.",
                "approval_requirement": "ANALYST_APPROVAL",
                "risk_level": "LOW",
                "rollback_possible": True,
                "evidence_basis": ["Structured incident fields only"],
            }
        ],
        "rollback_considerations": [
            "No operational change is proposed by the fallback plan.",
            "Rollback requirements depend on the future human-approved action.",
        ],
        "business_impact_considerations": [
            "Business impact cannot be fully assessed without asset ownership and service criticality.",
        ],
        "approval_requirements": [
            "Human analyst approval is required before any operational change.",
        ],
        "assumptions": [
            "Only structured incident fields are available to the fallback remediation planner.",
        ],
        "unsupported_claims": [],
        "human_validation_required": True,
        "limitations": [
            reason,
            "Fallback plan is conservative and intentionally avoids specific operational execution.",
        ],
    }


def _normalize_plan(value: dict[str, Any], incident_payload: dict[str, Any]) -> dict[str, Any]:
    plan = _fallback_plan(incident_payload, "normalization baseline")

    for key in plan:
        if key in value and value[key] not in (None, "", []):
            plan[key] = value[key]

    plan["human_validation_required"] = True
    plan["execution_supported"] = False
    plan.setdefault("assumptions", [])
    plan.setdefault("unsupported_claims", [])
    plan.setdefault("limitations", [])

    for action in plan.get("recommended_actions", []):
        if isinstance(action, dict):
            action["approval_requirement"] = action.get("approval_requirement") or "ANALYST_APPROVAL"
            action["rollback_possible"] = bool(action.get("rollback_possible", True))
            action["execution_supported"] = False
            action.setdefault("evidence_basis", [])

    return plan


def _governance_payload(
    plan: dict[str, Any],
    *,
    source: str,
    execution_supported: bool = False,
) -> dict[str, object]:
    assessment = assess_remediation_output_governance(
        plan=plan,
        source=source,
        execution_supported=execution_supported,
        fallback_used=source == "deterministic_fallback",
    )
    return assessment.to_payload()


def generate_remediation_intelligence(incident_id: int) -> dict[str, Any]:
    cached = _cache_get(incident_id)
    if cached is not None:
        return cached

    db = SessionLocal()

    try:
        try:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
        except SQLAlchemyError as exc:
            incident_payload = _minimal_incident_payload(incident_id)
            plan = _normalize_plan(
                _fallback_plan(
                    incident_payload,
                    "incident lookup failed before local AI remediation intelligence could run",
                ),
                incident_payload,
            )
            return {
                "incident_id": incident_id,
                "generated_at": utc_now().isoformat(),
                "source": "deterministic_fallback",
                "retry_attempted": False,
                "error_type": type(exc).__name__,
                "model_timeout_seconds": REMEDIATION_INTELLIGENCE_TIMEOUT_SECONDS,
                "execution_supported": False,
                "plan": plan,
                "governance": _governance_payload(
                    plan,
                    source="deterministic_fallback",
                    execution_supported=False,
                ),
            }

        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        try:
            persistent = _persistent_snapshot_get(db, incident_id)
        except SQLAlchemyError:
            db.rollback()
            persistent = None

        if persistent is not None:
            _cache_set(incident_id, persistent)
            return persistent

        incident_payload = _incident_payload(incident)
        prompt = _build_prompt(incident_payload)

        source = "local_ai"
        raw_output = ""
        llm_metadata: dict[str, Any] = {}
        parsed: dict[str, Any] | None = None
        retry_attempted = False
        error_type = None

        try:
            raw_output = call_ollama_chat(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a defensive AI SOC remediation advisor. "
                            "Return only valid JSON. No markdown. No chain-of-thought. No <think> tags."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                timeout_seconds=REMEDIATION_INTELLIGENCE_TIMEOUT_SECONDS,
                task=AiTask.REMEDIATION,
                severity=incident_payload.get("recommended_priority"),
                requested_mode="auto",
                user_triggered=True,
            )
            llm_metadata = get_last_llm_call_metadata()

            cleaned = sanitize_llm_output(raw_output)
            parsed = _extract_json_object(cleaned)

            if parsed is None or is_invalid_llm_output(raw_output):
                retry_attempted = True
                raw_output = call_ollama_chat(
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "The previous output was invalid. Return only valid JSON. "
                                "No markdown. No chain-of-thought. No <think> tags."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    timeout_seconds=REMEDIATION_INTELLIGENCE_TIMEOUT_SECONDS,
                    task=AiTask.REMEDIATION,
                    severity=incident_payload.get("recommended_priority"),
                    requested_mode="auto",
                    user_triggered=True,
                )
                llm_metadata = get_last_llm_call_metadata()

                cleaned = sanitize_llm_output(raw_output)
                parsed = _extract_json_object(cleaned)

            if parsed is None or is_invalid_llm_output(raw_output):
                source = "deterministic_fallback"
                parsed = _fallback_plan(
                    incident_payload,
                    "the local AI output was invalid or not valid JSON",
                )

        except Exception as exc:
            source = "deterministic_fallback"
            error_type = type(exc).__name__
            parsed = _fallback_plan(
                incident_payload,
                "the local AI call failed or timed out",
            )

        plan = _normalize_plan(parsed, incident_payload)

        result = {
            "incident_id": incident_id,
            "generated_at": utc_now().isoformat(),
            "source": source,
            "retry_attempted": retry_attempted,
            "error_type": error_type,
            "model_timeout_seconds": REMEDIATION_INTELLIGENCE_TIMEOUT_SECONDS,
            "model_profile": llm_metadata.get("profile"),
            "model": llm_metadata.get("model"),
            "model_task": AiTask.REMEDIATION.value,
            "execution_supported": False,
            "plan": plan,
            "governance": _governance_payload(
                plan,
                source=source,
                execution_supported=False,
            ),
        }
        try:
            _persistent_snapshot_set(db, incident_id, result)
        except SQLAlchemyError:
            db.rollback()
        _cache_set(incident_id, result)
        return result

    finally:
        db.close()
