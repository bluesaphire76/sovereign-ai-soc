from __future__ import annotations

import re
from collections import Counter
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ai_provider_redaction import RedactionOptions, redact_text
from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentCase,
)
from qdrant_knowledge import QdrantKnowledgeBase


router = APIRouter(tags=["Playbook Recommendations"])

KNOWLEDGE_BASE_SOURCE_TYPE = "knowledge_base"
PLAYBOOK_RECOMMENDATION_DECISION_BOUNDARY = (
    "Recommended playbooks are advisory knowledge-base context only. They must "
    "not apply remediation, change incident or case status, change severity, "
    "close cases or incidents, suppress alerts, apply Detection Control changes "
    "or replace RBAC, audit, deterministic checks and human validation."
)
PLAYBOOK_PAYLOAD_FIELDS = ["content_hash"]
ACTION_HEADING_MARKERS = (
    "analyst checks",
    "analyst actions",
    "recommended response",
    "required checks",
    "closure preconditions",
    "approval criteria",
    "useful fields",
    "escalation criteria",
    "tuning decision model",
)
GENERIC_TITLES = {
    "ai soc security knowledge base",
    "security knowledge base",
}
CATEGORY_KEYWORDS = {
    "network": [
        "dns",
        "suricata",
        "beacon",
        "beaconing",
        "domain",
        "sni",
        "tls",
        "http",
        "network",
        "protocol",
        "packet",
        "flow",
        "firewall",
        "proxy",
    ],
    "authentication": [
        "ssh",
        "sshd",
        "authentication",
        "auth",
        "sudo",
        "pam",
        "brute",
        "bruteforce",
        "brute-force",
        "login",
        "credential",
        "password",
        "privilege",
        "privileged",
        "account",
        "user",
    ],
    "closure": [
        "closure",
        "close",
        "closed",
        "false positive",
        "false-positive",
        "residual risk",
        "final severity",
        "approval",
        "approved",
    ],
    "remediation": [
        "remediation",
        "remediate",
        "proposal",
        "rollback",
        "containment",
        "contain",
        "isolate",
        "block",
        "execute",
        "dry-run",
    ],
    "detection_control": [
        "suppression",
        "suppress",
        "exception",
        "tuning",
        "detection control",
        "rule lifecycle",
        "noise",
        "matcher",
        "scope",
    ],
}
MIN_RELEVANCE_SCORE = 2
INCIDENT_PLAYBOOK_CATEGORIES = {"authentication", "network"}
CASE_PLAYBOOK_CATEGORIES = {
    "authentication",
    "network",
    "closure",
    "remediation",
    "detection_control",
}


def _short_text(value: Any, *, max_chars: int = 700) -> str:
    text = " ".join(safe_text(value).split())
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _safe_query_part(value: Any, *, max_chars: int = 700) -> str:
    result = redact_text(
        _short_text(value, max_chars=max_chars),
        RedactionOptions(
            redact_ips=True,
            redact_usernames=True,
            redact_hostnames=True,
            redact_file_paths=True,
        ),
    )
    return safe_text(result.value)


def _normalize_line(value: str) -> str:
    text = value.strip()
    text = re.sub(r"^[-*]\s+", "", text)
    text = re.sub(r"^\d+[.)]\s+", "", text)
    text = text.strip(" ;")
    if not text:
        return ""
    return f"{text[0].upper()}{text[1:]}".rstrip(".") + "."


def _markdown_title(text: str, source: str) -> str:
    h1_title = ""
    h2_title = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## ") and not h2_title:
            h2_title = line[3:].strip()
        if line.startswith("# ") and not h1_title:
            candidate = line[2:].strip()
            if candidate.lower() not in GENERIC_TITLES:
                h1_title = candidate

    if h1_title:
        return h1_title
    if h2_title:
        return h2_title

    source_name = safe_text(source).split("/")[-1].replace(".md", "").replace("_", " ")
    return source_name.title() if source_name else "Recommended SOC Playbook"


def _category_scores(text: str, *, title: str = "", source: str = "") -> Counter[str]:
    haystack = f"{title} {source} {text}".lower()
    scores: Counter[str] = Counter()

    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            pattern = re.escape(keyword.lower())
            count = len(re.findall(rf"(?<![a-z0-9]){pattern}(?![a-z0-9])", haystack))
            if count:
                weight = 3 if keyword in title.lower() else 1
                scores[category] += count * weight

    return scores


def _playbook_category(text: str, source: str) -> str:
    title = _markdown_title(text, source)
    scores = _category_scores(text, title=title, source=source)
    if not scores:
        return "general"
    return scores.most_common(1)[0][0]


def _target_profile(
    text: str,
    *,
    allowed_categories: set[str] | None = None,
) -> dict[str, Any]:
    scores = _category_scores(text)
    if allowed_categories is not None:
        scores = Counter(
            {
                category: score
                for category, score in scores.items()
                if category in allowed_categories
            }
        )
    categories = [
        category
        for category, score in scores.most_common()
        if score >= MIN_RELEVANCE_SCORE
    ]

    return {
        "allowed_categories": sorted(allowed_categories or CATEGORY_KEYWORDS.keys()),
        "categories": categories,
        "scores": dict(scores),
    }


def _profile_summary(profile: dict[str, Any]) -> str:
    categories = profile.get("categories") or []
    if not categories:
        return "general"
    return ", ".join(categories[:3])


def _relevance_score(
    *,
    category: str,
    title: str,
    text: str,
    source: str,
    target_profile: dict[str, Any],
) -> int:
    target_scores = Counter(target_profile.get("scores") or {})
    playbook_scores = _category_scores(text, title=title, source=source)
    score = 0

    for category_name, target_score in target_scores.items():
        if category_name == category:
            score += 6
        score += min(int(target_score), 6) * min(int(playbook_scores.get(category_name, 0)), 5)

    if category in target_profile.get("categories", []):
        score += 4

    return score


def _default_checks(category: str, target_type: str) -> list[str]:
    case_or_incident = "case" if target_type == "case" else "incident"
    if category == "network":
        return [
            "Review DNS evidence for repeated domains, first-seen time, suspicious TLDs and regular query intervals.",
            "Review network evidence for Suricata signatures, SNI, protocol anomalies, ports and direction.",
            "Correlate network indicators with endpoint, authentication or case evidence before escalation.",
            f"Add or update a {case_or_incident} action if manual validation is still required.",
        ]
    if category == "authentication":
        return [
            "Review failed and successful authentication events around the detection window.",
            "Identify targeted accounts, source host, destination host and privileged identities.",
            "Compare with maintenance windows, scanners, lab tests and historical false positives.",
            f"Escalate the {case_or_incident} only when deterministic evidence supports compromise or misuse.",
        ]
    if category == "closure":
        return [
            "Verify evidence summary, root cause, actions, residual risk and final severity rationale.",
            "Check that open actions are resolved or explicitly accepted as residual risk.",
            "Confirm false-positive rationale with deterministic evidence, not only semantic similarity.",
            "Record human approval before closure.",
        ]
    if category == "remediation":
        return [
            "Create or review a remediation proposal before any operational action.",
            "Check evidence basis, blast radius, rollback option and approval requirement.",
            "Run dry-run or readiness checks when available.",
            "Preserve audit trail and human approval for high-risk changes.",
        ]
    if category == "detection_control":
        return [
            "Confirm the event is benign, expected and recurring.",
            "Review scope, owner, expiration and business justification.",
            "Validate that tuning does not hide high-risk or attack behavior.",
            "Use Detection Control validation and approval before applying any change.",
        ]
    return [
        "Review the retrieved playbook against the current evidence.",
        "Validate the suggested procedure with deterministic telemetry.",
        "Document why the guidance applies or does not apply.",
        f"Create a {case_or_incident} action when manual follow-up is required.",
    ]


def _extract_recommended_checks(
    text: str,
    *,
    category: str,
    target_type: str,
    max_items: int = 4,
) -> list[str]:
    lines = text.replace("\r\n", "\n").splitlines()
    checks: list[str] = []
    capture = False

    for raw_line in lines:
        line = raw_line.strip()
        lower = line.rstrip(":").lower()

        if not line:
            continue

        if line.startswith("#"):
            capture = any(marker in lower for marker in ACTION_HEADING_MARKERS)
            continue

        if line.endswith(":"):
            capture = any(marker in lower for marker in ACTION_HEADING_MARKERS)
            continue

        if not capture:
            continue

        if line.startswith(("-", "*")) or re.match(r"^\d+[.)]\s+", line):
            normalized = _normalize_line(line)
            if normalized and "qdrant" not in normalized.lower():
                checks.append(normalized)
            if len(checks) >= max_items:
                break

    defaults = _default_checks(category, target_type)
    for item in defaults:
        if len(checks) >= max_items:
            break
        if item not in checks:
            checks.append(item)

    return checks[:max_items]


def _gui_targets(category: str, target_type: str) -> list[str]:
    if target_type == "case":
        common = ["Related incidents", "Case timeline", "Investigation Graph"]
        if category == "closure":
            return ["Case closure checklist", "Case workflow audit", *common[:2]]
        if category == "remediation":
            return ["Governed Remediation", "Case action plan", "Case workflow audit", *common[:1]]
        return [*common, "Case action plan"]

    common = ["Evidence & Correlation", "Investigation Graph", "Technical Evidence Appendix"]
    if category == "network":
        return ["DNS Evidence", "Network Evidence", *common]
    if category == "remediation":
        return ["Governed Remediation", "Remediation Governance", "Remediation audit"]
    return common


def _why_suggested(
    category: str,
    target_type: str,
    target_profile: dict[str, Any],
    relevance_score: int,
) -> list[str]:
    scope = "case" if target_type == "case" else "incident"
    categories = target_profile.get("categories") or []
    reasons = []
    if category in categories:
        reasons.append(
            f"The current {scope} context contains {category.replace('_', ' ')} indicators."
        )
    elif relevance_score > 0:
        reasons.append(
            f"The current {scope} context partially overlaps with this playbook category."
        )
    else:
        reasons.append(
            f"Qdrant matched this playbook against the current {scope} context."
        )

    if category == "network":
        reasons.append("The retrieved guidance is relevant to DNS, Suricata or network telemetry review.")
    elif category == "authentication":
        reasons.append("The retrieved guidance is relevant to authentication, SSH, sudo or credential-access review.")
    elif category == "closure":
        reasons.append("The retrieved guidance is relevant to closure readiness, false-positive rationale or residual-risk review.")
    elif category == "remediation":
        reasons.append("The retrieved guidance is relevant to governed remediation, approval or rollback review.")
    elif category == "detection_control":
        reasons.append("The retrieved guidance is relevant to exception, suppression or detection tuning review.")
    else:
        reasons.append("The retrieved guidance may support analyst triage and evidence review.")

    return reasons


def _operational_use(category: str) -> str:
    if category == "network":
        return "Use it to decide which DNS, Suricata and network evidence to inspect next."
    if category == "authentication":
        return "Use it to structure authentication triage and decide whether escalation evidence exists."
    if category == "closure":
        return "Use it to check closure readiness and documentation quality before human approval."
    if category == "remediation":
        return "Use it to prepare or review a governed remediation proposal."
    if category == "detection_control":
        return "Use it to prepare a narrow, reviewed Detection Control change request."
    return "Use it as analyst guidance for the next evidence review step."


def build_incident_playbook_query(incident: Incident) -> str:
    raw_parts = [
        incident.rule,
        incident.agent,
        incident.mitre,
        incident.recommended_priority,
        incident.correlation_type,
        incident.attack_chain,
        incident.escalation_reason,
        incident.ai_analysis,
    ]
    profile = _target_profile(
        " ".join(safe_text(part) for part in raw_parts),
        allowed_categories=INCIDENT_PLAYBOOK_CATEGORIES,
    )
    parts = [
        f"Find SOC playbooks for incident category: {_profile_summary(profile)}.",
        f"Rule: {_safe_query_part(incident.rule, max_chars=220)}",
        f"Agent: {_safe_query_part(incident.agent, max_chars=160)}",
        f"MITRE: {_safe_query_part(incident.mitre, max_chars=160)}",
        f"Level: {incident.level}",
        f"Risk Score: {incident.risk_score}",
        f"Recommended Priority: {_safe_query_part(incident.recommended_priority, max_chars=120)}",
        f"Correlation Type: {_safe_query_part(incident.correlation_type, max_chars=160)}",
        f"Attack Chain: {_safe_query_part(incident.attack_chain, max_chars=500)}",
        f"Escalation Reason: {_safe_query_part(incident.escalation_reason, max_chars=500)}",
        f"AI Analysis: {_safe_query_part(incident.ai_analysis, max_chars=900)}",
    ]
    return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=2400)


def build_case_playbook_query(
    case: IncidentCase,
    *,
    incidents: list[Incident],
    actions: list[CaseAction],
    closure: CaseClosureChecklist | None,
    latest_analysis: CaseAIAnalysis | None,
) -> str:
    incident_lines = [
        (
            f"Incident {incident.id}: rule={incident.rule}; agent={incident.agent}; "
            f"mitre={incident.mitre}; correlation={incident.correlation_type}; "
            f"risk={incident.risk_score}; priority={incident.recommended_priority}; "
            f"attack_chain={incident.attack_chain}; escalation={incident.escalation_reason}; "
            f"analysis={incident.ai_analysis}"
        )
        for incident in incidents[:8]
    ]
    action_lines = [
        (
            f"{action.category}: {action.title}; status={action.status}; "
            f"priority={action.priority}; description={action.description}"
        )
        for action in actions[:8]
    ]
    profile = _target_profile(
        " ".join(
            safe_text(part)
            for part in [
                case.title,
                case.status,
                case.severity_review or case.severity,
                case.correlation_type,
                case.summary,
                " ".join(incident_lines),
                " ".join(action_lines),
                getattr(closure, "closure_decision", None),
                getattr(closure, "residual_risk", None),
                getattr(latest_analysis, "analysis", None),
            ]
        ),
        allowed_categories=CASE_PLAYBOOK_CATEGORIES,
    )
    parts = [
        f"Find SOC playbooks for case category: {_profile_summary(profile)}.",
        f"Case Title: {_safe_query_part(case.title, max_chars=260)}",
        f"Case Status: {_safe_query_part(case.status, max_chars=120)}",
        f"Case Severity: {_safe_query_part(case.severity_review or case.severity, max_chars=120)}",
        f"Case Risk Score: {case.risk_score}",
        f"Case Correlation Type: {_safe_query_part(case.correlation_type, max_chars=180)}",
        f"Case Summary: {_safe_query_part(case.summary, max_chars=900)}",
        f"Linked Incident Context: {_safe_query_part(' '.join(incident_lines), max_chars=1200)}",
        f"Case Action Context: {_safe_query_part(' '.join(action_lines), max_chars=1000)}",
        f"Closure Decision: {_safe_query_part(getattr(closure, 'closure_decision', None), max_chars=160)}",
        f"Residual Risk: {_safe_query_part(getattr(closure, 'residual_risk', None), max_chars=700)}",
        f"Latest AI Analysis: {_safe_query_part(getattr(latest_analysis, 'analysis', None), max_chars=900)}",
    ]
    return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=3200)


def _recommendation_item(
    context: dict[str, Any],
    *,
    target_type: str,
    target_profile: dict[str, Any],
) -> dict[str, Any]:
    text = safe_text(context.get("text"))
    source = safe_text(context.get("source"))
    title = _markdown_title(text, source)
    category = _playbook_category(text, source)
    relevance_score = _relevance_score(
        category=category,
        title=title,
        text=text,
        source=source,
        target_profile=target_profile,
    )
    return {
        "card_type": "playbook_action_card",
        "title": title,
        "category": category,
        "relevance_score": relevance_score,
        "why_suggested": _why_suggested(
            category,
            target_type,
            target_profile,
            relevance_score,
        ),
        "recommended_checks": _extract_recommended_checks(
            text,
            category=category,
            target_type=target_type,
        ),
        "gui_targets": _gui_targets(category, target_type),
        "operational_use": _operational_use(category),
        "source_type": safe_text(context.get("source_type")) or KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": source,
        "score": context.get("score"),
        "excerpt": _short_text(text, max_chars=520),
        "chunk_index": context.get("chunk_index"),
        "content_hash": safe_text(context.get("content_hash")),
    }


def _base_response(
    *,
    target_type: str,
    target_id: int,
    enabled: bool,
) -> dict[str, Any]:
    return {
        "target_type": target_type,
        "target_id": target_id,
        "enabled": enabled,
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "recommendations": [],
        "result_count": 0,
        "decision_boundary": PLAYBOOK_RECOMMENDATION_DECISION_BOUNDARY,
        "message": (
            "Playbook recommendations are read-only analyst guidance; no "
            "operational state was changed."
        ),
    }


def _retrieve_playbooks(
    query: str,
    *,
    target_type: str,
    target_id: int,
    target_profile: dict[str, Any],
    limit: int,
    knowledge_base_factory,
) -> dict[str, Any]:
    kb = knowledge_base_factory()
    base_response = _base_response(
        target_type=target_type,
        target_id=target_id,
        enabled=bool(kb.config.enabled),
    )

    if not kb.config.enabled:
        return {
            **base_response,
            "status": "DISABLED",
            "message": "Semantic memory is disabled.",
        }

    try:
        contexts = kb.retrieve_contexts(
            query,
            limit=25,
            source_type=KNOWLEDGE_BASE_SOURCE_TYPE,
            payload_fields=PLAYBOOK_PAYLOAD_FIELDS,
        )
    except Exception as exc:
        return {
            **base_response,
            "status": "WARN",
            "error_type": exc.__class__.__name__,
            "message": (
                "Playbook recommendation search failed; no operational state "
                "was changed."
            ),
        }

    candidate_items = [
        _recommendation_item(
            context,
            target_type=target_type,
            target_profile=target_profile,
        )
        for context in contexts
    ]
    ranked_items = sorted(
        candidate_items,
        key=lambda item: (
            int(item.get("relevance_score") or 0),
            float(item.get("score") or 0),
        ),
        reverse=True,
    )

    diverse_items: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    allowed_categories = set(target_profile.get("allowed_categories") or [])
    target_categories = set(target_profile.get("categories") or [])
    for item in ranked_items:
        item_category = safe_text(item.get("category"))
        if allowed_categories and item_category not in allowed_categories:
            continue
        if target_categories and item_category not in target_categories:
            continue
        if target_categories and int(item.get("relevance_score") or 0) < MIN_RELEVANCE_SCORE:
            continue
        key = (item_category, safe_text(item.get("title")).lower())
        if key in seen_keys:
            continue
        seen_keys.add(key)
        diverse_items.append(item)
        if len(diverse_items) >= limit:
            break

    recommendations = diverse_items
    message = (
        "Playbook recommendations are read-only analyst guidance; no "
        "operational state was changed."
    )
    if not recommendations:
        message = (
            "No context-specific playbook passed strict relevance filtering; "
            "no operational state was changed."
        )
    return {
        **base_response,
        "status": "OK",
        "recommendations": recommendations,
        "result_count": len(recommendations),
        "target_profile": {
            "categories": target_profile.get("categories") or [],
            "allowed_categories": target_profile.get("allowed_categories") or [],
        },
        "message": message,
    }


def build_incident_playbook_recommendations(
    db,
    incident_id: int,
    *,
    limit: int = 4,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    profile = _target_profile(
        " ".join(
            safe_text(part)
            for part in [
                incident.rule,
                incident.agent,
                incident.mitre,
                incident.recommended_priority,
                incident.correlation_type,
                incident.attack_chain,
                incident.escalation_reason,
                incident.ai_analysis,
            ]
        ),
        allowed_categories=INCIDENT_PLAYBOOK_CATEGORIES,
    )
    return _retrieve_playbooks(
        build_incident_playbook_query(incident),
        target_type="incident",
        target_id=incident_id,
        target_profile=profile,
        limit=limit,
        knowledge_base_factory=knowledge_base_factory,
    )


def build_case_playbook_recommendations(
    db,
    case_id: int,
    *,
    limit: int = 4,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
    if not case:
        raise ValueError(f"Case {case_id} not found")

    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.risk_score.desc(), Incident.id.desc())
        .limit(8)
        .all()
    )
    actions = (
        db.query(CaseAction)
        .filter(CaseAction.case_id == case_id)
        .order_by(CaseAction.updated_at.desc(), CaseAction.id.desc())
        .limit(8)
        .all()
    )
    closure = (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )
    latest_analysis = (
        db.query(CaseAIAnalysis)
        .filter(CaseAIAnalysis.case_id == case_id)
        .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
        .first()
    )
    profile = _target_profile(
        " ".join(
            safe_text(part)
            for part in [
                case.title,
                case.status,
                case.severity_review or case.severity,
                case.correlation_type,
                case.summary,
                *[
                    (
                        f"{incident.rule} {incident.mitre} {incident.correlation_type} "
                        f"{incident.attack_chain} {incident.escalation_reason} "
                        f"{incident.ai_analysis}"
                    )
                    for incident in incidents
                ],
                *[
                    f"{action.category} {action.title} {action.description}"
                    for action in actions
                ],
                getattr(closure, "closure_decision", None),
                getattr(closure, "residual_risk", None),
                getattr(latest_analysis, "analysis", None),
            ]
        ),
        allowed_categories=CASE_PLAYBOOK_CATEGORIES,
    )

    return _retrieve_playbooks(
        build_case_playbook_query(
            case,
            incidents=incidents,
            actions=actions,
            closure=closure,
            latest_analysis=latest_analysis,
        ),
        target_type="case",
        target_id=case_id,
        target_profile=profile,
        limit=limit,
        knowledge_base_factory=knowledge_base_factory,
    )


@router.get("/incidents/{incident_id}/recommended-playbooks")
def get_incident_playbook_recommendations(
    incident_id: int,
    limit: int = Query(default=4, ge=1, le=8),
):
    db = SessionLocal()

    try:
        return build_incident_playbook_recommendations(db, incident_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc
    finally:
        db.close()


@router.get("/cases/{case_id}/recommended-playbooks")
def get_case_playbook_recommendations(
    case_id: int,
    limit: int = Query(default=4, ge=1, le=8),
):
    db = SessionLocal()

    try:
        return build_case_playbook_recommendations(db, case_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc
    finally:
        db.close()
