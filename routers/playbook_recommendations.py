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
from recommended_playbooks_llm import (
    apply_generation_to_recommendations,
    build_case_generation_facts,
    build_incident_generation_facts,
    generate_recommended_playbooks,
)
from routers.similar_incidents import build_similar_incidents_response
from playbook_retrieval_hints import (
    PlaybookRetrievalHints,
    build_playbook_retrieval_query,
    case_retrieval_text,
    infer_case_playbook_hints,
    infer_incident_playbook_hints,
    incident_retrieval_text,
    playbook_retrieval_filter_stages,
)


router = APIRouter(tags=["Playbook Recommendations"])

KNOWLEDGE_BASE_SOURCE_TYPE = "knowledge_base"
PLAYBOOK_RECOMMENDATION_DECISION_BOUNDARY = (
    "Recommended playbooks are advisory knowledge-base context only. They must "
    "not apply remediation, change incident or case status, change severity, "
    "close cases or incidents, suppress alerts, apply Detection Control changes "
    "or replace RBAC, audit, deterministic checks and human validation."
)
PLAYBOOK_PAYLOAD_FIELDS = [
    "content_hash",
    "doc_type",
    "kb_type",
    "title",
    "domain",
    "playbook_source",
    "incident_types",
    "severity_hint",
    "mitre_tactics",
    "mitre_techniques",
    "applicability",
    "not_applicable_when",
    "recommended_for_pages",
    "tags",
    "section",
    "section_order",
    "file_path",
    "content_kind",
    "content_preview",
]
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
    "linux_host": [
        "linux",
        "systemd",
        "service",
        "daemon",
        "package",
        "apt",
        "rpm",
        "yum",
        "dpkg",
        "persistence",
        "process",
        "host",
        "privilege escalation",
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
INCIDENT_PLAYBOOK_CATEGORIES = {"authentication", "network", "linux_host", "closure"}
CASE_PLAYBOOK_CATEGORIES = {
    "authentication",
    "network",
    "linux_host",
    "closure",
    "remediation",
    "detection_control",
}
DOMAIN_CATEGORY_MAP = {
    "authentication": "authentication",
    "dns": "network",
    "network_suricata": "network",
    "linux_host": "linux_host",
    "governance": "closure",
}
SECTION_RELEVANCE_WEIGHTS = {
    "investigation steps": 18,
    "initial triage": 16,
    "evidence to collect": 16,
    "detection signals": 14,
    "correlation checks": 13,
    "false positive conditions": 12,
    "escalation criteria": 12,
    "containment actions": 10,
    "remediation actions": 10,
    "closure criteria": 9,
    "when to use": 8,
    "purpose": 2,
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


def _metadata_category(context: dict[str, Any], text: str, source: str) -> str:
    domain = safe_text(context.get("domain")).lower()
    if domain in DOMAIN_CATEGORY_MAP:
        return DOMAIN_CATEGORY_MAP[domain]
    return _playbook_category(text, source)


def _metadata_list(context: dict[str, Any], field_name: str) -> list[str]:
    value = context.get(field_name)
    if isinstance(value, list):
        return [safe_text(item) for item in value if safe_text(item)]
    text = safe_text(value)
    return [text] if text else []


def _match_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9.]+", "_", safe_text(value).lower()).strip("_")


def _match_set(values: list[str] | tuple[str, ...]) -> set[str]:
    return {key for key in (_match_key(value) for value in values) if key}


def _metadata_overlap(context_values: list[str], hint_values: list[str] | tuple[str, ...]) -> set[str]:
    hint_keys = _match_set(hint_values)
    matches: set[str] = set()
    for value in context_values:
        key = _match_key(value)
        if key and key in hint_keys:
            matches.add(value)
    return matches


def _retrieval_hints_from_profile(target_profile: dict[str, Any]) -> dict[str, Any]:
    hints = target_profile.get("retrieval_hints")
    return hints if isinstance(hints, dict) else {}


def _profile_with_hints(
    text: str,
    *,
    hints: PlaybookRetrievalHints,
    allowed_categories: set[str],
) -> dict[str, Any]:
    profile = _target_profile(
        f"{text} {hints.ranking_text()}",
        allowed_categories=allowed_categories,
    )
    profile["retrieval_hints"] = hints.to_public_dict()
    return profile


def _recommended_for_playbooks(context: dict[str, Any]) -> bool:
    targets = [item.lower() for item in _metadata_list(context, "recommended_for_pages")]
    if not targets:
        return True
    return "recommended_playbooks" in targets


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
        "text": text,
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
    context: dict[str, Any] | None = None,
) -> int:
    target_scores = Counter(target_profile.get("scores") or {})
    playbook_scores = _category_scores(text, title=title, source=source)
    retrieval_hints = _retrieval_hints_from_profile(target_profile)
    score = 0

    for category_name, target_score in target_scores.items():
        if category_name == category:
            score += 6
        score += min(int(target_score), 6) * min(int(playbook_scores.get(category_name, 0)), 5)

    if category in target_profile.get("categories", []):
        score += 4

    target_text = safe_text(target_profile.get("text")).lower()
    metadata_context = context or {}
    metadata_values: list[str] = [
        title,
        safe_text(metadata_context.get("domain")),
        safe_text(metadata_context.get("playbook_source")),
        *_metadata_list(metadata_context, "incident_types"),
        *_metadata_list(metadata_context, "tags"),
        *_metadata_list(metadata_context, "mitre_tactics"),
        *_metadata_list(metadata_context, "mitre_techniques"),
        *_metadata_list(metadata_context, "applicability"),
    ]
    for value in metadata_values:
        normalized = safe_text(value).lower()
        if not normalized:
            continue
        tokens = [token for token in re.findall(r"[a-z0-9.]+", normalized) if len(token) >= 3]
        if normalized in target_text:
            score += 4
        elif any(token in target_text for token in tokens):
            score += 2

    if context:
        if safe_text(context.get("playbook_source")).lower() == safe_text(
            retrieval_hints.get("source")
        ).lower() and safe_text(context.get("playbook_source")):
            score += 22
        if safe_text(context.get("domain")).lower() == safe_text(
            retrieval_hints.get("domain")
        ).lower() and safe_text(context.get("domain")):
            score += 18

        incident_type_matches = _metadata_overlap(
            _metadata_list(context, "incident_types"),
            retrieval_hints.get("incident_types") or [],
        )
        supporting_type_matches = _metadata_overlap(
            _metadata_list(context, "incident_types"),
            retrieval_hints.get("supporting_incident_types") or [],
        )
        tactic_matches = _metadata_overlap(
            _metadata_list(context, "mitre_tactics"),
            retrieval_hints.get("mitre_tactics") or [],
        )
        technique_matches = _metadata_overlap(
            _metadata_list(context, "mitre_techniques"),
            retrieval_hints.get("mitre_techniques") or [],
        )
        tag_matches = _metadata_overlap(
            _metadata_list(context, "tags"),
            [
                *(retrieval_hints.get("tags") or []),
                *(retrieval_hints.get("supporting_tags") or []),
            ],
        )
        score += len(incident_type_matches) * 28
        score += len(supporting_type_matches) * 8
        score += len(technique_matches) * 14
        score += len(tactic_matches) * 10
        score += len(tag_matches) * 6
        score += _section_relevance(context)

    return score


def _section_relevance(context: dict[str, Any]) -> int:
    section = safe_text(context.get("section")).lower()
    if not section:
        return 0
    return SECTION_RELEVANCE_WEIGHTS.get(section, 4)


def _matched_metadata(context: dict[str, Any], target_profile: dict[str, Any]) -> list[str]:
    retrieval_hints = _retrieval_hints_from_profile(target_profile)
    matches: list[str] = []

    if safe_text(context.get("playbook_source")).lower() == safe_text(
        retrieval_hints.get("source")
    ).lower() and safe_text(context.get("playbook_source")):
        matches.append("source")
    if safe_text(context.get("domain")).lower() == safe_text(
        retrieval_hints.get("domain")
    ).lower() and safe_text(context.get("domain")):
        matches.append("domain")
    if _metadata_overlap(
        _metadata_list(context, "incident_types"),
        retrieval_hints.get("incident_types") or [],
    ):
        matches.append("incident_type")
    if _metadata_overlap(
        _metadata_list(context, "incident_types"),
        retrieval_hints.get("supporting_incident_types") or [],
    ):
        matches.append("supporting_incident_type")
    if _metadata_overlap(
        _metadata_list(context, "mitre_techniques"),
        retrieval_hints.get("mitre_techniques") or [],
    ):
        matches.append("mitre_technique")
    if _metadata_overlap(
        _metadata_list(context, "mitre_tactics"),
        retrieval_hints.get("mitre_tactics") or [],
    ):
        matches.append("mitre_tactic")
    if _metadata_overlap(
        _metadata_list(context, "tags"),
        [
            *(retrieval_hints.get("tags") or []),
            *(retrieval_hints.get("supporting_tags") or []),
        ],
    ):
        matches.append("tag")
    if _section_relevance(context) >= 10:
        matches.append("section")

    return matches


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
    if category == "linux_host":
        return [
            "Review host-level process, package, service and persistence evidence around the detection window.",
            "Confirm whether the change maps to approved maintenance, deployment or configuration management.",
            "Correlate package or systemd activity with authentication anomalies and outbound network behavior.",
            f"Escalate the {case_or_incident} when host changes are unauthorized, persistent or linked to compromise.",
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
    if category == "linux_host":
        return ["Technical Evidence Appendix", "Evidence & Correlation", "Investigation Graph"]
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
    elif category == "linux_host":
        reasons.append("The retrieved guidance is relevant to Linux host activity, packages, services or persistence review.")
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
    if category == "linux_host":
        return "Use it to structure Linux host triage for package, service, process or persistence evidence."
    if category == "closure":
        return "Use it to check closure readiness and documentation quality before human approval."
    if category == "remediation":
        return "Use it to prepare or review a governed remediation proposal."
    if category == "detection_control":
        return "Use it to prepare a narrow, reviewed Detection Control change request."
    return "Use it as analyst guidance for the next evidence review step."


def build_incident_playbook_query(incident: Incident) -> str:
    hints = infer_incident_playbook_hints(incident)
    facts = _safe_query_part(incident_retrieval_text(incident), max_chars=1800)
    return _short_text(
        build_playbook_retrieval_query(
            target_type="incident",
            facts=facts,
            hints=hints,
        ),
        max_chars=3600,
    )


def build_case_playbook_query(
    case: IncidentCase,
    *,
    incidents: list[Incident],
    actions: list[CaseAction],
    closure: CaseClosureChecklist | None,
    latest_analysis: CaseAIAnalysis | None,
) -> str:
    hints = infer_case_playbook_hints(
        case,
        incidents=incidents,
        actions=actions,
        closure=closure,
        latest_analysis=latest_analysis,
    )
    facts = _safe_query_part(
        case_retrieval_text(
            case,
            incidents=incidents,
            actions=actions,
            closure=closure,
            latest_analysis=latest_analysis,
        ),
        max_chars=2400,
    )
    return _short_text(
        build_playbook_retrieval_query(
            target_type="case",
            facts=facts,
            hints=hints,
        ),
        max_chars=4200,
    )


def _recommendation_item(
    context: dict[str, Any],
    *,
    target_type: str,
    target_profile: dict[str, Any],
) -> dict[str, Any]:
    text = safe_text(context.get("text"))
    source = safe_text(context.get("source"))
    title = safe_text(context.get("title")) or _markdown_title(text, source)
    category = _metadata_category(context, text, source)
    relevance_score = _relevance_score(
        category=category,
        title=title,
        text=text,
        source=source,
        target_profile=target_profile,
        context=context,
    )
    matched_metadata = _matched_metadata(context, target_profile)
    why_suggested = _why_suggested(
        category,
        target_type,
        target_profile,
        relevance_score,
    )
    if matched_metadata:
        why_suggested.insert(
            0,
            f"Matched playbook metadata: {', '.join(matched_metadata)}.",
        )
    return {
        "card_type": "playbook_action_card",
        "title": title,
        "category": category,
        "relevance_score": relevance_score,
        "why_suggested": why_suggested,
        "matched_metadata": matched_metadata,
        "section_relevance": _section_relevance(context),
        "retrieval_stage": safe_text(context.get("retrieval_stage")),
        "recommended_checks": _extract_recommended_checks(
            text,
            category=category,
            target_type=target_type,
        ),
        "gui_targets": _gui_targets(category, target_type),
        "operational_use": _operational_use(category),
        "source_type": safe_text(context.get("source_type")) or KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": source,
        "file_path": safe_text(context.get("file_path")) or source,
        "doc_type": safe_text(context.get("doc_type")),
        "kb_type": safe_text(context.get("kb_type")),
        "content_kind": safe_text(context.get("content_kind")),
        "domain": safe_text(context.get("domain")),
        "playbook_source": safe_text(context.get("playbook_source")),
        "incident_types": _metadata_list(context, "incident_types"),
        "severity_hint": _metadata_list(context, "severity_hint"),
        "mitre_tactics": _metadata_list(context, "mitre_tactics"),
        "mitre_techniques": _metadata_list(context, "mitre_techniques"),
        "applicability": _metadata_list(context, "applicability"),
        "not_applicable_when": _metadata_list(context, "not_applicable_when"),
        "recommended_for_pages": _metadata_list(context, "recommended_for_pages"),
        "tags": _metadata_list(context, "tags"),
        "section": safe_text(context.get("section")),
        "section_order": context.get("section_order"),
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


def _context_identity(context: dict[str, Any]) -> tuple[str, str, str]:
    return (
        safe_text(context.get("source")) or safe_text(context.get("file_path")),
        str(context.get("chunk_index")),
        safe_text(context.get("content_hash")) or safe_text(context.get("id")),
    )


def _context_playbook_key(context: dict[str, Any]) -> str:
    return (
        safe_text(context.get("file_path"))
        or safe_text(context.get("source"))
        or safe_text(context.get("title"))
        or safe_text(context.get("content_hash"))
    ).lower()


def _item_playbook_key(item: dict[str, Any]) -> str:
    return (
        safe_text(item.get("file_path"))
        or safe_text(item.get("source"))
        or safe_text(item.get("title"))
        or safe_text(item.get("content_hash"))
    ).lower()


def _ranked_candidate_items(
    contexts: list[dict[str, Any]],
    *,
    target_type: str,
    target_profile: dict[str, Any],
) -> list[dict[str, Any]]:
    candidate_items = [
        _recommendation_item(
            context,
            target_type=target_type,
            target_profile=target_profile,
        )
        for context in contexts
    ]
    return sorted(
        candidate_items,
        key=lambda item: (
            int(item.get("relevance_score") or 0),
            int(item.get("section_relevance") or 0),
            float(item.get("score") or 0),
        ),
        reverse=True,
    )


def _group_recommendations(
    ranked_items: list[dict[str, Any]],
    *,
    target_profile: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    allowed_categories = set(target_profile.get("allowed_categories") or [])

    def candidate_pool(*, require_allowed: bool, require_relevance: bool) -> list[dict[str, Any]]:
        pool: list[dict[str, Any]] = []
        for item in ranked_items:
            item_category = safe_text(item.get("category"))
            if require_allowed and allowed_categories and item_category not in allowed_categories:
                continue
            if require_relevance and int(item.get("relevance_score") or 0) < MIN_RELEVANCE_SCORE:
                continue
            pool.append(item)
        return pool

    pool = candidate_pool(require_allowed=True, require_relevance=True)
    if not pool:
        pool = candidate_pool(require_allowed=True, require_relevance=False)
    if not pool:
        pool = candidate_pool(require_allowed=False, require_relevance=False)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in pool:
        key = _item_playbook_key(item)
        if not key:
            continue
        grouped.setdefault(key, []).append(item)

    recommendations: list[dict[str, Any]] = []
    for _key, items in sorted(
        grouped.items(),
        key=lambda entry: (
            int(entry[1][0].get("relevance_score") or 0),
            int(entry[1][0].get("section_relevance") or 0),
            float(entry[1][0].get("score") or 0),
        ),
        reverse=True,
    ):
        section_ranked = sorted(
            items,
            key=lambda item: (
                int(item.get("section_relevance") or 0),
                int(item.get("relevance_score") or 0),
                float(item.get("score") or 0),
            ),
            reverse=True,
        )
        best = dict(items[0])
        sections_used: list[str] = []
        supporting_chunks: list[dict[str, Any]] = []
        matched_metadata: list[str] = []
        seen_metadata: set[str] = set()

        for item in section_ranked:
            section = safe_text(item.get("section")) or "Document"
            if section not in sections_used and len(sections_used) < 4:
                sections_used.append(section)
            if len(supporting_chunks) < 4:
                supporting_chunks.append(
                    {
                        "section": section,
                        "chunk_index": item.get("chunk_index"),
                        "score": item.get("score"),
                        "relevance_score": item.get("relevance_score"),
                        "excerpt": item.get("excerpt"),
                    }
                )
            for field_name in item.get("matched_metadata") or []:
                if field_name in seen_metadata:
                    continue
                seen_metadata.add(field_name)
                matched_metadata.append(field_name)

        best["sections_used"] = sections_used
        best["supporting_chunks"] = supporting_chunks
        best["matched_metadata"] = matched_metadata or best.get("matched_metadata") or []
        if sections_used:
            best["why_selected"] = (
                f"Selected from {len(items)} retrieved section"
                f"{'' if len(items) == 1 else 's'}; strongest sections: "
                f"{', '.join(sections_used[:3])}."
            )
        else:
            best["why_selected"] = "Selected from retrieved Qdrant playbook context."
        recommendations.append(best)
        if len(recommendations) >= limit:
            break

    return recommendations


def _recommended_playbook_summaries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "title": item.get("title"),
            "file_path": item.get("file_path") or item.get("source"),
            "domain": item.get("domain"),
            "source": item.get("playbook_source"),
            "incident_types": item.get("incident_types") or [],
            "matched_metadata": item.get("matched_metadata") or [],
            "sections_used": item.get("sections_used") or [],
            "why_selected": item.get("why_selected"),
            "retrieval_stage": item.get("retrieval_stage"),
        }
        for item in items
    ]


def _apply_llm_generation(
    response: dict[str, Any],
    *,
    target_type: str,
    current_facts: dict[str, Any],
    similar_incidents: list[dict[str, Any]] | None,
    severity: str | None,
    llm_generator,
) -> dict[str, Any]:
    recommendations = list(response.get("recommendations") or [])
    if not recommendations:
        return response

    generation_kwargs = {
        "target_type": target_type,
        "current_facts": current_facts,
        "recommendations": recommendations,
        "similar_incidents": similar_incidents,
        "severity": severity,
    }
    generation = generate_recommended_playbooks(
        **generation_kwargs,
        **({"llm_generator": llm_generator} if llm_generator is not None else {}),
    )
    enriched_recommendations = apply_generation_to_recommendations(
        recommendations,
        generation,
    )
    generation_metadata = generation.get("generation") or {}
    source = safe_text(generation_metadata.get("source"))
    message = (
        "Recommended playbooks were synthesized by the configured AI provider "
        "from current facts and retrieved Qdrant context. Human review is required."
    )
    if source == "deterministic_fallback":
        message = (
            "The AI provider was unavailable or returned invalid output. "
            "Structured deterministic playbook guidance is shown and requires "
            "analyst review."
        )

    return {
        **response,
        "recommendations": enriched_recommendations,
        "recommended_playbooks": _recommended_playbook_summaries(
            enriched_recommendations
        ),
        "selection_summary": generation.get("selection_summary"),
        "generated_markdown": generation.get("generated_markdown"),
        "generation": generation_metadata,
        "generation_limitations": generation.get("limitations") or [],
        "message": message,
    }


def _retrieve_playbooks(
    query: str,
    *,
    target_type: str,
    target_id: int,
    target_profile: dict[str, Any],
    retrieval_hints: PlaybookRetrievalHints,
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
        contexts: list[dict[str, Any]] = []
        seen_context_keys: set[tuple[str, str, str]] = set()
        seen_playbook_keys: set[str] = set()
        for stage in playbook_retrieval_filter_stages(retrieval_hints):
            stage_contexts = kb.retrieve_contexts(
                query,
                limit=25,
                source_type=KNOWLEDGE_BASE_SOURCE_TYPE,
                payload_filter=stage.payload_filter,
                payload_fields=PLAYBOOK_PAYLOAD_FIELDS,
            )
            for context in stage_contexts:
                if not _recommended_for_playbooks(context):
                    continue
                key = _context_identity(context)
                if key not in seen_context_keys:
                    enriched_context = dict(context)
                    enriched_context["retrieval_stage"] = stage.name
                    contexts.append(enriched_context)
                    seen_context_keys.add(key)
                    playbook_key = _context_playbook_key(enriched_context)
                    if playbook_key:
                        seen_playbook_keys.add(playbook_key)
            if len(seen_playbook_keys) >= limit:
                break
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

    ranked_items = _ranked_candidate_items(
        contexts,
        target_type=target_type,
        target_profile=target_profile,
    )
    recommendations = _group_recommendations(
        ranked_items,
        target_profile=target_profile,
        limit=limit,
    )
    message = (
        "Playbook recommendations are read-only analyst guidance; no "
        "operational state was changed."
    )
    if not recommendations:
        message = (
            "No Qdrant playbook context was returned for this target; "
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
            "retrieval_hints": target_profile.get("retrieval_hints") or {},
        },
        "recommended_playbooks": _recommended_playbook_summaries(recommendations),
        "message": message,
    }


def build_incident_playbook_recommendations(
    db,
    incident_id: int,
    *,
    limit: int = 4,
    knowledge_base_factory=QdrantKnowledgeBase,
    generate_llm: bool = False,
    llm_generator=None,
    similar_incidents_builder=build_similar_incidents_response,
) -> dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    retrieval_hints = infer_incident_playbook_hints(incident)
    profile = _profile_with_hints(
        incident_retrieval_text(incident),
        hints=retrieval_hints,
        allowed_categories=INCIDENT_PLAYBOOK_CATEGORIES,
    )
    knowledge_base = knowledge_base_factory()

    def shared_knowledge_base_factory():
        return knowledge_base

    response = _retrieve_playbooks(
        build_incident_playbook_query(incident),
        target_type="incident",
        target_id=incident_id,
        target_profile=profile,
        retrieval_hints=retrieval_hints,
        limit=limit,
        knowledge_base_factory=shared_knowledge_base_factory,
    )
    if not generate_llm or not response.get("recommendations"):
        return response

    similar_incidents: list[dict[str, Any]] = []
    try:
        similar_response = similar_incidents_builder(
            db,
            incident_id,
            limit=3,
            knowledge_base_factory=shared_knowledge_base_factory,
        )
        if safe_text(similar_response.get("status")).upper() == "OK":
            similar_incidents = list(similar_response.get("results") or [])[:3]
    except Exception:
        similar_incidents = []

    current_facts = build_incident_generation_facts(incident)
    current_facts["deterministic_retrieval_hints"] = (
        retrieval_hints.to_public_dict()
    )
    return _apply_llm_generation(
        response,
        target_type="incident",
        current_facts=current_facts,
        similar_incidents=similar_incidents,
        severity=safe_text(incident.recommended_priority) or safe_text(incident.level),
        llm_generator=llm_generator,
    )


def build_case_playbook_recommendations(
    db,
    case_id: int,
    *,
    limit: int = 4,
    knowledge_base_factory=QdrantKnowledgeBase,
    generate_llm: bool = False,
    llm_generator=None,
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
    retrieval_hints = infer_case_playbook_hints(
        case,
        incidents=incidents,
        actions=actions,
        closure=closure,
        latest_analysis=latest_analysis,
    )
    profile = _profile_with_hints(
        case_retrieval_text(
            case,
            incidents=incidents,
            actions=actions,
            closure=closure,
            latest_analysis=latest_analysis,
        ),
        hints=retrieval_hints,
        allowed_categories=CASE_PLAYBOOK_CATEGORIES,
    )

    knowledge_base = knowledge_base_factory()
    response = _retrieve_playbooks(
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
        retrieval_hints=retrieval_hints,
        limit=limit,
        knowledge_base_factory=lambda: knowledge_base,
    )
    if not generate_llm or not response.get("recommendations"):
        return response

    current_facts = build_case_generation_facts(
        case,
        incidents=incidents,
        actions=actions,
        closure=closure,
        latest_analysis=latest_analysis,
    )
    current_facts["deterministic_retrieval_hints"] = (
        retrieval_hints.to_public_dict()
    )
    return _apply_llm_generation(
        response,
        target_type="case",
        current_facts=current_facts,
        similar_incidents=None,
        severity=safe_text(case.severity_review or case.severity),
        llm_generator=llm_generator,
    )


@router.get("/incidents/{incident_id}/recommended-playbooks")
def get_incident_playbook_recommendations(
    incident_id: int,
    limit: int = Query(default=4, ge=1, le=8),
):
    db = SessionLocal()

    try:
        return build_incident_playbook_recommendations(
            db,
            incident_id,
            limit=limit,
            generate_llm=True,
        )
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
        return build_case_playbook_recommendations(
            db,
            case_id,
            limit=limit,
            generate_llm=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc
    finally:
        db.close()
