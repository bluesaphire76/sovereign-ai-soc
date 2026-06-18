from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from investigation_ai.adapters import safe_text
from playbook_retrieval_catalog import EXPANDED_PLAYBOOK_SIGNAL_RULES


PLAYBOOK_TARGET_PAGE = "recommended_playbooks"
PLAYBOOK_BASE_FILTER = {
    "doc_type": "playbook",
    "content_kind": "playbook_section",
    "recommended_for_pages": PLAYBOOK_TARGET_PAGE,
}
INCIDENT_TEXT_FIELDS = (
    "title",
    "description",
    "source",
    "rule",
    "rule_groups",
    "rule_id",
    "agent",
    "level",
    "severity",
    "mitre",
    "risk_score",
    "correlation_type",
    "correlation_summary",
    "attack_chain",
    "escalation_reason",
    "recommended_priority",
    "ai_analysis",
    "raw_alert",
    "security_alert",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "hostname",
    "username",
    "user",
    "process_name",
    "command",
    "file_path",
    "network_protocol",
    "dns_query",
    "suricata_signature",
    "wazuh_rule_category",
)
INCIDENT_PRIMARY_RETRIEVAL_FIELDS = (
    "title",
    "description",
    "source",
    "rule",
    "rule_groups",
    "rule_id",
    "agent",
    "level",
    "severity",
    "mitre",
    "raw_alert",
    "security_alert",
)
CASE_TEXT_FIELDS = (
    "title",
    "status",
    "severity",
    "severity_review",
    "risk_score",
    "summary",
    "correlation_type",
    "closure_decision",
    "residual_risk",
    "analysis",
)


@dataclass(frozen=True)
class PlaybookRetrievalHints:
    platform: str = ""
    source: str = ""
    domain: str = ""
    incident_types: tuple[str, ...] = ()
    supporting_incident_types: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    supporting_tags: tuple[str, ...] = ()
    mitre_tactics: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    evidence_terms: tuple[str, ...] = ()
    matched_signals: tuple[str, ...] = ()
    confidence: str = "low"

    def all_incident_types(self) -> tuple[str, ...]:
        return _dedupe([*self.incident_types, *self.supporting_incident_types])

    def selection_incident_types(self) -> tuple[str, ...]:
        primary = self.incident_types[:1]
        return _dedupe([*primary, *self.supporting_incident_types])

    def all_tags(self) -> tuple[str, ...]:
        return _dedupe([*self.tags, *self.supporting_tags])

    def ranking_text(self) -> str:
        return " ".join(
            [
                self.platform,
                self.source,
                self.domain,
                " ".join(self.all_incident_types()),
                " ".join(self.all_tags()),
                " ".join(self.mitre_tactics),
                " ".join(self.mitre_techniques),
                " ".join(self.evidence_terms),
                " ".join(self.matched_signals),
            ]
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "source": self.source,
            "domain": self.domain,
            "incident_types": list(self.incident_types),
            "supporting_incident_types": list(self.supporting_incident_types),
            "tags": list(self.tags),
            "supporting_tags": list(self.supporting_tags),
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "evidence_terms": list(self.evidence_terms),
            "matched_signals": list(self.matched_signals),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class PlaybookRetrievalFilterStage:
    name: str
    payload_filter: dict[str, Any] | None


def _dedupe(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = safe_text(value).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return tuple(result)


def _has_any(text: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _raise_confidence(current: str, candidate: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return candidate if order.get(candidate, 0) > order.get(current, 0) else current


def _object_text(value: Any, fields: tuple[str, ...]) -> str:
    parts: list[str] = []
    for field_name in fields:
        try:
            part = getattr(value, field_name, None)
        except Exception:
            part = None
        text = safe_text(part)
        if text:
            parts.append(f"{field_name}: {text}")
    return "\n".join(parts)


def incident_retrieval_text(incident: Any) -> str:
    return _object_text(incident, INCIDENT_TEXT_FIELDS)


def incident_primary_retrieval_text(incident: Any) -> str:
    """Return authoritative detection fields used to choose playbooks.

    Derived AI analysis and correlation summaries remain useful generation
    context, but they may contain hypotheses or stale cross-platform wording
    and must not drive deterministic playbook selection.
    """

    return _object_text(incident, INCIDENT_PRIMARY_RETRIEVAL_FIELDS)


def case_retrieval_text(
    case: Any,
    *,
    incidents: list[Any] | tuple[Any, ...] = (),
    actions: list[Any] | tuple[Any, ...] = (),
    closure: Any | None = None,
    latest_analysis: Any | None = None,
) -> str:
    parts = [_object_text(case, CASE_TEXT_FIELDS)]
    parts.extend(_object_text(incident, INCIDENT_TEXT_FIELDS) for incident in incidents[:8])
    for action in actions[:8]:
        parts.append(
            _object_text(
                action,
                (
                    "category",
                    "title",
                    "description",
                    "priority",
                    "status",
                    "result",
                    "notes",
                ),
            )
        )
    if closure is not None:
        parts.append(_object_text(closure, CASE_TEXT_FIELDS))
    if latest_analysis is not None:
        parts.append(_object_text(latest_analysis, CASE_TEXT_FIELDS))
    return "\n".join(part for part in parts if part)


def infer_playbook_retrieval_hints(text: str) -> PlaybookRetrievalHints:
    haystack = safe_text(text).lower()
    platform = ""
    source = ""
    domain = ""
    incident_types: list[str] = []
    supporting_incident_types: list[str] = []
    tags: list[str] = []
    supporting_tags: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    evidence_terms: list[str] = []
    matched_signals: list[str] = []
    confidence = "low"

    windows_platform_signal = _has_any(
        haystack,
        (
            r"\bwindows\b",
            r"data[._]win\b",
            r"microsoft-windows-",
            r"windows event( id)?",
            r"\bevent id (4624|4625|4672|4698|4720|4732|5007|5061|5140|5145|7045|1102)\b",
            r"\bsysmon\b",
        ),
    )
    linux_platform_signal = not windows_platform_signal and _has_any(
        haystack,
        (
            r"\blinux\b",
            r"\bsshd\b",
            r"\bsystemd\b",
            r"/etc/(passwd|shadow|sudoers|ssh)",
            r"/(tmp|var/tmp|dev/shm)\b",
        ),
    )
    if windows_platform_signal:
        platform = "windows"
        source = "wazuh"
        domain = "windows_host"
        supporting_incident_types.extend(
            ("evidence_collection_standard", "severity_classification")
        )
        tags.extend(("windows", "wazuh"))
        supporting_tags.extend(("evidence", "severity", "governance"))
        evidence_terms.append("Windows endpoint and Event Log telemetry")
        matched_signals.append("windows_platform")
        confidence = _raise_confidence(confidence, "medium")
    elif linux_platform_signal:
        platform = "linux"
        tags.append("linux")
        evidence_terms.append("Linux host telemetry")
        matched_signals.append("linux_platform")
        confidence = _raise_confidence(confidence, "medium")

    def add(
        *,
        signal: str,
        match: bool,
        match_source: str = "",
        match_domain: str = "",
        types: tuple[str, ...] = (),
        supporting_types: tuple[str, ...] = (),
        match_tags: tuple[str, ...] = (),
        supporting_match_tags: tuple[str, ...] = (),
        tactics: tuple[str, ...] = (),
        techniques: tuple[str, ...] = (),
        terms: tuple[str, ...] = (),
    ) -> None:
        nonlocal source, domain, confidence
        if not match:
            return
        if not source and match_source:
            source = match_source
        if not domain and match_domain:
            domain = match_domain
        incident_types.extend(types)
        supporting_incident_types.extend(supporting_types)
        tags.extend(match_tags)
        supporting_tags.extend(supporting_match_tags)
        mitre_tactics.extend(tactics)
        mitre_techniques.extend(techniques)
        evidence_terms.extend(terms)
        matched_signals.append(signal)
        confidence = _raise_confidence(confidence, "high" if types else "medium")

    matched_catalog_rules = sorted(
        (rule for rule in EXPANDED_PLAYBOOK_SIGNAL_RULES if rule.matches(haystack)),
        key=lambda rule: rule.priority,
        reverse=True,
    )
    for rule in matched_catalog_rules:
        add(
            signal=rule.signal,
            match=True,
            match_source=rule.source,
            match_domain=rule.domain,
            types=rule.incident_types,
            supporting_types=rule.supporting_incident_types,
            match_tags=rule.tags,
            supporting_match_tags=rule.supporting_tags,
            tactics=rule.tactics,
            techniques=rule.techniques,
            terms=rule.evidence_terms,
        )

    add(
        signal="windows_audit_failure",
        match=windows_platform_signal
        and _has_any(
            haystack,
            (
                r"windows audit failure event",
                r"\baudit_failure\b",
                r"(event( id)? )?5061",
                r"cryptographic operation.{0,160}(failed|failure|return code)",
            ),
        ),
        match_source="wazuh",
        match_domain="windows_host",
        types=("windows_audit_failure", "windows_security_audit_failure"),
        supporting_types=(
            "evidence_collection_standard",
            "severity_classification",
        ),
        match_tags=("windows", "audit-failure", "security-event", "wazuh"),
        supporting_match_tags=(
            "evidence",
            "severity",
            "false-positive",
            "governance",
        ),
        terms=(
            "Windows Security audit failure with event-specific evidence review",
        ),
    )

    ssh_signal = _has_any(haystack, (r"\bssh\b", r"\bsshd\b", r"openssh", r"pam_unix"))
    failed_ssh_signal = ssh_signal and _has_any(
        haystack,
        (
            r"failed password",
            r"authentication failure",
            r"invalid user",
            r"failed login",
            r"repeated failed",
            r"brute[- ]?force",
            r"\bt1110\b",
        ),
    )
    successful_ssh_signal = ssh_signal and _has_any(
        haystack,
        (
            r"accepted password",
            r"accepted publickey",
            r"successful login",
            r"login success",
            r"session opened",
            r"\bt1078\b",
        ),
    )
    add(
        signal="ssh_success_after_failures",
        match=not windows_platform_signal and failed_ssh_signal and successful_ssh_signal,
        match_source="wazuh",
        match_domain="authentication",
        types=(
            "ssh_success_after_failures",
            "possible_account_compromise",
            "credential_attack",
            "ssh_bruteforce",
        ),
        supporting_types=("ssh_bruteforce", "sudo_privilege_escalation"),
        match_tags=("ssh", "successful-login", "failed-login", "account-compromise", "wazuh"),
        supporting_match_tags=("sudo", "privilege-escalation"),
        tactics=("Credential Access", "Initial Access", "Privilege Escalation"),
        techniques=("T1110", "T1021.004", "T1078"),
        terms=(
            "failed SSH attempts followed by successful authentication",
            "post-login privilege review",
        ),
    )
    add(
        signal="ssh_bruteforce",
        match=not windows_platform_signal and failed_ssh_signal and not successful_ssh_signal,
        match_source="wazuh",
        match_domain="authentication",
        types=("ssh_bruteforce", "repeated_failed_login", "credential_attack"),
        match_tags=("ssh", "brute-force", "authentication", "wazuh"),
        tactics=("Credential Access", "Initial Access"),
        techniques=("T1110", "T1021.004"),
        terms=("repeated failed SSH authentication attempts",),
    )

    add(
        signal="sudo_privilege_escalation",
        match=not windows_platform_signal
        and _has_any(
            haystack,
            (
                r"\bsudo\b",
                r"command=",
                r"privileged command",
                r"root command",
                r"privilege escalation",
                r"\bt1548\b",
            ),
        ),
        match_source="wazuh",
        match_domain="authentication",
        types=("sudo_privilege_escalation", "privileged_command_execution"),
        match_tags=("sudo", "privilege-escalation", "linux", "wazuh"),
        tactics=("Privilege Escalation", "Credential Access"),
        techniques=("T1548", "T1078"),
        terms=("suspicious sudo activity or privileged command execution",),
    )

    add(
        signal="suspicious_package_activity",
        match=_has_any(
            haystack,
            (
                r"\bapt(-get)?\b",
                r"\bdpkg\b",
                r"\byum\b",
                r"\bdnf\b",
                r"package install",
                r"installed package",
                r"repository change",
            ),
        ),
        match_source="wazuh",
        match_domain="linux_host",
        types=("suspicious_package_activity", "unauthorized_software_installation"),
        match_tags=("package-manager", "software-install", "linux", "wazuh"),
        tactics=("Execution", "Persistence"),
        techniques=("T1105", "T1059", "T1543"),
        terms=("unexpected Linux package manager activity",),
    )

    add(
        signal="suspicious_systemd_service",
        match=_has_any(
            haystack,
            (
                r"\bsystemd\b",
                r"\.service\b",
                r"execstart",
                r"service enabled",
                r"service started",
                r"\bt1543\.002\b",
            ),
        ),
        match_source="wazuh",
        match_domain="linux_host",
        types=("suspicious_systemd_service", "linux_persistence"),
        match_tags=("systemd", "persistence", "service", "linux", "wazuh"),
        tactics=("Persistence", "Privilege Escalation"),
        techniques=("T1543.002",),
        terms=("suspicious systemd service creation or modification",),
    )

    suricata_signal = _has_any(haystack, (r"\bsuricata\b", r"\bets\b", r"ids alert"))
    port_scan_signal = _has_any(
        haystack,
        (
            r"port scan",
            r"\bscan\b",
            r"network reconnaissance",
            r"reconnaissance",
            r"\bt1046\b",
            r"\bt1595\b",
        ),
    )
    add(
        signal="suricata_port_scan",
        match=suricata_signal and port_scan_signal,
        match_source="suricata",
        match_domain="network_suricata",
        types=("port_scan", "network_reconnaissance", "suspicious_probe"),
        supporting_types=("suricata_high_severity_alert",),
        match_tags=("suricata", "port-scan", "reconnaissance", "network"),
        supporting_match_tags=("high-severity", "network-alert"),
        tactics=("Discovery", "Reconnaissance"),
        techniques=("T1046", "T1595"),
        terms=("Suricata port scan or network reconnaissance alert",),
    )
    add(
        signal="suricata_high_severity_alert",
        match=suricata_signal and not port_scan_signal,
        match_source="suricata",
        match_domain="network_suricata",
        types=("suricata_high_severity_alert", "network_intrusion_alert"),
        match_tags=("suricata", "network-alert", "ids", "high-severity"),
        tactics=("Command and Control", "Initial Access"),
        terms=("high severity Suricata or IDS network alert",),
    )

    dns_signal = _has_any(haystack, (r"\bdns\b", r"domain", r"query", r"\bt1071\.004\b"))
    dns_tunnel_signal = dns_signal and _has_any(
        haystack,
        (
            r"tunnel",
            r"tunneling",
            r"exfil",
            r"high entropy",
            r"long subdomain",
            r"\btxt\b",
            r"high query volume",
            r"\bt1048\b",
        ),
    )
    dns_c2_signal = dns_signal and _has_any(
        haystack,
        (
            r"beacon",
            r"beaconing",
            r"regular interval",
            r"periodic",
            r"command and control",
            r"\bc2\b",
            r"\bt1071\.004\b",
        ),
    )
    add(
        signal="dns_tunneling",
        match=dns_tunnel_signal,
        match_source="dns",
        match_domain="dns",
        types=("dns_tunneling", "dns_exfiltration", "suspicious_dns_volume"),
        supporting_types=("dns_c2_beaconing",),
        match_tags=("dns", "tunneling", "exfiltration", "high-entropy"),
        supporting_match_tags=("c2", "beaconing"),
        tactics=("Command and Control", "Exfiltration"),
        techniques=("T1071.004", "T1048"),
        terms=("DNS tunneling, exfiltration or high-volume query pattern",),
    )
    add(
        signal="dns_c2_beaconing",
        match=dns_c2_signal and not dns_tunnel_signal,
        match_source="dns",
        match_domain="dns",
        types=("dns_c2_beaconing", "command_and_control", "suspicious_dns_activity"),
        supporting_types=("dns_tunneling", "suricata_high_severity_alert"),
        match_tags=("dns", "c2", "beaconing", "command-and-control"),
        supporting_match_tags=("suricata", "network-alert"),
        tactics=("Command and Control",),
        techniques=("T1071.004",),
        terms=("repeated DNS queries with possible command-and-control beaconing",),
    )

    benign_review_signal = _has_any(
        haystack,
        (
            r"false positive",
            r"approved scanner",
            r"approved vulnerability scan",
            r"approved penetration test",
            r"maintenance window",
            r"known admin",
            r"benign",
            r"test window",
        ),
    )
    if incident_types or benign_review_signal:
        supporting_incident_types.extend(("false_positive_review", "benign_activity_validation"))
        supporting_tags.extend(("false-positive", "governance", "analyst-decision"))
        if benign_review_signal:
            matched_signals.append("false_positive_review")
            evidence_terms.append("benign activity and false positive validation")

    return PlaybookRetrievalHints(
        platform=platform,
        source=source,
        domain=domain,
        incident_types=_dedupe(incident_types),
        supporting_incident_types=_dedupe(supporting_incident_types),
        tags=_dedupe(tags),
        supporting_tags=_dedupe(supporting_tags),
        mitre_tactics=_dedupe(mitre_tactics),
        mitre_techniques=_dedupe(mitre_techniques),
        evidence_terms=_dedupe(evidence_terms),
        matched_signals=_dedupe(matched_signals),
        confidence=confidence,
    )


def infer_incident_playbook_hints(incident: Any) -> PlaybookRetrievalHints:
    return infer_playbook_retrieval_hints(incident_primary_retrieval_text(incident))


def infer_case_playbook_hints(
    case: Any,
    *,
    incidents: list[Any] | tuple[Any, ...] = (),
    actions: list[Any] | tuple[Any, ...] = (),
    closure: Any | None = None,
    latest_analysis: Any | None = None,
) -> PlaybookRetrievalHints:
    return infer_playbook_retrieval_hints(
        case_retrieval_text(
            case,
            incidents=incidents,
            actions=actions,
            closure=closure,
            latest_analysis=latest_analysis,
        )
    )


def build_playbook_retrieval_query(
    *,
    target_type: str,
    facts: str,
    hints: PlaybookRetrievalHints,
) -> str:
    fact_summary = " ".join(safe_text(facts).split())[:1800]
    lines = [
        f"Recommended playbook retrieval for AI SOC {target_type}.",
        f"Source: {hints.source or 'unknown'}",
        f"Domain: {hints.domain or 'unknown'}",
        f"Incident type candidates: {', '.join(hints.incident_types) or 'unknown'}",
        f"Supporting incident types: {', '.join(hints.supporting_incident_types) or 'false_positive_review'}",
        f"MITRE tactics: {', '.join(hints.mitre_tactics) or 'unknown'}",
        f"MITRE techniques: {', '.join(hints.mitre_techniques) or 'unknown'}",
        f"Tags: {', '.join(hints.all_tags()) or 'unknown'}",
        f"Matched signals: {', '.join(hints.matched_signals) or 'generic'}",
        f"Evidence summary: {', '.join(hints.evidence_terms) or fact_summary or 'No structured incident facts available.'}",
        (
            "Required context: when to use, detection signals, initial triage, "
            "evidence to collect, investigation steps, correlation checks, "
            "false positive conditions, escalation criteria, containment actions, "
            "remediation actions, closure criteria."
        ),
        f"Target page: {PLAYBOOK_TARGET_PAGE}",
        f"Current {target_type} facts: {fact_summary}",
    ]
    return " ".join(line for line in lines if safe_text(line))


def playbook_retrieval_filter_stages(
    hints: PlaybookRetrievalHints,
) -> list[PlaybookRetrievalFilterStage]:
    stages: list[PlaybookRetrievalFilterStage] = []
    base = dict(PLAYBOOK_BASE_FILTER)
    first_type = hints.incident_types[0] if hints.incident_types else ""
    first_technique = hints.mitre_techniques[0] if hints.mitre_techniques else ""

    if hints.source and hints.domain and first_type and first_technique:
        stages.append(
            PlaybookRetrievalFilterStage(
                "strong_source_domain_type_mitre",
                {
                    **base,
                    "playbook_source": hints.source,
                    "domain": hints.domain,
                    "incident_types": first_type,
                    "mitre_techniques": first_technique,
                },
            )
        )
    if hints.source and hints.domain and first_type:
        stages.append(
            PlaybookRetrievalFilterStage(
                "strong_source_domain_type",
                {
                    **base,
                    "playbook_source": hints.source,
                    "domain": hints.domain,
                    "incident_types": first_type,
                },
            )
        )
    if first_type:
        stages.append(
            PlaybookRetrievalFilterStage(
                "primary_incident_type",
                {**base, "incident_types": first_type},
            )
        )
    for supporting_type in hints.supporting_incident_types[:4]:
        stages.append(
            PlaybookRetrievalFilterStage(
                "supporting_incident_type",
                {**base, "incident_types": supporting_type},
            )
        )
    if hints.domain and first_type:
        stages.append(
            PlaybookRetrievalFilterStage(
                "medium_domain_type",
                {**base, "domain": hints.domain, "incident_types": first_type},
            )
        )
    if hints.source and hints.domain:
        stages.append(
            PlaybookRetrievalFilterStage(
                "medium_source_domain",
                {**base, "playbook_source": hints.source, "domain": hints.domain},
            )
        )
    if hints.domain:
        stages.append(
            PlaybookRetrievalFilterStage("medium_domain", {**base, "domain": hints.domain})
        )
    if hints.source:
        stages.append(
            PlaybookRetrievalFilterStage(
                "medium_source", {**base, "playbook_source": hints.source}
            )
        )

    stages.append(PlaybookRetrievalFilterStage("broad_playbook", base))
    stages.append(PlaybookRetrievalFilterStage("broad_knowledge_base", None))

    deduped: list[PlaybookRetrievalFilterStage] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for stage in stages:
        key = tuple(sorted((safe_text(k), safe_text(v)) for k, v in (stage.payload_filter or {}).items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(stage)
    return deduped
