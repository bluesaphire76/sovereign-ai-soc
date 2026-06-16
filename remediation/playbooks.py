from __future__ import annotations

from dataclasses import asdict, dataclass

from .catalog import (
    ACTION_CREATE_CASE_ACTION,
    ACTION_CREATE_DETECTION_RULE_DRAFT,
    ACTION_CREATE_EXCEPTION_DRAFT,
    ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
    ACTION_GENERATE_CONTAINMENT_CHECKLIST,
    ACTION_GENERATE_REMEDIATION_PLAN,
    ACTION_PREPARE_IP_BLOCK,
    ACTION_PREPARE_SERVICE_RESTART,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
)


@dataclass(frozen=True)
class RemediationPlaybookTemplate:
    playbook_key: str
    display_name: str
    description: str
    incident_categories: list[str]
    recommended_actions: list[str]
    checklist_items: list[str]
    required_evidence: list[str]
    suggested_owner_role: str
    risk_level: str
    supported_connector_actions: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


PLAYBOOK_TEMPLATES: tuple[RemediationPlaybookTemplate, ...] = (
    RemediationPlaybookTemplate(
        "BRUTE_FORCE_SSH_INVESTIGATION",
        "Brute Force SSH Investigation",
        "Validate failed SSH authentication bursts and decide containment actions.",
        ["authentication", "ssh", "brute_force"],
        [
            "Review source IP reputation",
            "Check successful login after the brute-force window",
            "Validate impacted account",
            "Increase monitoring window",
            "Prepare IP block proposal if source remains suspicious",
        ],
        [
            "Confirm failed-login burst timing",
            "Check successful authentication after the burst",
            "Review MFA, account lockout and source reputation",
            "Document whether containment is required",
        ],
        ["Raw authentication alerts", "Affected host", "User/account context", "Source IP"],
        "ANALYST",
        RISK_MEDIUM,
        [ACTION_CREATE_CASE_ACTION, ACTION_GENERATE_CONTAINMENT_CHECKLIST, ACTION_PREPARE_IP_BLOCK],
    ),
    RemediationPlaybookTemplate(
        "SUSPICIOUS_SUDO_ESCALATION",
        "Suspicious Sudo Escalation",
        "Review elevated command activity and preserve evidence before containment.",
        ["linux", "sudo", "privilege_escalation"],
        [
            "Review command and user context",
            "Validate whether sudo activity was expected",
            "Create containment checklist if privilege abuse is suspected",
        ],
        [
            "Preserve audit logs",
            "Check recent login source",
            "Confirm owner and business purpose",
        ],
        ["Sudo audit event", "User identity", "Host ownership"],
        "ANALYST",
        RISK_MEDIUM,
        [ACTION_CREATE_CASE_ACTION, ACTION_GENERATE_CONTAINMENT_CHECKLIST],
    ),
    RemediationPlaybookTemplate(
        "SUSPICIOUS_PACKAGE_ACTIVITY",
        "Suspicious Package Activity",
        "Review package install/update signals before remediation or closure.",
        ["linux", "package", "fim"],
        [
            "Validate package source",
            "Compare activity against maintenance window",
            "Prepare detection tuning if noisy and benign",
        ],
        [
            "Check package name and version",
            "Verify change ticket or maintenance record",
            "Review host criticality",
        ],
        ["Package activity event", "Host inventory", "Maintenance record"],
        "ANALYST",
        RISK_MEDIUM,
        [ACTION_CREATE_CASE_ACTION, ACTION_CREATE_DETECTION_RULE_DRAFT],
    ),
    RemediationPlaybookTemplate(
        "NOISY_OPERATIONAL_BASELINE_REVIEW",
        "Noisy Operational Baseline Review",
        "Review recurring benign telemetry and prepare a governed suppression draft.",
        ["noise", "baseline", "operations"],
        [
            "Confirm repeated benign pattern",
            "Define narrow match criteria",
            "Create a noise suppression draft with expiration/review notes",
        ],
        [
            "Validate host/source scope",
            "Confirm false-positive rationale",
            "Set owner and review date",
        ],
        ["Matched alerts", "Business justification", "Owner"],
        "ANALYST",
        RISK_MEDIUM,
        [ACTION_CREATE_NOISE_SUPPRESSION_DRAFT, ACTION_CREATE_CASE_ACTION],
    ),
    RemediationPlaybookTemplate(
        "FALSE_POSITIVE_REVIEW",
        "False Positive Review",
        "Prepare closure or exception review without muting detection automatically.",
        ["false_positive", "exception"],
        [
            "Document false-positive evidence",
            "Create exception draft only if scope is narrow",
            "Keep high-risk exceptions under admin approval",
        ],
        [
            "Confirm benign root cause",
            "Define matcher scope",
            "Record expiration or no-expiration justification",
        ],
        ["Evidence reviewed", "Matcher scope", "Business justification"],
        "ANALYST",
        RISK_HIGH,
        [ACTION_CREATE_EXCEPTION_DRAFT, ACTION_CREATE_CASE_ACTION],
    ),
    RemediationPlaybookTemplate(
        "CASE_CLOSURE_READINESS",
        "Case Closure Readiness",
        "Prepare closure actions and residual-risk notes.",
        ["case", "closure"],
        [
            "Review open actions",
            "Document evidence and root cause",
            "Capture residual risk and closure decision",
        ],
        [
            "All evidence reviewed",
            "Actions resolved or cancelled",
            "Closure decision approved",
        ],
        ["Case actions", "Closure checklist", "Audit history"],
        "ANALYST",
        RISK_LOW,
        [ACTION_CREATE_CASE_ACTION, ACTION_GENERATE_REMEDIATION_PLAN],
    ),
    RemediationPlaybookTemplate(
        "DETECTION_RULE_TUNING",
        "Detection Rule Tuning",
        "Prepare detection lifecycle drafts for reviewed rule tuning.",
        ["detection_engineering", "rule_tuning"],
        [
            "Review rule hit quality",
            "Define tuning matcher and validation scenario",
            "Create detection lifecycle draft only",
        ],
        [
            "Confirm signal loss risk",
            "Document MITRE mapping",
            "Validate with representative sample events",
        ],
        ["Rule hit samples", "Validation scenario", "Owner"],
        "ANALYST",
        RISK_MEDIUM,
        [ACTION_CREATE_DETECTION_RULE_DRAFT, ACTION_CREATE_NOISE_SUPPRESSION_DRAFT],
    ),
)

PLAYBOOKS_BY_KEY = {item.playbook_key: item for item in PLAYBOOK_TEMPLATES}


def list_playbook_templates() -> list[dict]:
    return [item.to_dict() for item in PLAYBOOK_TEMPLATES]


def get_playbook_template(playbook_key: str) -> RemediationPlaybookTemplate | None:
    return PLAYBOOKS_BY_KEY.get(str(playbook_key or "").upper().strip())
