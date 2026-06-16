from __future__ import annotations

from dataclasses import asdict, dataclass


ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

MODE_DOCUMENT_ONLY = "DOCUMENT_ONLY"
MODE_INTERNAL_DRAFT = "INTERNAL_DRAFT"
MODE_INTERNAL_LINK = "INTERNAL_LINK"
MODE_PROPOSAL_ONLY = "PROPOSAL_ONLY"
MODE_EXECUTION_DEFERRED = "EXECUTION_DEFERRED"
MODE_DISABLED = "DISABLED"

ACTION_CREATE_CASE_ACTION = "CREATE_CASE_ACTION"
ACTION_GENERATE_REMEDIATION_PLAN = "GENERATE_REMEDIATION_PLAN"
ACTION_GENERATE_CONTAINMENT_CHECKLIST = "GENERATE_CONTAINMENT_CHECKLIST"
ACTION_CREATE_DETECTION_RULE_DRAFT = "CREATE_DETECTION_RULE_DRAFT"
ACTION_CREATE_NOISE_SUPPRESSION_DRAFT = "CREATE_NOISE_SUPPRESSION_DRAFT"
ACTION_CREATE_EXCEPTION_DRAFT = "CREATE_EXCEPTION_DRAFT"
ACTION_LINK_RECOMMENDED_ACTION_TO_CASE = "LINK_RECOMMENDED_ACTION_TO_CASE"
ACTION_PREPARE_SERVICE_RESTART = "PREPARE_SERVICE_RESTART"
ACTION_PREPARE_RULE_DISABLE = "PREPARE_RULE_DISABLE"
ACTION_PREPARE_IP_BLOCK = "PREPARE_IP_BLOCK"
ACTION_PREPARE_EXTERNAL_TICKET = "PREPARE_EXTERNAL_TICKET"
ACTION_PREPARE_SOAR_PLAYBOOK = "PREPARE_SOAR_PLAYBOOK"

CONNECTOR_CASE_MANAGEMENT = "case_management"
CONNECTOR_DETECTION_CONTROL = "detection_control"
CONNECTOR_REPORT_GENERATOR = "report_generator"
CONNECTOR_SERVICE_OPERATIONS = "service_operations"
CONNECTOR_TICKETING_PLACEHOLDER = "ticketing_placeholder"
CONNECTOR_FIREWALL_PLACEHOLDER = "firewall_placeholder"
CONNECTOR_SOAR_PLACEHOLDER = "soar_placeholder"
CONNECTOR_EDR_PLACEHOLDER = "edr_placeholder"

ACTION_TYPES = {
    ACTION_CREATE_CASE_ACTION,
    ACTION_GENERATE_REMEDIATION_PLAN,
    ACTION_GENERATE_CONTAINMENT_CHECKLIST,
    ACTION_CREATE_DETECTION_RULE_DRAFT,
    ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
    ACTION_CREATE_EXCEPTION_DRAFT,
    ACTION_LINK_RECOMMENDED_ACTION_TO_CASE,
    ACTION_PREPARE_SERVICE_RESTART,
    ACTION_PREPARE_RULE_DISABLE,
    ACTION_PREPARE_IP_BLOCK,
    ACTION_PREPARE_EXTERNAL_TICKET,
    ACTION_PREPARE_SOAR_PLAYBOOK,
}

RISK_ORDER = {
    RISK_LOW: 1,
    RISK_MEDIUM: 2,
    RISK_HIGH: 3,
}


@dataclass(frozen=True)
class RemediationActionCatalogItem:
    action_type: str
    display_name: str
    description: str
    risk_level: str
    execution_mode: str
    connector_key: str
    requires_approval: bool
    requires_admin_approval: bool
    dry_run_supported: bool
    execution_supported_in_step13: bool
    rollback_supported: bool
    allowed_roles: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


ACTION_CATALOG: tuple[RemediationActionCatalogItem, ...] = (
    RemediationActionCatalogItem(
        ACTION_CREATE_CASE_ACTION,
        "Create case action",
        "Create a low-risk internal case task for analyst follow-up.",
        RISK_LOW,
        MODE_INTERNAL_LINK,
        CONNECTOR_CASE_MANAGEMENT,
        True,
        False,
        True,
        True,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_GENERATE_REMEDIATION_PLAN,
        "Generate remediation plan",
        "Create deterministic plan text for review and attachment to the incident or case.",
        RISK_LOW,
        MODE_DOCUMENT_ONLY,
        CONNECTOR_REPORT_GENERATOR,
        True,
        False,
        True,
        True,
        False,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_GENERATE_CONTAINMENT_CHECKLIST,
        "Generate containment checklist",
        "Create a review checklist without executing containment.",
        RISK_LOW,
        MODE_DOCUMENT_ONLY,
        CONNECTOR_REPORT_GENERATOR,
        True,
        False,
        True,
        True,
        False,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_CREATE_DETECTION_RULE_DRAFT,
        "Create detection rule draft",
        "Create a Detection Control Plane lifecycle draft only.",
        RISK_MEDIUM,
        MODE_INTERNAL_DRAFT,
        CONNECTOR_DETECTION_CONTROL,
        True,
        True,
        True,
        True,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
        "Create noise suppression draft",
        "Create a Detection Control Plane noise-suppression draft only.",
        RISK_MEDIUM,
        MODE_INTERNAL_DRAFT,
        CONNECTOR_DETECTION_CONTROL,
        True,
        True,
        True,
        True,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_CREATE_EXCEPTION_DRAFT,
        "Create exception draft",
        "Create a Detection Control Plane exception draft only.",
        RISK_HIGH,
        MODE_INTERNAL_DRAFT,
        CONNECTOR_DETECTION_CONTROL,
        True,
        True,
        True,
        True,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_LINK_RECOMMENDED_ACTION_TO_CASE,
        "Link recommendation to case",
        "Link a recommendation to an existing case for tracking.",
        RISK_LOW,
        MODE_INTERNAL_LINK,
        CONNECTOR_CASE_MANAGEMENT,
        True,
        False,
        True,
        True,
        False,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_PREPARE_SERVICE_RESTART,
        "Prepare service restart",
        "Prepare a governed restart proposal; no restart is executed.",
        RISK_MEDIUM,
        MODE_EXECUTION_DEFERRED,
        CONNECTOR_SERVICE_OPERATIONS,
        True,
        True,
        True,
        False,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_PREPARE_RULE_DISABLE,
        "Prepare rule disable",
        "Prepare a rule-disable proposal; no rule is disabled automatically.",
        RISK_HIGH,
        MODE_PROPOSAL_ONLY,
        CONNECTOR_DETECTION_CONTROL,
        True,
        True,
        True,
        False,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_PREPARE_IP_BLOCK,
        "Prepare IP block",
        "Prepare an IP block proposal; no firewall or EDR action is executed.",
        RISK_HIGH,
        MODE_PROPOSAL_ONLY,
        CONNECTOR_FIREWALL_PLACEHOLDER,
        True,
        True,
        True,
        False,
        True,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_PREPARE_EXTERNAL_TICKET,
        "Prepare external ticket",
        "Document a future external ticket request without sending it.",
        RISK_MEDIUM,
        MODE_PROPOSAL_ONLY,
        CONNECTOR_TICKETING_PLACEHOLDER,
        True,
        True,
        True,
        False,
        False,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
    RemediationActionCatalogItem(
        ACTION_PREPARE_SOAR_PLAYBOOK,
        "Prepare SOAR playbook",
        "Document a SOAR playbook request without invoking any SOAR API.",
        RISK_HIGH,
        MODE_DISABLED,
        CONNECTOR_SOAR_PLACEHOLDER,
        True,
        True,
        True,
        False,
        False,
        [ROLE_ADMIN, ROLE_ANALYST],
    ),
)

ACTION_CATALOG_BY_TYPE = {item.action_type: item for item in ACTION_CATALOG}


def list_action_catalog() -> list[dict]:
    return [item.to_dict() for item in ACTION_CATALOG]


def get_action_catalog_item(action_type: str) -> RemediationActionCatalogItem | None:
    return ACTION_CATALOG_BY_TYPE.get(str(action_type or "").upper().strip())


def normalize_action_type(value: str | None, *, fallback: str = ACTION_GENERATE_REMEDIATION_PLAN) -> str:
    normalized = str(value or "").upper().strip()
    return normalized if normalized in ACTION_TYPES else fallback


def strictest_risk(*levels: str | None) -> str:
    normalized = [str(level or "").upper().strip() for level in levels if level]
    valid = [level for level in normalized if level in RISK_ORDER]
    if not valid:
        return RISK_LOW
    return max(valid, key=lambda level: RISK_ORDER[level])
