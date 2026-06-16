from __future__ import annotations

from dataclasses import asdict, dataclass

from .catalog import (
    CONNECTOR_CASE_MANAGEMENT,
    CONNECTOR_DETECTION_CONTROL,
    CONNECTOR_EDR_PLACEHOLDER,
    CONNECTOR_FIREWALL_PLACEHOLDER,
    CONNECTOR_REPORT_GENERATOR,
    CONNECTOR_SERVICE_OPERATIONS,
    CONNECTOR_SOAR_PLACEHOLDER,
    CONNECTOR_TICKETING_PLACEHOLDER,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
)


@dataclass(frozen=True)
class RemediationConnectorCatalogItem:
    connector_key: str
    display_name: str
    description: str
    connector_type: str
    enabled: bool
    execution_supported: bool
    proposal_supported: bool
    risk_level: str
    requires_approval: bool
    requires_admin: bool
    capabilities: list[str]
    step13_notice: str

    def to_dict(self) -> dict:
        return asdict(self)


CONNECTOR_CATALOG: tuple[RemediationConnectorCatalogItem, ...] = (
    RemediationConnectorCatalogItem(
        CONNECTOR_CASE_MANAGEMENT,
        "Case Management",
        "Creates or links internal case actions and review tasks.",
        "CASE_MANAGEMENT",
        True,
        True,
        True,
        RISK_LOW,
        True,
        False,
        ["create_case_action", "link_proposal_to_case"],
        "Only internal AI SOC case records are created.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_DETECTION_CONTROL,
        "Detection Control Plane",
        "Creates governed detection rule, noise suppression or exception drafts.",
        "DETECTION_CONTROL",
        True,
        True,
        True,
        RISK_MEDIUM,
        True,
        True,
        ["create_detection_rule_draft", "create_noise_suppression_draft", "create_exception_draft"],
        "Drafts are created only; they are not submitted, approved, applied or restarted automatically.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_REPORT_GENERATOR,
        "Report Generator",
        "Creates deterministic remediation plan or containment checklist text.",
        "REPORT_GENERATOR",
        True,
        True,
        True,
        RISK_LOW,
        True,
        False,
        ["generate_remediation_plan", "generate_containment_checklist"],
        "Document-only output is attached as an internal review record.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_SERVICE_OPERATIONS,
        "Service Operations",
        "Prepares service restart proposals and links to the existing Service Operations UI.",
        "SERVICE_OPERATIONS",
        True,
        False,
        True,
        RISK_MEDIUM,
        True,
        True,
        ["prepare_restart_proposal", "link_service_operations"],
        "No systemctl, docker or service restart command is executed in Step 13.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_TICKETING_PLACEHOLDER,
        "Ticketing placeholder",
        "Documents a future external ticket request.",
        "TICKETING_PLACEHOLDER",
        False,
        False,
        True,
        RISK_MEDIUM,
        True,
        True,
        ["prepare_ticket_payload"],
        "External connector execution is not enabled in this release.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_FIREWALL_PLACEHOLDER,
        "Firewall placeholder",
        "Documents a future firewall change request.",
        "FIREWALL_PLACEHOLDER",
        False,
        False,
        True,
        RISK_HIGH,
        True,
        True,
        ["prepare_ip_block_payload"],
        "No firewall, network or EDR action is executed in Step 13.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_SOAR_PLACEHOLDER,
        "SOAR placeholder",
        "Documents a future SOAR playbook request.",
        "SOAR_PLACEHOLDER",
        False,
        False,
        True,
        RISK_HIGH,
        True,
        True,
        ["prepare_soar_playbook_payload"],
        "No SOAR API call is made in Step 13.",
    ),
    RemediationConnectorCatalogItem(
        CONNECTOR_EDR_PLACEHOLDER,
        "EDR placeholder",
        "Documents a future EDR containment request.",
        "EDR_PLACEHOLDER",
        False,
        False,
        True,
        RISK_HIGH,
        True,
        True,
        ["prepare_edr_action_payload"],
        "No EDR API call or endpoint action is made in Step 13.",
    ),
)

CONNECTOR_CATALOG_BY_KEY = {item.connector_key: item for item in CONNECTOR_CATALOG}


def list_connector_catalog() -> list[dict]:
    return [item.to_dict() for item in CONNECTOR_CATALOG]


def get_connector(connector_key: str) -> RemediationConnectorCatalogItem | None:
    return CONNECTOR_CATALOG_BY_KEY.get(str(connector_key or "").strip())
