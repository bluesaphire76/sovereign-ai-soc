from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


REPO_ROOT = Path(__file__).resolve().parent


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)

    if raw is None:
        return default

    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)

    if raw is None:
        return default

    try:
        return int(raw)
    except ValueError:
        return default


def _safe_text(element: ElementTree.Element | None) -> str | None:
    if element is None or element.text is None:
        return None

    value = element.text.strip()
    return value or None


def _rule_field_values(rule: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}

    for field in rule.findall("field"):
        name = field.attrib.get("name")
        value = _safe_text(field)

        if name and value:
            values[name] = value

    return values


def _wazuh_rule_items() -> list[dict[str, Any]]:
    rules_dir = REPO_ROOT / "deploy" / "wazuh" / "rules"
    items: list[dict[str, Any]] = []

    if not rules_dir.exists():
        return items

    for file_path in sorted(rules_dir.glob("*.xml")):
        try:
            root = ElementTree.parse(file_path).getroot()
        except ElementTree.ParseError as exc:
            items.append(
                {
                    "id": f"wazuh-file-error:{_relative(file_path)}",
                    "name": file_path.name,
                    "type": "WAZUH_RULE_FILE",
                    "source": "wazuh",
                    "scope": "global",
                    "target": _relative(file_path),
                    "status": "ERROR",
                    "managed": True,
                    "requires_reload": True,
                    "last_seen": None,
                    "description": "Wazuh XML rule file could not be parsed.",
                    "reason": str(exc),
                    "metadata": {"path": _relative(file_path)},
                }
            )
            continue

        for rule in root.findall(".//rule"):
            rule_id = rule.attrib.get("id") or "unknown"
            level = rule.attrib.get("level") or "unknown"
            description = _safe_text(rule.find("description")) or f"Wazuh rule {rule_id}"
            group = _safe_text(rule.find("group"))
            fields = _rule_field_values(rule)

            if "dns_telemetry" in (group or "") or "dns" in file_path.name.lower():
                rule_type = "DNS_TELEMETRY_RULE"
                target = fields.get("event_type") or "dns telemetry"
            elif "demo" in file_path.name.lower():
                rule_type = "DEMO_WAZUH_RULE"
                target = fields.get("scenario") or fields.get("source") or "demo scenario"
            else:
                rule_type = "WAZUH_CUSTOM_RULE"
                target = fields.get("source") or fields.get("event_type") or "wazuh manager"

            items.append(
                {
                    "id": f"wazuh-rule:{rule_id}",
                    "name": description,
                    "type": rule_type,
                    "source": "wazuh",
                    "scope": "global",
                    "target": target,
                    "status": "ACTIVE",
                    "managed": True,
                    "requires_reload": True,
                    "last_seen": None,
                    "description": description,
                    "reason": "Repository-managed Wazuh custom rule discovered from deploy/wazuh/rules.",
                    "metadata": {
                        "rule_id": rule_id,
                        "level": level,
                        "group": group,
                        "fields": fields,
                        "path": _relative(file_path),
                    },
                }
            )

    return items


def _suricata_items() -> list[dict[str, Any]]:
    compose_path = REPO_ROOT / "deploy" / "suricata" / "docker-compose.yml"
    rules_dir = REPO_ROOT / "deploy" / "suricata" / "rules"

    items: list[dict[str, Any]] = []

    if compose_path.exists():
        items.append(
            {
                "id": "suricata:sensor-compose",
                "name": "Suricata Docker sensor",
                "type": "SURICATA_SENSOR",
                "source": "suricata",
                "scope": "global",
                "target": "ai-soc-suricata",
                "status": "ACTIVE",
                "managed": True,
                "requires_reload": False,
                "last_seen": None,
                "description": "Repository-managed Suricata Docker sensor definition.",
                "reason": "Inventory item discovered from deploy/suricata/docker-compose.yml.",
                "metadata": {"path": _relative(compose_path)},
            }
        )

    if rules_dir.exists():
        local_rule_files = [
            path
            for path in sorted(rules_dir.glob("*"))
            if path.is_file() and path.name != ".gitkeep"
        ]

        if local_rule_files:
            for path in local_rule_files:
                items.append(
                    {
                        "id": f"suricata-rule-file:{path.name}",
                        "name": path.name,
                        "type": "SURICATA_RULE_FILE",
                        "source": "suricata",
                        "scope": "global",
                        "target": _relative(path),
                        "status": "PENDING_REVIEW",
                        "managed": True,
                        "requires_reload": True,
                        "last_seen": None,
                        "description": "Repository-managed Suricata local rule file.",
                        "reason": "Local Suricata rule file discovered under deploy/suricata/rules.",
                        "metadata": {"path": _relative(path)},
                    }
                )
        else:
            items.append(
                {
                    "id": "suricata:local-rules-placeholder",
                    "name": "Suricata local rules directory",
                    "type": "SURICATA_RULE_DIRECTORY",
                    "source": "suricata",
                    "scope": "global",
                    "target": _relative(rules_dir),
                    "status": "EMPTY",
                    "managed": True,
                    "requires_reload": False,
                    "last_seen": None,
                    "description": "Suricata local rules directory exists but no local rule files are currently managed.",
                    "reason": "Directory contains no active local rule files yet.",
                    "metadata": {"path": _relative(rules_dir)},
                }
            )

    return items


def _telemetry_sources() -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []

    source_definitions = [
        {
            "id": "source:wazuh",
            "name": "Wazuh host and endpoint telemetry",
            "type": "WAZUH",
            "source": "wazuh",
            "target": "Wazuh Indexer / Manager",
            "paths": ["ai_soc_worker.py", "wazuh_ingest_state.py"],
            "description": "Primary host and endpoint telemetry source used by the ingestion pipeline.",
        },
        {
            "id": "source:suricata",
            "name": "Suricata network telemetry",
            "type": "SURICATA",
            "source": "suricata",
            "target": "deploy/suricata/logs/eve.json",
            "paths": [
                "deploy/suricata/docker-compose.yml",
                "workers/suricata_ingest_worker.py",
                "scripts/ingest_suricata_eve.py",
            ],
            "description": "Network IDS telemetry source normalized into network events.",
        },
        {
            "id": "source:dns-telemetry",
            "name": "DNS telemetry collector",
            "type": "DNS_TELEMETRY",
            "source": "dns_telemetry",
            "target": "Wazuh JSON localfile / DNS normalizer",
            "paths": [
                "deploy/dns/ai-soc-dns-collector.py",
                "scripts/ingest_dns_events_from_wazuh.py",
                "deploy/wazuh/rules/ai_soc_dns_telemetry_rules.xml",
            ],
            "description": "Endpoint DNS context collected as JSON and normalized into DNS events.",
        },
    ]

    for definition in source_definitions:
        existing_paths = [
            path for path in definition["paths"] if (REPO_ROOT / path).exists()
        ]

        status = "ACTIVE" if existing_paths else "UNKNOWN"

        sources.append(
            {
                "id": definition["id"],
                "name": definition["name"],
                "type": definition["type"],
                "source": definition["source"],
                "scope": "global",
                "target": definition["target"],
                "status": status,
                "managed": True,
                "requires_reload": False,
                "last_seen": None,
                "description": definition["description"],
                "reason": "Source discovered from repository-managed collectors, workers or rule files.",
                "metadata": {
                    "configured_paths": definition["paths"],
                    "existing_paths": existing_paths,
                },
            }
        )

    return sources


def _policy_items() -> list[dict[str, Any]]:
    noise_enabled = _env_bool("NOISE_SUPPRESSION_ENABLED", True)
    noise_max_level = _env_int("NOISE_SUPPRESSION_MAX_LEVEL", 3)

    correlation_window = _env_int("CORRELATION_PRECHECK_WINDOW_MINUTES", 15)
    create_incident_level = _env_int("CORRELATION_CREATE_INCIDENT_LEVEL", 7)
    recent_volume_threshold = _env_int("CORRELATION_RECENT_VOLUME_THRESHOLD", 5)
    aggregate_threshold = _env_int("CORRELATION_AGGREGATE_COUNT_THRESHOLD", 10)

    return [
        {
            "id": "policy:noise-suppression",
            "name": "Noise suppression policy",
            "type": "NOISE_SUPPRESSION_POLICY",
            "source": "ai_soc",
            "scope": "global",
            "target": "low-signal operational events",
            "status": "ACTIVE" if noise_enabled else "DISABLED",
            "managed": True,
            "requires_reload": True,
            "last_seen": None,
            "description": "Suppresses known low-value operational telemetry before incident creation.",
            "reason": "Runtime policy derived from noise_suppression.py and environment configuration.",
            "metadata": {
                "enabled_env": "NOISE_SUPPRESSION_ENABLED",
                "enabled": noise_enabled,
                "max_level_env": "NOISE_SUPPRESSION_MAX_LEVEL",
                "max_level": noise_max_level,
                "source_file": "noise_suppression.py",
            },
        },
        {
            "id": "policy:correlation-precheck",
            "name": "Correlation-first incident creation",
            "type": "CORRELATION_POLICY",
            "source": "ai_soc",
            "scope": "global",
            "target": "security alerts before incident creation",
            "status": "ACTIVE",
            "managed": True,
            "requires_reload": True,
            "last_seen": None,
            "description": "Evaluates severity, MITRE context, recent volume, aggregates and attack-chain patterns before creating incidents.",
            "reason": "Runtime policy derived from correlation_precheck.py and environment configuration.",
            "metadata": {
                "window_minutes": correlation_window,
                "create_incident_level": create_incident_level,
                "recent_volume_threshold": recent_volume_threshold,
                "aggregate_count_threshold": aggregate_threshold,
                "source_file": "correlation_precheck.py",
            },
        },
        {
            "id": "policy:dns-context-only",
            "name": "DNS telemetry context-only policy",
            "type": "DNS_CONTEXT_POLICY",
            "source": "ai_soc",
            "scope": "global",
            "target": "dns_events",
            "status": "ACTIVE",
            "managed": True,
            "requires_reload": False,
            "last_seen": None,
            "description": "DNS telemetry is treated as investigation context and not as standalone proof of compromise.",
            "reason": "Policy documented in DNS telemetry and reporting flows.",
            "metadata": {
                "source_files": [
                    "report_dns_context.py",
                    "docs/v0.5-dns-telemetry-pilot.md",
                    "docs/security-model.md",
                ]
            },
        },
    ]


def _exception_items() -> list[dict[str, Any]]:
    noise_enabled = _env_bool("NOISE_SUPPRESSION_ENABLED", True)

    return [
        {
            "id": "exception:safe-sudo-operational-commands",
            "name": "Safe sudo operational command suppression",
            "type": "NOISE_EXCEPTION",
            "source": "ai_soc",
            "scope": "global",
            "target": "sudo/systemctl operational commands",
            "status": "ACTIVE" if noise_enabled else "DISABLED",
            "managed": True,
            "requires_reload": True,
            "last_seen": None,
            "description": "Known-safe sudo command prefixes are treated as operational noise when policy conditions match.",
            "reason": "Prevents routine administrative checks from becoming incidents.",
            "metadata": {
                "source_file": "noise_suppression.py",
                "env": "NOISE_SUPPRESSION_SAFE_SUDO_COMMAND_PREFIXES",
            },
        },
        {
            "id": "exception:dns-query-no-incident",
            "name": "DNS query telemetry does not create incidents by itself",
            "type": "DNS_TELEMETRY_EXCEPTION",
            "source": "ai_soc",
            "scope": "global",
            "target": "Wazuh rule 100510 / dns_events",
            "status": "ACTIVE",
            "managed": True,
            "requires_reload": False,
            "last_seen": None,
            "description": "Normal DNS query telemetry is normalized for context and suppressed from standalone incident creation.",
            "reason": "DNS telemetry is contextual evidence, not direct causality.",
            "metadata": {
                "rule_id": "100510",
                "source_file": "noise_suppression.py",
            },
        },
    ]


def _service_control_items() -> list[dict[str, Any]]:
    return [
        {
            "id": "service:wazuh-manager",
            "name": "Wazuh manager",
            "type": "SERVICE_CONTROL",
            "source": "wazuh",
            "scope": "global",
            "target": "single-node-wazuh.manager-1",
            "status": "READ_ONLY",
            "managed": False,
            "requires_reload": True,
            "last_seen": None,
            "description": "Future controlled restart/reload target. Disabled in Step 10A.",
            "reason": "Service control actions are intentionally not enabled in the read-only foundation.",
            "metadata": {"action_enabled": False},
        },
        {
            "id": "service:suricata",
            "name": "Suricata sensor",
            "type": "SERVICE_CONTROL",
            "source": "suricata",
            "scope": "global",
            "target": "ai-soc-suricata",
            "status": "READ_ONLY",
            "managed": False,
            "requires_reload": True,
            "last_seen": None,
            "description": "Future controlled reload/restart target. Disabled in Step 10A.",
            "reason": "Service control actions are intentionally not enabled in the read-only foundation.",
            "metadata": {"action_enabled": False},
        },
        {
            "id": "service:ai-soc-worker",
            "name": "AI SOC worker",
            "type": "SERVICE_CONTROL",
            "source": "ai_soc",
            "scope": "global",
            "target": "ai-soc-worker",
            "status": "READ_ONLY",
            "managed": False,
            "requires_reload": True,
            "last_seen": None,
            "description": "Future controlled restart target. Disabled in Step 10A.",
            "reason": "Service control actions are intentionally not enabled in the read-only foundation.",
            "metadata": {"action_enabled": False},
        },
    ]


def _count_status(items: list[dict[str, Any]], status: str) -> int:
    return sum(1 for item in items if item.get("status") == status)


def get_detection_control_inventory() -> dict[str, Any]:
    wazuh_rules = _wazuh_rule_items()
    suricata_items = _suricata_items()

    rules = wazuh_rules + [
        item for item in suricata_items if item["type"] == "SURICATA_RULE_FILE"
    ]

    telemetry_sources = _telemetry_sources()
    policies = _policy_items()
    exceptions = _exception_items()
    service_controls = _service_control_items()

    inventory_items = rules + exceptions + telemetry_sources + policies + service_controls

    summary = {
        "total_items": len(inventory_items),
        "total_rules": len(rules),
        "active_rules": _count_status(rules, "ACTIVE"),
        "disabled_rules": _count_status(rules, "DISABLED"),
        "exceptions": len(exceptions),
        "telemetry_sources": len(telemetry_sources),
        "policies": len(policies),
        "service_controls": len(service_controls),
        "managed_items": sum(1 for item in inventory_items if item.get("managed")),
        "unmanaged_items": sum(1 for item in inventory_items if not item.get("managed")),
        "pending_review": _count_status(inventory_items, "PENDING_REVIEW"),
        "read_only": True,
        "generated_at": _utc_now(),
    }

    return {
        "summary": summary,
        "rules": rules,
        "exceptions": exceptions,
        "telemetry_sources": telemetry_sources,
        "policies": policies,
        "service_controls": service_controls,
    }
