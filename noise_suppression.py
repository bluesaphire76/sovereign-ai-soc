import os
import re

from dotenv import load_dotenv

load_dotenv()

NOISE_SUPPRESSION_ENABLED = (
    os.getenv("NOISE_SUPPRESSION_ENABLED", "true").strip().lower()
    in {"1", "true", "yes", "on"}
)
NOISE_SUPPRESSION_MAX_LEVEL = int(os.getenv("NOISE_SUPPRESSION_MAX_LEVEL", "3"))

DEFAULT_SAFE_SUDO_COMMAND_PREFIXES = [
    "/usr/bin/systemctl status",
    "/usr/bin/journalctl",
    "/usr/bin/systemctl restart ai-soc-api",
    "/usr/bin/systemctl restart ai-soc-frontend",
    "/usr/bin/systemctl restart ai-soc-worker",
]


def _csv_env(name: str, default_values: list[str]) -> list[str]:
    raw = os.getenv(name)

    if not raw:
        return default_values

    return [item.strip() for item in raw.split(",") if item.strip()]


SAFE_SUDO_COMMAND_PREFIXES = _csv_env(
    "NOISE_SUPPRESSION_SAFE_SUDO_COMMAND_PREFIXES",
    DEFAULT_SAFE_SUDO_COMMAND_PREFIXES,
)


def _get(data: dict, *path):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

        if current is None:
            return None

    return current


def _int_value(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _string(value) -> str:
    return str(value or "").strip()


def _lower(value) -> str:
    return _string(value).lower()


def _groups(alert: dict) -> set[str]:
    groups = _get(alert, "rule", "groups") or []

    if isinstance(groups, list):
        return {_lower(item) for item in groups}

    return {_lower(groups)} if groups else set()


def _has_mitre_mapping(alert: dict) -> bool:
    mitre = _get(alert, "rule", "mitre")

    if not mitre:
        return False

    if isinstance(mitre, dict):
        return any(bool(value) for value in mitre.values())

    if isinstance(mitre, (list, tuple, set)):
        return bool(mitre)

    text = _string(mitre)

    return text not in {"", "{}", "[]", "None", "null"}


def _full_log(alert: dict) -> str:
    return _string(alert.get("full_log"))


def _extract_sudo_command(full_log: str) -> str | None:
    match = re.search(r"\bCOMMAND=(?P<command>.+)$", full_log)

    if not match:
        return None

    return match.group("command").strip()


def _safe_sudo_command(command: str | None) -> bool:
    if not command:
        return False

    normalized = command.strip()

    return any(
        normalized == prefix or normalized.startswith(f"{prefix} ")
        for prefix in SAFE_SUDO_COMMAND_PREFIXES
    )



def _is_vulnerability_package_finding(rule_id: str, rule_description: str) -> bool:
    """Identify Wazuh package vulnerability findings.

    These are useful vulnerability-management telemetry, but they should not
    create one SOC incident per CVE/package finding.
    """

    normalized_description = rule_description.lower().strip()

    if rule_id in {"23504", "23505", "23506"}:
        return "cve-" in normalized_description and " affects " in normalized_description

    return False

def evaluate_noise_suppression(
    alert: dict,
    aggregation_result: dict | None = None,
) -> dict:
    aggregation_result = aggregation_result or {}

    rule_id = _string(_get(alert, "rule", "id"))
    rule_description = _string(_get(alert, "rule", "description"))
    level = _int_value(_get(alert, "rule", "level"))
    groups = _groups(alert)
    decoder = _lower(_get(alert, "decoder", "name"))
    location = _lower(alert.get("location"))
    full_log = _full_log(alert)
    full_log_lower = full_log.lower()
    aggregate_count = _int_value(aggregation_result.get("count"))

    base = {
        "should_suppress": False,
        "decision": "NOT_NOISE",
        "policy_id": None,
        "reasons": [],
        "rule_id": rule_id,
        "rule_description": rule_description,
        "level": level,
        "groups": sorted(groups),
        "decoder": decoder,
        "location": location,
        "aggregate_count": aggregate_count,
    }

    if not NOISE_SUPPRESSION_ENABLED:
        base["reasons"].append("noise suppression disabled")
        return base

    if _is_vulnerability_package_finding(rule_id, rule_description):
        base.update(
            {
                "should_suppress": True,
                "decision": "SUPPRESSED_NOISE",
                "policy_id": "wazuh_vulnerability_package_finding",
                "reasons": [
                    "Wazuh package vulnerability finding suppressed from incident creation.",
                    "Vulnerability/package findings remain available as raw/security telemetry.",
                    "These findings should be handled through vulnerability management or aggregated reporting, not one SOC incident per CVE.",
                ],
                "category": "vulnerability_management_context",
            }
        )
        return base

    if level > NOISE_SUPPRESSION_MAX_LEVEL:
        base["reasons"].append(
            f"level {level} above noise max level {NOISE_SUPPRESSION_MAX_LEVEL}"
        )
        return base

    if _has_mitre_mapping(alert):
        base["reasons"].append("MITRE mapping present")
        return base

    if rule_id in {"5501", "5502"}:
        is_pam_sudo_session = (
            decoder == "pam"
            and "pam" in groups
            and "syslog" in groups
            and "pam_unix(sudo:session)" in full_log_lower
        )

        if is_pam_sudo_session:
            session_action = (
                "opened" if "session opened" in full_log_lower else
                "closed" if "session closed" in full_log_lower else
                None
            )

            if session_action:
                return {
                    **base,
                    "should_suppress": True,
                    "decision": "SUPPRESS",
                    "policy_id": "LOW_LEVEL_PAM_SUDO_SESSION_NOISE",
                    "reasons": [
                        f"low-level PAM sudo session {session_action}",
                        f"aggregate_count={aggregate_count}",
                    ],
                }

    if rule_id == "5402":
        command = _extract_sudo_command(full_log)

        is_sudo_event = (
            decoder == "sudo"
            and "sudo" in groups
            and "syslog" in groups
            and "successful sudo to root" in rule_description.lower()
        )

        if is_sudo_event and _safe_sudo_command(command):
            return {
                **base,
                "should_suppress": True,
                "decision": "SUPPRESS",
                "policy_id": "LOW_LEVEL_SAFE_SUDO_OPERATIONAL_NOISE",
                "reasons": [
                    "low-level safe operational sudo command",
                    f"command={command}",
                    f"aggregate_count={aggregate_count}",
                ],
                "sudo_command": command,
            }

        if is_sudo_event:
            base["reasons"].append(
                f"sudo command not in safe operational allowlist: {command}"
            )
            base["sudo_command"] = command
            return base

    base["reasons"].append("no noise suppression policy matched")
    return base
