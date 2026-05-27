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





def _syscheck_path(alert: dict) -> str:
    syscheck = alert.get("syscheck")

    if not isinstance(syscheck, dict):
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        syscheck = data.get("syscheck") if isinstance(data.get("syscheck"), dict) else {}

    return _string(syscheck.get("path"))


def _syscheck_mode(alert: dict) -> str:
    syscheck = alert.get("syscheck")

    if not isinstance(syscheck, dict):
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        syscheck = data.get("syscheck") if isinstance(data.get("syscheck"), dict) else {}

    return _lower(syscheck.get("mode"))


def _is_sensitive_integrity_path(path: str) -> bool:
    normalized = _lower(path)

    if not normalized:
        return True

    sensitive_exact = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/ssh",
        "/usr/sbin/sshd",
        "/usr/bin/systemctl",
    }

    if normalized in sensitive_exact:
        return True

    sensitive_prefixes = (
        "/etc/ssh/",
        "/etc/pam.d/",
        "/etc/sudoers.d/",
        "/etc/cron.",
        "/etc/cron/",
        "/var/spool/cron/",
        "/root/.ssh/",
        "/home/",
        "/etc/systemd/system/",
        "/lib/systemd/system/",
    )

    if any(normalized.startswith(prefix) for prefix in sensitive_prefixes):
        return True

    sensitive_fragments = (
        "authorized_keys",
        "id_rsa",
        "id_ed25519",
        "known_hosts",
    )

    return any(fragment in normalized for fragment in sensitive_fragments)


def _is_package_managed_runtime_path(path: str) -> bool:
    normalized = _lower(path)

    package_prefixes = (
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/usr/share/",
        "/lib/",
        "/lib64/",
        "/bin/",
        "/sbin/",
    )

    return any(normalized.startswith(prefix) for prefix in package_prefixes)


def _is_package_update_fim_context(alert: dict, rule_id: str, rule_description: str) -> bool:
    normalized_description = _lower(rule_description)

    if rule_id != "550":
        return False

    if "integrity checksum changed" not in normalized_description:
        return False

    if _syscheck_mode(alert) != "scheduled":
        return False

    path = _syscheck_path(alert)

    if not _is_package_managed_runtime_path(path):
        return False

    if _is_sensitive_integrity_path(path):
        return False

    return True

def _is_dns_telemetry_finding(rule_id: str, rule_description: str) -> bool:
    """Identify AI SOC DNS telemetry events.

    DNS telemetry is investigation context. Normal DNS queries must be normalized
    into dns_events but must not create SOC incidents by themselves.
    """

    normalized_rule_id = str(rule_id or "").strip()
    normalized_description = str(rule_description or "").lower().strip()

    if normalized_rule_id == "100510":
        return True

    if normalized_description.startswith("ai soc dns telemetry query:"):
        return True

    return False



def _is_windows_cis_benchmark_finding(rule_description: str) -> bool:
    """Identify Windows CIS benchmark compliance findings.

    CIS benchmark findings are endpoint compliance posture signals. They should
    remain available as raw/security telemetry, but they should not create one
    SOC incident per control finding by themselves.
    """

    normalized_description = _lower(rule_description)

    return (
        "cis microsoft windows" in normalized_description
        and "benchmark" in normalized_description
        and "ensure '" in normalized_description
    )

def _is_vulnerability_resolution_finding(rule_description: str) -> bool:
    """Identify Wazuh vulnerability lifecycle events for resolved CVEs.

    These events mean a previously detected vulnerable package was updated or
    the vulnerability feed changed. They are useful telemetry, but they should
    not create SOC incidents by themselves.
    """

    normalized_description = _lower(rule_description)

    if "cve-" not in normalized_description:
        return False

    if "was solved due to an update in the agent or feed" in normalized_description:
        return True

    return False

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

    if _is_package_update_fim_context(alert, rule_id, rule_description):
        syscheck_path = _syscheck_path(alert)
        base.update(
            {
                "should_suppress": True,
                "decision": "SUPPRESSED_NOISE",
                "policy_id": "package_update_file_integrity_context",
                "reasons": [
                    "Package-managed file integrity change suppressed from automatic incident creation.",
                    "The change was observed by scheduled FIM on a package-managed runtime path.",
                    "The path is not classified as security-sensitive by the AI SOC policy.",
                    "File integrity telemetry remains available as raw/security telemetry.",
                ],
                "category": "package_update_file_integrity_context",
                "syscheck_path": syscheck_path,
            }
        )
        return base

    if _is_dns_telemetry_finding(rule_id, rule_description):
        base.update(
            {
                "should_suppress": True,
                "decision": "SUPPRESSED_NOISE",
                "policy_id": "ai_soc_dns_telemetry_context",
                "reasons": [
                    "AI SOC DNS telemetry event suppressed from automatic incident creation.",
                    "DNS queries remain available as raw/security telemetry and normalized dns_events.",
                    "A normal DNS query does not represent a SOC incident unless another detection rule provides explicit malicious context.",
                ],
                "category": "dns_telemetry_context",
            }
        )
        return base

    if _is_windows_cis_benchmark_finding(rule_description):
        base.update(
            {
                "should_suppress": True,
                "decision": "SUPPRESSED_NOISE",
                "policy_id": "windows_cis_benchmark_compliance_context",
                "reasons": [
                    "Windows CIS benchmark compliance finding suppressed from automatic SOC incident creation.",
                    "The finding remains available as raw/security telemetry for endpoint hardening and compliance review.",
                    "Compliance posture checks should be handled through compliance reporting or aggregated hardening workflows, not one incident per benchmark control.",
                ],
                "category": "windows_compliance_posture_context",
            }
        )
        return base

    if _is_vulnerability_resolution_finding(rule_description):
        base.update(
            {
                "should_suppress": True,
                "decision": "SUPPRESSED_NOISE",
                "policy_id": "wazuh_vulnerability_resolution_context",
                "reasons": [
                    "Wazuh vulnerability resolution event suppressed from automatic incident creation.",
                    "The CVE was reported as solved due to a package update or vulnerability feed update.",
                    "Resolution lifecycle telemetry remains available as raw/security telemetry.",
                    "A resolved CVE notification does not represent an active SOC incident by itself.",
                ],
                "category": "vulnerability_resolution_context",
            }
        )
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
