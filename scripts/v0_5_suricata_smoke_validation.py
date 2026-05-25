from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from database import engine


REPORT_DIR = Path("reports/validation")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def run_command(command: list[str], timeout: int = 10) -> dict:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return {
            "command": " ".join(command),
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "ok": result.returncode == 0,
        }

    except Exception as exc:
        return {
            "command": " ".join(command),
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "ok": False,
            "error_type": type(exc).__name__,
        }


def check_database() -> dict:
    checks: dict = {}

    with engine.begin() as conn:
        checks["network_events_total"] = conn.execute(
            text("select count(*) from network_events")
        ).scalar()

        checks["network_events_by_type"] = [
            {"event_type": row[0], "count": row[1]}
            for row in conn.execute(
                text("""
                    select event_type, count(*)
                    from network_events
                    group by event_type
                    order by count(*) desc
                """)
            ).fetchall()
        ]

        checks["latest_network_event"] = dict(
            conn.execute(
                text("""
                    select id, event_type, event_timestamp, created_at, src_ip, dest_ip, hostname, app_proto, alert_signature
                    from network_events
                    order by event_timestamp desc nulls last, created_at desc nulls last, id desc
                    limit 1
                """)
            ).mappings().fetchone()
            or {}
        )

        checks["suricata_ingest_state"] = dict(
            conn.execute(
                text("""
                    select source, file_path, byte_offset, updated_at, details
                    from suricata_ingest_state
                    where source = 'suricata'
                """)
            ).mappings().fetchone()
            or {}
        )

        checks["incident_with_network_evidence_candidate"] = dict(
            conn.execute(
                text("""
                    select id, timestamp, agent, rule, status, risk_score
                    from incidents
                    order by id desc
                    limit 1
                """)
            ).mappings().fetchone()
            or {}
        )

        checks["latest_case"] = dict(
            conn.execute(
                text("""
                    select id, title, status
                    from incident_cases
                    order by id desc
                    limit 1
                """)
            ).mappings().fetchone()
            or {}
        )

    return checks


def check_imports() -> dict:
    modules = [
        "routers.network_events",
        "routers.incident_network_evidence",
        "report_network_evidence",
        "incident_ai_brief",
        "report_builder",
        "evidence_pack_builder",
        "platform_health",
    ]

    results = {}

    for module in modules:
        try:
            __import__(module)
            results[module] = {"ok": True}
        except Exception as exc:
            results[module] = {
                "ok": False,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    return results


def check_builders(db_checks: dict) -> dict:
    results = {}

    incident = db_checks.get("incident_with_network_evidence_candidate") or {}
    case = db_checks.get("latest_case") or {}

    incident_id = incident.get("id")
    case_id = case.get("id")

    if incident_id:
        try:
            from report_builder import build_incident_report

            report = build_incident_report(int(incident_id))
            markdown = report.get("markdown", "")

            results["incident_report"] = {
                "ok": True,
                "incident_id": incident_id,
                "has_network_evidence": "Network Evidence" in markdown,
                "has_suricata": "Suricata" in markdown,
                "payload_has_network_evidence": "network_evidence" in json.dumps(report.get("payload", {}), default=str),
                "filename": report.get("filename"),
            }

        except Exception as exc:
            results["incident_report"] = {
                "ok": False,
                "incident_id": incident_id,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

        try:
            from incident_ai_brief import build_ai_brief_preview

            preview = build_ai_brief_preview(int(incident_id))
            evidence_used = preview.get("brief", {}).get("evidence_used", [])
            serialized = json.dumps(preview, ensure_ascii=False, default=str)

            results["ai_brief_preview"] = {
                "ok": True,
                "incident_id": incident_id,
                "source": preview.get("source"),
                "has_suricata_or_network": "suricata" in serialized.lower() or "network" in serialized.lower(),
                "evidence_used_count": len(evidence_used) if isinstance(evidence_used, list) else 0,
            }

        except Exception as exc:
            results["ai_brief_preview"] = {
                "ok": False,
                "incident_id": incident_id,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    else:
        results["incident_report"] = {"ok": False, "reason": "no_incident_available"}
        results["ai_brief_preview"] = {"ok": False, "reason": "no_incident_available"}

    if case_id:
        try:
            from report_builder import build_case_report
            from evidence_pack_builder import build_case_evidence_pack

            case_report = build_case_report(int(case_id))
            evidence_pack = build_case_evidence_pack(int(case_id))

            results["case_report"] = {
                "ok": True,
                "case_id": case_id,
                "has_network_evidence": "Network Evidence" in case_report.get("markdown", ""),
                "has_suricata": "Suricata" in case_report.get("markdown", ""),
                "payload_has_network_summary": "network_evidence_summary" in json.dumps(case_report.get("payload", {}), default=str),
                "filename": case_report.get("filename"),
            }

            results["case_evidence_pack"] = {
                "ok": True,
                "case_id": case_id,
                "has_network_evidence": "Network Evidence" in evidence_pack.get("markdown", ""),
                "has_suricata": "Suricata" in evidence_pack.get("markdown", ""),
                "payload_has_network_summary": "network_evidence_summary" in json.dumps(evidence_pack.get("payload", {}), default=str),
                "filename": evidence_pack.get("filename"),
            }

        except Exception as exc:
            results["case_report_or_evidence_pack"] = {
                "ok": False,
                "case_id": case_id,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    else:
        results["case_report"] = {"ok": False, "reason": "no_case_available"}
        results["case_evidence_pack"] = {"ok": False, "reason": "no_case_available"}

    return results


def main() -> None:
    generated_at = datetime.now(timezone.utc).isoformat()

    docker_check = run_command(
        ["docker", "inspect", "-f", "{{.State.Running}}", "ai-soc-suricata"]
    )

    systemd_check = run_command(
        ["systemctl", "is-active", "ai-soc-suricata-ingest"]
    )

    db_checks = check_database()
    import_checks = check_imports()
    builder_checks = check_builders(db_checks)

    result = {
        "generated_at": generated_at,
        "validation": "v0.5_suricata_network_telemetry",
        "docker_suricata": docker_check,
        "systemd_suricata_ingest": systemd_check,
        "database": db_checks,
        "imports": import_checks,
        "builders": builder_checks,
    }

    output_file = REPORT_DIR / f"v0.5-suricata-smoke-validation-{generated_at.replace(':', '').replace('+00:00', 'Z')}.json"
    latest_file = REPORT_DIR / "v0.5-suricata-smoke-validation-latest.json"

    output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    latest_file.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str))

    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
