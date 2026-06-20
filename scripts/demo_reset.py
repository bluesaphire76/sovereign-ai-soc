#!/usr/bin/env python3
"""Transactionally remove only records owned by the stable demo seed."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts import demo_seed


class UnsafeResetError(RuntimeError):
    """Raised when demo ownership or relationship safety cannot be proven."""


@dataclass
class ResetPlan:
    rows: dict[str, list[Any]] = field(default_factory=dict)
    safety_checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {name: len(rows) for name, rows in self.rows.items()}


DELETE_ORDER = (
    "case_ai_analyses",
    "case_actions",
    "case_audit",
    "case_links",
    "cases",
    "incident_notes",
    "incident_audit",
    "incidents",
)


def _query_all(db: Any, model: Any, *criteria: Any) -> list[Any]:
    query = db.query(model)
    if criteria:
        query = query.filter(*criteria)
    return list(query.all())


def _require_all_owned(
    rows: list[Any],
    owned_rows: list[Any],
    label: str,
) -> None:
    owned_ids = {id(row) for row in owned_rows}
    if any(id(row) not in owned_ids for row in rows):
        raise UnsafeResetError(
            f"Reset blocked: non-demo {label} is attached to demo-owned records."
        )


def collect_reset_plan(
    db: Any,
    models: Any,
    *,
    available_tables: set[str] | None = None,
) -> ResetPlan:
    tables = available_tables or set(models.Base.metadata.tables)
    incident_markers = [scenario.external_id for scenario in demo_seed.SCENARIOS]
    incidents = _query_all(
        db,
        models.Incident,
        models.Incident.wazuh_doc_id.in_(incident_markers),
    )
    if any(not demo_seed.is_owned_incident(row) for row in incidents):
        raise UnsafeResetError(
            "Reset blocked: a stable incident marker is owned by a non-demo record."
        )

    case = (
        db.query(models.IncidentCase)
        .filter(models.IncidentCase.group_key == demo_seed.CASE_GROUP_KEY)
        .first()
    )
    if case is not None and not demo_seed.is_owned_case(case):
        raise UnsafeResetError(
            "Reset blocked: the stable case marker is owned by a non-demo record."
        )

    incident_ids = {incident.id for incident in incidents}
    case_id = case.id if case is not None else None
    plan = ResetPlan(
        rows={name: [] for name in DELETE_ORDER},
        safety_checks=[
            (
                "Incident ownership requires exact "
                f"{demo_seed.DEMO_ACTOR}:incident:* markers and synthetic "
                "payload flags."
            ),
            (
                "Case ownership requires exact group key "
                f"{demo_seed.CASE_GROUP_KEY} and creator "
                f"{demo_seed.DEMO_ACTOR}."
            ),
            "All attached records must match exact seed-specific fields.",
            (
                "Raw events, security alerts, reports, remediation and "
                "non-demo records are never deletion targets."
            ),
        ],
    )
    plan.rows["incidents"] = incidents
    if case is not None:
        plan.rows["cases"] = [case]

    if not incident_ids and case_id is None:
        return plan

    if incident_ids:
        incident_audits = _query_all(
            db,
            models.IncidentAudit,
            models.IncidentAudit.incident_id.in_(incident_ids),
        )
        scenario_ids = {scenario.scenario_id for scenario in demo_seed.SCENARIOS}
        owned_audits = [
            row
            for row in incident_audits
            if row.created_by == demo_seed.DEMO_ACTOR
            and row.event_type == "DEMO_SEED_CREATED"
            and row.new_value in scenario_ids
            and row.comment == demo_seed.DECISION_BOUNDARY
        ]
        _require_all_owned(incident_audits, owned_audits, "incident audit")
        plan.rows["incident_audit"] = owned_audits

        incident_notes = _query_all(
            db,
            models.IncidentNote,
            models.IncidentNote.incident_id.in_(incident_ids),
        )
        owned_notes = [
            row
            for row in incident_notes
            if row.created_by == demo_seed.DEMO_ACTOR
            and str(row.note or "").startswith("[DEMO]")
            and "synthetic" in str(row.note or "").lower()
        ]
        _require_all_owned(incident_notes, owned_notes, "incident note")
        plan.rows["incident_notes"] = owned_notes

    link_criteria = []
    if incident_ids:
        link_criteria.append(models.CaseIncident.incident_id.in_(incident_ids))
    if case_id is not None:
        link_criteria.append(models.CaseIncident.case_id == case_id)
    links: list[Any] = []
    if link_criteria:
        from sqlalchemy import or_

        links = _query_all(db, models.CaseIncident, or_(*link_criteria))
    owned_links = [
        row
        for row in links
        if case_id is not None
        and row.case_id == case_id
        and row.incident_id in incident_ids
        and row.relationship_type == "SYNTHETIC_CORRELATED"
    ]
    _require_all_owned(links, owned_links, "case/incident link")
    plan.rows["case_links"] = owned_links

    if case_id is not None:
        case_audits = _query_all(
            db,
            models.CaseAudit,
            models.CaseAudit.case_id == case_id,
        )
        owned_case_audits = [
            row
            for row in case_audits
            if row.created_by == demo_seed.DEMO_ACTOR
            and row.event_type == "DEMO_SEED_CREATED"
            and row.new_value == demo_seed.CASE_GROUP_KEY
            and row.comment == demo_seed.DECISION_BOUNDARY
        ]
        _require_all_owned(case_audits, owned_case_audits, "case audit")
        plan.rows["case_audit"] = owned_case_audits

        actions = _query_all(
            db,
            models.CaseAction,
            models.CaseAction.case_id == case_id,
        )
        owned_actions = [
            row
            for row in actions
            if row.created_by == demo_seed.DEMO_ACTOR
            and row.title == "[DEMO] Review synthetic authentication evidence"
        ]
        _require_all_owned(actions, owned_actions, "case action")
        plan.rows["case_actions"] = owned_actions

        analyses = _query_all(
            db,
            models.CaseAIAnalysis,
            models.CaseAIAnalysis.case_id == case_id,
        )
        owned_analyses = [
            row
            for row in analyses
            if row.created_by == demo_seed.DEMO_ACTOR
            and row.model == "deterministic-demo-placeholder"
            and str(row.analysis or "").startswith("[DEMO]")
        ]
        _require_all_owned(analyses, owned_analyses, "case AI analysis")
        plan.rows["case_ai_analyses"] = owned_analyses

        for table_name, model in (
            ("case_closure_checklists", models.CaseClosureChecklist),
            ("case_ai_generation_jobs", models.CaseAiGenerationJob),
        ):
            if table_name in tables and _query_all(
                db,
                model,
                model.case_id == case_id,
            ):
                raise UnsafeResetError(
                    f"Reset blocked: {table_name} contains records not "
                    "created by the demo seed."
                )

    if "remediation_proposals" in tables:
        criteria = []
        if incident_ids:
            criteria.append(models.RemediationProposal.incident_id.in_(incident_ids))
        if case_id is not None:
            criteria.append(models.RemediationProposal.case_id == case_id)
        if criteria:
            from sqlalchemy import or_

            if _query_all(db, models.RemediationProposal, or_(*criteria)):
                raise UnsafeResetError(
                    "Reset blocked: a remediation proposal references "
                    "demo-owned records."
                )

    if incident_ids:
        blockers = (
            (
                "security alerts",
                models.SecurityAlert,
                models.SecurityAlert.incident_id.in_(incident_ids),
            ),
            (
                "event aggregates",
                models.EventAggregate,
                models.EventAggregate.last_incident_id.in_(incident_ids),
            ),
            (
                "investigation sessions",
                models.InvestigationSessionRecord,
                models.InvestigationSessionRecord.incident_id.in_(incident_ids),
            ),
            (
                "investigation similarity history",
                models.InvestigationSimilarityHistoryRecord,
                (
                    models.InvestigationSimilarityHistoryRecord.incident_id.in_(
                        incident_ids
                    )
                    | models.InvestigationSimilarityHistoryRecord
                    .related_incident_id.in_(incident_ids)
                ),
            ),
        )
        for label, model, criterion in blockers:
            if model.__tablename__ in tables and _query_all(db, model, criterion):
                raise UnsafeResetError(
                    f"Reset blocked: {label} references demo-owned incidents."
                )

    return plan


def apply_reset(db: Any, plan: ResetPlan) -> dict[str, int]:
    deleted_counts: dict[str, int] = {}
    for name in DELETE_ORDER:
        rows = plan.rows.get(name, [])
        for row in rows:
            db.delete(row)
        deleted_counts[name] = len(rows)
    db.flush()
    return deleted_counts


def _report(
    *,
    dry_run: bool,
    result: str,
    exit_code: int,
    planned: dict[str, int] | None = None,
    deleted: dict[str, int] | None = None,
    safety_checks: list[str] | None = None,
    warnings: list[str] | None = None,
    final_status: dict[str, Any] | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "result": result,
        "exit_code": exit_code,
        "dry_run": dry_run,
        "applied": not dry_run and result == "DEMO_RESET_APPLIED",
        "marker": demo_seed.DEMO_ACTOR,
        "planned_deletions": planned or {name: 0 for name in DELETE_ORDER},
        "deleted_counts": deleted or {name: 0 for name in DELETE_ORDER},
        "safety_checks": safety_checks or [],
        "warnings": warnings or [],
        "final_status": final_status or {},
    }
    if message:
        report["message"] = message
    return report


def database_operation(mode: str) -> tuple[dict[str, Any], int]:
    dry_run = mode != "apply"
    try:
        engine, session_factory, dependencies = demo_seed.load_database()
        inspect_function, models = dependencies
        demo_seed.validate_schema(engine, inspect_function)
        available_tables = set(inspect_function(engine).get_table_names())
        db = session_factory()
    except Exception as exc:
        report = _report(
            dry_run=dry_run,
            result="DEMO_RESET_NOT_READY",
            exit_code=1,
            message=(
                "Application database cannot be inspected safely: "
                f"{exc.__class__.__name__}"
            ),
        )
        return report, 1

    try:
        plan = collect_reset_plan(
            db,
            models,
            available_tables=available_tables,
        )
        if dry_run:
            report = _report(
                dry_run=True,
                result="DEMO_RESET_DRY_RUN_READY",
                exit_code=0,
                planned=plan.counts,
                safety_checks=plan.safety_checks,
                warnings=plan.warnings,
            )
            return report, 0

        deleted = apply_reset(db, plan)
        final_status = demo_seed.seed_status(db, models)
        if final_status.get("unsafe_collisions"):
            raise UnsafeResetError(
                "Unexpected stable marker collision after reset."
            )
        if final_status.get("complete"):
            raise UnsafeResetError(
                "Post-reset verification still reports a complete demo dataset."
            )
        db.commit()
        report = _report(
            dry_run=False,
            result="DEMO_RESET_APPLIED",
            exit_code=0,
            planned=plan.counts,
            deleted=deleted,
            safety_checks=plan.safety_checks
            + [
                (
                    "Transaction committed only after all ownership and "
                    "relationship checks passed."
                ),
                (
                    "Post-reset demo status confirms no complete seeded "
                    "dataset remains."
                ),
            ],
            warnings=plan.warnings,
            final_status=demo_seed.status_metadata(final_status),
        )
        return report, 0
    except UnsafeResetError as exc:
        db.rollback()
        report = _report(
            dry_run=dry_run,
            result="DEMO_RESET_NOT_READY",
            exit_code=1,
            message=str(exc),
        )
        return report, 1
    except Exception as exc:
        db.rollback()
        report = _report(
            dry_run=dry_run,
            result="DEMO_RESET_NOT_READY",
            exit_code=1,
            message=f"Demo reset failed safely: {exc.__class__.__name__}",
        )
        return report, 1
    finally:
        db.close()


def print_human(report: dict[str, Any]) -> None:
    print("Sovereign AI SOC Demo Reset")
    print(f"[INFO] Stable marker: {report['marker']}")
    print(f"[INFO] Mode: {'dry-run' if report['dry_run'] else 'apply'}")
    if report.get("message"):
        print(f"[FAIL] {report['message']}")
        if report["dry_run"]:
            print("[DRY-RUN] No database changes were made")
        else:
            print("[OK] Transaction rolled back; no changes were committed")
    else:
        label = "Would remove" if report["dry_run"] else "Removed"
        counts = (
            report["planned_deletions"]
            if report["dry_run"]
            else report["deleted_counts"]
        )
        for name, count in counts.items():
            print(f"[INFO] {label} {count} {name.replace('_', ' ')}")
        for check in report["safety_checks"]:
            print(f"[OK] {check}")
        if report["dry_run"]:
            print("[DRY-RUN] No database changes were made")
        else:
            print("[OK] No non-demo records were touched")
            seed_result = report["final_status"].get("seed_result", "UNKNOWN")
            print(f"[OK] Final demo seed status: {seed_result}")
    print()
    print(f"Result: {report['result']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove only stable-marker-owned synthetic demo records.",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if not args.apply:
        args.dry_run = True
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report, exit_code = database_operation("apply" if args.apply else "dry-run")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
