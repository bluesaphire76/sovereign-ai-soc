from __future__ import annotations


def padded_id(value: int) -> str:
    return f"{value:06d}"


def incident_enterprise_report_filename(incident_id: int, extension: str = "md") -> str:
    return f"incident-{padded_id(incident_id)}-enterprise-report.{extension}"


def incident_evidence_pack_filename(incident_id: int, extension: str = "md") -> str:
    return f"incident-{padded_id(incident_id)}-evidence-pack.{extension}"


def case_enterprise_report_filename(case_id: int, extension: str = "md") -> str:
    return f"case-{padded_id(case_id)}-enterprise-report.{extension}"


def case_evidence_pack_filename(case_id: int, extension: str = "md") -> str:
    return f"case-{padded_id(case_id)}-evidence-pack.{extension}"


def case_executive_pdf_filename(case_id: int) -> str:
    return f"case-{padded_id(case_id)}-executive-ai-soc-report.pdf"
