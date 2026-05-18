from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from evidence_pack_builder import build_case_evidence_pack
from executive_pdf_builder import build_case_executive_pdf
from report_builder import build_case_report, build_incident_report

router = APIRouter()


@router.get("/reports/incidents/{incident_id}")
def export_incident_report(
    incident_id: int,
    format: str = Query("markdown"),
):
    if format not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="format must be markdown or json")

    try:
        report = build_incident_report(incident_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if format == "json":
        filename = report["filename"].replace(".md", ".json")

        return JSONResponse(
            content=report["payload"],
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    return Response(
        content=report["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report['filename']}"',
        },
    )


@router.get("/reports/cases/{case_id}")
def export_case_report(
    case_id: int,
    format: str = Query("markdown"),
):
    if format not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="format must be markdown or json")

    try:
        report = build_case_report(case_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if format == "json":
        filename = report["filename"].replace(".md", ".json")

        return JSONResponse(
            content=report["payload"],
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    return Response(
        content=report["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report['filename']}"',
        },
    )


@router.get("/reports/cases/{case_id}/executive-pdf")
def export_case_executive_pdf(case_id: int):
    try:
        report = build_case_executive_pdf(case_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Resource not found.")

    return Response(
        content=report["pdf"],
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{report['filename']}"',
        },
    )


@router.get("/reports/cases/{case_id}/evidence-pack")
def export_case_evidence_pack(
    case_id: int,
    format: str = Query("markdown"),
):
    if format not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="format must be markdown or json")

    try:
        report = build_case_evidence_pack(case_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if format == "json":
        filename = report["filename"].replace(".md", ".json")

        return JSONResponse(
            content=report["payload"],
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    return Response(
        content=report["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report['filename']}"',
        },
    )
