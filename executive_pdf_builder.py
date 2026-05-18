from __future__ import annotations

from io import BytesIO
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from database import SessionLocal
from report_builder import build_case_payload, format_value


BRAND_DARK = colors.HexColor("#0f172a")
BRAND_BLUE = colors.HexColor("#0891b2")
BRAND_GREEN = colors.HexColor("#059669")
BRAND_ORANGE = colors.HexColor("#ea580c")
BRAND_RED = colors.HexColor("#dc2626")
LIGHT_BG = colors.HexColor("#f8fafc")
BORDER = colors.HexColor("#cbd5e1")


def p(value) -> str:
    if value is None:
        return "-"

    return escape(str(value))


def bool_label(value) -> str:
    return "READY" if value else "BLOCKED"


def severity_color(value: str | None):
    severity = (value or "LOW").upper()

    if severity == "CRITICAL":
        return BRAND_RED
    if severity == "HIGH":
        return BRAND_ORANGE
    if severity == "MEDIUM":
        return colors.HexColor("#ca8a04")

    return BRAND_GREEN


def status_color(value: str | None):
    status = (value or "OPEN").upper()

    if status in {"CLOSED", "FALSE_POSITIVE"}:
        return BRAND_GREEN
    if status in {"ESCALATED"}:
        return BRAND_RED
    if status in {"INVESTIGATING", "TRIAGED"}:
        return BRAND_BLUE

    return BRAND_ORANGE


def make_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "ExecutiveTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=BRAND_DARK,
            alignment=TA_LEFT,
            spaceAfter=14,
        ),
        "subtitle": ParagraphStyle(
            "ExecutiveSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=18,
        ),
        "section": ParagraphStyle(
            "SectionHeading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=BRAND_DARK,
            spaceBefore=16,
            spaceAfter=8,
        ),
        "normal": ParagraphStyle(
            "NormalExecutive",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b"),
        ),
        "small": ParagraphStyle(
            "SmallExecutive",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#475569"),
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#475569"),
        ),
        "value": ParagraphStyle(
            "Value",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=BRAND_DARK,
        ),
        "center": ParagraphStyle(
            "Center",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            alignment=TA_CENTER,
            textColor=colors.white,
        ),
        "ai_heading": ParagraphStyle(
            "AIHeading",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=BRAND_DARK,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "bullet": ParagraphStyle(
            "Bullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            leftIndent=12,
            firstLineIndent=-8,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=3,
        ),
        "ai_note": ParagraphStyle(
            "AINote",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748b"),
            spaceBefore=6,
        ),
    }

    return styles


def paragraph(text, style):
    return Paragraph(p(text), style)


def split_long_text(value: str, max_len: int = 650) -> list[str]:
    text = value.strip()

    if len(text) <= max_len:
        return [text]

    chunks = []
    current = ""

    for sentence in text.replace("\n", " ").split(". "):
        candidate = f"{current}. {sentence}" if current else sentence

        if len(candidate) <= max_len:
            current = candidate
        else:
            if current:
                chunks.append(current.strip())
            current = sentence

    if current:
        chunks.append(current.strip())

    return chunks


def normalize_ai_line(line: str) -> str:
    cleaned = line.strip()

    while cleaned.startswith("#"):
        cleaned = cleaned[1:].strip()

    cleaned = cleaned.replace("**", "")
    cleaned = cleaned.replace("__", "")

    return cleaned.strip()


def add_structured_ai_text(
    story: list,
    ai_text: str,
    styles: dict,
    max_chars: int = 3200,
):
    text = (ai_text or "").strip()

    if not text:
        story.append(Paragraph("No AI analysis text available.", styles["normal"]))
        return

    truncated = len(text) > max_chars
    text = text[:max_chars]

    lines = text.splitlines()
    paragraph_buffer = []

    def flush_paragraph_buffer():
        if not paragraph_buffer:
            return

        paragraph = " ".join(item.strip() for item in paragraph_buffer if item.strip())
        paragraph_buffer.clear()

        for chunk in split_long_text(paragraph):
            story.append(Paragraph(p(chunk), styles["normal"]))
            story.append(Spacer(1, 0.10 * cm))

    for raw_line in lines:
        line = raw_line.strip()

        if not line:
            flush_paragraph_buffer()
            story.append(Spacer(1, 0.08 * cm))
            continue

        normalized = normalize_ai_line(line)

        if not normalized:
            continue

        is_heading = (
            raw_line.lstrip().startswith("#")
            or normalized.endswith(":")
            or normalized.lower() in {
                "summary",
                "executive summary",
                "assessment",
                "risk assessment",
                "recommended actions",
                "recommendation",
                "recommendations",
                "next steps",
                "conclusion",
                "impact",
                "evidence",
            }
        )

        is_bullet = (
            normalized.startswith("- ")
            or normalized.startswith("* ")
            or normalized.startswith("• ")
        )

        if is_heading and len(normalized) <= 80:
            flush_paragraph_buffer()
            story.append(Paragraph(p(normalized.rstrip(":")), styles["ai_heading"]))
            continue

        if is_bullet:
            flush_paragraph_buffer()
            bullet_text = normalized[2:].strip()
            story.append(Paragraph(f"• {p(bullet_text)}", styles["bullet"]))
            continue

        paragraph_buffer.append(normalized)

    flush_paragraph_buffer()

    if truncated:
        story.append(
            Paragraph(
                "AI analysis was shortened for the executive PDF. See the Markdown report or Analyst Evidence Pack for the full analysis.",
                styles["ai_note"],
            )
        )



def workflow_decision_note(status: str | None) -> str:
    normalized = (status or "").upper()

    if normalized in {"CLOSED", "FALSE_POSITIVE"}:
        return "The case has reached a terminal workflow state. Retain the report as evidence of review and decision."

    if normalized in {"ESCALATED", "INVESTIGATING"}:
        return "The case requires active investigation or management attention until ownership, evidence and remediation are confirmed."

    if normalized in {"OPEN", "NEW", "TRIAGED"}:
        return "The case remains open for human review. Evidence, ownership, residual risk and closure decision should be documented before closure."

    return "The workflow status should be reviewed by an analyst before external distribution."


def severity_governance_note(severity: str | None, severity_review: str | None) -> str:
    current = (severity or "").upper()
    reviewed = (severity_review or "").upper()

    if current and reviewed and current != reviewed:
        return (
            "The reviewed severity differs from the current case severity. "
            "A human validation step is required before using this report for executive or audit purposes."
        )

    return "No severity review discrepancy is currently visible in the case metadata."


def closure_readiness_note(readiness: dict | None) -> str:
    readiness = readiness or {}

    if readiness.get("ready_to_close"):
        return "The case appears ready for closure review based on the configured closure checklist."

    blockers = readiness.get("blocking_items") or []
    if blockers:
        return (
            "Closure is blocked because mandatory closure fields or decisions are still missing: "
            + ", ".join(str(item) for item in blockers[:6])
            + ("." if len(blockers) <= 6 else ", ...")
        )

    return "Closure is not yet confirmed. Review the checklist and open actions before changing workflow status."


def build_decision_brief(case, readiness, styles):
    rows = [
        ("Workflow decision", workflow_decision_note(case.get("status"))),
        (
            "Severity governance",
            severity_governance_note(
                case.get("severity"),
                case.get("severity_review"),
            ),
        ),
        ("Closure readiness", closure_readiness_note(readiness)),
        ("SLA posture", case.get("sla_status")),
    ]

    return build_key_value_table(rows, styles)

def build_key_value_table(rows: list[tuple[str, object]], styles):
    data = [
        [
            Paragraph(p(label), styles["label"]),
            Paragraph(p(value), styles["normal"]),
        ]
        for label, value in rows
    ]

    table = Table(data, colWidths=[4.2 * cm, 11.6 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    return table


def build_metric_cards(case, readiness, actions, incidents, styles):
    status = case.get("status")
    severity = case.get("severity")
    ready = readiness.get("ready_to_close")

    open_actions = [
        action
        for action in actions
        if action.get("status") in {"OPEN", "IN_PROGRESS"}
    ]

    data = [
        [
            Paragraph("Status", styles["label"]),
            Paragraph("Severity", styles["label"]),
            Paragraph("Closure", styles["label"]),
            Paragraph("Open Actions", styles["label"]),
        ],
        [
            Paragraph(p(status), styles["value"]),
            Paragraph(p(severity), styles["value"]),
            Paragraph(bool_label(ready), styles["value"]),
            Paragraph(str(len(open_actions)), styles["value"]),
        ],
        [
            Paragraph("Risk Score", styles["label"]),
            Paragraph("Linked Incidents", styles["label"]),
            Paragraph("SLA Status", styles["label"]),
            Paragraph("Owner", styles["label"]),
        ],
        [
            Paragraph(p(case.get("risk_score")), styles["value"]),
            Paragraph(str(len(incidents)), styles["value"]),
            Paragraph(p(case.get("sla_status")), styles["value"]),
            Paragraph(p(case.get("owner")), styles["value"]),
        ],
    ]

    table = Table(
        data,
        colWidths=[4.0 * cm, 4.0 * cm, 4.0 * cm, 4.0 * cm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
                ("BACKGROUND", (0, 2), (-1, 2), LIGHT_BG),
                ("TEXTCOLOR", (0, 1), (0, 1), status_color(status)),
                ("TEXTCOLOR", (1, 1), (1, 1), severity_color(severity)),
                ("TEXTCOLOR", (2, 1), (2, 1), BRAND_GREEN if ready else BRAND_ORANGE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    return table


def build_actions_table(actions, styles):
    if not actions:
        return paragraph("No actions available.", styles["normal"])

    data = [
        [
            Paragraph("ID", styles["label"]),
            Paragraph("Title", styles["label"]),
            Paragraph("Priority", styles["label"]),
            Paragraph("Status", styles["label"]),
        ]
    ]

    for action in actions:
        data.append(
            [
                Paragraph(str(action.get("id")), styles["small"]),
                Paragraph(p(action.get("title")), styles["small"]),
                Paragraph(p(action.get("priority")), styles["small"]),
                Paragraph(p(action.get("status")), styles["small"]),
            ]
        )

    table = Table(data, colWidths=[1.3 * cm, 9.0 * cm, 2.7 * cm, 3.0 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return table


def build_incidents_table(incidents, styles):
    if not incidents:
        return paragraph("No linked incidents available.", styles["normal"])

    data = [
        [
            Paragraph("ID", styles["label"]),
            Paragraph("Rule", styles["label"]),
            Paragraph("Level", styles["label"]),
            Paragraph("Risk", styles["label"]),
            Paragraph("Priority", styles["label"]),
        ]
    ]

    for incident in incidents[:12]:
        data.append(
            [
                Paragraph(str(incident.get("id")), styles["small"]),
                Paragraph(p(incident.get("rule")), styles["small"]),
                Paragraph(p(incident.get("level")), styles["small"]),
                Paragraph(p(incident.get("risk_score")), styles["small"]),
                Paragraph(p(incident.get("recommended_priority")), styles["small"]),
            ]
        )

    table = Table(
        data,
        colWidths=[1.2 * cm, 8.4 * cm, 1.8 * cm, 2.0 * cm, 2.6 * cm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return table


def add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(2 * cm, 1.2 * cm, "Sovereign AI SOC - Executive Case Report")
    canvas.drawRightString(19 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def build_executive_pdf_bytes(payload: dict) -> bytes:
    styles = make_styles()

    case = payload["case"]
    analysis = payload.get("case_ai_analysis")
    actions = payload.get("case_actions", [])
    incidents = payload.get("incidents", [])
    readiness = payload.get("case_closure_readiness", {})
    checklist = payload.get("case_closure_checklist")

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title=f"Executive Case Report #{case['id']}",
        author="Sovereign AI SOC",
    )

    story = []

    story.append(Paragraph(f"Executive Case Report #{case['id']}", styles["title"]))
    story.append(
        Paragraph(
            f"{p(case.get('title'))}<br/>Generated at: {p(payload.get('generated_at'))}",
            styles["subtitle"],
        )
    )

    story.append(build_metric_cards(case, readiness, actions, incidents, styles))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("Executive Decision Brief", styles["section"]))
    story.append(build_decision_brief(case, readiness, styles))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("Executive Summary", styles["section"]))
    story.append(
        build_key_value_table(
            [
                ("Case Status", case.get("status")),
                ("Severity", case.get("severity")),
                ("Risk Score", case.get("risk_score")),
                ("Host", case.get("agent")),
                ("Correlation Type", case.get("correlation_type")),
                ("Owner", case.get("owner")),
                ("SLA Status", case.get("sla_status")),
                ("Closure Readiness", bool_label(readiness.get("ready_to_close"))),
            ],
            styles,
        )
    )

    missing_items = readiness.get("missing_items", [])

    story.append(Paragraph("Closure Decision", styles["section"]))

    if checklist:
        story.append(
            build_key_value_table(
                [
                    ("Closure Decision", checklist.get("closure_decision")),
                    ("Final Severity", checklist.get("final_severity")),
                    ("Reviewed By", checklist.get("reviewed_by")),
                    ("Reviewed At", checklist.get("reviewed_at")),
                    ("Closure Reason", checklist.get("closure_reason")),
                    ("Residual Risk", checklist.get("residual_risk")),
                ],
                styles,
            )
        )
    else:
        story.append(Paragraph("No closure checklist available.", styles["normal"]))

    if missing_items:
        story.append(Paragraph("Blocking Items", styles["section"]))
        for item in missing_items:
            story.append(Paragraph(f"- {p(item)}", styles["normal"]))

    story.append(Paragraph("AI Case Analysis", styles["section"]))

    if analysis:
        story.append(
            build_key_value_table(
                [
                    ("Model", analysis.get("model")),
                    ("Recommended Status", analysis.get("recommended_status")),
                    ("Recommended Severity", analysis.get("recommended_severity")),
                    ("Generated At", analysis.get("created_at")),
                ],
                styles,
            )
        )
        story.append(Spacer(1, 0.3 * cm))

        ai_text = analysis.get("analysis") or "No AI analysis text available."
        add_structured_ai_text(story, ai_text, styles)
    else:
        story.append(Paragraph("No AI case analysis available.", styles["normal"]))

    story.append(PageBreak())

    story.append(Paragraph("Action Plan Overview", styles["section"]))
    story.append(build_actions_table(actions, styles))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("Linked Incident Overview", styles["section"]))
    story.append(build_incidents_table(incidents, styles))

    if len(incidents) > 12:
        story.append(
            Paragraph(
                f"Only the first 12 linked incidents are shown. Full evidence is available in the Analyst Evidence Pack. Total incidents: {len(incidents)}.",
                styles["small"],
            )
        )

    story.append(Paragraph("Case Metadata", styles["section"]))
    story.append(
        build_key_value_table(
            [
                ("Group Key", case.get("group_key")),
                ("Created By", case.get("created_by")),
                ("Created At", case.get("created_at")),
                ("Updated At", case.get("updated_at")),
                ("Last Reviewed By", case.get("last_reviewed_by")),
                ("Last Reviewed At", case.get("last_reviewed_at")),
                ("Status Reason", case.get("status_reason")),
            ],
            styles,
        )
    )

    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)

    return buffer.getvalue()


def build_case_executive_pdf(case_id: int) -> dict:
    db = SessionLocal()

    try:
        payload = build_case_payload(db, case_id)
        pdf_bytes = build_executive_pdf_bytes(payload)

        return {
            "filename": f"case_{case_id}_executive_report.pdf",
            "pdf": pdf_bytes,
            "payload": payload,
        }

    finally:
        db.close()
