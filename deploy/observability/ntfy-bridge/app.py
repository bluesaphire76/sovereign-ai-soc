import os
from typing import Any

import httpx
from fastapi import FastAPI, Request


app = FastAPI(title="AI SOC Alertmanager ntfy Bridge")


NTFY_URL = os.getenv("NTFY_URL", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "").strip()
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "").strip()
NTFY_TIMEOUT_SECONDS = float(os.getenv("NTFY_TIMEOUT_SECONDS", "10"))


def _severity_priority(severity: str) -> str:
    severity = severity.lower().strip()
    if severity == "critical":
        return "urgent"
    if severity == "warning":
        return "high"
    return "default"


def _format_alert(payload: dict[str, Any]) -> tuple[str, str, str]:
    status = str(payload.get("status", "unknown")).upper()
    common_labels = payload.get("commonLabels", {}) or {}
    group_labels = payload.get("groupLabels", {}) or {}
    alerts = payload.get("alerts", []) or []

    alertname = common_labels.get("alertname") or group_labels.get("alertname") or "AI SOC Alert"
    severity = common_labels.get("severity", "unknown")
    service = common_labels.get("service", "unknown-service")

    title = f"AI SOC {status}: {alertname}"

    lines = [
        f"Status: {status}",
        f"Severity: {severity}",
        f"Service: {service}",
        f"Alerts: {len(alerts)}",
        "",
    ]

    for alert in alerts[:5]:
        labels = alert.get("labels", {}) or {}
        annotations = alert.get("annotations", {}) or {}

        lines.extend(
            [
                f"- {labels.get('alertname', alertname)}",
                f"  severity: {labels.get('severity', severity)}",
                f"  service: {labels.get('service', service)}",
                f"  domain: {labels.get('domain', 'unknown-domain')}",
                f"  summary: {annotations.get('summary', '')}",
                f"  description: {annotations.get('description', '')}",
                "",
            ]
        )

    if len(alerts) > 5:
        lines.append(f"...and {len(alerts) - 5} more alerts")

    priority = _severity_priority(str(severity))

    return title, "\n".join(lines), priority


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/alertmanager/ntfy")
async def alertmanager_ntfy(request: Request) -> dict[str, Any]:
    if not NTFY_TOPIC:
        return {"status": "error", "reason": "missing NTFY_TOPIC"}

    payload = await request.json()
    title, message, priority = _format_alert(payload)

    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": "rotating_light,shield",
    }

    if NTFY_TOKEN:
        headers["Authorization"] = f"Bearer {NTFY_TOKEN}"

    url = f"{NTFY_URL}/{NTFY_TOPIC}"

    async with httpx.AsyncClient(timeout=NTFY_TIMEOUT_SECONDS) as client:
        response = await client.post(url, content=message.encode("utf-8"), headers=headers)

    if response.status_code >= 400:
        return {
            "status": "error",
            "ntfy_status_code": response.status_code,
            "ntfy_response": response.text,
        }

    return {
        "status": "sent",
        "ntfy_status_code": response.status_code,
        "priority": priority,
    }
