import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Europe/Zurich")
LOCAL_TZ = ZoneInfo(APP_TIMEZONE)


def parse_timestamp_to_utc(value):
    if not value:
        return None

    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

    # Wazuh @timestamp should be UTC. If timezone is missing, treat it as UTC.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def normalize_timestamp_utc(value):
    try:
        dt = parse_timestamp_to_utc(value)
    except (ValueError, TypeError):
        return value

    if not dt:
        return None

    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def format_timestamp_local(value):
    try:
        dt = parse_timestamp_to_utc(value)
    except (ValueError, TypeError):
        return value

    if not dt:
        return None

    return dt.astimezone(LOCAL_TZ).strftime("%d.%m.%Y %H:%M:%S %Z")
