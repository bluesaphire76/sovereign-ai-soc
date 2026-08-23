from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from services.assistant.v3.contracts import AnalyticalTimeWindow


ZURICH = ZoneInfo("Europe/Zurich")
_DAYS_PATTERN = re.compile(
    r"\b(?:last|past|ultim[ei]|scors[ei])\s+(\d{1,3})\s+(?:days?|giorni?)\b",
    re.IGNORECASE,
)


def _normalized(value: str) -> str:
    folded = unicodedata.normalize("NFKD", value.casefold())
    return " ".join("".join(ch for ch in folded if not unicodedata.combining(ch)).split())


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _window(start: datetime, end: datetime, resolution: str) -> AnalyticalTimeWindow:
    if start >= end:
        raise ValueError("analytical time window start must precede end")
    return AnalyticalTimeWindow(
        start_utc=_utc_text(start),
        end_utc=_utc_text(end),
        resolution=resolution,
    )


@dataclass(frozen=True)
class ResolvedTemporalSelection:
    current: AnalyticalTimeWindow | None
    previous: AnalyticalTimeWindow | None = None
    routing_status: str = "resolved"


class ZurichTemporalResolver:
    def resolve(
        self,
        text: str,
        *,
        now: datetime | None = None,
        compare_periods: bool = False,
    ) -> ResolvedTemporalSelection:
        current = (now or datetime.now(timezone.utc)).astimezone(ZURICH)
        normalized = _normalized(text)
        start: datetime | None = None
        end = current
        resolution: str | None = None

        if any(value in normalized for value in ("last 24 hours", "past 24 hours", "ultime 24 ore")):
            start = current - timedelta(hours=24)
            resolution = "LAST_24_HOURS"
        else:
            days = _DAYS_PATTERN.search(normalized)
            if days is not None:
                day_count = int(days.group(1))
                if not 1 <= day_count <= 366:
                    return ResolvedTemporalSelection(None)
                start = current - timedelta(days=day_count)
                resolution = f"LAST_{day_count}_DAYS"
            elif any(value in normalized for value in ("this week", "questa settimana")):
                start = current.replace(hour=0, minute=0, second=0, microsecond=0)
                start -= timedelta(days=start.weekday())
                resolution = "THIS_WEEK"
            elif any(value in normalized for value in ("today", "oggi")):
                start = current.replace(hour=0, minute=0, second=0, microsecond=0)
                resolution = "TODAY"
            elif any(
                value in normalized
                for value in ("ultimo mese", "last month")
            ):
                return ResolvedTemporalSelection(
                    None,
                    routing_status="ambiguous_time_window",
                )
            elif any(value in normalized for value in ("previous month", "last calendar month", "mese precedente", "scorso mese", "mese scorso")):
                month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                previous_end = month_start
                previous_day = month_start - timedelta(days=1)
                start = previous_day.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                end = previous_end
                resolution = "PREVIOUS_MONTH"
            elif any(value in normalized for value in ("this month", "questo mese", "mese corrente")):
                start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                resolution = "THIS_MONTH"

        if start is None or resolution is None:
            return ResolvedTemporalSelection(None, routing_status="not_present")
        selected = _window(start, end, resolution)
        if not compare_periods:
            return ResolvedTemporalSelection(selected)
        duration = end - start
        previous_end = start
        previous_start = previous_end - duration
        return ResolvedTemporalSelection(
            selected,
            _window(previous_start, previous_end, f"PREVIOUS_{resolution}"),
        )
