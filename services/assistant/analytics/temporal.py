from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from dateparser.conf import Settings
from dateparser.date import DateDataParser
from dateparser.languages.loader import LocaleDataLoader
from dateparser.search import search_dates
from dateutil import parser as dateutil_parser
from dateutil.relativedelta import relativedelta
from text_to_num import alpha2digit

from services.assistant.analytics.nlu_runtime import DependencyDocument
from services.assistant.v3.contracts import AnalyticalTimeWindow


ZURICH = ZoneInfo("Europe/Zurich")


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


def _start_of_day(value: datetime) -> datetime:
    return value.replace(hour=0, minute=0, second=0, microsecond=0)


def _start_of_week(value: datetime) -> datetime:
    return _start_of_day(value) - timedelta(days=value.weekday())


def _start_of_month(value: datetime) -> datetime:
    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _previous_month_start(value: datetime) -> datetime:
    return _start_of_month(_start_of_month(value) - timedelta(days=1))


def _shifted_calendar_window(
    current: datetime,
    *,
    period: str,
    offset: int,
) -> tuple[datetime, datetime] | None:
    if offset < 1:
        return None
    if period == "day":
        end = _start_of_day(current) - timedelta(days=offset - 1)
        return end - timedelta(days=1), end
    if period == "week":
        end = _start_of_week(current) - timedelta(weeks=offset - 1)
        return end - timedelta(weeks=1), end
    if period == "month":
        end = _start_of_month(current) - relativedelta(months=offset - 1)
        return end - relativedelta(months=1), end
    if period == "year":
        current_year = current.replace(
            month=1,
            day=1,
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )
        end = current_year - relativedelta(years=offset - 1)
        return end - relativedelta(years=1), end
    return None


def _duration_resolution(start: datetime, end: datetime, period: str) -> str:
    seconds = max(1, int((end - start).total_seconds()))
    week_seconds = int(timedelta(weeks=1).total_seconds())
    day_seconds = int(timedelta(days=1).total_seconds())
    hour_seconds = int(timedelta(hours=1).total_seconds())
    if period == "hour" and seconds % hour_seconds == 0:
        return f"LAST_{seconds // hour_seconds}_HOURS"
    if period == "week" and seconds % week_seconds == 0:
        return f"LAST_{seconds // week_seconds}_WEEKS"
    if seconds % day_seconds == 0:
        return f"LAST_{seconds // day_seconds}_DAYS"
    if seconds % hour_seconds == 0:
        return f"LAST_{seconds // hour_seconds}_HOURS"
    return "ROLLING_INTERVAL"


@dataclass(frozen=True)
class ResolvedTemporalSelection:
    current: AnalyticalTimeWindow | None
    previous: AnalyticalTimeWindow | None = None
    routing_status: str = "resolved"


class ZurichTemporalResolver:
    def _settings(self, current: datetime) -> dict[str, object]:
        return {
            "RELATIVE_BASE": current,
            "TIMEZONE": "Europe/Zurich",
            "TO_TIMEZONE": "Europe/Zurich",
            "RETURN_AS_TIMEZONE_AWARE": True,
            "PREFER_DATES_FROM": "past",
        }

    @staticmethod
    def _language(
        document: DependencyDocument | None,
    ) -> Literal["en", "it"] | None:
        return document.language if document is not None else None

    @staticmethod
    def _translation_tokens(text: str, language: str) -> tuple[str, ...]:
        locale = LocaleDataLoader().get_locale(language)
        translated = locale.translate(text, settings=Settings())
        return tuple(item.casefold() for item in translated.split() if item.strip())

    def _canonical_period(self, text: str, languages: list[str]) -> str | None:
        periods = ("hour", "day", "week", "month", "year")
        for language in languages:
            tokens = self._translation_tokens(text, language)
            selected = next((item for item in periods if item in tokens), None)
            if selected is not None:
                return selected
        return None

    def canonical_period_term(
        self,
        text: str,
        *,
        language: Literal["en", "it"],
    ) -> str | None:
        return self._canonical_period(text, [language])

    def is_temporal_term(
        self,
        text: str,
        *,
        language: Literal["en", "it"],
        now: datetime | None = None,
    ) -> bool:
        if self._canonical_period(text, [language]) is not None:
            return True
        current = (now or datetime.now(timezone.utc)).astimezone(ZURICH)
        parsed = DateDataParser(
            languages=[language],
            settings=self._settings(current),
        ).get_date_data(text)
        return parsed.date_obj is not None

    def _temporal_text(
        self,
        text: str,
        *,
        document: DependencyDocument | None,
        languages: list[str],
        settings: dict[str, object],
    ) -> str:
        if document is None:
            return text
        canonical_roots: list[int] = []
        relative_roots: list[int] = []
        for token in document.tokens:
            canonical_period = self._canonical_period(
                token.text,
                languages,
            ) or self._canonical_period(token.lemma, languages)
            parsed_dates = [
                DateDataParser(
                    languages=[language],
                    settings=settings,
                ).get_date_data(token.text)
                for language in languages
            ]
            parsed_periods = {
                item.period for item in parsed_dates if item.date_obj is not None
            }
            absolute_token = not token.text.isdigit() and any(
                not character.isalnum() for character in token.text
            )
            if canonical_period is not None and token.upos != "ADV":
                canonical_roots.append(token.token_id)
            elif parsed_periods and (
                token.upos == "ADV"
                or (
                    token.upos in {"NOUN", "PROPN"}
                    and parsed_periods.intersection(
                        {"day", "week", "month", "year"}
                    )
                )
                or (
                    token.upos == "NUM"
                    and (
                        absolute_token
                        or any(
                            child.relation == "flat"
                            for child in document.children(token.token_id)
                        )
                    )
                )
            ):
                relative_roots.append(token.token_id)
        roots = canonical_roots or relative_roots
        if not roots:
            return ""
        selected = set(roots)
        frontier = list(roots)
        for _depth in range(3):
            next_frontier: list[int] = []
            for parent_id in frontier:
                for child in document.children(parent_id):
                    if child.token_id in selected:
                        continue
                    selected.add(child.token_id)
                    next_frontier.append(child.token_id)
            frontier = next_frontier
        frontier = list(roots)
        for _depth in range(3):
            next_frontier = []
            for child_id in frontier:
                child = document.token(child_id)
                parent = document.token(child.head_id) if child is not None else None
                if parent is None or parent.upos in {"VERB", "AUX"}:
                    continue
                if parent.token_id not in selected:
                    selected.add(parent.token_id)
                    next_frontier.append(parent.token_id)
                selected.update(
                    sibling.token_id
                    for sibling in document.children(parent.token_id)
                )
            frontier = next_frontier
        return " ".join(
            token.text
            for token in document.tokens
            if token.token_id in selected
        )

    @staticmethod
    def _document_dates(
        document: DependencyDocument | None,
        *,
        languages: list[str],
        settings: dict[str, object],
        current: datetime,
    ) -> tuple[datetime, ...]:
        if document is None:
            return ()
        selected: list[datetime] = []
        for token in document.tokens:
            if token.upos != "NUM":
                continue
            flat = tuple(
                child
                for child in document.children(token.token_id)
                if child.relation == "flat"
            )
            absolute_token = any(
                not character.isalnum() for character in token.text
            )
            if not flat and not absolute_token:
                continue
            phrase = " ".join(
                item.text
                for item in sorted((token, *flat), key=lambda value: value.token_id)
            )
            parsed = None
            for language in languages:
                parsed = DateDataParser(
                    languages=[language],
                    settings=settings,
                ).get_date_data(phrase).date_obj
                if parsed is not None:
                    break
            if parsed is None and absolute_token:
                try:
                    parsed = dateutil_parser.parse(
                        phrase,
                        default=current,
                        fuzzy=False,
                    )
                except (TypeError, ValueError, OverflowError):
                    parsed = None
            if parsed is None:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=ZURICH)
            selected.append(parsed.astimezone(ZURICH))
        return tuple(dict.fromkeys(selected))

    def _document_duration(
        self,
        document: DependencyDocument | None,
        *,
        language: str | None,
    ) -> tuple[int, str] | None:
        if document is None or language is None:
            return None
        for token in document.tokens:
            if token.upos != "NUM":
                continue
            numeric_text = alpha2digit(token.text, language, threshold=0)
            if not numeric_text.isdigit():
                continue
            quantity = int(numeric_text)
            if quantity < 1 or quantity > 3660:
                continue
            head = document.token(token.head_id)
            candidates = (
                head,
                document.token(head.head_id) if head is not None else None,
            )
            period = next(
                (
                    selected
                    for item in candidates
                    if item is not None
                    and (
                        selected := self.canonical_period_term(
                            item.lemma,
                            language=document.language,
                        )
                    )
                    is not None
                ),
                None,
            )
            if period is not None:
                return quantity, period
        return None

    def _calendar_window(
        self,
        text: str,
        *,
        language: str,
        current: datetime,
        settings: dict[str, object],
    ) -> tuple[datetime, datetime, str] | str | None:
        data = DateDataParser(languages=[language], settings=settings).get_date_data(text)
        selected = data.date_obj
        if selected is None:
            return None
        selected = selected.astimezone(ZURICH)
        tokens = self._translation_tokens(text, language)
        if data.period == "day":
            if selected.date() == current.date():
                return _start_of_day(current), current, "TODAY"
            if selected.date() == (current - timedelta(days=1)).date():
                start = _start_of_day(selected)
                return start, start + timedelta(days=1), "YESTERDAY"
        if data.period == "week":
            selected_start = _start_of_week(selected)
            current_start = _start_of_week(current)
            if selected_start == current_start:
                return selected_start, current, "THIS_WEEK"
            if selected_start == current_start - timedelta(weeks=1):
                return selected_start, current_start, "PREVIOUS_WEEK"
        if data.period == "month":
            selected_start = _start_of_month(selected)
            current_start = _start_of_month(current)
            if selected_start == current_start:
                return selected_start, current, "THIS_MONTH"
            if selected_start == _previous_month_start(current):
                if "ago" not in tokens:
                    return "ambiguous_time_window"
                return selected_start, current_start, "PREVIOUS_MONTH"
        return None

    def _rolling_window(
        self,
        text: str,
        *,
        languages: list[str],
        current: datetime,
        settings: dict[str, object],
        temporal_relation: str | None,
        document_dates: tuple[datetime, ...] = (),
    ) -> tuple[datetime, datetime, str] | None:
        matches: list[tuple[str, datetime, list[str]]] = []
        original_matches = search_dates(
            text,
            languages=languages,
            settings=settings,
        ) or []
        if original_matches:
            matches.extend(
                (matched_text, value, languages)
                for matched_text, value in original_matches
            )
        else:
            for language in languages:
                translated = " ".join(self._translation_tokens(text, language))
                matches.extend(
                    (matched_text, value, ["en"])
                    for matched_text, value in search_dates(
                        translated,
                        languages=["en"],
                        settings=settings,
                    )
                    or []
                )
        normalized_matches: list[tuple[str, datetime, list[str], str]] = []
        for matched_text, value, matched_languages in matches:
            data = DateDataParser(
                languages=matched_languages,
                settings=settings,
            ).get_date_data(matched_text)
            selected = value.astimezone(ZURICH).replace(microsecond=0)
            if data.period == "month":
                selected = _start_of_month(selected)
            elif data.period == "year":
                selected = selected.replace(
                    month=1,
                    day=1,
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                )
            normalized_matches.append(
                (matched_text, selected, matched_languages, data.period)
            )
        distinct_dates = sorted(
            {value for _matched, value, _languages, _period in normalized_matches}.union(
                value.replace(microsecond=0) for value in document_dates
            )
        )
        if len(distinct_dates) >= 2:
            start = distinct_dates[0]
            end = distinct_dates[-1]
            if end == _start_of_day(end):
                end += timedelta(days=1)
            return start, end, "ABSOLUTE_RANGE"
        if temporal_relation == "END_BOUNDARY" and distinct_dates:
            return (
                datetime(1970, 1, 1, tzinfo=ZURICH),
                distinct_dates[0],
                "BEFORE_ABSOLUTE",
            )
        if temporal_relation == "START_BOUNDARY" and distinct_dates:
            return distinct_dates[0], current, "SINCE_ABSOLUTE"
        if temporal_relation == "RANGE_BOUNDARY" and distinct_dates:
            return distinct_dates[0], current, "SINCE_ABSOLUTE"
        for matched_text, start, matched_languages, matched_period in normalized_matches:
            canonical_period = self._canonical_period(
                matched_text,
                matched_languages,
            )
            data_period = matched_period
            if canonical_period == "day" and start.date() == current.date():
                return _start_of_day(current), current, "TODAY"
            if canonical_period == "day" and start.date() == (
                current - timedelta(days=1)
            ).date():
                selected_day = _start_of_day(start)
                return selected_day, selected_day + timedelta(days=1), "YESTERDAY"
            if canonical_period == "week":
                selected_week = _start_of_week(start)
                current_week = _start_of_week(current)
                if selected_week == current_week:
                    return selected_week, current, "THIS_WEEK"
                if selected_week == current_week - timedelta(weeks=1):
                    return selected_week, current_week, "PREVIOUS_WEEK"
            if canonical_period == "month":
                selected_month = _start_of_month(start)
                current_month = _start_of_month(current)
                if selected_month == current_month:
                    return selected_month, current, "THIS_MONTH"
                if selected_month == _previous_month_start(current):
                    return selected_month, current_month, "PREVIOUS_MONTH"
            if canonical_period is None and data_period == "day" and start < current:
                selected_day = _start_of_day(start)
                return selected_day, selected_day + timedelta(days=1), "ABSOLUTE_DAY"
            if not start < current:
                continue
            duration = current - start
            if duration > timedelta(days=3660):
                continue
            return start, current, _duration_resolution(
                start,
                current,
                canonical_period or data_period,
            )
        return None

    def resolve(
        self,
        text: str,
        *,
        now: datetime | None = None,
        compare_periods: bool = False,
        document: DependencyDocument | None = None,
        temporal_relation: str | None = None,
        day_part: str | None = None,
        calendar_period_shift: int | None = None,
    ) -> ResolvedTemporalSelection:
        current = (now or datetime.now(timezone.utc)).astimezone(ZURICH)
        language = self._language(document)
        languages = [language] if language is not None else ["it", "en"]
        settings = self._settings(current)
        temporal_text = self._temporal_text(
            text,
            document=document,
            languages=languages,
            settings=settings,
        )
        if not temporal_text and search_dates(
            text,
            languages=languages,
            settings=settings,
        ):
            temporal_text = text
        if language is not None and temporal_text:
            temporal_text = alpha2digit(
                temporal_text,
                language,
                threshold=0,
            )

        anchor_matches = search_dates(
            temporal_text,
            languages=languages,
            settings=settings,
        ) or []

        if day_part is not None and day_part != "NONE" and not anchor_matches:
            start_hour, end_hour = {
                "MORNING": (0, 12),
                "AFTERNOON": (12, 18),
                "EVENING": (18, 24),
                "NIGHT": (18, 24),
            }[day_part]
            start = _start_of_day(current) + timedelta(hours=start_hour)
            scheduled_end = _start_of_day(current) + timedelta(hours=end_hour)
            end = (
                scheduled_end
                if current <= start
                else min(current, scheduled_end)
            )
            if start < end:
                return ResolvedTemporalSelection(
                    _window(start, end, f"THIS_{day_part}"),
                )

        if day_part is not None and day_part != "NONE" and anchor_matches:
            anchor = anchor_matches[0][1].astimezone(ZURICH)
            start_hour, end_hour = {
                "MORNING": (0, 12),
                "AFTERNOON": (12, 18),
                "EVENING": (18, 24),
                "NIGHT": (18, 24),
            }[day_part]
            part_start = _start_of_day(anchor) + timedelta(hours=start_hour)
            part_end = _start_of_day(anchor) + timedelta(hours=end_hour)
            if temporal_relation in {"START_BOUNDARY", "RANGE_BOUNDARY"}:
                if part_start < current:
                    return ResolvedTemporalSelection(
                        _window(part_start, current, f"SINCE_{day_part}"),
                    )
            elif temporal_relation == "END_BOUNDARY":
                return ResolvedTemporalSelection(
                    _window(
                        datetime(1970, 1, 1, tzinfo=ZURICH),
                        part_end,
                        f"BEFORE_{day_part}",
                    ),
                )
            elif part_start < min(part_end, current):
                return ResolvedTemporalSelection(
                    _window(
                        part_start,
                        min(part_end, current),
                        day_part,
                    ),
                )

        document_dates = self._document_dates(
            document,
            languages=languages,
            settings=settings,
            current=current,
        )

        canonical_period = self._canonical_period(temporal_text, languages)
        if canonical_period is not None and calendar_period_shift is not None:
            shifted = _shifted_calendar_window(
                current,
                period=canonical_period,
                offset=calendar_period_shift,
            )
            if shifted is not None:
                start, end = shifted
                resolution = (
                    f"PREVIOUS_{canonical_period.upper()}"
                    if calendar_period_shift == 1
                    else (
                        f"{calendar_period_shift}_PERIODS_BEFORE_CURRENT_"
                        f"{canonical_period.upper()}"
                    )
                )
                selected = _window(start, end, resolution)
                if not compare_periods:
                    return ResolvedTemporalSelection(selected)
                duration = end - start
                return ResolvedTemporalSelection(
                    selected,
                    _window(
                        start - duration,
                        start,
                        f"PREVIOUS_{resolution}",
                    ),
                )
        structured_duration = self._document_duration(
            document,
            language=language,
        )
        if structured_duration is not None:
            quantity, period = structured_duration
            unit = {
                "hour": timedelta(hours=1),
                "day": timedelta(days=1),
                "week": timedelta(weeks=1),
                "month": timedelta(days=30),
                "year": timedelta(days=365),
            }[period]
            start = current - (quantity * unit)
            resolution = _duration_resolution(start, current, period)
            selected = _window(start, current, resolution)
            if not compare_periods:
                return ResolvedTemporalSelection(selected)
            return ResolvedTemporalSelection(
                selected,
                _window(
                    start - (quantity * unit),
                    start,
                    f"PREVIOUS_{resolution}",
                ),
            )
        if temporal_relation == "CURRENT_PERIOD" and canonical_period is not None:
            current_start = {
                "day": _start_of_day,
                "week": _start_of_week,
                "month": _start_of_month,
                "year": lambda value: value.replace(
                    month=1,
                    day=1,
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                ),
            }.get(canonical_period)
            if current_start is not None:
                start = current_start(current)
                resolution = f"THIS_{canonical_period.upper()}"
                selected = _window(start, current, resolution)
                if not compare_periods:
                    return ResolvedTemporalSelection(selected)
                duration = current - start
                return ResolvedTemporalSelection(
                    selected,
                    _window(start - duration, start, f"PREVIOUS_{resolution}"),
                )
        if (
            temporal_relation == "PREVIOUS_PERIOD"
            and canonical_period is not None
        ):
            if canonical_period == "day":
                end = _start_of_day(current)
                start = end - timedelta(days=1)
            elif canonical_period == "week":
                end = _start_of_week(current)
                start = end - timedelta(weeks=1)
            elif canonical_period == "month":
                end = _start_of_month(current)
                start = _previous_month_start(current)
            elif canonical_period == "year":
                end = current.replace(
                    month=1,
                    day=1,
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                )
                start = end.replace(year=end.year - 1)
            else:
                start = end = current
            resolution = f"PREVIOUS_{canonical_period.upper()}"
            selected = _window(start, end, resolution)
            if not compare_periods:
                return ResolvedTemporalSelection(selected)
            duration = end - start
            return ResolvedTemporalSelection(
                selected,
                _window(start - duration, start, f"PREVIOUS_{resolution}"),
            )

        calendar: tuple[datetime, datetime, str] | str | None = None
        for selected_language in languages:
            calendar = self._calendar_window(
                temporal_text,
                language=selected_language,
                current=current,
                settings=settings,
            )
            if calendar is not None:
                break
        if calendar == "ambiguous_time_window":
            return ResolvedTemporalSelection(None, routing_status=calendar)
        resolved = calendar or self._rolling_window(
            temporal_text,
            languages=languages,
            current=current,
            settings=settings,
            temporal_relation=temporal_relation,
            document_dates=document_dates,
        )
        if resolved is None and canonical_period == "month":
            return ResolvedTemporalSelection(
                None,
                routing_status="ambiguous_time_window",
            )
        if resolved is None:
            return ResolvedTemporalSelection(None, routing_status="not_present")

        start, end, resolution = resolved
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
