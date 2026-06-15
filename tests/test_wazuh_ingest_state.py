from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from wazuh_ingest_state import build_wazuh_alert_query, iso_utc


def test_wazuh_alert_query_uses_initial_gte_without_watermark():
    watermark = SimpleNamespace(last_timestamp=None, last_doc_id=None)

    query, query_info = build_wazuh_alert_query(watermark, limit=25)
    timestamp_range = query["query"]["range"]["@timestamp"]

    assert query["size"] == 25
    assert "gte" in timestamp_range
    assert "gt" not in timestamp_range
    assert query_info["query_strategy"] in {
        "initial_lookback_window",
        "initial_max_catchup_window",
    }


def test_wazuh_alert_query_advances_strictly_after_existing_watermark():
    last_timestamp = iso_utc(datetime.now(timezone.utc) - timedelta(minutes=1))
    watermark = SimpleNamespace(last_timestamp=last_timestamp, last_doc_id="abc123")

    query, query_info = build_wazuh_alert_query(watermark, limit=150)
    timestamp_range = query["query"]["range"]["@timestamp"]

    assert query["sort"] == [
        {"@timestamp": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]
    assert timestamp_range == {"gt": last_timestamp}
    assert query_info["query_strategy"] == "watermark_strict"
    assert query_info["query_range"] == {"gt": last_timestamp}
