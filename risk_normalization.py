from __future__ import annotations


def _int_value(value, default=0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def priority_from_score(score: int | float | None) -> str:
    value = _int_value(score)

    if value >= 80:
        return "CRITICAL"
    if value >= 60:
        return "HIGH"
    if value >= 40:
        return "MEDIUM"

    return "LOW"


def severity_from_score(score: int | float | None) -> str:
    return priority_from_score(score)


def base_score_from_wazuh_level(level: int | None) -> int:
    value = _int_value(level)

    if value >= 14:
        return 85
    if value >= 12:
        return 75
    if value >= 10:
        return 65
    if value >= 8:
        return 50
    if value >= 7:
        return 40
    if value >= 4:
        return 25
    if value >= 1:
        return 10

    return 0


def no_chain_cap_for_level(level: int | None) -> int:
    value = _int_value(level)

    if value <= 3:
        return 25
    if value <= 5:
        return 35
    if value <= 7:
        return 55
    if value <= 9:
        return 70
    if value <= 11:
        return 79

    return 85


def normalize_correlation_score(
    *,
    level: int | None,
    pattern_score: int | None,
    volume_score: int | None,
    aggregate_score: int | None = 0,
    chain_bonus: int | None,
    matched_chains: list[dict] | None,
) -> dict:
    chains = matched_chains or []

    base_score = base_score_from_wazuh_level(level)

    if chains:
        normalized_pattern_score = min(_int_value(pattern_score), 25)
        normalized_volume_score = min(_int_value(volume_score), 20)
        normalized_aggregate_score = min(_int_value(aggregate_score), 15)
        normalized_chain_bonus = min(_int_value(chain_bonus), 45)
        cap = 100
    else:
        normalized_pattern_score = min(_int_value(pattern_score), 15)
        normalized_volume_score = min(_int_value(volume_score), 15)
        normalized_aggregate_score = min(_int_value(aggregate_score), 10)
        normalized_chain_bonus = 0
        cap = no_chain_cap_for_level(level)

    raw_score = (
        base_score
        + normalized_pattern_score
        + normalized_volume_score
        + normalized_aggregate_score
        + normalized_chain_bonus
    )

    final_score = max(0, min(raw_score, cap, 100))
    recommended_priority = priority_from_score(final_score)

    return {
        "final_score": final_score,
        "recommended_priority": recommended_priority,
        "severity": severity_from_score(final_score),
        "base_score": base_score,
        "pattern_score": normalized_pattern_score,
        "volume_score": normalized_volume_score,
        "aggregate_score": normalized_aggregate_score,
        "chain_bonus": normalized_chain_bonus,
        "raw_score_before_cap": raw_score,
        "cap": cap,
        "matched_chain_count": len(chains),
        "policy": "v0.4_risk_normalization",
    }


def should_auto_escalate(
    *,
    score: int | None,
    matched_chains: list[dict] | None,
) -> bool:
    value = _int_value(score)
    chains = matched_chains or []

    if value < 80:
        return False

    return any(
        str(chain.get("priority") or "").upper() == "CRITICAL"
        or _int_value(chain.get("score_bonus")) >= 50
        for chain in chains
    )
