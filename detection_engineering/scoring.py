from __future__ import annotations

from .models import DetectionEngineeringConfidence, DetectionEngineeringSeverity


def clamp_score(value: object) -> int:
    try:
        numeric = int(round(float(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return min(100, max(0, numeric))


def calculate_recurrence_score(*, alert_count: int = 0, incident_count: int = 0) -> int:
    if alert_count <= 0 and incident_count <= 0:
        return 0

    score = 0
    if alert_count >= 100:
        score += 45
    elif alert_count >= 50:
        score += 35
    elif alert_count >= 20:
        score += 25
    elif alert_count >= 5:
        score += 12

    if incident_count >= 10:
        score += 35
    elif incident_count >= 4:
        score += 24
    elif incident_count >= 2:
        score += 12

    return clamp_score(score)


def calculate_noise_score(
    *,
    alert_count: int = 0,
    incident_count: int = 0,
    suppressed_count: int = 0,
    false_positive_count: int = 0,
    low_severity_count: int = 0,
) -> int:
    if alert_count <= 0 and suppressed_count <= 0:
        return 0

    score = 0
    total_observations = max(1, alert_count + suppressed_count)
    suppression_ratio = suppressed_count / total_observations
    low_severity_ratio = low_severity_count / max(1, alert_count)
    incident_ratio = incident_count / max(1, alert_count)

    if suppression_ratio >= 0.70:
        score += 35
    elif suppression_ratio >= 0.35:
        score += 24
    elif suppression_ratio > 0:
        score += 12

    if false_positive_count >= 10:
        score += 30
    elif false_positive_count >= 3:
        score += 18
    elif false_positive_count > 0:
        score += 10

    if low_severity_ratio >= 0.75:
        score += 22
    elif low_severity_ratio >= 0.40:
        score += 12

    if alert_count >= 50 and incident_ratio <= 0.10:
        score += 18
    elif alert_count >= 20 and incident_ratio <= 0.20:
        score += 10

    return clamp_score(score)


def calculate_detection_quality_score(
    *,
    noise_score: int = 0,
    recurrence_score: int = 0,
    mitre_present: bool = False,
    evidence_count: int = 0,
) -> int:
    score = 78
    score -= min(35, noise_score // 2)
    if recurrence_score >= 60:
        score -= 12
    elif recurrence_score >= 35:
        score -= 6

    if mitre_present:
        score += 8
    else:
        score -= 10

    if evidence_count >= 5:
        score += 6
    elif evidence_count == 0:
        score -= 18

    return clamp_score(score)


def calculate_confidence(*, evidence_count: int = 0, recurrence_score: int = 0, unsupported: bool = False) -> DetectionEngineeringConfidence:
    if unsupported or evidence_count <= 0:
        return DetectionEngineeringConfidence.SPECULATIVE
    if evidence_count >= 5 and recurrence_score >= 40:
        return DetectionEngineeringConfidence.HIGH
    if evidence_count >= 2:
        return DetectionEngineeringConfidence.MEDIUM
    return DetectionEngineeringConfidence.LOW


def severity_from_scores(*, noise_score: int = 0, recurrence_score: int = 0, quality_score: int = 100) -> DetectionEngineeringSeverity:
    if noise_score >= 80 or quality_score <= 30:
        return DetectionEngineeringSeverity.HIGH
    if noise_score >= 55 or recurrence_score >= 70 or quality_score <= 50:
        return DetectionEngineeringSeverity.MEDIUM
    if noise_score >= 30 or recurrence_score >= 35 or quality_score <= 70:
        return DetectionEngineeringSeverity.LOW
    return DetectionEngineeringSeverity.INFO


def calculate_expected_benefit(category: str, *, evidence_count: int = 0, recurrence_score: int = 0) -> str:
    if recurrence_score >= 60 or evidence_count >= 10:
        return f"High operational benefit expected for {category.lower()} after analyst validation."
    if recurrence_score >= 25 or evidence_count >= 3:
        return f"Moderate operational benefit expected for {category.lower()} after analyst validation."
    return f"Limited benefit expected for {category.lower()} unless additional supporting evidence is found."


def calculate_operational_risk(category: str, *, confidence: DetectionEngineeringConfidence) -> str:
    if category in {"SUPPRESSION_CANDIDATE", "THRESHOLD_TUNING", "NOISE_REDUCTION"}:
        return (
            "Medium operational risk: improper tuning or suppression can hide relevant security signals. "
            "Change must be reviewed, tested and reversible."
        )
    if category in {"CORRELATION_IMPROVEMENT", "RULE_DEDUPLICATION"}:
        return (
            "Low to medium operational risk: detection logic changes may alter incident volume and should be "
            "validated against historical data."
        )
    if confidence == DetectionEngineeringConfidence.SPECULATIVE:
        return "Low immediate risk because no implementation should occur until additional evidence is collected."
    return "Low operational risk when treated as analyst-review guidance only."
