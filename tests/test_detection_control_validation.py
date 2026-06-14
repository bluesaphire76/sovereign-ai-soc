from detection_control_validation import validate_detection_control_payload


def valid_payload(**overrides):
    payload = {
        "name": "Suppress benign sudo status checks",
        "type": "NOISE_SUPPRESSION",
        "scope": "host:darkstar",
        "matcher_kind": "REGEX",
        "matcher_value": r"systemctl status ai-soc-(api|frontend)",
        "reason": "Routine operational checks should not create incidents.",
        "owner": "soc-admin",
        "enabled": True,
    }
    payload.update(overrides)
    return payload


def test_detection_control_validation_accepts_governed_payload():
    result = validate_detection_control_payload(valid_payload())

    assert result.valid is True
    assert result.severity == "OK"
    assert result.messages == []


def test_detection_control_validation_rejects_broad_matcher():
    result = validate_detection_control_payload(valid_payload(matcher_value=".*"))

    assert result.valid is False
    assert result.severity == "ERROR"
    assert any("too broad" in message for message in result.messages)


def test_detection_control_validation_rejects_malformed_regex():
    result = validate_detection_control_payload(valid_payload(matcher_value="[unterminated"))

    assert result.valid is False
    assert any("Regex matcher does not compile" in message for message in result.messages)


def test_detection_control_validation_rejects_malformed_json():
    result = validate_detection_control_payload(
        valid_payload(
            type="EXCEPTION",
            matcher_kind="JSON",
            matcher_value='{"field": "rule.id"',
        )
    )

    assert result.valid is False
    assert any("Matcher JSON is malformed" in message for message in result.messages)


def test_detection_control_validation_warns_on_global_suppression_scope():
    result = validate_detection_control_payload(
        valid_payload(scope="global", matcher_kind="EXACT", matcher_value="known-safe-event")
    )

    assert result.valid is True
    assert result.severity == "WARNING"
    assert result.warnings


def test_detection_control_validation_accepts_inventory_control_types():
    for rule_type in ["TELEMETRY_SOURCE", "SERVICE_CONTROL"]:
        result = validate_detection_control_payload(
            valid_payload(
                type=rule_type,
                matcher_kind="EXACT",
                matcher_value=f"{rule_type.lower()}:inventory-target",
            )
        )

        assert result.valid is True
