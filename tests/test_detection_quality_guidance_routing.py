import json
from unittest.mock import patch

import detection_quality_guidance as guidance
from ai_model_policy import AiTask


def _clear_guidance_cache():
    with guidance._GUIDANCE_CACHE_LOCK:
        guidance._GUIDANCE_CACHE.clear()
        guidance._GUIDANCE_INFLIGHT_LOCKS.clear()


def test_detection_quality_guidance_uses_standard_action_how_to_routing():
    _clear_guidance_cache()
    calls = []

    def fake_generate_ai_response(**kwargs):
        calls.append(kwargs)

        return {
            "text": json.dumps(
                {
                    "how_to_execute": [
                        "Review the weakest synthetic scenario.",
                        "Validate expected MITRE and priority mappings.",
                        "Re-run the synthetic scenario after tuning.",
                    ],
                    "validation_notes": "Human validation is required before release.",
                }
            ),
            "profile": "standard",
            "model": "standard:model",
            "fallback_used": False,
            "error_type": None,
            "latency_ms": 12,
        }

    with patch(
        "detection_quality_guidance.generate_ai_response",
        side_effect=fake_generate_ai_response,
    ):
        result = guidance.generate_detection_quality_guidance(
            {
                "scenario_name": "ssh_bruteforce",
                "recommended_action": "Review MITRE mapping gaps.",
                "force_refresh": True,
            }
        )

    assert len(calls) == 1
    assert calls[0]["task"] == AiTask.ACTION_HOW_TO
    assert calls[0]["requested_mode"] == "standard"
    assert calls[0]["user_triggered"] is True
    assert result["source"] == "local_ai"
    assert result["model"] == "standard:model"
    assert result["llm_profile"] == "standard"
    assert result["llm_fallback_used"] is False
    assert result["llm_latency_ms"] == 12


def test_detection_quality_guidance_keeps_deterministic_fallback_on_empty_llm_text():
    _clear_guidance_cache()

    with patch(
        "detection_quality_guidance.generate_ai_response",
        return_value={
            "text": "",
            "profile": "fast",
            "model": "fast:model",
            "fallback_used": True,
            "error_type": "Timeout",
            "latency_ms": 25,
        },
    ):
        result = guidance.generate_detection_quality_guidance(
            {
                "scenario_name": "ssh_bruteforce",
                "recommended_action": "Review MITRE mapping gaps.",
                "force_refresh": True,
            }
        )

    assert result["source"] == "deterministic_fallback"
    assert result["model"] == "fast:model"
    assert result["llm_profile"] == "fast"
    assert result["llm_fallback_used"] is True
    assert result["llm_latency_ms"] == 25
    assert len(result["how_to_execute"]) >= 3
