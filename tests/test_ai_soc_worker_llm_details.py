from __future__ import annotations

import ai_soc_worker


def test_worker_llm_details_include_last_provider_metadata(monkeypatch):
    monkeypatch.setattr(
        ai_soc_worker,
        "get_last_llm_call_metadata",
        lambda: {
            "profile": "fast",
            "model": "ai-soc-fast",
            "provider_key": "local_llama_cpp",
            "provider_type": "LOCAL_LLAMA_CPP",
            "fallback_used": False,
            "error_type": None,
            "latency_ms": 42,
        },
    )

    details = ai_soc_worker._llm_worker_details()

    assert details["llm_last_profile"] == "fast"
    assert details["llm_last_model"] == "ai-soc-fast"
    assert details["llm_last_provider_key"] == "local_llama_cpp"
    assert details["llm_last_provider_type"] == "LOCAL_LLAMA_CPP"
    assert details["llm_last_fallback_used"] is False
    assert details["llm_last_latency_ms"] == 42
