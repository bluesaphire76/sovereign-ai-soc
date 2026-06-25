from __future__ import annotations

from routers import metrics as metrics_router


def test_ai_provider_metrics_include_llama_cpp_and_filter_default(monkeypatch):
    payload = {
        "status": "OK",
        "components": [
            {
                "component": "ai_runtime",
                "status": "OK",
                "details": {
                    "provider_registry": {
                        "default_provider": "local_llama_cpp",
                        "fallback_provider": "local_ollama",
                        "active_provider": {
                            "provider_key": "local_llama_cpp",
                            "provider_type": "LOCAL_LLAMA_CPP",
                            "model": "ai-soc-fast",
                            "external": False,
                        },
                        "fallback_provider_details": {
                            "provider_key": "local_ollama",
                        },
                        "providers": [
                            {
                                "provider_key": "local_llama_cpp",
                                "provider_type": "LOCAL_LLAMA_CPP",
                                "reachable": True,
                                "details": {
                                    "profiles": [
                                        {
                                            "profile": "fast",
                                            "model": "ai-soc-fast",
                                            "available": True,
                                            "active": True,
                                            "status": "loaded",
                                        },
                                        {
                                            "profile": "ignored",
                                            "model": "default",
                                            "available": True,
                                            "active": False,
                                            "status": "unloaded",
                                        },
                                    ]
                                },
                            }
                        ],
                    }
                },
            }
        ],
    }

    monkeypatch.setattr(metrics_router, "get_platform_health", lambda: payload)

    metrics_router._collect_platform_health_metrics()
    output = metrics_router.generate_latest().decode("utf-8")

    assert "ai_soc_ai_provider_active_info{" in output
    assert 'provider_key="local_llama_cpp"' in output
    assert 'provider_type="LOCAL_LLAMA_CPP"' in output
    assert 'model="ai-soc-fast"' in output
    assert 'external="false"' in output
    assert 'ai_soc_ai_provider_fallback_info{provider_key="local_ollama"} 1.0' in output
    assert "ai_soc_llama_cpp_router_up 1.0" in output
    assert 'ai_soc_llama_cpp_model_loaded{model_id="ai-soc-fast"} 1.0' in output
    assert 'ai_soc_llama_cpp_model_available{model_id="ai-soc-fast"} 1.0' in output
    assert 'ai_soc_llama_cpp_model_status{model_id="ai-soc-fast",status="loaded"} 1.0' in output
    assert 'model_id="default"' not in output


def test_llm_model_in_use_metric_exposes_current_profile_model_pair(monkeypatch):
    quality_payload = {
        "status": "OK",
        "components": [
            {
                "component": "ai_soc_worker",
                "status": "OK",
                "details": {
                    "details": {
                        "llm_last_profile": "quality",
                        "llm_last_model": "ai-soc-quality",
                        "llm_last_provider_key": "local_llama_cpp",
                        "llm_last_provider_type": "LOCAL_LLAMA_CPP",
                        "llm_last_fallback_used": False,
                    }
                },
            }
        ],
    }
    fast_payload = {
        "status": "OK",
        "components": [
            {
                "component": "ai_soc_worker",
                "status": "OK",
                "details": {
                    "details": {
                        "llm_last_profile": "fast",
                        "llm_last_model": "ai-soc-fast",
                        "llm_last_provider_key": "local_llama_cpp",
                        "llm_last_provider_type": "LOCAL_LLAMA_CPP",
                        "llm_last_fallback_used": False,
                    }
                },
            }
        ],
    }

    monkeypatch.setattr(metrics_router, "get_platform_health", lambda: quality_payload)

    metrics_router._collect_platform_health_metrics()
    output = metrics_router.generate_latest().decode("utf-8")
    llm_lines = [
        line
        for line in output.splitlines()
        if line.startswith("ai_soc_llm_model_in_use{")
    ]

    assert 'ai_soc_llm_model_in_use{model="ai-soc-quality",profile="quality"} 1.0' in output
    assert all("provider_key=" not in line for line in llm_lines)
    assert all("fallback=" not in line for line in llm_lines)
    assert 'model="qwen3.5:4b"' not in output

    monkeypatch.setattr(metrics_router, "get_platform_health", lambda: fast_payload)

    metrics_router._collect_platform_health_metrics()
    output = metrics_router.generate_latest().decode("utf-8")
    llm_lines = [
        line
        for line in output.splitlines()
        if line.startswith("ai_soc_llm_model_in_use{")
    ]

    assert 'ai_soc_llm_model_in_use{model="ai-soc-fast",profile="fast"} 1.0' in output
    assert 'ai_soc_llm_model_in_use{model="ai-soc-quality",profile="quality"}' not in output
    assert all("provider_key=" not in line for line in llm_lines)
    assert all("fallback=" not in line for line in llm_lines)
