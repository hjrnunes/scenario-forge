"""Tests for STPA infra LLM client (InfraLLM-01 through InfraLLM-07)."""

from __future__ import annotations

import pytest

from scenario_forge.stpa.infra.llm import LLMClient, LLMResult


class TestInfraLLMClient:
    """LLM client construction and configuration."""

    def test_llm_01_resolves_base_url_from_env(self, monkeypatch):
        """InfraLLM-01: base_url resolved from SCENARIO_FORGE_MODEL_BASE_URL."""
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "http://test:8080")
        monkeypatch.delenv("SCENARIO_FORGE_API_KEY", raising=False)
        client = LLMClient()
        assert client.base_url == "http://test:8080"

    def test_llm_02_resolves_model_from_env(self, monkeypatch):
        """InfraLLM-02: model name resolved from SCENARIO_FORGE_MODEL_NAME."""
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_NAME", "test-model")
        client = LLMClient(base_url="http://test:8080")
        assert client.model == "test-model"

    def test_llm_03_explicit_args_override_env(self, monkeypatch):
        """InfraLLM-03: explicit args override environment variables."""
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "http://env:8080")
        client = LLMClient(base_url="http://explicit:8080", model="explicit-model")
        assert client.base_url == "http://explicit:8080"
        assert client.model == "explicit-model"

    def test_llm_04_without_base_url_raises_value_error(self, monkeypatch):
        """InfraLLM-04: no base_url raises ValueError with expected message."""
        monkeypatch.delenv("SCENARIO_FORGE_MODEL_BASE_URL", raising=False)
        with pytest.raises(ValueError, match="No LLM endpoint configured"):
            LLMClient()

    def test_llm_05_auto_injects_openrouter_headers(self, monkeypatch):
        """InfraLLM-05: OpenRouter base_url triggers default header injection."""
        monkeypatch.delenv("SCENARIO_FORGE_EXTRA_HEADERS", raising=False)
        client = LLMClient(base_url="https://openrouter.ai/api/v1")
        assert client.extra_headers is not None
        assert "HTTP-Referer" in client.extra_headers
        assert "X-Title" in client.extra_headers

    def test_llm_06_default_temperature_is_0_4(self, monkeypatch):
        """InfraLLM-06: default temperature is 0.4."""
        monkeypatch.delenv("SCENARIO_FORGE_TEMPERATURE", raising=False)
        client = LLMClient(base_url="http://test:8080")
        assert client.temperature == 0.4


class TestInfraLLMResult:
    """LLMResult data model."""

    def test_llm_07_result_carries_content_and_telemetry(self):
        """InfraLLM-07: LLMResult carries content and usage telemetry."""
        result = LLMResult(
            content="text",
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
        )
        assert result.content == "text"
        assert result.prompt_tokens == 100
        assert result.completion_tokens == 50
        assert result.duration_ms == 5000
