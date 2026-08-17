"""Tests for STPA infra LLM client (InfraLLM-01 through InfraLLM-07)."""

from __future__ import annotations

from unittest.mock import MagicMock

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

    def test_llm_06a_explicit_max_tokens_override_env(self, monkeypatch):
        """InfraLLM-06a: explicit max_completion_tokens overrides env var."""
        monkeypatch.setenv("SCENARIO_FORGE_MAX_COMPLETION_TOKENS", "2000")
        client = LLMClient(base_url="http://test:8080", max_completion_tokens=500)
        assert client.max_completion_tokens == 500

    def test_llm_06b_max_tokens_from_env_when_not_explicit(self, monkeypatch):
        """InfraLLM-06b: max_completion_tokens resolved from env when not explicit."""
        monkeypatch.setenv("SCENARIO_FORGE_MAX_COMPLETION_TOKENS", "2000")
        client = LLMClient(base_url="http://test:8080")
        assert client.max_completion_tokens == 2000

    def test_llm_06c_max_tokens_none_when_unspecified(self, monkeypatch):
        """InfraLLM-06c: max_completion_tokens is None when not specified."""
        monkeypatch.delenv("SCENARIO_FORGE_MAX_COMPLETION_TOKENS", raising=False)
        client = LLMClient(base_url="http://test:8080")
        assert client.max_completion_tokens is None


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


class TestInfraLLMComplete:
    """LLMClient.complete method with mocked OpenAI client."""

    def _make_mock_client(self, content="response", parsed=None,
                          prompt_tokens=100, completion_tokens=50,
                          usage="default"):
        """Build a mock OpenAI client with a canned response."""
        client = LLMClient(base_url="http://test:8080", model="test-model")

        mock_msg = MagicMock()
        mock_msg.content = content
        mock_msg.parsed = parsed if parsed is not None else content

        mock_choice = MagicMock()
        mock_choice.message = mock_msg

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        if usage == "default":
            mock_response.usage = MagicMock(
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens
            )
        elif usage is None:
            mock_response.usage = None
        else:
            mock_response.usage = usage

        client._client = MagicMock()
        client._client.chat.completions.create.return_value = mock_response
        client._client.beta.chat.completions.parse.return_value = mock_response
        return client

    def test_complete_unstructured_returns_content(self):
        """Complete without response_format returns plain content."""
        client = self._make_mock_client(content="hello world")
        result = client.complete("system", "user")
        assert result.content == "hello world"
        assert result.system_prompt == "system"
        assert result.user_prompt == "user"
        assert result.duration_ms >= 0
        assert result.duration_ms < 60000

    def test_complete_structured_returns_parsed(self):
        """Complete with response_format returns parsed content."""
        client = self._make_mock_client(parsed={"key": "value"})
        result = client.complete("system", "user", response_format=dict)
        assert result.content == {"key": "value"}

    def test_complete_passes_effective_max_tokens(self):
        """Complete passes max_completion_tokens to the API."""
        client = self._make_mock_client()
        client.complete("s", "u", max_completion_tokens=500)
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["max_completion_tokens"] == 500

    def test_complete_passes_effective_temperature(self):
        """Complete passes temperature to the API."""
        client = self._make_mock_client()
        client.complete("s", "u", temperature=0.9)
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["temperature"] == 0.9

    def test_complete_uses_default_max_tokens_when_not_explicit(self):
        """Complete uses self.max_completion_tokens when not passed explicitly."""
        client = self._make_mock_client()
        client.max_completion_tokens = 2000
        client.complete("s", "u")
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["max_completion_tokens"] == 2000

    def test_complete_omits_max_tokens_when_none(self):
        """Complete omits max_completion_tokens when both explicit and default are None."""
        client = self._make_mock_client()
        client.max_completion_tokens = None
        client.complete("s", "u")
        call_kwargs = client._client.chat.completions.create.call_args
        assert "max_completion_tokens" not in call_kwargs.kwargs

    def test_complete_returns_telemetry_from_usage(self):
        """Complete returns prompt_tokens and completion_tokens from usage."""
        client = self._make_mock_client(
            usage=MagicMock(prompt_tokens=200, completion_tokens=100)
        )
        result = client.complete("s", "u")
        assert result.prompt_tokens == 200
        assert result.completion_tokens == 100

    def test_complete_handles_missing_usage(self):
        """Complete handles response with no usage info (defaults to 0)."""
        client = self._make_mock_client(usage=None)
        result = client.complete("s", "u")
        assert result.prompt_tokens == 0
        assert result.completion_tokens == 0
