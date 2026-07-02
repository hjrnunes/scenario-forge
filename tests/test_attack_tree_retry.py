"""Tests for attack tree YAML generation retry logic (bead 40s).

Covers:
1. Successful parse on first attempt -- no retry.
2. Failed first attempt, successful retry -- returns the retried result.
3. Both attempts fail -- raises the original error.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
)
from scenario_forge.pipeline.generate import _call_attack_tree


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_TREE_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: LEAF
  zone: input
"""

_INVALID_YAML = "{{{{not yaml at all: ][]["


def _make_seed(seed_id: str = "AP-T2-05") -> MagicMock:
    seed = MagicMock()
    seed.seed_id = seed_id
    seed.mechanism_name = "Test Mechanism"
    seed.mechanism_description = "A test mechanism"
    seed.threat_name = "Test Threat"
    seed.threat_description = "A test threat"
    seed.atlas_technique_ids = []
    seed.owasp_llm_ids = []
    seed.agentic_threat_ids = []
    return seed


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Test narrative",
        summary="A test summary",
        entry_point="user chat interface",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft malicious input",
                effect="Input accepted",
                control_point=None,
            ),
        ],
    )


def _make_llm_result(content: str) -> LLMResult:
    return LLMResult(
        content=content,
        prompt_tokens=100,
        completion_tokens=200,
        duration_ms=500,
        system_prompt="system",
        user_prompt="user",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAttackTreeRetry:
    """Tests for retry logic in _call_attack_tree."""

    def test_success_on_first_attempt_no_retry(self) -> None:
        """When YAML parses successfully on the first try, no retry is made."""
        seed = _make_seed()
        narrative = _make_narrative()
        first_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.return_value = first_result

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
        )

        assert tree.root.id == "n1"
        assert result is first_result
        # Only one call to the LLM
        assert client.complete.call_count == 1

    def test_retry_on_first_failure_returns_retried_result(self) -> None:
        """When first attempt fails but retry succeeds, return retry result."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
        )

        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

        # The retry call's user prompt should mention the error
        retry_call_args = client.complete.call_args_list[1]
        retry_user_prompt = retry_call_args.kwargs.get(
            "user_prompt", retry_call_args[1] if len(retry_call_args[1]) > 1 else ""
        )
        assert "not valid YAML" in retry_user_prompt

    def test_both_attempts_fail_raises_original_error(self) -> None:
        """When both attempts fail, the original error is raised."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result("also: [broken: yaml: {{")

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception) as exc_info:
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
            )

        # Should be the original error, not the retry error
        assert client.complete.call_count == 2
        # The original error is from parsing _INVALID_YAML
        assert "even after colon sanitization" in str(exc_info.value)

    def test_retry_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """A WARNING log is emitted when the first parse fails."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        import logging

        with caplog.at_level(logging.WARNING, logger="scenario_forge.pipeline.generate"):
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
            )

        assert any(
            "Attack tree YAML parse failed, retrying" in record.message
            for record in caplog.records
        )
