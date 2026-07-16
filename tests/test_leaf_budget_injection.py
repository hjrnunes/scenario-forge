"""Tests for explicit leaf budget injection into the call2 user prompt.

Covers:
1. Budget computation: 2*technique_count+2 for >0 techniques, 5 for zero.
2. Template variables technique_count and leaf_budget appear in rendered prompt.
3. Budget values are correct for 0, 1, 2, and 3 techniques.
"""

from __future__ import annotations

from unittest.mock import MagicMock

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


def _make_seed(
    seed_id: str = "AP-T2-05",
    technique_ids: list[str] | None = None,
) -> MagicMock:
    seed = MagicMock()
    seed.seed_id = seed_id
    seed.attack_pattern_name = "Test Mechanism"
    seed.attack_pattern_description = "A test mechanism"
    seed.threat_name = "Test Threat"
    seed.threat_description = "A test threat"
    seed.atlas_technique_ids = technique_ids or []
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
# Tests: budget computation
# ---------------------------------------------------------------------------


class TestLeafBudgetComputation:
    """Verify the budget formula produces correct values."""

    def _call_and_capture_prompt(
        self,
        technique_ids: list[str] | None = None,
        pinned: list[str] | None = None,
    ) -> str:
        """Call _call_attack_tree and return the user_prompt sent to the LLM."""
        seed = _make_seed(technique_ids=technique_ids)
        narrative = _make_narrative()
        client = MagicMock()
        client.complete.return_value = _make_llm_result(_VALID_TREE_YAML)

        _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            pinned_technique_ids=pinned,
        )

        # The first call's user_prompt kwarg
        call_kwargs = client.complete.call_args_list[0].kwargs
        return call_kwargs["user_prompt"]

    def test_zero_techniques_budget_5(self) -> None:
        """With 0 techniques, leaf_budget defaults to 5."""
        prompt = self._call_and_capture_prompt(technique_ids=[])
        assert "0 technique(s)" in prompt
        assert "at most 5 leaf nodes" in prompt

    def test_one_technique_budget_4(self) -> None:
        """With 1 technique, budget = 2*1+2 = 4."""
        prompt = self._call_and_capture_prompt(
            technique_ids=["AML.T0051"],
        )
        assert "1 technique(s)" in prompt
        assert "at most 4 leaf nodes" in prompt

    def test_two_techniques_budget_6(self) -> None:
        """With 2 techniques, budget = 2*2+2 = 6."""
        prompt = self._call_and_capture_prompt(
            technique_ids=["AML.T0051", "AML.T0052"],
        )
        assert "2 technique(s)" in prompt
        assert "at most 6 leaf nodes" in prompt

    def test_three_techniques_budget_8(self) -> None:
        """With 3 techniques, budget = 2*3+2 = 8."""
        prompt = self._call_and_capture_prompt(
            technique_ids=["AML.T0051", "AML.T0052", "AML.T0053"],
        )
        assert "3 technique(s)" in prompt
        assert "at most 8 leaf nodes" in prompt

    def test_pinned_techniques_override_seed(self) -> None:
        """When pinned_technique_ids is set, budget uses those, not seed's."""
        prompt = self._call_and_capture_prompt(
            technique_ids=["AML.T0051", "AML.T0052", "AML.T0053"],
            pinned=["AML.T0051"],
        )
        # Should use pinned count (1), not seed count (3)
        assert "1 technique(s)" in prompt
        assert "at most 4 leaf nodes" in prompt

    def test_leaf_budget_section_header_present(self) -> None:
        """The rendered prompt contains the Leaf Budget section header."""
        prompt = self._call_and_capture_prompt(technique_ids=["AML.T0051"])
        assert "## Leaf Budget (MANDATORY)" in prompt


class TestLeafBudgetTemplateRendering:
    """Verify the template renders correctly with budget variables."""

    def test_template_renders_without_error(self) -> None:
        """call2_user.j2 renders without Jinja2 UndefinedError."""
        from scenario_forge.prompts import render_prompt

        seed = _make_seed(technique_ids=["AML.T0051"])
        narrative = _make_narrative()

        # Should not raise jinja2.UndefinedError
        result = render_prompt(
            "call2_user.j2",
            seed=seed,
            use_case="test",
            arch_section="",
            actor_section="",
            technique_context="",
            technique_constraint="",
            narrative=narrative,
            technique_count=1,
            leaf_budget=4,
        )

        assert "1 technique(s)" in result
        assert "at most 4 leaf nodes" in result
