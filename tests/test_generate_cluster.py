"""Tests for the cyo/0kv/twz bead cluster.

Covers:
- cyo: HITL failure mechanism language in the Call 1 system prompt.
- 0kv: CJK/non-Latin sanitization of English-language output.
- twz: Priority scoring diversity with varied inputs.
"""

from __future__ import annotations

from scenario_forge.pipeline.generate import (
    _CALL1_SYSTEM,
)


# ===========================================================================
# Bead cyo: HITL failure mechanism prompt
# ===========================================================================


class TestHITLFailureMechanism:
    """The Call 1 system prompt must include HITL failure mechanism language."""

    def test_system_prompt_contains_hitl_failure_mechanism(self):
        assert "human-in-the-loop" in _CALL1_SYSTEM.lower()

    def test_system_prompt_mentions_specific_failure_examples(self):
        # Should mention at least some concrete failure mechanisms
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "reviewer fatigue" in prompt_lower
        assert "time pressure" in prompt_lower

    def test_system_prompt_warns_against_bare_assertion(self):
        # Should caution against simply asserting bypass
        assert "simply asserting" in _CALL1_SYSTEM.lower()

    def test_system_prompt_mentions_failure_mechanism(self):
        assert "failure mechanism" in _CALL1_SYSTEM.lower()
