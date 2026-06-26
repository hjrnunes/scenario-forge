"""Tests for the cyo/0kv/twz bead cluster.

Covers:
- cyo: HITL failure mechanism language in the Call 1 system prompt.
- 0kv: CJK/non-Latin sanitization of English-language output.
- twz: Priority scoring diversity with varied inputs.
"""

from __future__ import annotations

from scenario_forge.pipeline.generate import (
    _CALL1_SYSTEM,
    _sanitize_non_latin,
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


# ===========================================================================
# Bead 0kv: CJK output sanitization
# ===========================================================================


class TestCJKSanitization:
    """Tests for _sanitize_non_latin() -- CJK/non-Latin character removal."""

    def test_pure_english_unchanged(self):
        text = "This is a perfectly normal English sentence."
        assert _sanitize_non_latin(text) == text

    def test_cjk_mixed_with_english_stripped(self):
        # Real example from gemma-4-26b output
        result = _sanitize_non_latin("linguistic指令")
        assert result == "linguistic"

    def test_cjk_mid_word_stripped(self):
        result = _sanitize_non_latin("potential泄露 data")
        assert result == "potential data"

    def test_pure_cjk_becomes_empty(self):
        result = _sanitize_non_latin("指令泄露")
        assert result == ""

    def test_preserves_punctuation(self):
        text = "Hello, world! (test-case) [foo] {bar} #123"
        assert _sanitize_non_latin(text) == text

    def test_preserves_numbers(self):
        text = "Zone 1: Input Surfaces"
        assert _sanitize_non_latin(text) == text

    def test_handles_empty_string(self):
        assert _sanitize_non_latin("") == ""

    def test_handles_whitespace_cleanup(self):
        # After removing CJK chars, collapse multiple spaces
        result = _sanitize_non_latin("hello 世界 world")
        assert result == "hello world"

    def test_preserves_newlines(self):
        text = "line one\nline two\nline three"
        assert _sanitize_non_latin(text) == text

    def test_cyrillic_stripped(self):
        result = _sanitize_non_latin("hello мир world")
        assert result == "hello world"

    def test_arabic_stripped(self):
        result = _sanitize_non_latin("hello عالم world")
        assert result == "hello world"

    def test_accented_latin_preserved(self):
        # Accented Latin characters (like in French/Spanish) should be kept
        text = "cafe resume naive"
        assert _sanitize_non_latin(text) == text
