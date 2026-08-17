"""Hardening tests for the STPA HTML report module.

These tests target specific mutants that survived the initial mutation
testing pass.  They are kept separate from the main unit/acceptance
tests per the SwarmForge convention.
"""

from __future__ import annotations

import pytest

from scenario_forge.stpa.report.template import (
    _build_call_entry_html,
    _build_eval_gauge,
    build_html,
    build_llm_call_inspector,
)


# ---------------------------------------------------------------------------
# _build_eval_gauge — rate * 100 percentage calculation
# ---------------------------------------------------------------------------


class TestEvalGaugePercentage:
    """Verify that the gauge converts rate to percentage via * 100."""

    @pytest.mark.parametrize("rate,expected_pct", [
        (0.85, "85%"),
        (0.0, "0%"),
        (1.0, "100%"),
        (0.5, "50%"),
        (0.123, "12%"),
    ])
    def test_gauge_shows_correct_percentage(self, rate, expected_pct):
        """The gauge width and text must reflect rate * 100."""
        html = _build_eval_gauge("metric", rate)
        # The percentage appears in the width style and the pct text
        assert expected_pct in html, (
            f"Expected {expected_pct} in gauge HTML for rate={rate}, got: {html}"
        )

    def test_gauge_width_matches_percentage(self):
        """The CSS width must use rate * 100, not rate / 100."""
        html = _build_eval_gauge("metric", 0.85)
        # width:85% should be present, not width:0%
        assert "width:85%" in html or 'width: 85%' in html, (
            f"Expected width:85% for rate=0.85, got: {html}"
        )

    def test_gauge_zero_rate_shows_zero_width(self):
        """A rate of 0.0 must produce 0% width, not a tiny fraction."""
        html = _build_eval_gauge("metric", 0.0)
        assert "width:0%" in html or 'width: 0%' in html


# ---------------------------------------------------------------------------
# build_llm_call_inspector — success default and failed count
# ---------------------------------------------------------------------------


class TestLlmCallInspectorSuccessDefault:
    """Calls without a 'success' key must default to successful (True)."""

    def test_call_without_success_key_counts_as_success(self):
        """A call dict without 'success' should be counted as successful."""
        calls = [{"stage": "sp1", "step": "s1"}]  # no "success" key
        html = build_llm_call_inspector(calls)
        # Total should be 1, Successful should be 1, Failed should be 0
        assert "Total: <strong>1</strong>" in html
        assert "Successful: <strong>1</strong>" in html
        assert "Failed: <strong>0</strong>" in html

    def test_mixed_calls_with_and_without_success_key(self):
        """Mix of calls with and without 'success' key."""
        calls = [
            {"stage": "sp1", "step": "s1"},  # no key → success
            {"stage": "sp2", "step": "s2", "success": False},  # explicit fail
        ]
        html = build_llm_call_inspector(calls)
        assert "Total: <strong>2</strong>" in html
        assert "Successful: <strong>1</strong>" in html
        assert "Failed: <strong>1</strong>" in html

    def test_all_calls_without_success_key(self):
        """All calls without 'success' key should all be successful."""
        calls = [{"stage": "s1"}, {"stage": "s2"}, {"stage": "s3"}]
        html = build_llm_call_inspector(calls)
        assert "Successful: <strong>3</strong>" in html
        assert "Failed: <strong>0</strong>" in html


class TestLlmCallInspectorFailedCount:
    """The failed count must be total - success, not total + success."""

    def test_failed_count_is_total_minus_success(self):
        """Failed = total - success, not total + success."""
        calls = [
            {"stage": "s1", "success": True},
            {"stage": "s2", "success": True},
            {"stage": "s3", "success": False},
            {"stage": "s4", "success": False},
        ]
        html = build_llm_call_inspector(calls)
        assert "Total: <strong>4</strong>" in html
        assert "Successful: <strong>2</strong>" in html
        assert "Failed: <strong>2</strong>" in html

    def test_all_failed(self):
        """When all calls fail, failed count equals total."""
        calls = [
            {"stage": "s1", "success": False},
            {"stage": "s2", "success": False},
            {"stage": "s3", "success": False},
        ]
        html = build_llm_call_inspector(calls)
        assert "Total: <strong>3</strong>" in html
        assert "Successful: <strong>0</strong>" in html
        assert "Failed: <strong>3</strong>" in html

    def test_all_successful(self):
        """When all calls succeed, failed count is 0."""
        calls = [
            {"stage": "s1", "success": True},
            {"stage": "s2", "success": True},
        ]
        html = build_llm_call_inspector(calls)
        assert "Failed: <strong>0</strong>" in html


# ---------------------------------------------------------------------------
# _build_call_entry_html — success default and token/duration defaults
# ---------------------------------------------------------------------------


class TestCallEntrySuccessDefault:
    """Entry without 'success' key must default to successful (True)."""

    def test_entry_without_success_shows_ok_indicator(self):
        """An entry without 'success' key should show OK, not FAILED."""
        entry = {"stage": "sp1", "step": "s1"}  # no "success" key
        html = _build_call_entry_html(entry, 0)
        assert "OK" in html
        assert "FAILED" not in html
        assert "failed" not in html

    def test_entry_without_success_has_no_failed_class(self):
        """An entry without 'success' key should not have 'failed' CSS class."""
        entry = {"stage": "sp1", "step": "s1"}
        html = _build_call_entry_html(entry, 0)
        assert "call-entry failed" not in html
        # Should have the base class without 'failed'
        assert "call-entry" in html


class TestCallEntryTokenDefaults:
    """Entry without token keys must default to 0, not 1."""

    def test_entry_without_prompt_tokens_shows_zero(self):
        """Missing prompt_tokens should render as 0, not 1."""
        entry = {"stage": "sp1", "step": "s1"}
        html = _build_call_entry_html(entry, 0)
        # The token display is "tokens={prompt_tokens}+{completion_tokens}"
        # With defaults, it should be "tokens=0+0"
        assert "tokens=0+0" in html, (
            f"Expected tokens=0+0 for missing token keys, got: {html}"
        )

    def test_entry_without_completion_tokens_shows_zero(self):
        """Missing completion_tokens should render as 0."""
        entry = {"stage": "sp1", "step": "s1", "prompt_tokens": 100}
        html = _build_call_entry_html(entry, 0)
        assert "tokens=100+0" in html

    def test_entry_with_explicit_tokens(self):
        """Explicit token values are rendered correctly."""
        entry = {
            "stage": "sp1", "step": "s1",
            "prompt_tokens": 100, "completion_tokens": 50,
        }
        html = _build_call_entry_html(entry, 0)
        assert "tokens=100+50" in html


class TestCallEntryDurationDefault:
    """Entry without duration_ms must default to 0, not 1."""

    def test_entry_without_duration_shows_zero(self):
        """Missing duration_ms should render as 0ms, not 1ms."""
        entry = {"stage": "sp1", "step": "s1"}
        html = _build_call_entry_html(entry, 0)
        assert "duration=0ms" in html, (
            f"Expected duration=0ms for missing duration, got: {html}"
        )

    def test_entry_with_explicit_duration(self):
        """Explicit duration is rendered correctly."""
        entry = {"stage": "sp1", "step": "s1", "duration_ms": 250}
        html = _build_call_entry_html(entry, 0)
        assert "duration=250ms" in html


# ---------------------------------------------------------------------------
# build_html — has_sp2 and sp2_html logical guard
# ---------------------------------------------------------------------------


class TestBuildHtmlSp2Guard:
    """SP2 section should only render when has_sp2 AND sp2_html are truthy."""

    def test_has_sp2_true_but_empty_html_no_arrow(self):
        """When has_sp2=True but sp2_html='', no arrow or SP2 section."""
        html = build_html(
            sp1_html="<div>SP1</div>",
            sp2_html="",
            has_sp2=True,
            has_sp3=False,
        )
        # No produces-arrow between SP1 and SP2
        arrow_count = html.count('<div class="produces-arrow"')
        assert arrow_count == 0, (
            f"Expected 0 arrows with empty sp2_html, got {arrow_count}"
        )

    def test_has_sp2_false_with_html_no_arrow(self):
        """When has_sp2=False but sp2_html has content, no SP2 arrow."""
        html = build_html(
            sp1_html="<div>SP1</div>",
            sp2_html="<div>SP2 content</div>",
            has_sp2=False,
            has_sp3=False,
        )
        arrow_count = html.count('<div class="produces-arrow"')
        assert arrow_count == 0

    def test_has_sp2_true_with_html_renders_arrow(self):
        """When both has_sp2=True and sp2_html non-empty, arrow is present."""
        html = build_html(
            sp1_html="<div>SP1</div>",
            sp2_html="<div>SP2</div>",
            has_sp2=True,
            has_sp3=False,
        )
        arrow_count = html.count('<div class="produces-arrow"')
        assert arrow_count == 1

    def test_has_sp2_true_with_empty_html_does_not_render_sp2_content(self):
        """Empty sp2_html must not appear in the output even when has_sp2=True."""
        html = build_html(
            sp1_html="<div>SP1</div>",
            sp2_html="",
            has_sp2=True,
            has_sp3=False,
        )
        # The empty sp2_html string itself won't add content, but the key
        # test is that the produces-arrow is not rendered
        assert '<div class="produces-arrow"' not in html
