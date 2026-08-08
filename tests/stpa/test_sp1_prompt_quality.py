"""Tests for Stage 1 prompt quality fixes."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model import PROMPTS_DIR

_STAGE1A_SYSTEM = "stage1a_system.j2"
_STAGE1A_USER = "stage1a_user.j2"
_STAGE1B_SYSTEM = "stage1b_system.j2"

# System templates that take zero template variables — they are pure
# static prompts whose rendered output equals their raw text.
_ZERO_VAR_SYSTEM_TEMPLATES = [
    "stage1a_system.j2",
    "stage1b_system.j2",
    "stage2_call1_system.j2",
    "stage2_call2_system.j2",
    "stage2_call3_system.j2",
    "revision_system.j2",
]


def _text(template_name: str) -> str:
    return (PROMPTS_DIR / template_name).read_text()


def _render(template_name: str, **variables: object) -> str:
    return TemplateLoader(PROMPTS_DIR).render_prompt(template_name, **variables)


def test_pqf_01_stage1a_quality_section_follows_structural_requirements() -> None:
    text = _text(_STAGE1A_SYSTEM)
    assert "## Quality requirements" in text
    assert text.index("## Quality requirements") > text.index(
        "## Structural requirements"
    )


def test_pqf_02_stage1a_hazard_specificity_patterns() -> None:
    text = _text(_STAGE1A_SYSTEM)
    assert "### Hazard specificity" in text
    assert "at least one specific component" in text
    assert "too generic" in text
    assert "LLM outputs are manipulated via prompt injection to bypass security controls" in text
    assert "System generates biased or discriminatory content" in text
    assert "patient chatbot generates an inaccurate surgical procedure explanation" in text
    assert "refund processing API executes an unauthorized refund amount" in text


def test_pqf_03_stage1a_loss_specificity() -> None:
    text = _text(_STAGE1A_SYSTEM)
    assert "### Loss specificity" in text
    assert "concrete consequences" in text
    assert "not restatements of the risk card" in text


def test_pqf_04_stage1a_acronym_expansion() -> None:
    text = _text(_STAGE1A_SYSTEM)
    assert "### Acronym expansion" in text
    assert "Personally Identifiable Information (PII)" in text
    assert "first expansion" in text
    assert "short form alone is acceptable" in text


def test_pqf_05_stage1a_gap_analysis_replaces_passive_definition() -> None:
    text = _text(_STAGE1A_SYSTEM)
    assert "gap analysis" in text
    assert "key capabilities, integration points, and operational characteristics" in text
    assert "unaddressed capability failure is a use-case-derived loss" in text
    assert "empty use_case_losses list should be rare" in text
    assert "losses identified from the use-case description that no risk card covers" not in text


def test_pqf_06_stage1a_user_hazards_instruction() -> None:
    text = _text(_STAGE1A_USER)
    assert "grounded in this system's specific architecture and mission" in text
    assert "concrete component, data flow, or integration point" in text
    assert "System-level hazards, each linking to at least one loss." not in text


def test_pqf_07_stage1a_user_gap_analysis_instruction() -> None:
    text = _text(_STAGE1A_USER)
    assert "explicit gap analysis" in text
    assert "architectural component, integration point, and operational characteristic" in text
    assert "empty list is acceptable only if" in text
    assert "Losses from the use-case that no risk card covers." not in text


def test_pqf_08_stage1b_acronym_quality_requirements() -> None:
    text = _text(_STAGE1B_SYSTEM)
    assert "## Quality requirements" in text
    assert "Retrieval-Augmented Generation (RAG)" in text
    assert "first expansion" in text
    assert "short form alone is acceptable" in text
    assert "KC sub-code identifiers" in text
    assert "KCX-HITL" in text


def test_pqf_09_system_templates_render_quality_requirements() -> None:
    stage1a = _render(_STAGE1A_SYSTEM)
    stage1b = _render(_STAGE1B_SYSTEM)
    for fragment in (
        "Quality requirements",
        "Hazard specificity",
        "Loss specificity",
        "Acronym expansion",
        "gap analysis",
    ):
        assert fragment in stage1a
    assert "Quality requirements" in stage1b
    assert "Retrieval-Augmented Generation (RAG)" in stage1b


def test_pqf_10_stage1a_user_renders_with_use_case_and_empty_risk_cards() -> None:
    rendered = _render(
        _STAGE1A_USER,
        use_case_text="A patient chatbot integrated with EHR systems",
        risk_cards=[],
    )
    assert "grounded in this system's specific architecture" in rendered
    assert "explicit gap analysis" in rendered
    assert "A patient chatbot integrated with EHR systems" in rendered


def test_pqf_11_stage1a_user_preserves_jinja_variables() -> None:
    text = _text(_STAGE1A_USER)
    assert "{{ use_case_text }}" in text
    assert "{% if risk_cards %}" in text
    assert "{{ card.risk_id }}" in text


def test_pqf_12_stage1a_preserves_existing_sections() -> None:
    text = _text(_STAGE1A_SYSTEM)
    for section in (
        "## Structural requirements",
        "## ID conventions",
        "## Definitions",
        "## Output categories (four)",
    ):
        assert section in text


def test_pqf_13_stage1b_quality_section_follows_emphasis() -> None:
    text = _text(_STAGE1B_SYSTEM)
    assert "## Emphasis" in text
    assert text.index("## Quality requirements") > text.index("## Emphasis")


# ---------------------------------------------------------------------------
# Property-based tests for template rendering
#
# These tests verify invariants that hold across broad input ranges:
#
# - **Zero-variable system templates render without error**: every static
#   system prompt is valid Jinja2 and renders to its raw text.
# - **Rendering idempotence**: rendering a system template twice produces
#   identical output.
# - **No unrendered Jinja2 markers**: rendered system templates contain no
#   ``{{`` or ``{%`` sequences.
# - **Use-case text injection**: ``stage1a_user.j2`` always includes the
#   provided ``use_case_text`` verbatim in its rendered output.
# - **Empty-risk-cards fallback**: ``stage1a_user.j2`` with an empty list
#   always shows the "No risk cards provided" fallback.
# - **Section ordering invariant**: "Quality requirements" always follows
#   "Structural requirements" in the rendered ``stage1a_system.j2``.
# ---------------------------------------------------------------------------

# Printable text without Jinja2 delimiters — safe for variable injection.
_st_safe_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters=("{", "}")),
    min_size=1,
    max_size=200,
)


class TestTemplateRenderingProperties:
    """Property-based invariants for prompt template rendering."""

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqp_01_zero_var_system_template_renders_to_raw_text(
        self,
        template_name: str,
    ) -> None:
        """A zero-variable system template renders identically to its raw text."""
        rendered = _render(template_name)
        raw = _text(template_name)
        assert rendered == raw

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqp_02_system_template_rendering_is_idempotent(
        self,
        template_name: str,
    ) -> None:
        """Rendering a system template twice produces identical output."""
        first = _render(template_name)
        second = _render(template_name)
        assert first == second

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqp_03_no_unrendered_jinja_markers_in_system_templates(
        self,
        template_name: str,
    ) -> None:
        """Rendered system templates contain no ``{{`` or ``{%`` markers."""
        rendered = _render(template_name)
        assert "{{" not in rendered
        assert "{%" not in rendered

    @given(use_case_text=_st_safe_text)
    @settings(max_examples=50, deadline=None)
    def test_pqp_04_stage1a_user_injects_use_case_text_verbatim(
        self,
        use_case_text: str,
    ) -> None:
        """stage1a_user.j2 always includes the provided use_case_text verbatim."""
        rendered = _render(_STAGE1A_USER, use_case_text=use_case_text, risk_cards=[])
        assert use_case_text in rendered

    @given(use_case_text=_st_safe_text)
    @settings(max_examples=20, deadline=None)
    def test_pqp_05_stage1a_user_empty_risk_cards_shows_fallback(
        self,
        use_case_text: str,
    ) -> None:
        """stage1a_user.j2 with empty risk_cards shows the fallback message."""
        rendered = _render(_STAGE1A_USER, use_case_text=use_case_text, risk_cards=[])
        assert "No risk cards provided" in rendered

    @given(use_case_text=_st_safe_text)
    @settings(max_examples=20, deadline=None)
    def test_pqp_06_stage1a_quality_section_follows_structural_in_render(
        self,
        use_case_text: str,
    ) -> None:
        """In rendered stage1a_system, Quality requirements follows Structural."""
        rendered = _render(_STAGE1A_SYSTEM)
        assert "## Structural requirements" in rendered
        assert "## Quality requirements" in rendered
        assert rendered.index("## Quality requirements") > rendered.index(
            "## Structural requirements"
        )
