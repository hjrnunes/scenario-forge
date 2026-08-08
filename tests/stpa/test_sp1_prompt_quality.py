"""Tests for Stage 1 prompt quality fixes."""

from __future__ import annotations

from pathlib import Path

from scenario_forge.stpa.infra.templates import TemplateLoader


PROMPTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "scenario_forge"
    / "stpa"
    / "system_model"
    / "prompts"
)


def _text(template_name: str) -> str:
    return (PROMPTS_DIR / template_name).read_text()


def _render(template_name: str, **variables: object) -> str:
    return TemplateLoader(PROMPTS_DIR).render_prompt(template_name, **variables)


def test_pqf_01_stage1a_quality_section_follows_structural_requirements() -> None:
    text = _text("stage1a_system.j2")
    assert "## Quality requirements" in text
    assert text.index("## Quality requirements") > text.index(
        "## Structural requirements"
    )


def test_pqf_02_stage1a_hazard_specificity_patterns() -> None:
    text = _text("stage1a_system.j2")
    assert "### Hazard specificity" in text
    assert "at least one specific component" in text
    assert "too generic" in text
    assert "LLM outputs are manipulated via prompt injection to bypass security controls" in text
    assert "System generates biased or discriminatory content" in text
    assert "patient chatbot generates an inaccurate surgical procedure explanation" in text
    assert "refund processing API executes an unauthorized refund amount" in text


def test_pqf_03_stage1a_loss_specificity() -> None:
    text = _text("stage1a_system.j2")
    assert "### Loss specificity" in text
    assert "concrete consequences" in text
    assert "not restatements of the risk card" in text


def test_pqf_04_stage1a_acronym_expansion() -> None:
    text = _text("stage1a_system.j2")
    assert "### Acronym expansion" in text
    assert "Personally Identifiable Information (PII)" in text
    assert "first expansion" in text
    assert "short form alone is acceptable" in text


def test_pqf_05_stage1a_gap_analysis_replaces_passive_definition() -> None:
    text = _text("stage1a_system.j2")
    assert "gap analysis" in text
    assert "key capabilities, integration points, and operational characteristics" in text
    assert "unaddressed capability failure is a use-case-derived loss" in text
    assert "empty use_case_losses list should be rare" in text
    assert "losses identified from the use-case description that no risk card covers" not in text


def test_pqf_06_stage1a_user_hazards_instruction() -> None:
    text = _text("stage1a_user.j2")
    assert "grounded in this system's specific architecture and mission" in text
    assert "concrete component, data flow, or integration point" in text
    assert "System-level hazards, each linking to at least one loss." not in text


def test_pqf_07_stage1a_user_gap_analysis_instruction() -> None:
    text = _text("stage1a_user.j2")
    assert "explicit gap analysis" in text
    assert "architectural component, integration point, and operational characteristic" in text
    assert "empty list is acceptable only if" in text
    assert "Losses from the use-case that no risk card covers." not in text


def test_pqf_08_stage1b_acronym_quality_requirements() -> None:
    text = _text("stage1b_system.j2")
    assert "## Quality requirements" in text
    assert "Retrieval-Augmented Generation (RAG)" in text
    assert "first expansion" in text
    assert "short form alone is acceptable" in text
    assert "KC sub-code identifiers" in text
    assert "KCX-HITL" in text


def test_pqf_09_system_templates_render_quality_requirements() -> None:
    stage1a = _render("stage1a_system.j2")
    stage1b = _render("stage1b_system.j2")
    for fragment in ("Quality requirements", "Hazard specificity", "Loss specificity",
                     "Acronym expansion", "gap analysis"):
        assert fragment in stage1a
    assert "Quality requirements" in stage1b
    assert "Retrieval-Augmented Generation (RAG)" in stage1b


def test_pqf_10_stage1a_user_renders_with_use_case_and_empty_risk_cards() -> None:
    rendered = _render(
        "stage1a_user.j2",
        use_case_text="A patient chatbot integrated with EHR systems",
        risk_cards=[],
    )
    assert "grounded in this system's specific architecture" in rendered
    assert "explicit gap analysis" in rendered
    assert "A patient chatbot integrated with EHR systems" in rendered


def test_pqf_11_stage1a_user_preserves_jinja_variables() -> None:
    text = _text("stage1a_user.j2")
    assert "{{ use_case_text }}" in text
    assert "{{ risk_cards }}" in text


def test_pqf_12_stage1a_preserves_existing_sections() -> None:
    text = _text("stage1a_system.j2")
    for section in (
        "## Structural requirements",
        "## ID conventions",
        "## Definitions",
        "## Output categories (four)",
    ):
        assert section in text


def test_pqf_13_stage1b_quality_section_follows_emphasis() -> None:
    text = _text("stage1b_system.j2")
    assert "## Emphasis" in text
    assert text.index("## Quality requirements") > text.index("## Emphasis")
