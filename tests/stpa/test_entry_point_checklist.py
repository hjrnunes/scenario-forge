"""Tests for entry point category checklist in stage1b_system.j2 — EPCL-01 through EPCL-08.

Verifies that the stage1b_system.j2 template contains a 5-category entry point
checklist with concrete examples, controllability/direction annotations,
and notes about indirect ingress and dual-listing.
"""

from __future__ import annotations


import pytest
from jinja2 import Environment, FileSystemLoader

from scenario_forge.stpa.system_model._constants import PROMPTS_DIR


def _load_template_text() -> str:
    """Load the raw text of stage1b_system.j2."""
    path = PROMPTS_DIR / "stage1b_system.j2"
    return path.read_text(encoding="utf-8")


def _render_template() -> str:
    """Render stage1b_system.j2 with no variables."""
    env = Environment(
        loader=FileSystemLoader(str(PROMPTS_DIR)),
        keep_trailing_newline=True,
    )
    template = env.get_template("stage1b_system.j2")
    return template.render()


# ---------------------------------------------------------------------------
# EPCL-01: template contains entry point category checklist
# ---------------------------------------------------------------------------


class TestEPCL01ChecklistPresent:
    """EPCL-01: stage1b_system.j2 contains entry point category checklist."""

    def test_template_contains_checklist(self):
        text = _load_template_text()
        assert "entry point" in text.lower()
        assert "checklist" in text.lower()


# ---------------------------------------------------------------------------
# EPCL-02: all five entry point categories with examples
# ---------------------------------------------------------------------------


class TestEPCL02AllCategoriesWithExamples:
    """EPCL-02: stage1b_system.j2 contains all five entry point categories with examples."""

    @pytest.mark.parametrize(
        "category_name, example_text",
        [
            ("User input surfaces", "chat interface"),
            ("RAG/retrieval data sources", "knowledge base"),
            ("Tool execution results", "API call"),
            ("External data feeds", "third-party"),
            ("Admin/config interfaces", "admin dashboard"),
        ],
        ids=[
            "user_input_surfaces",
            "rag_retrieval",
            "tool_execution",
            "external_data_feeds",
            "admin_config",
        ],
    )
    def test_template_contains_category_and_example(self, category_name, example_text):
        text = _load_template_text()
        assert category_name in text
        assert example_text in text


# ---------------------------------------------------------------------------
# EPCL-03: each category specifies controllability
# ---------------------------------------------------------------------------


class TestEPCL03ControllabilitySpecified:
    """EPCL-03: each category specifies controllability."""

    @pytest.mark.parametrize(
        "category_name, controllability",
        [
            ("User input surfaces", "direct"),
            ("RAG/retrieval data sources", "indirect"),
            ("Tool execution results", "indirect"),
            ("External data feeds", "indirect"),
            ("Admin/config interfaces", "direct"),
        ],
        ids=[
            "user_input_direct",
            "rag_indirect",
            "tool_indirect",
            "external_indirect",
            "admin_direct",
        ],
    )
    def test_category_has_controllability(self, category_name, controllability):
        text = _load_template_text()
        assert category_name in text
        assert controllability in text


# ---------------------------------------------------------------------------
# EPCL-04: RAG retrieval category notes indirect ingress via poisoned content
# ---------------------------------------------------------------------------


class TestEPCL04RagIndirectIngress:
    """EPCL-04: RAG retrieval category notes indirect ingress via poisoned content."""

    def test_rag_category_notes_indirect_ingress(self):
        text = _load_template_text()
        assert "RAG/retrieval data sources" in text
        assert "indirect ingress" in text.lower()
        assert "poisoned" in text.lower()


# ---------------------------------------------------------------------------
# EPCL-05: template notes component can appear in both tool_inventory and entry_points
# ---------------------------------------------------------------------------


class TestEPCL05DualListing:
    """EPCL-05: template notes component can appear in both tool_inventory and entry_points."""

    def test_template_notes_dual_listing(self):
        text = _load_template_text()
        assert "both" in text.lower()
        assert "tool_inventory" in text
        assert "entry_points" in text


# ---------------------------------------------------------------------------
# EPCL-06: template renders without errors with checklist content
# ---------------------------------------------------------------------------


class TestEPCL06RendersWithoutErrors:
    """EPCL-06: template renders without errors with checklist content."""

    def test_template_renders_with_categories(self):
        rendered = _render_template()
        assert "User input surfaces" in rendered
        assert "RAG/retrieval data sources" in rendered
        assert "Tool execution results" in rendered
        assert "External data feeds" in rendered
        assert "Admin/config interfaces" in rendered


# ---------------------------------------------------------------------------
# EPCL-07: checklist preserves existing template sections
# ---------------------------------------------------------------------------


class TestEPCL07PreservesExistingSections:
    """EPCL-07: checklist preserves existing template sections."""

    @pytest.mark.parametrize(
        "section_header",
        [
            "## Schneider zones",
            "## Rules",
            "## Emphasis",
            "## Quality requirements",
        ],
        ids=["schneider_zones", "rules", "emphasis", "quality_requirements"],
    )
    def test_existing_sections_preserved(self, section_header):
        text = _load_template_text()
        assert section_header in text


# ---------------------------------------------------------------------------
# EPCL-08: checklist section appears after Rules section
# ---------------------------------------------------------------------------


class TestEPCL08ChecklistAfterRules:
    """EPCL-08: checklist section appears after the Rules section."""

    def test_checklist_after_rules(self):
        text = _load_template_text()
        rules_pos = text.find("## Rules")
        assert rules_pos != -1, "## Rules section not found"
        # The entry point checklist should appear after the Rules section
        after_rules = text[rules_pos:]
        assert "entry point" in after_rules.lower()
        assert "checklist" in after_rules.lower()
