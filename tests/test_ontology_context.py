"""Tests for _build_ontology_context in scenario_forge.pipeline.generate."""

from __future__ import annotations

from scenario_forge.pipeline.generate import _build_ontology_context


class TestBuildOntologyContext:
    """Tests for the focused ontology context block builder."""

    def test_basic_output_structure(self):
        """Block contains section header and all three sub-sections."""
        result = _build_ontology_context(
            entry_point_name="user prompts via chat interface",
            entry_point_direction="input",
            zones=["input", "reasoning"],
            technique_ids=["AML.T0054"],
        )
        assert "## Ontology Context" in result
        assert "### Pinned Entry Point" in result
        assert "### Active Zones" in result
        assert "### Pinned Techniques" in result

    def test_entry_point_with_direction(self):
        """Entry point name and direction appear in the output."""
        result = _build_ontology_context(
            entry_point_name="API endpoint",
            entry_point_direction="bidirectional",
            zones=["input"],
            technique_ids=[],
        )
        assert "API endpoint" in result
        assert "(direction: bidirectional)" in result

    def test_entry_point_without_direction(self):
        """When direction is None, no direction label appears."""
        result = _build_ontology_context(
            entry_point_name="chat interface",
            entry_point_direction=None,
            zones=["input"],
            technique_ids=[],
        )
        assert "chat interface" in result
        assert "(direction:" not in result

    def test_zones_listed(self):
        """All active zones appear in the output."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction=None,
            zones=["input", "reasoning", "tool_execution"],
            technique_ids=[],
        )
        assert "- input" in result
        assert "- reasoning" in result
        assert "- tool_execution" in result

    def test_empty_zones(self):
        """When zones is empty, the Active Zones section is omitted."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction=None,
            zones=[],
            technique_ids=["AML.T0054"],
        )
        assert "### Active Zones" not in result
        # Techniques section should still appear
        assert "### Pinned Techniques" in result

    def test_technique_with_known_id(self):
        """Known technique IDs include name and description."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction=None,
            zones=["input"],
            technique_ids=["AML.T0054"],
        )
        assert "**AML.T0054**" in result
        # Should have the technique name (LLM Jailbreak)
        assert "LLM Jailbreak" in result

    def test_technique_unknown_id(self):
        """Unknown technique IDs are still included (fallback to raw ID)."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction=None,
            zones=["input"],
            technique_ids=["AML.T9999"],
        )
        assert "**AML.T9999**" in result

    def test_no_techniques(self):
        """When technique_ids is empty, the Pinned Techniques section is omitted."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction="input",
            zones=["input", "reasoning"],
            technique_ids=[],
        )
        assert "### Pinned Techniques" not in result
        # Other sections should still appear
        assert "### Pinned Entry Point" in result
        assert "### Active Zones" in result

    def test_multiple_techniques(self):
        """Multiple technique IDs all appear in the output."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction=None,
            zones=["input"],
            technique_ids=["AML.T0054", "AML.T0053"],
        )
        assert "**AML.T0054**" in result
        assert "**AML.T0053**" in result

    def test_hard_constraint_language(self):
        """The block contains constraint language telling the LLM what NOT to do."""
        result = _build_ontology_context(
            entry_point_name="ep",
            entry_point_direction=None,
            zones=["input"],
            technique_ids=["AML.T0054"],
        )
        assert "ONLY" in result
        assert "Do NOT" in result

    def test_empty_entry_point_name(self):
        """Empty entry point name still produces the section."""
        result = _build_ontology_context(
            entry_point_name="",
            entry_point_direction=None,
            zones=["input"],
            technique_ids=[],
        )
        assert "### Pinned Entry Point" in result
        assert "## Ontology Context" in result
