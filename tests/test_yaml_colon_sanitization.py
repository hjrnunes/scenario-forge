"""Tests for YAML colon sanitization in attack tree parsing."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

from scenario_forge.pipeline.generate import (
    _parse_attack_tree_yaml,
    _sanitize_yaml_colons,
)


# ---------------------------------------------------------------------------
# _sanitize_yaml_colons unit tests
# ---------------------------------------------------------------------------


class TestSanitizeYamlColons:
    """Tests for the _sanitize_yaml_colons helper."""

    def test_value_with_colon_is_quoted(self) -> None:
        raw = "description: Human-in-the-loop: Investigator approval"
        result = _sanitize_yaml_colons(raw)
        assert result == 'description: "Human-in-the-loop: Investigator approval"'

    def test_value_without_colon_unchanged(self) -> None:
        raw = "description: A simple description"
        result = _sanitize_yaml_colons(raw)
        assert result == raw

    def test_already_double_quoted_value_unchanged(self) -> None:
        raw = 'description: "Already: quoted"'
        result = _sanitize_yaml_colons(raw)
        assert result == raw

    def test_already_single_quoted_value_unchanged(self) -> None:
        raw = "description: 'Already: quoted'"
        result = _sanitize_yaml_colons(raw)
        assert result == raw

    def test_mapping_key_without_value_unchanged(self) -> None:
        """A key followed by nothing (nested mapping) should not be modified."""
        raw = "root:\n  id: n1"
        result = _sanitize_yaml_colons(raw)
        assert result == raw

    def test_indented_value_with_colon(self) -> None:
        raw = "    description: Phase 1: Reconnaissance"
        result = _sanitize_yaml_colons(raw)
        assert result == '    description: "Phase 1: Reconnaissance"'

    def test_list_item_with_colon_in_value(self) -> None:
        raw = "  - label: Step 1: Initial access"
        result = _sanitize_yaml_colons(raw)
        assert result == '  - label: "Step 1: Initial access"'

    def test_multiple_colons_in_value(self) -> None:
        raw = "description: A: B: C: D"
        result = _sanitize_yaml_colons(raw)
        assert result == 'description: "A: B: C: D"'

    def test_internal_double_quotes_escaped(self) -> None:
        raw = 'description: He said "hello": world'
        result = _sanitize_yaml_colons(raw)
        assert result == 'description: "He said \\"hello\\": world"'

    def test_multiline_yaml_mixed(self) -> None:
        raw = (
            "id: tree-1\n"
            "goal: Test goal\n"
            "root:\n"
            "  id: n1\n"
            "  label: Root: main attack\n"
            "  gate: AND\n"
            "  description: Simple description\n"
        )
        result = _sanitize_yaml_colons(raw)
        lines = result.split("\n")
        # Only the label line should be modified
        assert lines[0] == "id: tree-1"
        assert lines[1] == "goal: Test goal"
        assert lines[2] == "root:"
        assert lines[3] == "  id: n1"
        assert lines[4] == '  label: "Root: main attack"'
        assert lines[5] == "  gate: AND"
        assert lines[6] == "  description: Simple description"

    def test_sanitized_yaml_is_parseable(self) -> None:
        """The whole point: after sanitization, YAML should parse."""
        raw = (
            "id: tree-1\n"
            "goal: Compromise: the target\n"
            "root:\n"
            "  id: n1\n"
            "  label: Step 1: Initial access via phishing\n"
            "  gate: LEAF\n"
            "  zone: input\n"
        )
        # Confirm raw fails
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(raw)

        sanitized = _sanitize_yaml_colons(raw)
        data = yaml.safe_load(sanitized)
        assert data["id"] == "tree-1"
        assert data["goal"] == "Compromise: the target"
        assert data["root"]["label"] == "Step 1: Initial access via phishing"


# ---------------------------------------------------------------------------
# _parse_attack_tree_yaml integration tests
# ---------------------------------------------------------------------------


class TestParseAttackTreeYamlColonHandling:
    """Test that _parse_attack_tree_yaml recovers from colon-in-value errors."""

    @staticmethod
    def _minimal_tree_yaml(description: str = "Clean description") -> str:
        """Return a minimal valid attack tree YAML string."""
        return (
            "id: tree-T2-S5\n"
            "seed_id: T2-S5\n"
            "goal: Test goal\n"
            "root:\n"
            "  id: n1\n"
            "  label: Root attack\n"
            f"  description: {description}\n"
            "  gate: LEAF\n"
            "  zone: input\n"
        )

    @staticmethod
    def _mock_seed(seed_id: str = "T2-S5") -> MagicMock:
        seed = MagicMock()
        seed.id = seed_id
        return seed

    def test_clean_yaml_parses_normally(self) -> None:
        raw = self._minimal_tree_yaml("A clean description")
        tree = _parse_attack_tree_yaml(raw, self._mock_seed())
        assert tree.root.description == "A clean description"

    def test_colon_in_value_recovered(self) -> None:
        """The exact bug scenario: unquoted colon in a description value."""
        raw = self._minimal_tree_yaml(
            "Human-in-the-loop: Investigator/Supervisor approval"
        )
        # Confirm this YAML is indeed broken for raw parsing
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(raw)

        # But _parse_attack_tree_yaml should recover
        tree = _parse_attack_tree_yaml(raw, self._mock_seed())
        assert tree.root.description == (
            "Human-in-the-loop: Investigator/Supervisor approval"
        )

    def test_colon_in_label_recovered(self) -> None:
        raw = (
            "id: tree-T2-S5\n"
            "seed_id: T2-S5\n"
            "goal: Test goal\n"
            "root:\n"
            "  id: n1\n"
            "  label: Phase 1: Reconnaissance via OSINT\n"
            "  gate: LEAF\n"
            "  zone: input\n"
        )
        tree = _parse_attack_tree_yaml(raw, self._mock_seed())
        assert tree.root.label == "Phase 1: Reconnaissance via OSINT"

    def test_code_fenced_yaml_with_colons(self) -> None:
        """Markdown code fences should be stripped before sanitization."""
        raw = (
            "```yaml\n"
            "id: tree-T2-S5\n"
            "seed_id: T2-S5\n"
            "goal: Test goal\n"
            "root:\n"
            "  id: n1\n"
            "  label: Step 1: Access\n"
            "  gate: LEAF\n"
            "  zone: input\n"
            "```\n"
        )
        tree = _parse_attack_tree_yaml(raw, self._mock_seed())
        assert tree.root.label == "Step 1: Access"

    def test_irrecoverable_yaml_raises(self) -> None:
        """Completely broken YAML should still raise after sanitization."""
        raw = "{{{{not yaml at all: ][]["
        with pytest.raises(yaml.YAMLError, match="even after colon sanitization"):
            _parse_attack_tree_yaml(raw, self._mock_seed())
