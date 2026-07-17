"""Tests for technique_id validation on AttackTreeNode.

Ensures both ATLAS (AML.T0054) and LAAF (S1, M2, L1) technique ID
formats are accepted, and invalid IDs are rejected.
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from scenario_forge.models.attack_tree import AttackTreeNode


def _make_leaf(technique_id: str | None = None) -> dict:
    """Build a minimal LEAF node dict with an optional technique_id."""
    node = {
        "id": "n1",
        "label": "Test node",
        "gate": "LEAF",
        "zone": "input",
    }
    if technique_id is not None:
        node["technique_id"] = technique_id
    return node


# ---- ATLAS format (AML.T + 4 digits, optional .3-digit sub) ----


class TestAtlasTechniqueIds:
    """ATLAS-format technique IDs should be accepted."""

    @pytest.mark.parametrize(
        "tid",
        [
            "AML.T0051",
            "AML.T0054",
            "AML.T0010",
            "AML.T9999",
            "AML.T0051.000",
            "AML.T0051.001",
            "AML.T0054.123",
        ],
    )
    def test_valid_atlas_ids(self, tid: str) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(technique_id=tid))
        assert node.technique_id == tid

    def test_none_is_valid(self) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(technique_id=None))
        assert node.technique_id is None


# ---- LAAF format ([SML] + digits) ----


class TestLaafTechniqueIds:
    """LAAF-format technique IDs should be accepted."""

    @pytest.mark.parametrize(
        "tid",
        [
            "S1",
            "S3",
            "M2",
            "M3",
            "M4",
            "L1",
            "S10",
            "M99",
            "L123",
        ],
    )
    def test_valid_laaf_ids(self, tid: str) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(technique_id=tid))
        assert node.technique_id == tid


# ---- Invalid IDs that should be rejected ----


class TestInvalidTechniqueIds:
    """Invalid technique IDs should be rejected by the pattern."""

    @pytest.mark.parametrize(
        "tid",
        [
            "T0054",           # missing AML. prefix
            "AML.T054",        # only 3 digits
            "AML.T00541",      # 5 digits
            "AML.T0054.01",    # sub-technique with 2 digits
            "AML.T0054.0001",  # sub-technique with 4 digits
            "aml.t0054",       # lowercase
            "ATLAS.T0054",     # wrong prefix
            "X1",              # invalid LAAF prefix letter
            "A1",              # not S, M, or L
            "s1",              # lowercase LAAF
            "S",               # missing digit
            "M0a",             # non-digit suffix
            "",                # empty string
            "random",          # arbitrary string
        ],
    )
    def test_invalid_ids_rejected(self, tid: str) -> None:
        with pytest.raises(ValidationError):
            AttackTreeNode.model_validate(_make_leaf(technique_id=tid))


# ---- Eval grounding regex for annotated text ----


class TestEvalGroundingTechniqueRegex:
    """The eval grounding regex should extract both ATLAS and LAAF IDs."""

    def test_atlas_id_extraction(self) -> None:
        from scenario_forge.eval.grounding import _TECHNIQUE_RE

        text = "The attacker uses [AML.T0054] jailbreak technique."
        matches = [m.group() for m in _TECHNIQUE_RE.finditer(text)]
        assert matches == ["[AML.T0054]"]

    def test_atlas_sub_technique_extraction(self) -> None:
        from scenario_forge.eval.grounding import _TECHNIQUE_RE

        text = "Indirect prompt injection [AML.T0051.001] is used."
        matches = [m.group() for m in _TECHNIQUE_RE.finditer(text)]
        assert matches == ["[AML.T0051.001]"]

    def test_laaf_id_extraction(self) -> None:
        from scenario_forge.eval.grounding import _TECHNIQUE_RE

        text = "The attacker employs [S1] social engineering and [M2] manipulation."
        matches = [m.group() for m in _TECHNIQUE_RE.finditer(text)]
        assert matches == ["[S1]", "[M2]"]

    def test_mixed_atlas_and_laaf(self) -> None:
        from scenario_forge.eval.grounding import _TECHNIQUE_RE

        text = "Combines [AML.T0054] with [L1] for the attack."
        matches = [m.group() for m in _TECHNIQUE_RE.finditer(text)]
        assert matches == ["[AML.T0054]", "[L1]"]

    def test_no_false_positives(self) -> None:
        from scenario_forge.eval.grounding import _TECHNIQUE_RE

        text = "The [API] endpoint uses [HTTP] protocol with [T7] threat."
        matches = [m.group() for m in _TECHNIQUE_RE.finditer(text)]
        # None of these should match: API/HTTP are not technique patterns,
        # and T7 is a threat ID not a LAAF technique ID
        assert matches == []
