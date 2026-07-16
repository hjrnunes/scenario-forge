"""Tests for tree-anchored skeleton builder.

Covers:
1. Single technique, single zone
2. Multiple techniques across different zones
3. Technique that doesn't match any narrative step (fallback zone)
4. Empty technique list
5. Skeleton formatting as YAML for prompt injection
6. Post-generation validation of mandatory leaves
7. Integration: skeleton section appears in rendered call2 prompt
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep
from scenario_forge.pipeline.generate import (
    _build_tree_skeleton,
    _format_skeleton_yaml,
    _validate_mandatory_leaves,
    _call_attack_tree,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_narrative(
    steps: list[NarrativeStep] | None = None,
    zone_sequence: list[str] | None = None,
) -> NarrativeLayer:
    if steps is None:
        steps = [
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft a prompt injection [AML.T0054] payload",
                effect="Input accepted by the system",
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="LLM processes the injected prompt",
                effect="Agent reasoning compromised",
            ),
            NarrativeStep(
                step_number=3,
                zone="tool_execution",
                action="Agent invokes unauthorized tool [AML.T0053]",
                effect="Tool executes attacker's command",
            ),
        ]
    if zone_sequence is None:
        zone_sequence = list(dict.fromkeys(s.zone for s in steps))
    return NarrativeLayer(
        title="Test narrative",
        summary="A test summary",
        entry_point="user chat interface",
        zone_sequence=zone_sequence,
        steps=steps,
    )


def _make_tree(technique_ids: list[str]) -> AttackTree:
    """Build a minimal valid tree with given technique IDs on leaves."""
    if not technique_ids:
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.LEAF, zone="input"
        )
    elif len(technique_ids) == 1:
        root = AttackTreeNode(
            id="n1",
            label="Root attack",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Setup step",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Technique leaf",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id=technique_ids[0],
                ),
            ],
        )
    else:
        children = []
        for i, tid in enumerate(technique_ids, start=1):
            children.append(
                AttackTreeNode(
                    id=f"n1.{i}",
                    label=f"Technique {tid}",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id=tid,
                )
            )
        root = AttackTreeNode(
            id="n1",
            label="Root attack",
            gate=GateType.OR,
            zone="input",
            children=children,
        )
    return AttackTree(
        id="tree-AP-T2-05", seed_id="AP-T2-05", goal="Test goal", root=root
    )


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


_VALID_TREE_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: AND
  zone: input
  children:
    - id: n1.1
      label: Inject prompt
      gate: LEAF
      zone: input
      technique_id: AML.T0054
    - id: n1.2
      label: Invoke tool
      gate: LEAF
      zone: tool_execution
      technique_id: AML.T0053
"""


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
# Tests: _build_tree_skeleton
# ---------------------------------------------------------------------------


class TestBuildTreeSkeleton:
    """Verify skeleton builder extracts technique-zone mappings."""

    def test_empty_techniques(self) -> None:
        """Empty technique list returns empty skeleton."""
        narrative = _make_narrative()
        result = _build_tree_skeleton(narrative, [], [])
        assert result == []

    def test_single_technique_matched(self) -> None:
        """Single technique matched by ID in step text."""
        narrative = _make_narrative()
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0054"],
            ["LLM Jailbreak"],
        )
        assert len(result) == 1
        leaf = result[0]
        assert leaf["id"] == "n0.1"
        assert leaf["technique_id"] == "AML.T0054"
        assert leaf["technique_name"] == "LLM Jailbreak"
        # AML.T0054 appears in step 1 (zone=input)
        assert leaf["zone"] == "input"

    def test_single_technique_matched_by_name(self) -> None:
        """Technique matched by name when ID is not in step text."""
        steps = [
            NarrativeStep(
                step_number=1,
                zone="reasoning",
                action="Perform LLM Jailbreak to bypass safety filters",
                effect="Safety constraints overridden",
            ),
        ]
        narrative = _make_narrative(steps=steps, zone_sequence=["reasoning"])
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0054"],
            ["LLM Jailbreak"],
        )
        assert len(result) == 1
        assert result[0]["zone"] == "reasoning"

    def test_multiple_techniques_different_zones(self) -> None:
        """Multiple techniques map to different zones from narrative."""
        narrative = _make_narrative()
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0054", "AML.T0053"],
            ["LLM Jailbreak", "AI Agent Tool Invocation"],
        )
        assert len(result) == 2
        assert result[0]["id"] == "n0.1"
        assert result[0]["technique_id"] == "AML.T0054"
        assert result[0]["zone"] == "input"  # step 1
        assert result[1]["id"] == "n0.2"
        assert result[1]["technique_id"] == "AML.T0053"
        assert result[1]["zone"] == "tool_execution"  # step 3

    def test_unmatched_technique_falls_back_to_first_zone(self) -> None:
        """Technique not found in any step text uses first zone as fallback."""
        narrative = _make_narrative()
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0070"],
            ["RAG Poisoning"],
        )
        assert len(result) == 1
        assert result[0]["technique_id"] == "AML.T0070"
        # Fallback to first zone in zone_sequence
        assert result[0]["zone"] == "input"

    def test_case_insensitive_matching(self) -> None:
        """Matching is case-insensitive for both IDs and names."""
        steps = [
            NarrativeStep(
                step_number=1,
                zone="memory",
                action="attacker performs rag poisoning attack",
                effect="Knowledge base corrupted",
            ),
        ]
        narrative = _make_narrative(steps=steps, zone_sequence=["memory"])
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0070"],
            ["RAG Poisoning"],
        )
        assert len(result) == 1
        assert result[0]["zone"] == "memory"

    def test_match_in_effect_field(self) -> None:
        """Techniques can also be matched in step effect text."""
        steps = [
            NarrativeStep(
                step_number=1,
                zone="tool_execution",
                action="Send request to API",
                effect="AI Agent Tool Invocation [AML.T0053] succeeds",
            ),
        ]
        narrative = _make_narrative(
            steps=steps, zone_sequence=["tool_execution"]
        )
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0053"],
            ["AI Agent Tool Invocation"],
        )
        assert len(result) == 1
        assert result[0]["zone"] == "tool_execution"

    def test_leaf_ids_are_sequential(self) -> None:
        """Leaf IDs are n0.1, n0.2, etc."""
        narrative = _make_narrative()
        result = _build_tree_skeleton(
            narrative,
            ["AML.T0054", "AML.T0053", "AML.T0070"],
            ["LLM Jailbreak", "AI Agent Tool Invocation", "RAG Poisoning"],
        )
        assert [leaf["id"] for leaf in result] == [
            "n0.1",
            "n0.2",
            "n0.3",
        ]


# ---------------------------------------------------------------------------
# Tests: _format_skeleton_yaml
# ---------------------------------------------------------------------------


class TestFormatSkeletonYaml:
    """Verify skeleton is formatted as a YAML block for the prompt."""

    def test_empty_skeleton_returns_empty_string(self) -> None:
        assert _format_skeleton_yaml([]) == ""

    def test_single_leaf_formatting(self) -> None:
        skeleton = [
            {
                "id": "n0.1",
                "technique_id": "AML.T0054",
                "technique_name": "LLM Jailbreak",
                "zone": "input",
            }
        ]
        result = _format_skeleton_yaml(skeleton)
        assert "## Mandatory Leaf Nodes" in result
        assert "technique_id: AML.T0054" in result
        assert "technique_name: LLM Jailbreak" in result
        assert "zone: input" in result
        assert "```yaml" in result
        assert "mandatory_leaves:" in result

    def test_connector_budget_matches_leaf_count_plus_two(self) -> None:
        """Additional connector budget equals mandatory leaf count + 2."""
        skeleton = [
            {
                "id": "n0.1",
                "technique_id": "AML.T0054",
                "technique_name": "LLM Jailbreak",
                "zone": "input",
            },
            {
                "id": "n0.2",
                "technique_id": "AML.T0053",
                "technique_name": "AI Agent Tool Invocation",
                "zone": "tool_execution",
            },
        ]
        result = _format_skeleton_yaml(skeleton)
        assert "4 additional connector/setup leaves" in result


# ---------------------------------------------------------------------------
# Tests: _validate_mandatory_leaves
# ---------------------------------------------------------------------------


class TestValidateMandatoryLeaves:
    """Verify post-generation validation of mandatory leaf presence."""

    def test_no_skeleton_no_warnings(self) -> None:
        """Empty skeleton produces no warnings."""
        tree = _make_tree(["AML.T0054"])
        gen_logger = logging.getLogger("scenario_forge.pipeline.generate")
        with CaptureHandler(gen_logger) as handler:
            _validate_mandatory_leaves(tree, [], "AP-T2-05")
            assert len(handler.records) == 0

    def test_all_mandatory_present_no_warnings(self) -> None:
        """All mandatory techniques present produces no warnings."""
        tree = _make_tree(["AML.T0054", "AML.T0053"])
        skeleton = [
            {
                "id": "n0.1",
                "technique_id": "AML.T0054",
                "technique_name": "LLM Jailbreak",
                "zone": "input",
            },
            {
                "id": "n0.2",
                "technique_id": "AML.T0053",
                "technique_name": "AI Agent Tool Invocation",
                "zone": "tool_execution",
            },
        ]
        gen_logger = logging.getLogger("scenario_forge.pipeline.generate")
        with CaptureHandler(gen_logger) as handler:
            _validate_mandatory_leaves(tree, skeleton, "AP-T2-05")
            assert not any(
                "missing" in r.getMessage().lower()
                for r in handler.records
            )

    def test_missing_technique_logs_warning(self) -> None:
        """Missing mandatory technique produces a warning."""
        # Tree only has AML.T0054, but skeleton requires both
        tree = _make_tree(["AML.T0054"])
        skeleton = [
            {
                "id": "n0.1",
                "technique_id": "AML.T0054",
                "technique_name": "LLM Jailbreak",
                "zone": "input",
            },
            {
                "id": "n0.2",
                "technique_id": "AML.T0053",
                "technique_name": "AI Agent Tool Invocation",
                "zone": "tool_execution",
            },
        ]
        gen_logger = logging.getLogger("scenario_forge.pipeline.generate")
        with CaptureHandler(gen_logger) as handler:
            _validate_mandatory_leaves(tree, skeleton, "AP-T2-05")
            warnings = [
                r
                for r in handler.records
                if "AML.T0053" in r.getMessage()
                and "missing" in r.getMessage().lower()
            ]
            assert len(warnings) == 1


# ---------------------------------------------------------------------------
# Tests: Integration — skeleton in call2 prompt
# ---------------------------------------------------------------------------


class TestSkeletonInCall2Prompt:
    """Verify that the skeleton section appears in the rendered call2 prompt."""

    def _call_and_capture_prompt(
        self,
        pinned_ids: list[str],
        pinned_names: list[str],
    ) -> str:
        seed = _make_seed(technique_ids=pinned_ids)
        narrative = _make_narrative()
        client = MagicMock()
        client.complete.return_value = _make_llm_result(_VALID_TREE_YAML)

        _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            pinned_technique_ids=pinned_ids,
            pinned_technique_names=pinned_names,
        )

        call_kwargs = client.complete.call_args_list[0].kwargs
        return call_kwargs["user_prompt"]

    def test_skeleton_section_present_with_pinned(self) -> None:
        """Skeleton section appears when pinned techniques are provided."""
        prompt = self._call_and_capture_prompt(
            pinned_ids=["AML.T0054"],
            pinned_names=["LLM Jailbreak"],
        )
        assert "## Mandatory Leaf Nodes" in prompt
        assert "technique_id: AML.T0054" in prompt
        assert "technique_name: LLM Jailbreak" in prompt

    def test_skeleton_absent_without_pinned(self) -> None:
        """Skeleton section is absent when no pinned techniques."""
        seed = _make_seed(technique_ids=["AML.T0054"])
        narrative = _make_narrative()
        client = MagicMock()
        client.complete.return_value = _make_llm_result(_VALID_TREE_YAML)

        _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            pinned_technique_ids=None,
            pinned_technique_names=None,
        )

        call_kwargs = client.complete.call_args_list[0].kwargs
        prompt = call_kwargs["user_prompt"]
        assert "## Mandatory Leaf Nodes" not in prompt

    def test_skeleton_zone_from_narrative(self) -> None:
        """Skeleton zone reflects narrative step where technique appears."""
        prompt = self._call_and_capture_prompt(
            pinned_ids=["AML.T0053"],
            pinned_names=["AI Agent Tool Invocation"],
        )
        # AML.T0053 appears in step 3 (zone=tool_execution)
        assert "zone: tool_execution" in prompt

    def test_leaf_budget_section_still_present(self) -> None:
        """Leaf budget section is preserved alongside skeleton section."""
        prompt = self._call_and_capture_prompt(
            pinned_ids=["AML.T0054"],
            pinned_names=["LLM Jailbreak"],
        )
        assert "## Leaf Budget (MANDATORY)" in prompt
        assert "## Mandatory Leaf Nodes" in prompt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class CaptureHandler(logging.Handler):
    """Context manager that captures log records from a specific logger."""

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__()
        self._logger = logger
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def __enter__(self) -> CaptureHandler:
        self._logger.addHandler(self)
        self._prev_level = self._logger.level
        self._logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *args: object) -> None:
        self._logger.removeHandler(self)
        self._logger.setLevel(self._prev_level)
