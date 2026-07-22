"""Tests for deterministic Gherkin projection (scenario-forge-z369).

Covers:
- _collect_leaf_nodes_dfs: depth-first leaf collection
- THREAT_VIOLATION_CATEGORY: mapping completeness
- _build_gherkin_template: tag generation, structure, leaf steps, marker
- Full Call 3 flow: template + assertion splicing
"""

from __future__ import annotations

from unittest.mock import MagicMock

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
from scenario_forge.models.capability_profile import CapabilityProfile, ConfidenceLevel, ToolInventoryEntry
from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep
from scenario_forge.pipeline.generate import (
    MAX_OR_PATHS,
    THREAT_VIOLATION_CATEGORY,
    _build_gherkin_template,
    _call_behavior_spec,
    _collect_leaf_nodes_dfs,
    _enumerate_paths,
    _ASSERTIONS_MARKER,
)
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.models.scenario import RiskCardRef


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_seed(threat_id: str = "T7", seed_id: str = "AP-T7-01") -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name="Misaligned & Deceptive Behavior",
        threat_description="Test threat description",
        attack_pattern_name="Social Engineering via Deception",
        attack_pattern_description="Test pattern description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0054"],
    )


def _make_profile(
    zones: list[str] | None = None,
) -> CapabilityProfile:
    z = zones or ["input", "reasoning"]
    kc = ["KC1.1"]
    kw = {}
    if "tool_execution" in z:
        kc.append("KC6.1.1")
        kw["tool_inventory"] = [ToolInventoryEntry(name="test_tool", description="A test tool")]
    if "memory" in z:
        kc.append("KC4.3")
    if "inter_agent" in z:
        kc.append("KC2.3")
    return CapabilityProfile(
        zones_active=z,
        entry_points=["user prompts via chat widget"],
        confidence=ConfidenceLevel.high,
        kc_subcodes=kc,
        **kw,
    )


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Deceptive Response Generation",
        summary="An attacker exploits the LLM to generate misleading outputs.",
        entry_point="user prompts via chat widget",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Submit crafted prompt",
                effect="Prompt accepted by input handler",
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Exploit reasoning engine",
                effect="Model generates deceptive output",
            ),
        ],
    )


def _make_leaf(
    node_id: str,
    label: str,
    zone: str,
    technique_id: str | None = None,
) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        technique_id=technique_id,
    )


def _make_tree_simple() -> AttackTree:
    """Two-leaf tree: n1 (AND) -> n1.1 (LEAF), n1.2 (LEAF)."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Generate misleading outputs",
        root=AttackTreeNode(
            id="n1",
            label="Root attack",
            gate=GateType.AND,
            zone="input",
            children=[
                _make_leaf("n1.1", "Inject crafted prompt", "input", "AML.T0051"),
                _make_leaf("n1.2", "Exploit reasoning bias", "reasoning", "AML.T0054"),
            ],
        ),
    )


def _make_tree_deep() -> AttackTree:
    """Deeper tree with nested AND/OR gates and 4 leaves."""
    return AttackTree(
        id="tree-AP-T5-01",
        seed_id="AP-T5-01",
        goal="Poison memory",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Phase 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        _make_leaf("n1.1.1", "Direct injection", "input", "AML.T0051"),
                        _make_leaf("n1.1.2", "Indirect injection", "input", "AML.T0043"),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Phase 2",
                    gate=GateType.AND,
                    zone="reasoning",
                    children=[
                        _make_leaf("n1.2.1", "Manipulate reasoning", "reasoning", "AML.T0054"),
                        _make_leaf("n1.2.2", "Persist to memory", "memory"),
                    ],
                ),
            ],
        ),
    )


def _make_tree_single_leaf() -> AttackTree:
    """Minimal tree: root is a single leaf node."""
    return AttackTree(
        id="tree-AP-T9-01",
        seed_id="AP-T9-01",
        goal="Single step attack",
        root=AttackTreeNode(
            id="n1",
            label="Direct exploit",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0051",
        ),
    )


def _make_tree_with_or_gate() -> AttackTree:
    """Tree with an OR gate: root(AND) -> step_A(LEAF), choice(OR) -> opt1(LEAF)/opt2(LEAF), step_B(LEAF)."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test OR gate",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                _make_leaf("n1.1", "Step A initial access", "input", "AML.T0051"),
                AttackTreeNode(
                    id="n1.2",
                    label="Choose attack vector",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        _make_leaf("n1.2.1", "Option 1 prompt injection", "reasoning", "AML.T0054"),
                        _make_leaf("n1.2.2", "Option 2 data poisoning", "reasoning", "AML.T0020"),
                    ],
                ),
                _make_leaf("n1.3", "Step B exfiltrate data", "reasoning"),
            ],
        ),
    )


def _make_tree_with_dual_or_gates() -> AttackTree:
    """Tree with two OR gates under AND root: cross-product of 2x2 = 4 paths."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test dual OR gates",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Choice 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        _make_leaf("n1.1.1", "Path A inject", "input", "AML.T0051"),
                        _make_leaf("n1.1.2", "Path B poison", "input", "AML.T0020"),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Choice 2",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        _make_leaf("n1.2.1", "Method X jailbreak", "reasoning", "AML.T0054"),
                        _make_leaf("n1.2.2", "Method Y exploit", "reasoning", "AML.T0043"),
                    ],
                ),
            ],
        ),
    )


def _make_tree_or_at_root() -> AttackTree:
    """Tree with OR gate as root: two alternative attack paths."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test OR at root",
        root=AttackTreeNode(
            id="n1",
            label="Root alternatives",
            gate=GateType.OR,
            zone="input",
            children=[
                _make_leaf("n1.1", "Direct attack via input", "input", "AML.T0051"),
                _make_leaf("n1.2", "Indirect attack via reasoning", "reasoning", "AML.T0054"),
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Tests: _collect_leaf_nodes_dfs
# ---------------------------------------------------------------------------


class TestCollectLeafNodesDfs:
    def test_simple_two_leaves(self):
        tree = _make_tree_simple()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert len(leaves) == 2
        assert leaves[0].id == "n1.1"
        assert leaves[1].id == "n1.2"

    def test_deep_tree_four_leaves_dfs_order(self):
        tree = _make_tree_deep()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert len(leaves) == 4
        assert [nd.id for nd in leaves] == ["n1.1.1", "n1.1.2", "n1.2.1", "n1.2.2"]

    def test_single_leaf_tree(self):
        tree = _make_tree_single_leaf()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert len(leaves) == 1
        assert leaves[0].id == "n1"
        assert leaves[0].technique_id == "AML.T0051"

    def test_leaf_nodes_have_leaf_gate(self):
        tree = _make_tree_deep()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        for leaf in leaves:
            assert leaf.gate == GateType.LEAF

    def test_preserves_technique_ids(self):
        tree = _make_tree_simple()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert leaves[0].technique_id == "AML.T0051"
        assert leaves[1].technique_id == "AML.T0054"


# ---------------------------------------------------------------------------
# Tests: THREAT_VIOLATION_CATEGORY mapping
# ---------------------------------------------------------------------------


class TestThreatViolationCategory:
    def test_all_t1_through_t17_mapped(self):
        for i in range(1, 18):
            key = f"T{i}"
            assert key in THREAT_VIOLATION_CATEGORY, f"Missing mapping for {key}"

    def test_tags_are_kebab_case(self):
        for threat_id, tag in THREAT_VIOLATION_CATEGORY.items():
            assert tag == tag.lower(), f"{threat_id}: tag not lowercase: {tag}"
            assert " " not in tag, f"{threat_id}: tag contains spaces: {tag}"
            assert "&" not in tag, f"{threat_id}: tag contains ampersand: {tag}"

    def test_known_mappings(self):
        assert THREAT_VIOLATION_CATEGORY["T1"] == "uncontrolled-autonomy"
        assert THREAT_VIOLATION_CATEGORY["T5"] == "memory-integrity-breach"
        assert THREAT_VIOLATION_CATEGORY["T10"] == "hitl-bypass"
        assert THREAT_VIOLATION_CATEGORY["T15"] == "human-manipulation"


# ---------------------------------------------------------------------------
# Tests: _build_gherkin_template
# ---------------------------------------------------------------------------


class TestBuildGherkinTemplate:
    def test_contains_id_tag(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert "@id:AP-T7-01-abc123" in template

    def test_contains_violation_category_tag(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(threat_id="T5"),
            scenario_tag="AP-T5-01-abc123",
        )
        assert "@memory-integrity-breach" in template

    def test_violation_category_for_each_threat_id(self):
        """Each threat_id produces its correct violation category tag."""
        for threat_id, expected_tag in THREAT_VIOLATION_CATEGORY.items():
            seed = _make_seed(threat_id=threat_id, seed_id=f"AP-{threat_id}-01")
            tree_id = f"tree-AP-{threat_id}-01"
            tree = AttackTree(
                id=tree_id,
                seed_id=f"AP-{threat_id}-01",
                goal="Test",
                root=AttackTreeNode(
                    id="n1",
                    label="Root",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        _make_leaf("n1.1", "Step A", "input"),
                        _make_leaf("n1.2", "Step B", "reasoning"),
                    ],
                ),
            )
            template = _build_gherkin_template(
                narrative=_make_narrative(),
                attack_tree=tree,
                profile=_make_profile(),
                seed=seed,
                scenario_tag=f"AP-{threat_id}-01-abc123",
            )
            assert f"@{expected_tag}" in template, (
                f"Expected @{expected_tag} for {threat_id}"
            )

    def test_feature_line_contains_title(self):
        narrative = _make_narrative()
        template = _build_gherkin_template(
            narrative=narrative,
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert f"Feature: {narrative.title}" in template

    def test_background_given_contains_entry_point(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert "Given user prompts via chat widget (input)" in template

    def test_when_and_steps_from_leaf_nodes(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert "When Inject crafted prompt [AML.T0051] (input)" in template
        assert "And Exploit reasoning bias [AML.T0054] (reasoning)" in template

    def test_leaf_without_technique_id(self):
        """Leaf nodes without technique_id omit the bracket annotation."""
        tree = _make_tree_deep()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(
                zones=["input", "reasoning", "memory"],
            ),
            seed=_make_seed(threat_id="T5", seed_id="AP-T5-01"),
            scenario_tag="AP-T5-01-abc123",
        )
        # n1.2.2 has no technique_id
        assert "And Persist to memory (memory)" in template

    def test_contains_assertions_marker(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert _ASSERTIONS_MARKER in template
        # Marker appears exactly once
        assert template.count(_ASSERTIONS_MARKER) == 1

    def test_single_leaf_tree(self):
        """A single-leaf tree produces only a When step, no And."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_single_leaf(),
            profile=_make_profile(),
            seed=_make_seed(threat_id="T9", seed_id="AP-T9-01"),
            scenario_tag="AP-T9-01-abc123",
        )
        assert "When Direct exploit [AML.T0051] (input)" in template
        # No "And" attack step line (And in Background is fine)
        scenario_section = template.split("Scenario:")[1]
        when_and_section = scenario_section.split(_ASSERTIONS_MARKER)[0]
        # Count lines starting with "    And " in the attack step block
        attack_and_lines = [
            line for line in when_and_section.split("\n")
            if line.strip().startswith("And ") and "(" in line and ")" in line
        ]
        assert len(attack_and_lines) == 0

    def test_depth_first_ordering(self):
        """Leaf nodes appear in depth-first order matching narrative phases."""
        tree = _make_tree_deep()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(
                zones=["input", "reasoning", "memory"],
            ),
            seed=_make_seed(threat_id="T5", seed_id="AP-T5-01"),
            scenario_tag="AP-T5-01-abc123",
        )
        # Extract the attack step lines from the scenario section
        scenario_part = template.split("Scenario:")[1]
        attack_lines = [
            line.strip() for line in scenario_part.split("\n")
            if line.strip().startswith(("When ", "And "))
        ]
        # First is When (n1.1.1 Direct injection)
        assert attack_lines[0].startswith("When Direct injection")
        # Last contains "Persist to memory"
        assert "Persist to memory" in attack_lines[-1]

    def test_additional_zones_in_background(self):
        """Background only includes zones actually present in the tree.

        Even if the profile has tool_execution active, it should not appear
        in Background if the tree has no leaf nodes in that zone.
        """
        profile = _make_profile(
            zones=["input", "reasoning", "tool_execution"],
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=profile,
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # tree only uses input and reasoning, so tool_execution should be absent
        assert "Tool Execution capabilities (tool_execution)" not in template
        # reasoning should still be present (it's in the tree)
        assert "Reasoning capabilities (reasoning)" in template

    def test_unknown_threat_id_uses_default(self):
        """Unknown threat_id falls back to misaligned-and-deceptive-behavior."""
        seed = _make_seed(threat_id="T99", seed_id="AP-T7-01")
        # Override threat_id on the seed manually
        seed.threat_id = "T99"
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=seed,
            scenario_tag="AP-T99-01-abc123",
        )
        assert "@misaligned-and-deceptive-behavior" in template

    # --- Regression tests for Gherkin projection bugs (scenario-forge-vaxe) ---

    def test_no_doubled_zone_label_in_entry_point(self):
        """Entry points already containing a zone suffix should not be doubled.

        Bug: 'user queries via app (input)' became '(input) (input)'.
        """
        narrative = NarrativeLayer(
            title="Test scenario",
            summary="Test summary",
            entry_point="user queries via Klarna app (input)",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Submit query",
                    effect="Query accepted",
                ),
            ],
        )
        template = _build_gherkin_template(
            narrative=narrative,
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Should appear exactly once, not doubled
        assert "(input) (input)" not in template
        assert "user queries via Klarna app (input)" in template

    def test_raw_technique_id_label_resolved(self):
        """Leaf nodes whose label is a raw technique ID should render
        the technique name instead."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    _make_leaf("n1.1", "AML.T0053", "input", "AML.T0053"),
                    _make_leaf("n1.2", "Normal label", "reasoning", "AML.T0054"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Raw ID should not appear as step text
        assert "When AML.T0053 [AML.T0053]" not in template
        # Should use the ATLAS name instead
        from scenario_forge.data.atlas import ATLAS_TECHNIQUE_NAMES
        expected_name = ATLAS_TECHNIQUE_NAMES["AML.T0053"]
        assert f"When {expected_name} [AML.T0053] (input)" in template
        # Normal labels remain unchanged
        assert "And Normal label [AML.T0054] (reasoning)" in template

    def test_background_excludes_unused_zones(self):
        """Background should only declare zones present in tree leaves,
        not all zones from the capability profile."""
        profile = _make_profile(
            zones=["input", "reasoning", "tool_execution"],
        )
        # Tree only uses input and reasoning
        tree = _make_tree_simple()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=profile,
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # tool_execution is in profile but not in tree leaves
        assert "tool_execution" not in template.split("Scenario:")[0]
        # reasoning IS in tree leaves and should be declared
        assert "Reasoning capabilities (reasoning)" in template


# ---------------------------------------------------------------------------
# Tests: Full Call 3 flow (template + assertion splicing)
# ---------------------------------------------------------------------------


class TestCallBehaviorSpecIntegration:
    def test_splicing_produces_valid_gherkin(self):
        """Template + LLM assertion block produces complete Gherkin."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = (
            "Then the model generates deceptive outputs\n"
            "But no content filter is triggered\n"
            "* Misleading information appears in user responses\n"
            "* Factual accuracy drops below baseline"
        )
        mock_result.prompt_tokens = 100
        mock_result.completion_tokens = 50
        mock_result.duration_ms = 1000
        mock_result.system_prompt = "test"
        mock_result.user_prompt = "test"
        mock_client.complete.return_value = mock_result

        gherkin, result = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test chatbot system",
            scenario_hash="abc123",
        )

        # Verify complete structure
        assert "@id:AP-T7-01-abc123" in gherkin
        assert "@misaligned-and-deceptive-behavior" in gherkin
        assert "Feature: Deceptive Response Generation" in gherkin
        assert "Background: Preconditions" in gherkin
        assert "When Inject crafted prompt [AML.T0051] (input)" in gherkin
        assert "And Exploit reasoning bias [AML.T0054] (reasoning)" in gherkin
        assert "Then the model generates deceptive outputs" in gherkin
        assert "But no content filter is triggered" in gherkin
        assert "* Misleading information appears in user responses" in gherkin

    def test_assertion_marker_is_replaced(self):
        """The {ASSERTIONS} marker is fully replaced in the output."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = "Then test assertion\nBut test but"
        mock_result.prompt_tokens = 50
        mock_result.completion_tokens = 20
        mock_result.duration_ms = 500
        mock_result.system_prompt = "test"
        mock_result.user_prompt = "test"
        mock_client.complete.return_value = mock_result

        gherkin, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test system",
            scenario_hash="abc123",
        )

        assert _ASSERTIONS_MARKER not in gherkin

    def test_returns_tuple_of_str_and_result(self):
        """Return type contract: (str, LLMResult)."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = "Then success\nBut no defense"
        mock_result.prompt_tokens = 50
        mock_result.completion_tokens = 20
        mock_result.duration_ms = 500
        mock_client.complete.return_value = mock_result

        result = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test",
            scenario_hash="abc123",
        )

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)

    def test_markdown_fence_stripped_from_llm_output(self):
        """Code fences in LLM output are stripped before splicing."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = "```gherkin\nThen success criterion\nBut defense fails\n```"
        mock_result.prompt_tokens = 50
        mock_result.completion_tokens = 20
        mock_result.duration_ms = 500
        mock_client.complete.return_value = mock_result

        gherkin, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test",
            scenario_hash="abc123",
        )

        assert "```" not in gherkin
        assert "Then success criterion" in gherkin
        assert "But defense fails" in gherkin

    def test_empty_content_raises_value_error(self):
        """Empty LLM output raises ValueError."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = ""
        mock_client.complete.return_value = mock_result

        try:
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_simple(),
                profile=_make_profile(),
                client=mock_client,
                use_case="Test",
                scenario_hash="abc123",
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "empty content" in str(e)

    def test_llm_receives_skeleton_in_prompt(self):
        """The LLM call receives the Gherkin skeleton in the user prompt."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = "Then test\nBut test"
        mock_result.prompt_tokens = 50
        mock_result.completion_tokens = 20
        mock_result.duration_ms = 500
        mock_client.complete.return_value = mock_result

        _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test",
            scenario_hash="abc123",
        )

        # Verify the LLM was called with the skeleton in the user prompt
        call_args = mock_client.complete.call_args
        user_prompt = call_args.kwargs.get("user_prompt", call_args[1] if len(call_args) > 1 else "")
        if not user_prompt:
            # Try positional args
            user_prompt = call_args[1][1] if len(call_args[1]) > 1 else ""
        # The user prompt should contain skeleton elements
        assert "Feature:" in user_prompt or "Gherkin" in user_prompt


# ---------------------------------------------------------------------------
# Tests: Then/But/* indentation (scenario-forge-7kk9 Fix 1)
# ---------------------------------------------------------------------------


class TestAssertionIndentation:
    """Verify that Then/But/* lines spliced into the Gherkin are 4-space indented."""

    def test_then_but_star_lines_indented(self):
        """All Then/But/* assertion lines should be at 4-space indent."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = (
            "Then the model generates deceptive outputs\n"
            "But no content filter is triggered\n"
            "* Misleading information appears in user responses\n"
            "* Factual accuracy drops below baseline"
        )
        mock_result.prompt_tokens = 100
        mock_result.completion_tokens = 50
        mock_result.duration_ms = 1000
        mock_result.system_prompt = "test"
        mock_result.user_prompt = "test"
        mock_client.complete.return_value = mock_result

        gherkin, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test chatbot system",
            scenario_hash="abc123",
        )

        for line in gherkin.split("\n"):
            stripped = line.strip()
            if stripped.startswith(("Then ", "But ", "* ")):
                assert line.startswith("    "), (
                    f"Assertion line not 4-space indented: {line!r}"
                )

    def test_but_star_not_at_column_zero(self):
        """But and * continuation lines must not be at column 0."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = (
            "Then attack succeeds\n"
            "But defense is bypassed\n"
            "* Data exfiltrated"
        )
        mock_result.prompt_tokens = 50
        mock_result.completion_tokens = 20
        mock_result.duration_ms = 500
        mock_result.system_prompt = "test"
        mock_result.user_prompt = "test"
        mock_client.complete.return_value = mock_result

        gherkin, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test",
            scenario_hash="abc123",
        )

        lines = gherkin.split("\n")
        for line in lines:
            if line.strip().startswith("But ") or line.strip().startswith("* "):
                assert not line.startswith("But "), (
                    f"'But' at column 0: {line!r}"
                )
                assert not line.startswith("* "), (
                    f"'*' at column 0: {line!r}"
                )


# ---------------------------------------------------------------------------
# Tests: Raw technique name substitution (scenario-forge-7kk9 Fix 2)
# ---------------------------------------------------------------------------


class TestRawTechniqueNameSubstitution:
    """Verify that leaf labels matching ATLAS technique names are replaced."""

    def test_verbatim_technique_name_replaced_with_description(self):
        """Leaf whose label is a verbatim ATLAS technique name should use
        the node's description instead."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="AI Agent Tool Invocation",
                        gate=GateType.LEAF,
                        zone="tool_execution",
                        technique_id="AML.T0053",
                        description="Agent invokes external API beyond scope",
                    ),
                    _make_leaf("n1.2", "Normal step label", "reasoning", "AML.T0054"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(zones=["input", "reasoning", "tool_execution"]),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Should NOT contain the raw technique name as step text
        assert "When AI Agent Tool Invocation [AML.T0053]" not in template
        # Should use the description
        assert "When Agent invokes external API beyond scope [AML.T0053] (tool_execution)" in template
        # Normal labels remain unchanged
        assert "And Normal step label [AML.T0054] (reasoning)" in template

    def test_verbatim_technique_name_fallback_without_description(self):
        """Leaf whose label is a technique name but has no description
        falls back to generic label."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Indirect Prompt Injection",
                        gate=GateType.LEAF,
                        zone="input",
                        technique_id="AML.T0051.001",
                        # no description
                    ),
                    _make_leaf("n1.2", "Other step", "reasoning"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Should NOT contain verbatim technique name as-is
        assert "When Indirect Prompt Injection [AML.T0051.001]" not in template
        # Should use generic fallback
        assert "When Execute attack step via Indirect Prompt Injection [AML.T0051.001] (input)" in template

    def test_case_insensitive_technique_name_match(self):
        """Matching should be case-insensitive."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="llm jailbreak",  # lowercase variant
                        gate=GateType.LEAF,
                        zone="input",
                        technique_id="AML.T0054",
                        description="Bypass safety via crafted prompts",
                    ),
                    _make_leaf("n1.2", "Other step", "reasoning"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Should use description, not the raw technique name
        assert "When Bypass safety via crafted prompts [AML.T0054] (input)" in template

    def test_non_technique_label_unchanged(self):
        """Labels that are NOT technique names should pass through unchanged."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    _make_leaf("n1.1", "Craft malicious payload", "input", "AML.T0051"),
                    _make_leaf("n1.2", "Exploit trust boundary", "reasoning"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert "When Craft malicious payload [AML.T0051] (input)" in template
        assert "And Exploit trust boundary (reasoning)" in template


# ---------------------------------------------------------------------------
# Tests: _enumerate_paths
# ---------------------------------------------------------------------------


class TestEnumeratePaths:
    def test_and_only_tree_single_path(self):
        """Pure AND tree produces a single path with all leaves."""
        tree = _make_tree_simple()
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 1
        assert [n.id for n in paths[0]] == ["n1.1", "n1.2"]

    def test_single_leaf_tree_one_path(self):
        """Single-leaf tree produces one path with one leaf."""
        tree = _make_tree_single_leaf()
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 1
        assert len(paths[0]) == 1
        assert paths[0][0].id == "n1"

    def test_or_gate_produces_alternative_paths(self):
        """Tree with OR gate produces one path per OR alternative."""
        tree = _make_tree_with_or_gate()
        paths = _enumerate_paths(tree.root)
        # OR gate with 2 children under AND with 2 other leaves -> 2 paths
        assert len(paths) == 2
        # Path 1: n1.1 + n1.2.1 + n1.3
        assert [n.id for n in paths[0]] == ["n1.1", "n1.2.1", "n1.3"]
        # Path 2: n1.1 + n1.2.2 + n1.3
        assert [n.id for n in paths[1]] == ["n1.1", "n1.2.2", "n1.3"]

    def test_dual_or_gates_cross_product(self):
        """Two OR gates under AND produce a cross-product of paths."""
        tree = _make_tree_with_dual_or_gates()
        paths = _enumerate_paths(tree.root)
        # 2x2 = 4 paths
        assert len(paths) == 4
        path_ids = {tuple(n.id for n in p) for p in paths}
        assert ("n1.1.1", "n1.2.1") in path_ids
        assert ("n1.1.1", "n1.2.2") in path_ids
        assert ("n1.1.2", "n1.2.1") in path_ids
        assert ("n1.1.2", "n1.2.2") in path_ids

    def test_or_at_root(self):
        """OR gate at root produces one path per child."""
        tree = _make_tree_or_at_root()
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 2
        assert [n.id for n in paths[0]] == ["n1.1"]
        assert [n.id for n in paths[1]] == ["n1.2"]

    def test_deep_tree_with_nested_or(self):
        """Deep tree with OR gate produces correct paths."""
        tree = _make_tree_deep()
        # n1 (AND) -> n1.1 (OR) -> [n1.1.1, n1.1.2], n1.2 (AND) -> [n1.2.1, n1.2.2]
        # Paths: n1.1.1+n1.2.1+n1.2.2, n1.1.2+n1.2.1+n1.2.2
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 2
        assert [n.id for n in paths[0]] == ["n1.1.1", "n1.2.1", "n1.2.2"]
        assert [n.id for n in paths[1]] == ["n1.1.2", "n1.2.1", "n1.2.2"]

    def test_preserves_leaf_data(self):
        """Enumerated paths preserve technique_id and zone on leaves."""
        tree = _make_tree_with_or_gate()
        paths = _enumerate_paths(tree.root)
        # First leaf in path 1 should have technique_id
        first_leaf = paths[0][0]
        assert first_leaf.technique_id == "AML.T0051"
        assert first_leaf.zone == "input"


# ---------------------------------------------------------------------------
# Tests: OR-gate-aware _build_gherkin_template
# ---------------------------------------------------------------------------


class TestBuildGherkinTemplateOrGates:
    def test_or_gate_produces_multiple_scenario_blocks(self):
        """Tree with OR gate generates separate Scenario blocks."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Should have 2 Scenario blocks
        import re
        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 2

    def test_or_gate_path_names(self):
        """Multi-path scenarios have '(Path N)' suffix."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert "Scenario: Deceptive Response Generation (Path 1)" in template
        assert "Scenario: Deceptive Response Generation (Path 2)" in template

    def test_or_gate_each_scenario_has_assertions_marker(self):
        """Each Scenario block has its own {ASSERTIONS} marker."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert template.count(_ASSERTIONS_MARKER) == 2

    def test_or_gate_shared_and_steps(self):
        """AND-gate steps appear in BOTH scenarios."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Step A (AND-required leaf) appears in both scenarios
        import re
        step_a_count = len(re.findall(r"Step A initial access", template))
        assert step_a_count == 2, f"Step A should appear in both scenarios, found {step_a_count}"
        # Step B appears in both too
        step_b_count = len(re.findall(r"Step B exfiltrate data", template))
        assert step_b_count == 2, f"Step B should appear in both scenarios, found {step_b_count}"

    def test_or_gate_alternatives_in_separate_scenarios(self):
        """Each OR alternative appears in exactly one Scenario block."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        # Split by Scenario blocks
        import re
        blocks = re.split(r"^\s*Scenario:", template, flags=re.MULTILINE)
        # blocks[0] is header, blocks[1] is Path 1, blocks[2] is Path 2
        assert len(blocks) == 3
        assert "Option 1 prompt injection" in blocks[1]
        assert "Option 2 data poisoning" in blocks[2]
        # Each option should NOT appear in the other scenario
        assert "Option 2 data poisoning" not in blocks[1]
        assert "Option 1 prompt injection" not in blocks[2]

    def test_dual_or_gates_four_scenarios(self):
        """Two OR gates produce 4 scenarios (2x2 cross-product)."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_dual_or_gates(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        import re
        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 4
        assert template.count(_ASSERTIONS_MARKER) == 4

    def test_or_at_root_two_scenarios(self):
        """OR gate at root produces 2 Scenario blocks."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_or_at_root(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        import re
        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 2
        assert "Direct attack via input" in template
        assert "Indirect attack via reasoning" in template

    def test_no_or_gate_single_scenario(self):
        """AND-only tree still produces single Scenario block without path suffix."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        import re
        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 1
        assert "(Path " not in template
        assert template.count(_ASSERTIONS_MARKER) == 1

    def test_shared_background_across_scenarios(self):
        """Background section appears once, shared by all scenarios."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert template.count("Background: Preconditions") == 1

    def test_or_gate_feature_header_once(self):
        """Feature header appears exactly once."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        assert template.count("Feature:") == 1

    def test_or_gate_correct_when_and_keywords(self):
        """Each Scenario block starts with When and uses And for subsequent steps."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="AP-T7-01-abc123",
        )
        import re
        blocks = re.split(r"^\s*Scenario:", template, flags=re.MULTILINE)
        for block in blocks[1:]:  # skip header
            attack_lines = [
                line.strip() for line in block.split("\n")
                if line.strip().startswith(("When ", "And ")) and "(" in line
            ]
            assert len(attack_lines) >= 1
            assert attack_lines[0].startswith("When ")
            for line in attack_lines[1:]:
                assert line.startswith("And ")


# ---------------------------------------------------------------------------
# Tests: OR-gate Call 3 assertion splicing
# ---------------------------------------------------------------------------


class TestCallBehaviorSpecOrGates:
    def test_all_assertion_markers_replaced_with_or_gates(self):
        """All {ASSERTIONS} markers are replaced when tree has OR gates."""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = "Then the attack succeeds\nBut defenses fail"
        mock_result.prompt_tokens = 100
        mock_result.completion_tokens = 50
        mock_result.duration_ms = 1000
        mock_result.system_prompt = "test"
        mock_result.user_prompt = "test"
        mock_client.complete.return_value = mock_result

        gherkin, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            client=mock_client,
            use_case="Test system",
            scenario_hash="abc123",
        )

        assert _ASSERTIONS_MARKER not in gherkin
        # Assertions should appear in both scenarios
        import re
        then_count = len(re.findall(r"Then the attack succeeds", gherkin))
        assert then_count == 2, f"Expected 2 Then blocks, got {then_count}"
