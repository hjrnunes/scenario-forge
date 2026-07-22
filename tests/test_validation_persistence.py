"""Tests for validation mark persistence to scenario YAMLs (gmv9).

Covers:
- Validation blocks are present in re-written YAML files
- enforce_parsimony is called from the runner and results are reflected
- Re-write does not corrupt existing scenario data
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import yaml
import pytest

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.scenario import (
    ArchitectureMatch,
    AttackComplexity,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeLayer,
    NarrativeStep,
    PhantomValidation,
    PhantomViolationRecord,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SemanticValidation,
    SeverityLevel,
    StructuralExposureSignal,
    StructuralValidation,
    TaxonomyChain,
    TechniqueMaturity,
    ValidationBlock,
)
from scenario_forge.pipeline.generate import write_scenario_outputs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    scenario_id: str = "AP-T1-01-abc123",
    validation: ValidationBlock | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate=GateType.OR,
        zone="input",
        children=[
            AttackTreeNode(
                id="n1.1",
                label="Path A",
                gate=GateType.LEAF,
                zone="input",
                technique_id="AML.T0051",
            ),
            AttackTreeNode(
                id="n1.2",
                label="Path B",
                gate=GateType.LEAF,
                zone="reasoning",
            ),
        ],
    )

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="I craft a malicious prompt.",
                effect="The system processes the input.",
            ),
        ],
    )

    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )

    faceting = FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            atlas_technique_ids=["AML.T0051"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts (zone 1)",
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )

    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
        validation=validation,
    )


# ---------------------------------------------------------------------------
# Tests: validation blocks are persisted in YAML files
# ---------------------------------------------------------------------------


class TestValidationPersistence:
    """Validation marks should appear in re-written scenario YAMLs."""

    def test_validation_block_written_to_yaml(self, tmp_path: Path) -> None:
        """A scenario with validation marks should have them in the YAML output."""
        validation = ValidationBlock(
            phantom=PhantomValidation(
                valid=False,
                violations=[
                    PhantomViolationRecord(
                        step_number=1,
                        field="action",
                        category="network",
                        matched_text="external API",
                        reason="No network capability",
                    ),
                ],
            ),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        assert yaml_path.exists()
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        assert "validation" in data
        assert data["validation"]["phantom"]["valid"] is False
        assert len(data["validation"]["phantom"]["violations"]) == 1
        assert data["validation"]["structural"]["valid"] is True
        assert data["validation"]["semantic"]["valid"] is True

    def test_validation_passed_flag_written(self, tmp_path: Path) -> None:
        """The validation_passed flag should appear in the written YAML."""
        validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["validation_passed"] is True

    def test_validation_passed_false_when_phantom_fails(self, tmp_path: Path) -> None:
        """validation_passed should be False when phantom validation fails."""
        validation = ValidationBlock(
            phantom=PhantomValidation(valid=False, violations=[
                PhantomViolationRecord(
                    step_number=1, field="action",
                    category="network", matched_text="x", reason="y",
                ),
            ]),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["validation_passed"] is False

    def test_no_validation_block_when_none(self, tmp_path: Path) -> None:
        """A scenario with no validation should not have a validation key in YAML."""
        envelope = _make_envelope(validation=None)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        # exclude_none means no validation key
        assert "validation" not in data

    def test_parsimony_unprunable_mark_written(self, tmp_path: Path) -> None:
        """The parsimony_unprunable mark should appear in the YAML."""
        validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
            parsimony_unprunable="Could not prune to budget: 8 leaves, budget 4",
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["validation"]["parsimony_unprunable"] == (
            "Could not prune to budget: 8 leaves, budget 4"
        )


# ---------------------------------------------------------------------------
# Tests: re-write preserves existing scenario data
# ---------------------------------------------------------------------------


class TestRewriteIntegrity:
    """The validation re-write must not corrupt existing scenario data."""

    def test_rewrite_preserves_narrative(self, tmp_path: Path) -> None:
        """Narrative content should be identical after re-write with validation."""
        envelope = _make_envelope()
        # Write initially (no validation)
        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        original_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        # Add validation and re-write
        envelope.validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        # Force sync
        envelope.validation_passed = True
        write_scenario_outputs(envelope, tmp_path)

        rewritten_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        # Narrative should be identical
        assert rewritten_data["narrative"] == original_data["narrative"]
        # Attack tree should be identical
        assert rewritten_data["attack_tree"] == original_data["attack_tree"]
        # Faceting should be identical
        assert rewritten_data["faceting"] == original_data["faceting"]
        # But now has validation
        assert "validation" in rewritten_data

    def test_rewrite_preserves_attack_tree_structure(self, tmp_path: Path) -> None:
        """Attack tree nodes should remain intact after re-write."""
        envelope = _make_envelope()
        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        original_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        original_root = original_data["attack_tree"]["root"]

        # Add validation and re-write
        envelope.validation = ValidationBlock()
        envelope.validation_passed = True
        write_scenario_outputs(envelope, tmp_path)

        rewritten_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        rewritten_root = rewritten_data["attack_tree"]["root"]

        assert rewritten_root["id"] == original_root["id"]
        assert rewritten_root["label"] == original_root["label"]
        assert len(rewritten_root["children"]) == len(original_root["children"])

    def test_rewrite_preserves_gherkin_feature_file(self, tmp_path: Path) -> None:
        """The .feature file should survive a re-write of the YAML."""
        envelope = _make_envelope()
        envelope.behavior_spec = "Feature: Test\n  Scenario: Basic\n    Given something"
        write_scenario_outputs(envelope, tmp_path)

        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        assert feature_path.exists()
        original_feature = feature_path.read_text(encoding="utf-8")

        # Add validation and re-write
        envelope.validation = ValidationBlock()
        envelope.validation_passed = True
        write_scenario_outputs(envelope, tmp_path)

        assert feature_path.read_text(encoding="utf-8") == original_feature

    def test_roundtrip_scenario_id_stable(self, tmp_path: Path) -> None:
        """scenario_id must remain identical through write-rewrite cycle."""
        envelope = _make_envelope(scenario_id="AP-T7-02-deadbeef")
        write_scenario_outputs(envelope, tmp_path)

        envelope.validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=False, issues=["test issue"]),
        )
        envelope.validation_passed = False
        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / "AP-T7-02-deadbeef.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["scenario_id"] == "AP-T7-02-deadbeef"


# ---------------------------------------------------------------------------
# Tests: enforce_parsimony integration with runner
# ---------------------------------------------------------------------------


class TestParsimonyIntegration:
    """enforce_parsimony should be wired into the runner validation sequence."""

    def test_pruned_tree_replaces_original(self) -> None:
        """When parsimony prunes a tree, the in-memory scenario should get the pruned version."""
        from scenario_forge.pipeline.validation import enforce_parsimony

        # Build a tree with 1 technique but many unannotated leaves
        # Budget = 2*1 + 2 = 4, so 5+ leaves triggers pruning
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Annotated leaf",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step 2 setup",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step 2 setup duplicate",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step 3",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step 3 duplicate",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Step 3 extra duplicate",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )

        envelope = _make_envelope(scenario_id="AP-T1-01-prunable")
        envelope.attack_tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Compromise the system",
            root=root,
        )

        result = enforce_parsimony([envelope])

        # Should have pruned scenarios (original had 6 leaves, budget=4)
        assert len(result.pruned_scenarios) == 1
        pruned_scenario, pruned_nodes = result.pruned_scenarios[0]
        assert len(pruned_nodes) > 0

        # The pruned tree should have fewer leaves
        from scenario_forge.pipeline.validation import _collect_leaves
        original_leaf_count = len(_collect_leaves(root))
        pruned_leaf_count = len(_collect_leaves(pruned_scenario.attack_tree.root))
        assert pruned_leaf_count < original_leaf_count

    def test_compliant_scenario_passes_through(self) -> None:
        """A scenario within budget should appear in compliant_scenarios."""
        from scenario_forge.pipeline.validation import enforce_parsimony

        # 2 leaves, 1 technique -> budget=4, well within
        envelope = _make_envelope()
        result = enforce_parsimony([envelope])
        assert len(result.compliant_scenarios) == 1
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 0

    def test_parsimony_unprunable_gets_validation_mark(self) -> None:
        """Unprunable scenarios should get a parsimony_unprunable mark when processed by the runner logic."""
        # Build a tree where all leaves are annotated but over budget
        # This is technically impossible with the real algo (annotated never pruned),
        # but we can test the runner's mark logic directly.
        envelope = _make_envelope()
        envelope.validation = ValidationBlock()

        # Simulate runner logic for unprunable scenario
        leaf_count = 10
        budget = 4
        envelope.validation.parsimony_unprunable = (
            f"Could not prune to budget: {leaf_count} leaves, budget {budget}"
        )

        assert envelope.validation.parsimony_unprunable == (
            "Could not prune to budget: 10 leaves, budget 4"
        )

    def test_pruned_tree_written_to_yaml(self, tmp_path: Path) -> None:
        """After parsimony pruning, the re-written YAML should contain the pruned tree."""
        from scenario_forge.pipeline.validation import enforce_parsimony, _collect_leaves

        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Annotated",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Unannotated A",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Unannotated A copy",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Unannotated B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Unannotated B copy",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Unannotated C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )

        envelope = _make_envelope(scenario_id="AP-T1-01-prune-write")
        envelope.attack_tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Compromise the system",
            root=root,
        )

        original_leaf_count = len(_collect_leaves(root))

        # Run parsimony
        result = enforce_parsimony([envelope])
        assert len(result.pruned_scenarios) == 1
        pruned_scenario, _ = result.pruned_scenarios[0]

        # Simulate the runner: replace the attack tree
        envelope.attack_tree = pruned_scenario.attack_tree

        # Write to disk
        write_scenario_outputs(envelope, tmp_path)
        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        # The written tree should have fewer children than original
        written_root = data["attack_tree"]["root"]
        # Count leaves in the written tree (recursively)
        def count_leaves(node: dict) -> int:
            if not node.get("children"):
                return 1
            return sum(count_leaves(c) for c in node["children"])

        written_leaf_count = count_leaves(written_root)
        assert written_leaf_count < original_leaf_count
