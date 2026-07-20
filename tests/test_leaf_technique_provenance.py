"""Tests for leaf technique provenance validation.

Covers:
- At least one provenance-matching leaf -> clean
- Technique IDs present but none from provenance set -> flagged
- All leaves unannotated (no technique_ids) -> flagged
- Consequence leaf exemption still works (unannotated consequence
  leaves do not block a scenario with a provenance match)
- Mixed batch (some clean, some flagged)
- Empty scenario list
- _is_consequence_leaf heuristic matches expected patterns
"""

from __future__ import annotations

from datetime import datetime

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
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SeverityLevel,
    StructuralExposureSignal,
    TaxonomyChain,
    TechniqueMaturity,
)
from scenario_forge.pipeline.validation import (
    LeafTechniqueViolation,
    _is_consequence_leaf,
    check_leaf_technique_provenance,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_envelope(
    root: AttackTreeNode,
    scenario_id: str = "AP-T1-01-abc123",
    atlas_provenance_ids: list[str] | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope with a custom tree root.

    Parameters
    ----------
    atlas_provenance_ids:
        ATLAS technique IDs from the seed's provenance.  Stored in
        ``scenario_seed_metadata["atlas_provenance_ids"]``.
    """
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft a malicious prompt.",
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

    seed_metadata = {
        "seed_id": "AP-T1-01",
        "threat_id": "T1",
        "threat_name": "Test Threat",
        "attack_pattern_name": "Test Pattern",
        "attack_pattern_description": "A test attack pattern.",
        "atlas_provenance_ids": atlas_provenance_ids or [],
    }

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        generated_at=datetime.now(),
        generator_version="0.1.0",
        scenario_seed_metadata=seed_metadata,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Tests: at least one provenance-matching leaf -> clean
# ---------------------------------------------------------------------------


class TestCleanScenarios:
    """Scenarios with at least one provenance-matching leaf are clean."""

    def test_one_leaf_matches_provenance(self) -> None:
        """A single annotated leaf matching provenance is sufficient."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_multiple_leaves_one_matches(self) -> None:
        """Only one leaf needs to match provenance for clean result."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Exploit reasoning flaw",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0099",  # Not in provenance
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_unannotated_leaves_alongside_provenance_match(self) -> None:
        """Unannotated leaves are excluded; provenance match still holds."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                    # No technique_id — legitimate unannotated step
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Trigger escalation",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id — legitimate unannotated step
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_partial_provenance_accepted(self) -> None:
        """Matching 1 of 2 provenance IDs is accepted (partial provenance)."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe behavior",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(
            root,
            atlas_provenance_ids=["AML.T0051", "AML.T0052"],
        )
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_deep_tree_provenance_match(self) -> None:
        """Deeply nested leaf matching provenance is found."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Stage 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0051",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Observe system behavior",
                            gate=GateType.LEAF,
                            zone="tool_execution",
                            # No technique_id
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Stage 2",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_empty_list(self) -> None:
        result = check_leaf_technique_provenance([])
        assert result.clean_count == 0
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: flagged scenarios
# ---------------------------------------------------------------------------


class TestFlaggedScenarios:
    """Scenarios without a provenance-matching leaf are flagged."""

    def test_technique_ids_none_from_provenance(self) -> None:
        """Leaves have technique_ids but none match provenance set."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0099",  # Not in provenance
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Exploit reasoning flaw",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0098",  # Not in provenance
                ),
            ],
        )
        scenario = _make_envelope(
            root,
            atlas_provenance_ids=["AML.T0051", "AML.T0052"],
        )
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 1
        assert result.clean_count == 0
        _, violations = result.flagged_scenarios[0]
        assert len(violations) == 1
        assert "AML.T0098" in violations[0].reason or "AML.T0099" in violations[0].reason
        assert "atlas_provenance_ids" in violations[0].reason

    def test_all_unannotated_leaves(self) -> None:
        """No leaves carry any technique_id at all -> flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Craft phishing lure",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Deliver payload via injection",
                    gate=GateType.LEAF,
                    zone="input",
                ),
            ],
        )
        scenario = _make_envelope(
            root,
            atlas_provenance_ids=["AML.T0051"],
        )
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 1
        assert result.clean_count == 0
        _, violations = result.flagged_scenarios[0]
        assert len(violations) == 1
        assert "No leaf nodes carry a technique_id" in violations[0].reason

    def test_no_seed_metadata(self) -> None:
        """Scenario with no seed metadata is flagged (empty provenance)."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=[])
        # Clear seed metadata to simulate missing data
        scenario.scenario_seed_metadata = None
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_empty_provenance_set(self) -> None:
        """Scenario with empty atlas_provenance_ids is flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=[])
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_violation_uses_root_node(self) -> None:
        """Violation references the root node (scenario-level issue)."""
        root = AttackTreeNode(
            id="n1",
            label="Attack Goal",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Some step",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Another step",
                    gate=GateType.LEAF,
                    zone="input",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 1
        _, violations = result.flagged_scenarios[0]
        assert violations[0].node_id == "n1"
        assert violations[0].label == "Attack Goal"
        assert violations[0].zone == "input"


# ---------------------------------------------------------------------------
# Tests: consequence leaf exemption still works
# ---------------------------------------------------------------------------


class TestConsequenceExemption:
    """Consequence leaves do not block clean status under new semantic.

    Unannotated leaves (including consequence leaves) are excluded from
    the check.  A scenario is clean as long as at least one annotated
    leaf matches the provenance set.
    """

    def test_consequence_leaf_with_provenance_match(self) -> None:
        """Consequence leaf (no technique_id) + provenance match -> clean."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Victim transfers funds to attacker account",
                    gate=GateType.LEAF,
                    zone="output",
                    # No technique_id — consequence leaf
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_data_exfiltrated_with_provenance_match(self) -> None:
        """Data exfiltration consequence leaf alongside provenance match."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Credentials stolen via side channel",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_only_consequence_leaves_flagged(self) -> None:
        """Tree with only consequence leaves (no technique_ids) is flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Victim transfers funds to attacker account",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="System fully compromised",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 1
        assert result.clean_count == 0


# ---------------------------------------------------------------------------
# Tests: mixed scenarios (some clean, some flagged)
# ---------------------------------------------------------------------------


class TestMixedBatch:
    """A batch with both clean and flagged scenarios."""

    def test_mixed_batch(self) -> None:
        """One clean scenario and one flagged in the same batch."""
        clean_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        clean = _make_envelope(
            clean_root,
            scenario_id="AP-T1-01-clean1",
            atlas_provenance_ids=["AML.T0051"],
        )

        flagged_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0099",  # Not in provenance
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Follow up step",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        flagged = _make_envelope(
            flagged_root,
            scenario_id="AP-T1-01-flagg1",
            atlas_provenance_ids=["AML.T0051"],
        )

        result = check_leaf_technique_provenance([clean, flagged])

        assert result.clean_count == 1
        assert result.flagged_count == 1
        assert result.clean_scenarios[0].scenario_id == "AP-T1-01-clean1"
        assert result.flagged_scenarios[0][0].scenario_id == "AP-T1-01-flagg1"


# ---------------------------------------------------------------------------
# Tests: _is_consequence_leaf heuristic
# ---------------------------------------------------------------------------


class TestIsConsequenceLeaf:
    """Unit tests for the _is_consequence_leaf heuristic."""

    def _node(self, label: str, description: str | None = None) -> AttackTreeNode:
        return AttackTreeNode(
            id="n1.1",
            label=label,
            description=description,
            gate=GateType.LEAF,
            zone="output",
        )

    def test_victim_transfers(self) -> None:
        assert _is_consequence_leaf(self._node("Victim transfers funds"))

    def test_victim_reveals(self) -> None:
        assert _is_consequence_leaf(self._node("Victim reveals credentials"))

    def test_data_exfiltrated(self) -> None:
        assert _is_consequence_leaf(self._node("Data exfiltrated to C2"))

    def test_credentials_stolen(self) -> None:
        assert _is_consequence_leaf(self._node("Credentials stolen via phishing"))

    def test_funds_diverted(self) -> None:
        assert _is_consequence_leaf(self._node("Funds diverted to attacker"))

    def test_system_compromised(self) -> None:
        assert _is_consequence_leaf(self._node("System compromised"))

    def test_system_fully_compromised(self) -> None:
        assert _is_consequence_leaf(self._node("System fully compromised"))

    def test_breach_completed(self) -> None:
        assert _is_consequence_leaf(self._node("Breach completed"))

    def test_attack_succeeds(self) -> None:
        assert _is_consequence_leaf(self._node("Attack succeeds"))

    def test_achieve_objective(self) -> None:
        assert _is_consequence_leaf(self._node("Achieve attack objective"))

    def test_exfiltrate_data(self) -> None:
        assert _is_consequence_leaf(self._node("Exfiltrate sensitive records"))

    def test_siphon_funds(self) -> None:
        assert _is_consequence_leaf(self._node("Siphon funds from account"))

    def test_gain_persistent_access(self) -> None:
        assert _is_consequence_leaf(self._node("Gain persistent access"))

    def test_obtain_unauthorized_access(self) -> None:
        assert _is_consequence_leaf(self._node("Obtain unauthorized access"))

    def test_impact_realized(self) -> None:
        assert _is_consequence_leaf(self._node("Impact realized across systems"))

    def test_information_leaked(self) -> None:
        assert _is_consequence_leaf(self._node("Information leaked to adversary"))

    def test_assets_compromised(self) -> None:
        assert _is_consequence_leaf(self._node("Assets compromised"))

    # --- Non-consequence labels (attack work) ---

    def test_inject_payload_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._node("Inject malicious payload"))

    def test_craft_phishing_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._node("Craft phishing lure"))

    def test_manipulate_reasoning_not_consequence(self) -> None:
        assert not _is_consequence_leaf(
            self._node("Manipulate reasoning via context injection")
        )

    def test_establish_rapport_not_consequence(self) -> None:
        assert not _is_consequence_leaf(
            self._node("Establish rapport with target employee")
        )

    def test_deliver_payload_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._node("Deliver social engineering payload"))

    def test_exploit_tool_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._node("Exploit tool execution vulnerability"))

    def test_bypass_guardrails_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._node("Bypass input guardrails"))

    def test_description_triggers_consequence(self) -> None:
        """Consequence pattern in description counts."""
        node = self._node(
            "Final step",
            description="The victim sends credentials to the attacker.",
        )
        assert _is_consequence_leaf(node)

    def test_label_only_no_description(self) -> None:
        """Attack-work label without description is not consequence."""
        node = self._node("Perform lateral movement")
        assert not _is_consequence_leaf(node)


# ---------------------------------------------------------------------------
# Tests: violation data class
# ---------------------------------------------------------------------------


class TestLeafTechniqueViolation:
    """Verify violation data class fields."""

    def test_fields(self) -> None:
        v = LeafTechniqueViolation(
            node_id="n1.2",
            label="Craft phishing lure",
            zone="input",
            reason="Missing technique provenance.",
        )
        assert v.node_id == "n1.2"
        assert v.label == "Craft phishing lure"
        assert v.zone == "input"
        assert "provenance" in v.reason
