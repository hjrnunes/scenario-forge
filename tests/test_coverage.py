"""Tests for post-generation coverage gap analysis (scenario-forge-n63).

Covers:
- All entry points covered (no gaps)
- Some entry points missing
- All entry points missing
- Zone coverage gaps
- Threat coverage gaps
- Empty scenarios list
- Coverage report output
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import CapabilityProfile
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
from scenario_forge.pipeline.coverage import (
    CoverageGaps,
    analyze_coverage_gaps,
    write_coverage_report,
)
from scenario_forge.pipeline.threats import ThreatSurface, ThreatSurfaceEntry


# ---------------------------------------------------------------------------
# Fixtures: helpers to build minimal valid objects
# ---------------------------------------------------------------------------


def _make_risk_card_ref(risk_id: str = "test-risk") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name="Test Risk",
        risk_description="A test risk.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _make_envelope(
    entry_point: str = "user prompts (zone 1)",
    zone_sequence: list[int] | None = None,
    agentic_threat_ids: list[str] | None = None,
    summary: str = "The attacker exploits user prompts to inject malicious instructions.",
    step_actions: list[str] | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if zone_sequence is None:
        zone_sequence = [1, 2]
    if agentic_threat_ids is None:
        agentic_threat_ids = ["T1"]
    if step_actions is None:
        step_actions = ["I craft a malicious prompt to inject commands."]

    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=zone_sequence[min(i, len(zone_sequence) - 1)],
            action=action,
            effect="The system processes the input.",
        )
        for i, action in enumerate(step_actions)
    ]

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary=summary,
        entry_point=entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
    )

    attack_tree = AttackTree(
        id="tree-T1-S1",
        seed_id="T1-S1",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone=1,
            children=[
                AttackTreeNode(id="n1.1", label="Path A", gate=GateType.LEAF, zone=1),
                AttackTreeNode(id="n1.2", label="Path B", gate=GateType.LEAF, zone=2),
            ],
        ),
    )

    faceting = FacetingMetadata(
        risk_card=_make_risk_card_ref(),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=agentic_threat_ids,
            scenario_seed="T1-S1",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=zone_sequence,
            architecture_match=ArchitectureMatch.explicit,
            entry_point=entry_point,
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
        scenario_id="T1-S1-abc123",
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


def _make_profile(
    entry_points: list[str] | None = None,
    zones_active: list[int] | None = None,
) -> CapabilityProfile:
    if entry_points is None:
        entry_points = [
            "user prompts (zone 1)",
            "document uploads (zone 1)",
            "admin console (zone 2)",
        ]
    if zones_active is None:
        zones_active = [1, 2, 3]
    return CapabilityProfile(
        zones_active=zones_active,
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=entry_points,
        confidence="high",
    )


def _make_threat_surface(
    threat_ids: list[list[str]] | None = None,
) -> ThreatSurface:
    """Build a ThreatSurface with the given threat IDs per entry."""
    if threat_ids is None:
        threat_ids = [["T1", "T2"]]
    entries = []
    for i, ids in enumerate(threat_ids):
        entries.append(
            ThreatSurfaceEntry(
                risk_card=_make_risk_card_ref(f"risk-{i}"),
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=ids,
                sub_scenarios=[f"{t}-S1" for t in ids],
            )
        )
    return ThreatSurface(entries=entries, governance_only=[])


# ---------------------------------------------------------------------------
# Coverage gap analysis tests (scenario-forge-n63)
# ---------------------------------------------------------------------------


class TestCoverageGaps:
    """Tests for analyze_coverage_gaps."""

    def test_all_entry_points_covered(self):
        """When every entry point has at least one scenario, no gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(entry_point="ep-a (zone 1)", agentic_threat_ids=["T1"]),
            _make_envelope(entry_point="ep-b (zone 2)", agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []
        assert not gaps.has_gaps

    def test_some_entry_points_missing(self):
        """When some entry points have no scenarios, they appear as gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)", "ep-c (zone 3)"],
            zones_active=[1, 2, 3],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="ep-a (zone 1)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_entry_points) == {"ep-b (zone 2)", "ep-c (zone 3)"}
        assert gaps.has_gaps

    def test_all_entry_points_missing(self):
        """No scenarios at all means every entry point is uncovered."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_entry_points) == {"ep-a (zone 1)", "ep-b (zone 2)"}

    def test_all_zones_covered(self):
        """When all active zones are traversed, no zone gaps."""
        profile = _make_profile(zones_active=[1, 2, 3])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=[1, 2, 3], agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == []

    def test_some_zones_uncovered(self):
        """Zones not traversed by any scenario appear as gaps."""
        profile = _make_profile(zones_active=[1, 2, 3])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=[1, 2], agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == [3]

    def test_all_threats_covered(self):
        """When every in-scope threat has at least one scenario, no gaps."""
        threat_surface = _make_threat_surface([["T1", "T2"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1", "T2"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == []

    def test_some_threats_uncovered(self):
        """Threats with no scenarios appear as gaps."""
        threat_surface = _make_threat_surface([["T1", "T2", "T3"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_threats) == {"T2", "T3"}

    def test_empty_scenarios_flags_everything(self):
        """With no scenarios, all entry points, zones, and threats are gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])

        gaps = analyze_coverage_gaps(profile, threat_surface, [])
        assert gaps.uncovered_entry_points == ["ep-a (zone 1)"]
        assert gaps.uncovered_zones == [1, 2]
        assert gaps.uncovered_threats == ["T1"]
        assert gaps.has_gaps

    def test_zones_across_multiple_scenarios(self):
        """Zone coverage is the union across all scenarios."""
        profile = _make_profile(zones_active=[1, 2, 3])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=[1], agentic_threat_ids=["T1"]),
            _make_envelope(zone_sequence=[2, 3], agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == []

    def test_threats_across_multiple_entries(self):
        """Threats from multiple threat surface entries are all checked."""
        threat_surface = _make_threat_surface([["T1"], ["T2"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == ["T2"]

    def test_to_dict(self):
        """CoverageGaps.to_dict returns a serializable dict."""
        gaps = CoverageGaps(
            uncovered_entry_points=["ep-a"],
            uncovered_zones=[3],
            uncovered_threats=["T5"],
        )
        d = gaps.to_dict()
        assert d["uncovered_entry_points"] == ["ep-a"]
        assert d["uncovered_zones"] == [3]
        assert d["uncovered_threats"] == ["T5"]

    def test_has_gaps_false_when_empty(self):
        """No gaps means has_gaps is False."""
        gaps = CoverageGaps()
        assert not gaps.has_gaps

    def test_has_gaps_true_for_entry_points(self):
        gaps = CoverageGaps(uncovered_entry_points=["ep-a"])
        assert gaps.has_gaps

    def test_has_gaps_true_for_zones(self):
        gaps = CoverageGaps(uncovered_zones=[3])
        assert gaps.has_gaps

    def test_has_gaps_true_for_threats(self):
        gaps = CoverageGaps(uncovered_threats=["T5"])
        assert gaps.has_gaps


# ---------------------------------------------------------------------------
# Coverage report output tests
# ---------------------------------------------------------------------------


class TestWriteCoverageReport:
    """Tests for write_coverage_report."""

    def test_writes_json_file(self, tmp_path: Path):
        gaps = CoverageGaps(
            uncovered_entry_points=["ep-a"],
            uncovered_zones=[3],
            uncovered_threats=["T5"],
        )

        path = write_coverage_report(gaps, tmp_path)
        assert path.exists()
        assert path.name == "coverage-gaps.json"

        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == ["ep-a"]
        assert data["coverage_gaps"]["uncovered_zones"] == [3]
        assert data["coverage_gaps"]["uncovered_threats"] == ["T5"]

    def test_writes_empty_gaps(self, tmp_path: Path):
        gaps = CoverageGaps()

        path = write_coverage_report(gaps, tmp_path)
        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == []
        assert data["coverage_gaps"]["uncovered_zones"] == []
        assert data["coverage_gaps"]["uncovered_threats"] == []
