"""Tests for post-generation coverage analysis.

Covers:
- Coverage gap analysis (scenario-forge-n63):
  - All entry points covered (no gaps)
  - Some entry points missing
  - All entry points missing
  - Zone coverage gaps
  - Threat coverage gaps
  - Empty scenarios list
- Attacker model diversity (scenario-forge-cw9):
  - Diverse actors (no flag)
  - Monotone actors (flagged)
  - Single scenario edge case
  - Unknown attacker model
  - Empty scenarios list
- Coverage report output
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

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
    AttackerDiversityResult,
    CoverageGaps,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    classify_attacker_model,
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
# Attacker model diversity tests (scenario-forge-cw9)
# ---------------------------------------------------------------------------


class TestClassifyAttackerModel:
    """Tests for the keyword-based attacker model classifier."""

    def test_insider_keywords(self):
        assert (
            classify_attacker_model("A disgruntled employee steals data") == "insider"
        )
        assert classify_attacker_model("The insider threat is real") == "insider"
        assert (
            classify_attacker_model("Rogue employee exfiltrates secrets") == "insider"
        )

    def test_supply_chain_keywords(self):
        assert (
            classify_attacker_model("Compromised vendor injects backdoor")
            == "supply_chain"
        )
        assert (
            classify_attacker_model("Supply chain attack via dependency")
            == "supply_chain"
        )
        assert (
            classify_attacker_model("Third-party library trojanized") == "supply_chain"
        )

    def test_social_engineer_keywords(self):
        assert (
            classify_attacker_model("Phishing email tricks the user")
            == "social_engineer"
        )
        assert (
            classify_attacker_model("Social engineer impersonates admin")
            == "social_engineer"
        )

    def test_privileged_user_keywords(self):
        assert (
            classify_attacker_model("Malicious admin abuses access")
            == "privileged_user"
        )
        assert (
            classify_attacker_model("Privileged user escalates permissions")
            == "privileged_user"
        )

    def test_external_attacker_keywords(self):
        assert (
            classify_attacker_model("External attacker sends crafted payload")
            == "external_attacker"
        )
        assert (
            classify_attacker_model("The attacker exploits a vulnerability")
            == "external_attacker"
        )
        assert (
            classify_attacker_model("A hacker breaks into the system")
            == "external_attacker"
        )

    def test_unknown_when_no_keywords(self):
        assert (
            classify_attacker_model("The system processes data normally") == "unknown"
        )

    def test_case_insensitive(self):
        assert classify_attacker_model("The INSIDER threat is real") == "insider"
        assert classify_attacker_model("SUPPLY CHAIN compromise") == "supply_chain"

    def test_priority_order_insider_over_external(self):
        """Insider keywords take priority over external attacker keywords."""
        result = classify_attacker_model("An insider attacker exfiltrates data")
        assert result == "insider"


class TestAnalyzeAttackerDiversity:
    """Tests for analyze_attacker_diversity."""

    def test_empty_scenarios(self):
        result = analyze_attacker_diversity([])
        assert result.model_counts == {}
        assert result.dominant_model is None
        assert result.is_flagged is False

    def test_diverse_attacker_models_no_flag(self):
        """When scenarios have varied attacker models, no flag."""
        scenarios = [
            _make_envelope(
                summary="An insider steals credentials.",
                step_actions=["I use my insider access to bypass controls."],
            ),
            _make_envelope(
                summary="A supply chain attack injects malicious code.",
                step_actions=["I compromise a third-party vendor."],
            ),
            _make_envelope(
                summary="A phishing campaign targets users.",
                step_actions=["I craft a social engineering email."],
            ),
            _make_envelope(
                summary="External attacker exploits API.",
                step_actions=["I send crafted payloads."],
            ),
            _make_envelope(
                summary="A privileged user abuses admin console.",
                step_actions=["I use malicious admin access."],
            ),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert not result.is_flagged
        assert len(result.model_counts) >= 4

    def test_monotone_external_attacker_flagged(self):
        """When >80% of scenarios use 'external_attacker', flag is raised."""
        scenarios = [
            _make_envelope(
                summary="The attacker injects prompts.",
                step_actions=["I craft a malicious prompt."],
            ),
            _make_envelope(
                summary="The attacker exploits the API.",
                step_actions=["I send malicious requests."],
            ),
            _make_envelope(
                summary="The attacker steals data.",
                step_actions=["I exfiltrate sensitive information."],
            ),
            _make_envelope(
                summary="The attacker modifies output.",
                step_actions=["I manipulate the response."],
            ),
            _make_envelope(
                summary="The attacker escapes the sandbox.",
                step_actions=["I break out of containment."],
            ),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.is_flagged
        assert result.dominant_model == "external_attacker"
        assert result.dominant_fraction > 0.8

    def test_exactly_at_threshold_not_flagged(self):
        """Exactly 80% (4/5) should NOT be flagged (> threshold, not >=)."""
        scenarios = [
            _make_envelope(
                summary="The attacker exploits a flaw.",
                step_actions=["I craft a malicious payload."],
            ),
            _make_envelope(
                summary="The attacker sends requests.",
                step_actions=["I exploit the endpoint."],
            ),
            _make_envelope(
                summary="The attacker steals tokens.",
                step_actions=["I capture authentication tokens."],
            ),
            _make_envelope(
                summary="The attacker escapes limits.",
                step_actions=["I bypass rate limiting."],
            ),
            _make_envelope(
                summary="An insider leaks data.",
                step_actions=["I use insider access to exfiltrate data."],
            ),
        ]

        result = analyze_attacker_diversity(scenarios)
        # 4 external + 1 insider = 4/5 = 0.8
        assert result.dominant_fraction == pytest.approx(0.8)
        assert not result.is_flagged

    def test_single_scenario_flagged(self):
        """One scenario = 100% one model, which is > 80%, so it IS flagged."""
        scenarios = [
            _make_envelope(
                summary="The attacker crafts malicious input.",
                step_actions=["I inject a prompt."],
            ),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.dominant_fraction == 1.0
        assert result.is_flagged

    def test_all_unknown_models_flagged(self):
        """Scenarios with no recognizable keywords are classified as unknown."""
        scenarios = [
            _make_envelope(
                summary="The system processes data.",
                step_actions=["Data flows through the pipeline."],
            ),
            _make_envelope(
                summary="Input is transformed.",
                step_actions=["Transformation occurs."],
            ),
            _make_envelope(
                summary="Output is generated.",
                step_actions=["Results are produced."],
            ),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.dominant_model == "unknown"
        assert result.is_flagged

    def test_to_dict(self):
        result = AttackerDiversityResult(
            model_counts={"external_attacker": 3, "insider": 1},
            dominant_model="external_attacker",
            dominant_fraction=0.75,
            is_flagged=False,
        )
        d = result.to_dict()
        assert d["model_counts"] == {"external_attacker": 3, "insider": 1}
        assert d["dominant_model"] == "external_attacker"
        assert d["dominant_fraction"] == 0.75
        assert d["is_flagged"] is False


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
        diversity = AttackerDiversityResult(
            model_counts={"external_attacker": 5},
            dominant_model="external_attacker",
            dominant_fraction=1.0,
            is_flagged=True,
        )

        path = write_coverage_report(gaps, tmp_path, diversity)
        assert path.exists()
        assert path.name == "coverage-gaps.json"

        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == ["ep-a"]
        assert data["coverage_gaps"]["uncovered_zones"] == [3]
        assert data["coverage_gaps"]["uncovered_threats"] == ["T5"]
        assert data["attacker_diversity"]["is_flagged"] is True
        assert data["attacker_diversity"]["dominant_model"] == "external_attacker"

    def test_writes_empty_gaps(self, tmp_path: Path):
        gaps = CoverageGaps()

        path = write_coverage_report(gaps, tmp_path)
        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == []
        assert data["coverage_gaps"]["uncovered_zones"] == []
        assert data["coverage_gaps"]["uncovered_threats"] == []
        assert "attacker_diversity" not in data

    def test_writes_with_attacker_diversity(self, tmp_path: Path):
        gaps = CoverageGaps()
        diversity = AttackerDiversityResult(
            model_counts={"insider": 2, "external_attacker": 3},
            dominant_model="external_attacker",
            dominant_fraction=0.6,
            is_flagged=False,
        )

        path = write_coverage_report(gaps, tmp_path, diversity)
        data = json.loads(path.read_text())
        assert data["attacker_diversity"]["dominant_model"] == "external_attacker"
        assert data["attacker_diversity"]["is_flagged"] is False
