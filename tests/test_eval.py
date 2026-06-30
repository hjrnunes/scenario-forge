"""Tests for the Tier 1 deterministic evaluation framework."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from scenario_forge.eval.consistency import (
    entry_point_agreement,
    score_consistency,
    step_node_correspondence,
    zone_alignment,
)
from scenario_forge.eval.diversity import (
    actor_type_entropy,
    capability_level_evenness,
    entry_point_entropy,
    score_diversity,
    title_uniqueness,
    zone_coverage,
)
from scenario_forge.eval.gherkin import (
    has_background,
    parse_success,
    score_gherkin,
    step_count,
    step_keyword_balance,
    tag_consistency,
)
from scenario_forge.eval.grounding import score_grounding
from scenario_forge.eval.runner import run_evaluation


# ---------------------------------------------------------------------------
# Fixtures: synthetic scenario data
# ---------------------------------------------------------------------------


def _make_scenario(
    scenario_id: str = "T7-S1-abc123",
    title: str = "Exploit Agent Reasoning via Prompt Injection",
    entry_point: str = "user prompts (zone 1)",
    zone_sequence: list[int] | None = None,
    steps: list[dict[str, Any]] | None = None,
    root_zone: int = 1,
    root_label: str = "Compromise agent via user prompts",
    root_threat_id: str = "T7",
    leaf_nodes: list[dict[str, Any]] | None = None,
    actor_type: str = "adversarial-user",
    capability_level: str = "intermediate",
) -> dict[str, Any]:
    """Build a minimal synthetic scenario dict."""
    if zone_sequence is None:
        zone_sequence = [1, 2, 3]
    if steps is None:
        steps = [
            {
                "step_number": 1,
                "zone": 1,
                "action": "Craft a malicious user prompt targeting the agent",
                "effect": "Agent receives adversarial input",
            },
            {
                "step_number": 2,
                "zone": 2,
                "action": "Exploit agent reasoning to bypass safety filters",
                "effect": "Agent processes malicious instructions",
            },
            {
                "step_number": 3,
                "zone": 3,
                "action": "Exfiltrate data via tool execution",
                "effect": "Sensitive data exposed to attacker",
            },
        ]

    if leaf_nodes is None:
        leaf_nodes = [
            {
                "id": "n1.1",
                "label": "Craft malicious prompt",
                "gate": "LEAF",
                "zone": 1,
                "threat_id": root_threat_id,
            },
            {
                "id": "n1.2",
                "label": "Bypass reasoning safety filters",
                "gate": "LEAF",
                "zone": 2,
                "threat_id": root_threat_id,
            },
        ]

    return {
        "scenario_id": scenario_id,
        "narrative": {
            "title": title,
            "summary": "An adversarial user exploits agent reasoning.",
            "entry_point": entry_point,
            "zone_sequence": zone_sequence,
            "steps": steps,
        },
        "attack_tree": {
            "id": "tree-T7-S1",
            "seed_id": "T7-S1",
            "goal": "Compromise agent via prompt injection",
            "root": {
                "id": "n1",
                "label": root_label,
                "gate": "AND",
                "zone": root_zone,
                "threat_id": root_threat_id,
                "children": leaf_nodes,
            },
        },
        "actor_profile": {
            "actor_type": actor_type,
            "motivation": "Financial gain",
            "objective": "Steal customer data",
            "capability_level": capability_level,
            "resources": ["open-source tools"],
            "campaign_context": "Targeted attack",
        },
        "faceting": {
            "risk_card": {
                "risk_id": "atlas-prompt-injection",
                "risk_name": "Prompt Injection",
                "risk_description": "Attacker injects instructions",
                "taxonomy": "ibm-risk-atlas",
                "confidence": 0.95,
                "grounding_confidence": "high",
            },
            "taxonomy_chain": {
                "owasp_llm_ids": ["LLM01"],
                "agentic_threat_ids": ["T7"],
                "scenario_seed": "T7-S1",
            },
            "capability_profile": {
                "zones_traversed": zone_sequence,
                "architecture_match": "explicit",
                "entry_point": entry_point,
            },
            "maestro_layers": [1, 2],
        },
        "priority": {
            "composite": 0.85,
            "signals": {
                "technique_maturity": "demonstrated",
                "risk_impact": "high",
                "risk_likelihood": "high",
                "attack_complexity": "low",
                "architecture_match": "explicit",
                "structural_exposure": "single_point_of_failure",
            },
        },
    }


_GHERKIN_VALID = """\
@misaligned-and-deceptive-behavior
Feature: Exploit Agent Reasoning via Prompt Injection

  Background:
    Given an AI agent with user prompts as the primary entry point
    And the agent has access to external tools

  Scenario: Adversarial user injects malicious prompt
    # Zone 1
    When the adversarial user crafts a malicious prompt
    Then the agent receives adversarial input
    # Zone 2
    When the agent processes the malicious instructions
    Then the safety filters are bypassed
    # Zone 3
    When the attacker exfiltrates data via tool execution
    Then sensitive data is exposed
"""

_GHERKIN_MINIMAL = """\
Feature: Minimal test

  Scenario: Basic
    Given a system
    When something happens
    Then it works
"""

_GHERKIN_INVALID = "This is not valid Gherkin at all."


# ===========================================================================
# Consistency tests
# ===========================================================================


class TestZoneAlignment:
    def test_perfect_alignment(self):
        scenario = _make_scenario(zone_sequence=[1, 2, 3])
        # Tree root is zone 1, children are zones 1 and 2
        # Narrative zones: {1, 2, 3}, Tree zones: {1, 2}
        score = zone_alignment(scenario)
        assert 0.0 <= score <= 1.0

    def test_with_gherkin(self):
        scenario = _make_scenario(zone_sequence=[1, 2, 3])
        score = zone_alignment(scenario, _GHERKIN_VALID)
        assert 0.0 <= score <= 1.0

    def test_identical_zones(self):
        scenario = _make_scenario(
            zone_sequence=[1, 2],
            steps=[
                {"step_number": 1, "zone": 1, "action": "act", "effect": "eff"},
                {"step_number": 2, "zone": 2, "action": "act", "effect": "eff"},
            ],
        )
        # Narrative zones {1, 2}, Tree zones {1, 2} -> Jaccard = 1.0
        score = zone_alignment(scenario)
        assert score == 1.0

    def test_no_zones(self):
        scenario = _make_scenario(zone_sequence=[])
        scenario["attack_tree"]["root"]["zone"] = 1
        score = zone_alignment(scenario)
        assert 0.0 <= score <= 1.0


class TestEntryPointAgreement:
    def test_entry_in_gherkin_background(self):
        scenario = _make_scenario(entry_point="user prompts (zone 1)")
        result = entry_point_agreement(scenario, _GHERKIN_VALID)
        assert result == 1

    def test_entry_in_tree_root(self):
        scenario = _make_scenario(
            entry_point="user prompts",
            root_label="Compromise agent via user prompts",
        )
        result = entry_point_agreement(scenario)
        assert result == 1

    def test_entry_nowhere(self):
        scenario = _make_scenario(
            entry_point="completely unrelated xyz abc",
            root_label="Something totally different qrs",
        )
        result = entry_point_agreement(scenario)
        assert result == 0

    def test_empty_entry_point(self):
        scenario = _make_scenario(entry_point="")
        result = entry_point_agreement(scenario)
        assert result == 0


class TestStepNodeCorrespondence:
    def test_some_matches(self):
        scenario = _make_scenario()
        score = step_node_correspondence(scenario)
        assert 0.0 <= score <= 1.0

    def test_no_steps(self):
        scenario = _make_scenario(steps=[])
        score = step_node_correspondence(scenario)
        assert score == 0.0

    def test_perfect_match(self):
        """Steps and leaves in the same zones with shared keywords."""
        scenario = _make_scenario(
            steps=[
                {
                    "step_number": 1,
                    "zone": 1,
                    "action": "Craft malicious prompt injection",
                    "effect": "Agent compromised",
                },
            ],
            leaf_nodes=[
                {
                    "id": "n1.1",
                    "label": "Craft malicious prompt",
                    "gate": "LEAF",
                    "zone": 1,
                    "threat_id": "T7",
                },
                {
                    "id": "n1.2",
                    "label": "Other node",
                    "gate": "LEAF",
                    "zone": 2,
                    "threat_id": "T7",
                },
            ],
        )
        score = step_node_correspondence(scenario)
        assert score == 1.0


class TestScoreConsistency:
    def test_returns_all_keys(self):
        scenario = _make_scenario()
        result = score_consistency(scenario, _GHERKIN_VALID)
        assert "zone_alignment" in result
        assert "entry_point_agreement" in result
        assert "step_node_correspondence" in result
        assert "mean" in result

    def test_mean_is_average(self):
        scenario = _make_scenario()
        result = score_consistency(scenario)
        expected_mean = (
            result["zone_alignment"]
            + result["entry_point_agreement"]
            + result["step_node_correspondence"]
        ) / 3
        assert abs(result["mean"] - round(expected_mean, 4)) < 0.001


# ===========================================================================
# Gherkin tests
# ===========================================================================


class TestParseSuccess:
    def test_valid_gherkin(self):
        assert parse_success(_GHERKIN_VALID) is True

    def test_minimal_gherkin(self):
        assert parse_success(_GHERKIN_MINIMAL) is True

    def test_invalid_gherkin(self):
        assert parse_success(_GHERKIN_INVALID) is False


class TestStepCount:
    def test_counts_all_keywords(self):
        count = step_count(_GHERKIN_VALID)
        assert count > 0

    def test_minimal(self):
        count = step_count(_GHERKIN_MINIMAL)
        assert count == 3  # Given, When, Then

    def test_empty(self):
        assert step_count("") == 0


class TestHasBackground:
    def test_with_background(self):
        assert has_background(_GHERKIN_VALID) is True

    def test_without_background(self):
        assert has_background(_GHERKIN_MINIMAL) is False


class TestStepKeywordBalance:
    def test_balance(self):
        balance = step_keyword_balance(_GHERKIN_VALID)
        assert balance["Given"] > 0
        assert balance["When"] > 0
        assert balance["Then"] > 0


class TestTagConsistency:
    def test_consistent_tags(self):
        texts = [
            "@prompt-injection\nFeature: A",
            "@prompt-injection\nFeature: B",
        ]
        result = tag_consistency(texts)
        assert result["inconsistent_groups"] == 0

    def test_inconsistent_tags(self):
        texts = [
            "@misaligned-and-deceptive-behavior\nFeature: A",
            "@misaligned-deceptive-behaviors\nFeature: B",
        ]
        result = tag_consistency(texts)
        # These should normalize to the same form
        assert result["inconsistent_groups"] >= 1

    def test_empty_input(self):
        result = tag_consistency([])
        assert result["inconsistent_groups"] == 0


class TestScoreGherkin:
    def test_batch_metrics(self):
        result = score_gherkin([_GHERKIN_VALID, _GHERKIN_MINIMAL])
        assert "parse_success_rate" in result
        assert "mean_step_count" in result
        assert "tag_consistency" in result
        assert "background_missing_warnings" in result
        assert result["parse_success_rate"] == 1.0
        # _GHERKIN_MINIMAL has no Background, so index 1 should be warned
        assert 1 in result["background_missing_warnings"]
        assert 0 not in result["background_missing_warnings"]

    def test_empty_batch(self):
        result = score_gherkin([])
        assert result["parse_success_rate"] == 0.0
        assert result["mean_step_count"] == 0.0

    def test_mixed_validity(self):
        result = score_gherkin([_GHERKIN_VALID, _GHERKIN_INVALID])
        assert result["parse_success_rate"] == 0.5

    def test_no_background_rate_in_output(self):
        """background_rate and mean_zone_annotation_rate are removed."""
        result = score_gherkin([_GHERKIN_VALID])
        assert "background_rate" not in result
        assert "mean_zone_annotation_rate" not in result

    def test_background_warning_emitted(self, caplog):
        """Warning is logged when a feature file lacks a Background."""
        import logging

        with caplog.at_level(logging.WARNING):
            result = score_gherkin([_GHERKIN_MINIMAL])
        assert result["background_missing_warnings"] == [0]
        assert "lacks a Background section" in caplog.text

    def test_all_have_background(self):
        result = score_gherkin([_GHERKIN_VALID, _GHERKIN_VALID])
        assert result["background_missing_warnings"] == []


# ===========================================================================
# Grounding tests
# ===========================================================================


class TestScoreGrounding:
    def test_valid_threat_ids(self):
        scenarios = [_make_scenario(root_threat_id="T7")]
        result = score_grounding(scenarios)
        # T7 is a valid OWASP agentic threat
        assert result["threat_id_validity"] == 1.0
        assert result["dangling_references"] == 0

    def test_invalid_threat_id(self):
        scenarios = [_make_scenario(root_threat_id="T99")]
        result = score_grounding(scenarios)
        assert result["threat_id_validity"] < 1.0
        assert result["dangling_references"] > 0

    def test_no_threats(self):
        scenario = _make_scenario()
        scenario["attack_tree"]["root"]["threat_id"] = None
        for child in scenario["attack_tree"]["root"]["children"]:
            child["threat_id"] = None
        result = score_grounding([scenario])
        # No references at all -> validity 1.0
        assert result["threat_id_validity"] == 1.0
        assert result["dangling_references"] == 0

    def test_mixed_validity(self):
        s1 = _make_scenario(root_threat_id="T7", scenario_id="s1")
        s2 = _make_scenario(root_threat_id="T99", scenario_id="s2")
        result = score_grounding([s1, s2])
        assert 0.0 < result["threat_id_validity"] < 1.0


# ===========================================================================
# Diversity tests
# ===========================================================================


class TestEntryPointEntropy:
    def test_uniform_distribution(self):
        scenarios = [
            _make_scenario(entry_point="api endpoints"),
            _make_scenario(entry_point="user prompts"),
            _make_scenario(entry_point="tool invocations"),
        ]
        result = entry_point_entropy(scenarios)
        assert result > 0.9  # High entropy for uniform

    def test_single_entry_point(self):
        scenarios = [
            _make_scenario(entry_point="user prompts"),
            _make_scenario(entry_point="user prompts"),
        ]
        result = entry_point_entropy(scenarios)
        assert result == 0.0

    def test_empty(self):
        result = entry_point_entropy([])
        assert result == 0.0


class TestZoneCoverage:
    def test_full_coverage(self):
        scenarios = [
            _make_scenario(zone_sequence=[1, 2, 3, 4, 5]),
        ]
        result = zone_coverage(scenarios)
        assert result == 1.0

    def test_partial_coverage(self):
        scenarios = [
            _make_scenario(zone_sequence=[1, 2]),
        ]
        result = zone_coverage(scenarios)
        assert result == 0.4

    def test_no_scenarios(self):
        result = zone_coverage([])
        assert result == 0.0


class TestActorTypeEntropy:
    def test_diverse_actors(self):
        scenarios = [
            _make_scenario(actor_type="adversarial-user"),
            _make_scenario(actor_type="cybercriminal"),
            _make_scenario(actor_type="nation-state"),
        ]
        result = actor_type_entropy(scenarios)
        assert result > 0.9

    def test_single_actor_type(self):
        scenarios = [
            _make_scenario(actor_type="adversarial-user"),
            _make_scenario(actor_type="adversarial-user"),
        ]
        result = actor_type_entropy(scenarios)
        assert result == 0.0


class TestCapabilityLevelEvenness:
    def test_even_distribution(self):
        scenarios = [
            _make_scenario(capability_level="novice"),
            _make_scenario(capability_level="intermediate"),
            _make_scenario(capability_level="advanced"),
            _make_scenario(capability_level="expert"),
        ]
        result = capability_level_evenness(scenarios)
        assert result == 1.0

    def test_single_level(self):
        scenarios = [
            _make_scenario(capability_level="intermediate"),
            _make_scenario(capability_level="intermediate"),
        ]
        result = capability_level_evenness(scenarios)
        assert result == 0.0


class TestTitleUniqueness:
    def test_unique_titles(self):
        scenarios = [
            _make_scenario(title="Memory Poisoning Attack on LLM Agent"),
            _make_scenario(title="Tool Execution Bypass via Injection"),
            _make_scenario(title="Credential Theft through Social Engineering"),
        ]
        result = title_uniqueness(scenarios)
        assert result > 0.5

    def test_identical_titles(self):
        scenarios = [
            _make_scenario(title="Same Title Here"),
            _make_scenario(title="Same Title Here"),
        ]
        result = title_uniqueness(scenarios)
        assert result == 0.0

    def test_single_scenario(self):
        scenarios = [_make_scenario(title="Only One")]
        result = title_uniqueness(scenarios)
        assert result == 1.0

    def test_empty(self):
        result = title_uniqueness([])
        assert result == 1.0


class TestScoreDiversity:
    def test_returns_all_keys(self):
        scenarios = [
            _make_scenario(
                actor_type="adversarial-user",
                capability_level="novice",
                entry_point="user prompts",
            ),
            _make_scenario(
                actor_type="cybercriminal",
                capability_level="expert",
                entry_point="api endpoints",
            ),
        ]
        result = score_diversity(scenarios)
        assert "entry_point_entropy" in result
        assert "zone_coverage" in result
        assert "actor_type_entropy" in result
        assert "capability_level_evenness" in result
        assert "title_uniqueness" in result


# ===========================================================================
# Runner / integration tests
# ===========================================================================


class TestRunEvaluation:
    def test_with_synthetic_data(self, tmp_path: Path):
        """Integration test: write synthetic data and run full evaluation."""
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()

        # Write scenario YAML files
        for i in range(3):
            s = _make_scenario(
                scenario_id=f"T7-S{i+1}-abc{i:03d}",
                title=f"Scenario {i+1}: {'ABCDEF'[i]} Attack",
                entry_point=["user prompts", "api endpoints", "tool calls"][i % 3],
                zone_sequence=[1, 2, (i % 5) + 1],
                actor_type=["adversarial-user", "cybercriminal", "nation-state"][i],
                capability_level=["novice", "intermediate", "advanced"][i],
            )
            yaml_path = scenarios_dir / f"scenario-{i}.yaml"
            yaml_path.write_text(
                yaml.dump(s, default_flow_style=False), encoding="utf-8"
            )

            # Write matching .feature files
            feature_path = scenarios_dir / f"scenario-{i}.feature"
            feature_path.write_text(_GHERKIN_VALID, encoding="utf-8")

        scorecard = run_evaluation(tmp_path)

        assert "evaluation" in scorecard
        ev = scorecard["evaluation"]
        assert ev["scenario_count"] == 3
        assert ev["feature_file_count"] == 3

        # Check all sections present
        assert "consistency" in ev
        assert "gherkin" in ev
        assert "grounding" in ev
        assert "diversity" in ev

        # Check consistency has per-scenario data
        assert "per_scenario" in ev["consistency"]
        assert len(ev["consistency"]["per_scenario"]) == 3
        assert "mean" in ev["consistency"]
        assert "stddev" in ev["consistency"]

        # Check gherkin metrics
        assert ev["gherkin"]["parse_success_rate"] == 1.0

        # Check grounding
        assert ev["grounding"]["threat_id_validity"] == 1.0

    def test_empty_directory(self, tmp_path: Path):
        """Should handle empty output directory gracefully."""
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()

        scorecard = run_evaluation(tmp_path)
        assert scorecard["evaluation"]["scenario_count"] == 0

    def test_no_scenarios_dir(self, tmp_path: Path):
        """Should handle missing scenarios directory."""
        scorecard = run_evaluation(tmp_path)
        assert scorecard["evaluation"]["scenario_count"] == 0

    def test_scenarios_without_features(self, tmp_path: Path):
        """Should work with YAML files but no .feature files."""
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()

        s = _make_scenario()
        yaml_path = scenarios_dir / "scenario-0.yaml"
        yaml_path.write_text(
            yaml.dump(s, default_flow_style=False), encoding="utf-8"
        )

        scorecard = run_evaluation(tmp_path)
        assert scorecard["evaluation"]["scenario_count"] == 1
        assert scorecard["evaluation"]["feature_file_count"] == 0

    def test_scorecard_yaml_serializable(self, tmp_path: Path):
        """Scorecard should be serializable to YAML and JSON."""
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()

        s = _make_scenario()
        yaml_path = scenarios_dir / "scenario-0.yaml"
        yaml_path.write_text(
            yaml.dump(s, default_flow_style=False), encoding="utf-8"
        )

        scorecard = run_evaluation(tmp_path)

        # YAML roundtrip
        yaml_text = yaml.dump(scorecard, default_flow_style=False)
        reloaded = yaml.safe_load(yaml_text)
        assert reloaded["evaluation"]["scenario_count"] == 1

        # JSON roundtrip
        json_text = json.dumps(scorecard, indent=2, default=str)
        reloaded_json = json.loads(json_text)
        assert reloaded_json["evaluation"]["scenario_count"] == 1
