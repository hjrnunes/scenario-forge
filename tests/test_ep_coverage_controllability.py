"""Tests for entry point coverage metric fix and controllability reclassification.

Bead m4a6: Two fixes for entry point diversity regression.

A. Coverage denominator must exclude output-direction entry points (they are
   structurally filtered out during candidate expansion and can never produce
   scenarios).
B. classify_entry_point() must downgrade 'system' controllability to 'indirect'
   when direction is not 'output' — a non-output direction means data flows in,
   so the attacker can influence the entry point at least indirectly.
"""

from __future__ import annotations

import pytest

from scenario_forge.eval.diversity import entry_point_entropy
from scenario_forge.pipeline.candidates import classify_entry_point


# ===========================================================================
# A. Coverage denominator excludes output-direction entry points
# ===========================================================================


class TestCoverageDenominatorExcludesOutput:
    """entry_point_entropy() coverage should use ingress-capable EP count."""

    @staticmethod
    def _scenarios_using(ep_names: list[str]) -> list[dict]:
        """Build minimal scenario dicts with the given entry point names."""
        return [
            {"narrative": {"entry_point": name}} for name in ep_names
        ]

    def test_coverage_excludes_output_eps(self):
        """With 3 ingress EPs + 1 output EP, denominator should be 3 not 4.

        If all 3 ingress EPs appear in scenarios, coverage = 3/3 = 1.0.
        """
        scenarios = self._scenarios_using(["ep-a", "ep-b", "ep-c"])
        # expected_entry_points = 3 (only ingress-capable)
        result = entry_point_entropy(scenarios, expected_entry_points=3)
        assert isinstance(result, dict)
        assert result["entry_point_coverage"] == 1.0

    def test_coverage_inflated_with_output_in_denominator(self):
        """Demonstrates the bug: if output EP were counted, coverage < 1.0."""
        scenarios = self._scenarios_using(["ep-a", "ep-b", "ep-c"])
        # If we incorrectly include the output EP -> denominator = 4
        result = entry_point_entropy(scenarios, expected_entry_points=4)
        assert isinstance(result, dict)
        # 3 unique / 4 expected = 0.75, not 1.0
        assert result["entry_point_coverage"] == 0.75

    def test_coverage_with_no_ingress_eps(self):
        """When all entry points are output-only, coverage should be 0.0."""
        scenarios = self._scenarios_using([])
        # 0 ingress EPs -> expected_entry_points = 0
        result = entry_point_entropy(scenarios, expected_entry_points=0)
        assert isinstance(result, dict)
        assert result["entry_point_coverage"] == 0.0

    def test_coverage_partial_ingress_usage(self):
        """When only some ingress EPs are used, coverage reflects that."""
        scenarios = self._scenarios_using(["ep-a"])
        # 2 ingress EPs available, only 1 used
        result = entry_point_entropy(scenarios, expected_entry_points=2)
        assert isinstance(result, dict)
        assert result["entry_point_coverage"] == 0.5


class TestRunnerCoverageDenominator:
    """Integration test: eval runner filters output EPs from the denominator."""

    def test_runner_filters_output_eps(self, tmp_path):
        """run_evaluation uses ingress-only count for expected_entry_points."""
        import yaml

        from scenario_forge.eval.runner import run_evaluation

        # Write a capability profile with mixed entry points
        cap_profile = {
            "entry_points": [
                {"name": "user chat", "direction": "input"},
                {"name": "document upload", "direction": "bidirectional"},
                {"name": "human escalation", "direction": "output"},
            ],
            "zones_active": ["input", "reasoning"],
        }
        (tmp_path / "capability-profile.yaml").write_text(
            yaml.dump(cap_profile), encoding="utf-8"
        )

        # Write scenarios using both ingress EPs
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()
        for i, ep in enumerate(["user chat", "document upload"]):
            scenario = {
                "scenario_id": f"s{i}",
                "narrative": {
                    "title": f"Scenario {i}",
                    "summary": "A test",
                    "entry_point": ep,
                    "zone_sequence": ["input", "reasoning"],
                    "steps": [],
                },
                "actor_profile": {
                    "actor_type": "external",
                    "goal_category": "data theft",
                    "capability_level": "intermediate",
                },
                "attack_tree": {"id": f"tree-{i}", "goal": "test", "root": {}},
            }
            (scenarios_dir / f"s{i}.yaml").write_text(
                yaml.dump(scenario), encoding="utf-8"
            )

        scorecard = run_evaluation(tmp_path)
        diversity = scorecard["evaluation"]["diversity"]
        ep_entropy = diversity["entry_point_entropy"]

        # With output EP excluded, expected = 2, actual unique = 2 -> 1.0
        assert isinstance(ep_entropy, dict)
        assert ep_entropy["entry_point_coverage"] == 1.0

    def test_runner_coverage_all_output_eps(self, tmp_path):
        """When all EPs are output-only, expected_entry_points = 0."""
        import yaml

        from scenario_forge.eval.runner import run_evaluation

        cap_profile = {
            "entry_points": [
                {"name": "response channel", "direction": "output"},
            ],
            "zones_active": ["input"],
        }
        (tmp_path / "capability-profile.yaml").write_text(
            yaml.dump(cap_profile), encoding="utf-8"
        )
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()

        scorecard = run_evaluation(tmp_path)
        diversity = scorecard["evaluation"]["diversity"]
        ep_entropy = diversity["entry_point_entropy"]

        # 0 ingress EPs -> expected = 0 -> coverage = 0.0
        assert isinstance(ep_entropy, dict)
        assert ep_entropy["entry_point_coverage"] == 0.0

    def test_runner_string_entry_points_not_filtered(self, tmp_path):
        """Plain-string entry points (no direction key) are always counted."""
        import yaml

        from scenario_forge.eval.runner import run_evaluation

        cap_profile = {
            "entry_points": ["user chat", "document upload", "API"],
            "zones_active": ["input"],
        }
        (tmp_path / "capability-profile.yaml").write_text(
            yaml.dump(cap_profile), encoding="utf-8"
        )
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()
        for i, ep in enumerate(["user chat", "document upload", "api"]):
            scenario = {
                "scenario_id": f"s{i}",
                "narrative": {
                    "title": f"S{i}",
                    "summary": "A test",
                    "entry_point": ep,
                    "zone_sequence": ["input"],
                    "steps": [],
                },
                "actor_profile": {
                    "actor_type": "external",
                    "goal_category": "data theft",
                    "capability_level": "intermediate",
                },
                "attack_tree": {"id": f"tree-{i}", "goal": "test", "root": {}},
            }
            (scenarios_dir / f"s{i}.yaml").write_text(
                yaml.dump(scenario), encoding="utf-8"
            )

        scorecard = run_evaluation(tmp_path)
        diversity = scorecard["evaluation"]["diversity"]
        ep_entropy = diversity["entry_point_entropy"]

        assert isinstance(ep_entropy, dict)
        assert ep_entropy["entry_point_coverage"] == 1.0


# ===========================================================================
# B. classify_entry_point controllability reclassification
# ===========================================================================


class TestControllabilityReclassification:
    """classify_entry_point() must downgrade 'system' to 'indirect' for
    non-output entry points."""

    def test_system_bidirectional_becomes_indirect(self):
        """Backend API (bidirectional, system) should be reclassified to indirect."""
        result = classify_entry_point(
            "backend service API calls", "bidirectional", "system"
        )
        assert result == "indirect"

    def test_system_input_becomes_indirect(self):
        """Input-direction with system controllability -> indirect."""
        result = classify_entry_point(
            "scheduled data feed", "input", "system"
        )
        assert result == "indirect"

    def test_system_output_stays_system(self):
        """Output-only with system controllability -> system (preserved)."""
        result = classify_entry_point(
            "human agent escalation triggers", "output", "system"
        )
        assert result == "system"

    def test_direct_controllability_preserved(self):
        """Explicit 'direct' is never downgraded regardless of direction."""
        assert classify_entry_point("chat", "input", "direct") == "direct"
        assert classify_entry_point("chat", "bidirectional", "direct") == "direct"
        assert classify_entry_point("chat", "output", "direct") == "direct"

    def test_indirect_controllability_preserved(self):
        """Explicit 'indirect' is never changed regardless of direction."""
        assert classify_entry_point("rag", "input", "indirect") == "indirect"
        assert classify_entry_point("rag", "bidirectional", "indirect") == "indirect"
        assert classify_entry_point("rag", "output", "indirect") == "indirect"


class TestControllabilityAdversarial:
    """Adversarial/edge cases for the controllability override."""

    def test_system_keyword_input_with_explicit_system(self):
        """An entry point with system keywords AND explicit system controllability
        but input direction: should be downgraded to indirect."""
        result = classify_entry_point(
            "internal backend scheduler API", "input", "system"
        )
        assert result == "indirect"

    def test_no_controllability_system_keyword_input_stays_system(self):
        """Without explicit controllability, system-keyword input EPs use
        the keyword heuristic and remain 'system' (the override only applies
        to explicit controllability)."""
        result = classify_entry_point(
            "internal backend scheduler API", "input", None
        )
        assert result == "system"

    def test_truly_output_only_system_entry_point(self):
        """A genuine output-only system entry point stays 'system'."""
        result = classify_entry_point(
            "monitoring dashboard alerts", "output", "system"
        )
        assert result == "system"

    def test_bidirectional_system_not_direct(self):
        """The override produces 'indirect', not 'direct' — even though
        the heuristic for bidirectional (without explicit controllability)
        would return 'direct'."""
        result = classify_entry_point(
            "backend service API calls", "bidirectional", "system"
        )
        assert result == "indirect"
        # Contrast: without explicit controllability, bidirectional -> direct
        result_heuristic = classify_entry_point(
            "backend service API calls", "bidirectional", None
        )
        assert result_heuristic == "direct"
