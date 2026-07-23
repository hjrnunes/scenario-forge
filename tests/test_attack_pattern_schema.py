"""Tests for attack pattern schema models and kill_chain field support (bead 05in).

Covers:
- KillChainStep and EvidenceLink Pydantic model validation
- AttackPattern model with and without kill_chain/evidence
- validate_attack_pattern() helper
- Loader pass-through: kill_chain survives YAML round-trip via load_attack_patterns
- Backward compatibility: patterns without kill_chain still load
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.models.attack_pattern import (
    AttackPattern,
    EvidenceLink,
    KillChainStep,
    validate_attack_pattern,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_PATTERN = {
    "id": "AP-T1-01",
    "threat_id": "T1",
    "name": "Test pattern",
    "description": "A test attack pattern.",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory"],
        "kc_requires": {"all": ["KCX-PMEM"], "any": ["KC4.3"]},
    },
}

PATTERN_WITH_KILL_CHAIN = {
    **MINIMAL_PATTERN,
    "id": "AP-T1-05",
    "name": "Memory poisoning via connected application injection",
    "kill_chain": [
        {
            "step": "setup",
            "tactic": "AML.TA0003",
            "techniques": ["AML.T0065", "AML.T0068"],
            "abstract_action": "Craft adversarial prompt injection concealed within shareable content.",
        },
        {
            "step": "delivery",
            "tactic": "AML.TA0004",
            "techniques": ["AML.T0093"],
            "abstract_action": "Deliver through a connected application the agent treats as trusted.",
        },
    ],
    "evidence": [
        {"source": "AML.CS0040", "type": "direct_demonstration"},
        {"source": "AML.CS0041", "type": "variant"},
    ],
}


# ---------------------------------------------------------------------------
# KillChainStep model tests
# ---------------------------------------------------------------------------


class TestKillChainStep:
    """Tests for the KillChainStep Pydantic model."""

    def test_valid_step(self):
        step = KillChainStep(
            step="setup",
            tactic="AML.TA0003",
            techniques=["AML.T0065"],
            abstract_action="Do something adversarial.",
        )
        assert step.step == "setup"
        assert step.tactic == "AML.TA0003"
        assert step.techniques == ["AML.T0065"]

    def test_invalid_tactic_format(self):
        """Tactic must match ^AML\\.TA\\d{4}$."""
        with pytest.raises(ValidationError, match="tactic"):
            KillChainStep(
                step="setup",
                tactic="WRONG-FORMAT",
                techniques=["AML.T0065"],
                abstract_action="Action.",
            )

    def test_tactic_missing_prefix(self):
        """Tactic without AML. prefix should fail."""
        with pytest.raises(ValidationError, match="tactic"):
            KillChainStep(
                step="setup",
                tactic="TA0003",
                techniques=["AML.T0065"],
                abstract_action="Action.",
            )

    def test_tactic_too_few_digits(self):
        """Tactic with fewer than 4 digits should fail."""
        with pytest.raises(ValidationError, match="tactic"):
            KillChainStep(
                step="setup",
                tactic="AML.TA003",
                techniques=["AML.T0065"],
                abstract_action="Action.",
            )

    def test_empty_techniques_list(self):
        """Techniques list must have at least 1 element."""
        with pytest.raises(ValidationError, match="techniques"):
            KillChainStep(
                step="setup",
                tactic="AML.TA0003",
                techniques=[],
                abstract_action="Action.",
            )

    def test_invalid_technique_id(self):
        """Technique IDs must start with AML.T."""
        with pytest.raises(ValidationError, match="AML.T"):
            KillChainStep(
                step="setup",
                tactic="AML.TA0003",
                techniques=["WRONG.X0001"],
                abstract_action="Action.",
            )

    def test_multiple_techniques(self):
        """Multiple technique IDs are accepted."""
        step = KillChainStep(
            step="exploitation",
            tactic="AML.TA0005",
            techniques=["AML.T0001", "AML.T0002", "AML.T0003"],
            abstract_action="Do multiple things.",
        )
        assert len(step.techniques) == 3


# ---------------------------------------------------------------------------
# EvidenceLink model tests
# ---------------------------------------------------------------------------


class TestEvidenceLink:
    """Tests for the EvidenceLink Pydantic model."""

    def test_valid_direct_demonstration(self):
        link = EvidenceLink(source="AML.CS0040", type="direct_demonstration")
        assert link.source == "AML.CS0040"
        assert link.type == "direct_demonstration"

    def test_valid_variant(self):
        link = EvidenceLink(source="AML.CS0041", type="variant")
        assert link.type == "variant"

    def test_valid_enrichment(self):
        link = EvidenceLink(source="NIST-REF-01", type="enrichment")
        assert link.type == "enrichment"

    def test_invalid_type(self):
        """Type must be one of the three allowed literals."""
        with pytest.raises(ValidationError, match="type"):
            EvidenceLink(source="AML.CS0040", type="invalid_type")


# ---------------------------------------------------------------------------
# AttackPattern model tests
# ---------------------------------------------------------------------------


class TestAttackPattern:
    """Tests for the AttackPattern Pydantic model."""

    def test_minimal_pattern_no_kill_chain(self):
        """Pattern without kill_chain or evidence validates fine."""
        pattern = AttackPattern.model_validate(MINIMAL_PATTERN)
        assert pattern.id == "AP-T1-01"
        assert pattern.kill_chain is None
        assert pattern.evidence is None

    def test_pattern_with_kill_chain(self):
        """Pattern with kill_chain and evidence validates correctly."""
        pattern = AttackPattern.model_validate(PATTERN_WITH_KILL_CHAIN)
        assert pattern.id == "AP-T1-05"
        assert pattern.kill_chain is not None
        assert len(pattern.kill_chain) == 2
        assert pattern.kill_chain[0].step == "setup"
        assert pattern.kill_chain[1].tactic == "AML.TA0004"
        assert pattern.evidence is not None
        assert len(pattern.evidence) == 2

    def test_pattern_with_nist_classification(self):
        """Pattern with nist_classification field validates."""
        data = {
            **MINIMAL_PATTERN,
            "nist_classification": {
                "attacker_goal": "integrity",
                "attacker_knowledge": "black_box",
                "learning_stage": "deployment",
                "attack_class": "poisoning.targeted_poisoning",
            },
        }
        pattern = AttackPattern.model_validate(data)
        assert pattern.nist_classification is not None
        assert pattern.nist_classification.attacker_goal == "integrity"

    def test_pattern_with_nist_no_attack_class(self):
        """NIST classification without optional attack_class field."""
        data = {
            **MINIMAL_PATTERN,
            "nist_classification": {
                "attacker_goal": "abuse",
                "attacker_knowledge": "gray_box",
                "learning_stage": "deployment",
            },
        }
        pattern = AttackPattern.model_validate(data)
        assert pattern.nist_classification.attack_class is None

    def test_kill_chain_only_no_evidence(self):
        """kill_chain without evidence is valid."""
        data = {
            **MINIMAL_PATTERN,
            "kill_chain": PATTERN_WITH_KILL_CHAIN["kill_chain"],
        }
        pattern = AttackPattern.model_validate(data)
        assert pattern.kill_chain is not None
        assert pattern.evidence is None

    def test_evidence_only_no_kill_chain(self):
        """evidence without kill_chain is valid."""
        data = {
            **MINIMAL_PATTERN,
            "evidence": [{"source": "AML.CS0040", "type": "direct_demonstration"}],
        }
        pattern = AttackPattern.model_validate(data)
        assert pattern.kill_chain is None
        assert pattern.evidence is not None

    def test_empty_kill_chain_list(self):
        """Empty kill_chain list is valid (no steps)."""
        data = {**MINIMAL_PATTERN, "kill_chain": []}
        pattern = AttackPattern.model_validate(data)
        assert pattern.kill_chain == []


# ---------------------------------------------------------------------------
# validate_attack_pattern() tests
# ---------------------------------------------------------------------------


class TestValidateAttackPattern:
    """Tests for the validate_attack_pattern() helper function."""

    def test_valid_pattern(self):
        result = validate_attack_pattern(MINIMAL_PATTERN)
        assert isinstance(result, AttackPattern)
        assert result.id == "AP-T1-01"

    def test_valid_pattern_with_kill_chain(self):
        result = validate_attack_pattern(PATTERN_WITH_KILL_CHAIN)
        assert result.kill_chain is not None
        assert len(result.kill_chain) == 2

    def test_invalid_pattern_raises(self):
        """Missing required fields should raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_attack_pattern({"id": "AP-T1-01"})

    def test_invalid_kill_chain_tactic(self):
        """Invalid tactic in kill_chain raises ValidationError."""
        data = {
            **MINIMAL_PATTERN,
            "kill_chain": [
                {
                    "step": "setup",
                    "tactic": "BAD",
                    "techniques": ["AML.T0065"],
                    "abstract_action": "Action.",
                }
            ],
        }
        with pytest.raises(ValidationError, match="tactic"):
            validate_attack_pattern(data)


# ---------------------------------------------------------------------------
# Loader pass-through tests
# ---------------------------------------------------------------------------


class TestLoaderPassThrough:
    """Tests that kill_chain field passes through the YAML loader."""

    def test_kill_chain_survives_round_trip(self, tmp_path: Path):
        """kill_chain present in YAML is accessible in loaded dict."""
        patterns_yaml = {
            "source": {"name": "test", "version": "0.1.0"},
            "patterns": {
                "AP-T1-05": {
                    "id": "AP-T1-05",
                    "threat_id": "T1",
                    "name": "Pattern with kill chain",
                    "description": "Test pattern with kill chain.",
                    "prerequisite_capabilities": {
                        "min_zones": ["input", "memory"],
                    },
                    "kill_chain": [
                        {
                            "step": "setup",
                            "tactic": "AML.TA0003",
                            "techniques": ["AML.T0065"],
                            "abstract_action": "Craft injection.",
                        },
                    ],
                    "evidence": [
                        {"source": "AML.CS0040", "type": "direct_demonstration"},
                    ],
                },
            },
        }

        p = tmp_path / "attack-patterns-test.yaml"
        p.write_text(yaml.dump(patterns_yaml, default_flow_style=False))

        result = load_attack_patterns(path=p)

        assert "AP-T1-05" in result
        pattern = result["AP-T1-05"]

        # kill_chain passes through as raw dict/list
        assert "kill_chain" in pattern
        assert len(pattern["kill_chain"]) == 1
        assert pattern["kill_chain"][0]["step"] == "setup"
        assert pattern["kill_chain"][0]["tactic"] == "AML.TA0003"

        # evidence passes through too
        assert "evidence" in pattern
        assert pattern["evidence"][0]["source"] == "AML.CS0040"

    def test_pattern_without_kill_chain_still_loads(self, tmp_path: Path):
        """Patterns without kill_chain load normally (backward compat)."""
        patterns_yaml = {
            "source": {"name": "test", "version": "0.1.0"},
            "patterns": {
                "AP-T1-01": {
                    "id": "AP-T1-01",
                    "threat_id": "T1",
                    "name": "Legacy pattern",
                    "description": "No kill chain here.",
                    "prerequisite_capabilities": {
                        "min_zones": ["input", "memory"],
                    },
                },
            },
        }

        p = tmp_path / "attack-patterns-legacy.yaml"
        p.write_text(yaml.dump(patterns_yaml, default_flow_style=False))

        result = load_attack_patterns(path=p)

        assert "AP-T1-01" in result
        pattern = result["AP-T1-01"]
        assert "kill_chain" not in pattern
        assert "evidence" not in pattern

    def test_mixed_patterns_with_and_without_kill_chain(self, tmp_path: Path):
        """File with both old and new format patterns loads correctly."""
        patterns_yaml = {
            "source": {"name": "test", "version": "0.1.0"},
            "patterns": {
                "AP-T1-01": {
                    "id": "AP-T1-01",
                    "threat_id": "T1",
                    "name": "Legacy pattern",
                    "description": "No kill chain.",
                    "prerequisite_capabilities": {"min_zones": ["input"]},
                },
                "AP-T1-05": {
                    "id": "AP-T1-05",
                    "threat_id": "T1",
                    "name": "New pattern",
                    "description": "Has kill chain.",
                    "prerequisite_capabilities": {"min_zones": ["input", "memory"]},
                    "kill_chain": [
                        {
                            "step": "setup",
                            "tactic": "AML.TA0003",
                            "techniques": ["AML.T0065"],
                            "abstract_action": "Setup action.",
                        },
                    ],
                },
            },
        }

        p = tmp_path / "attack-patterns-mixed.yaml"
        p.write_text(yaml.dump(patterns_yaml, default_flow_style=False))

        result = load_attack_patterns(path=p)

        assert len(result) == 2
        assert "kill_chain" not in result["AP-T1-01"]
        assert "kill_chain" in result["AP-T1-05"]

    def test_existing_patterns_still_load(self):
        """Real attack pattern files from the repo load without error."""
        result = load_attack_patterns()
        assert isinstance(result, dict)
        assert len(result) > 0

        # Spot-check: existing patterns should not have kill_chain yet
        for pid, pattern in result.items():
            assert "id" in pattern, f"{pid} missing 'id'"
            assert "threat_id" in pattern, f"{pid} missing 'threat_id'"

    def test_existing_patterns_validate_without_kill_chain(self):
        """All existing patterns validate through the model (kill_chain optional)."""
        patterns = load_attack_patterns()
        for pid, pattern in patterns.items():
            validated = validate_attack_pattern(pattern)
            assert validated.id == pid
            assert validated.kill_chain is None
