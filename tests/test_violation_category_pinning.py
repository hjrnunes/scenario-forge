"""Pin test for THREAT_VIOLATION_CATEGORY map.

Asserts that each threat_id maps to the canonical lowercase-kebab-case
of its OWASP Agentic Threat name.  This prevents silent drift between
the code-level constant and the prompt-level taxonomy.

Canonical names sourced from call2_system.j2 lines 90-107.
"""

from __future__ import annotations

import pytest

from scenario_forge.pipeline.generate.constants import THREAT_VIOLATION_CATEGORY


# Canonical OWASP Agentic Threat names (source: call2_system.j2).
_CANONICAL_NAMES: dict[str, str] = {
    "T1": "Memory Poisoning",
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T4": "Resource Overload",
    "T5": "Cascading Hallucination Attacks",
    "T6": "Goal Manipulation",
    "T7": "Misaligned and Deceptive Behavior",
    "T8": "Repudiation and Untraceability",
    "T9": "Identity Spoofing",
    "T10": "HITL Bypass",
    "T11": "Unexpected Code Execution",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agent",
    "T14": "Human Attack on Multi-Agent",
    "T15": "Human Manipulation",
    "T16": "Insecure Inter-Agent Protocol",
    "T17": "Supply Chain Compromise",
}


def _to_kebab_case(name: str) -> str:
    """Convert a human-readable name to lowercase-kebab-case."""
    return name.lower().replace(" ", "-")


class TestThreatViolationCategoryPinning:
    """Each threat_id must map to the kebab-case of its canonical OWASP name."""

    def test_all_threat_ids_present(self) -> None:
        """Map must contain all T1-T17 keys."""
        expected_ids = {f"T{i}" for i in range(1, 18)}
        assert set(THREAT_VIOLATION_CATEGORY.keys()) == expected_ids

    @pytest.mark.parametrize(
        "threat_id,canonical_name",
        list(_CANONICAL_NAMES.items()),
        ids=list(_CANONICAL_NAMES.keys()),
    )
    def test_category_matches_canonical_name(
        self, threat_id: str, canonical_name: str
    ) -> None:
        """Violation category tag must be kebab-case of canonical OWASP name."""
        expected = _to_kebab_case(canonical_name)
        actual = THREAT_VIOLATION_CATEGORY[threat_id]
        assert actual == expected, (
            f"{threat_id}: expected '{expected}' (from '{canonical_name}'), "
            f"got '{actual}'"
        )

    def test_no_extra_keys(self) -> None:
        """Map must not contain keys outside T1-T17."""
        valid_ids = {f"T{i}" for i in range(1, 18)}
        extra = set(THREAT_VIOLATION_CATEGORY.keys()) - valid_ids
        assert not extra, f"Unexpected keys in map: {extra}"
