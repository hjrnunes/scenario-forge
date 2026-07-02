"""Tests for threat gating logic.

Covers:
  - Logging of all gating decisions (silent filtering fix)
  - _has_vector_store fallback behaviour (premature gating fix)
  - _has_shared_writable_memory fallback behaviour
  - Attack-pattern filtering with Stage 1 vs Stage 2 data
"""

from __future__ import annotations

import logging

from scenario_forge.data.threat_gating import (
    _filter_attack_patterns,
    _has_shared_writable_memory,
    _has_vector_store,
    determine_threat_scope,
)
from scenario_forge.models import (
    CapabilityProfile,
    MemoryMechanism,
    MemoryPersistence,
    MemoryScope,
    MemoryType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_profile(
    *,
    has_persistent_memory: bool = False,
    zones_active: list[str] | None = None,
    multi_agent: bool = False,
    hitl: bool = False,
    memory_mechanisms: list[MemoryMechanism] | None = None,
) -> CapabilityProfile:
    """Build a CapabilityProfile with sensible defaults for testing."""
    if zones_active is None:
        zones = ["input", "reasoning", "tool_execution"]
        if has_persistent_memory:
            zones.append("memory")
        if multi_agent:
            zones.append("inter_agent")
    else:
        zones = zones_active
    return CapabilityProfile(
        zones_active=zones,
        has_persistent_memory=has_persistent_memory,
        multi_agent=multi_agent,
        hitl=hitl,
        entry_points=["user input (zone 1)"],
        confidence="medium",
        memory_mechanisms=memory_mechanisms,
    )


# ---------------------------------------------------------------------------
# Test attack-pattern dicts (synthetic, matching real YAML structure)
# ---------------------------------------------------------------------------

# AP-T2-05 requires vector_store + tool_execution
_AP_T2_05 = {
    "id": "AP-T2-05",
    "threat_id": "T2",
    "name": "Tool misuse via adversarial retrieval content",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory", "tool_execution"],
        "requires_vector_store": True,
        "requires_tool_execution": True,
    },
}

# AP-T2-04 requires persistent_memory + tool_execution
_AP_T2_04 = {
    "id": "AP-T2-04",
    "threat_id": "T2",
    "name": "Tool misuse via poisoned persistent memory",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory", "tool_execution"],
        "requires_persistent_memory": True,
        "requires_tool_execution": True,
    },
}

# AP-T2-01 has only basic zone prereqs (input + tool_execution)
_AP_T2_01 = {
    "id": "AP-T2-01",
    "threat_id": "T2",
    "name": "Tool misuse via direct prompt injection",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "requires_tool_execution": True,
    },
}

# AP-T1-04 requires shared writable memory + inter_agent zone
_AP_T1_04 = {
    "id": "AP-T1-04",
    "threat_id": "T1",
    "name": "Shared memory corruption for cross-agent influence",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory", "inter_agent"],
        "requires_shared_writable_memory": True,
    },
}

# AP-T1-01 has basic memory prereqs
_AP_T1_01 = {
    "id": "AP-T1-01",
    "threat_id": "T1",
    "name": "Memory poisoning via conversational injection",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory"],
        "requires_persistent_memory": True,
    },
}

# AP-T6-01 only requires input + reasoning (always passes for default profile)
_AP_T6_01 = {
    "id": "AP-T6-01",
    "threat_id": "T6",
    "name": "Incremental sub-goal injection for plan drift",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning"],
    },
}

# AP-T6-02 also only requires input + reasoning
_AP_T6_02 = {
    "id": "AP-T6-02",
    "threat_id": "T6",
    "name": "Direct instruction override for tool-chain hijacking",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning"],
    },
}


# ---------------------------------------------------------------------------
# _has_vector_store -- premature gating fix
# ---------------------------------------------------------------------------


class TestHasVectorStore:
    """Verify _has_vector_store handles Stage 1 (None) vs Stage 2 data."""

    def test_returns_true_when_memory_mechanisms_none_and_has_persistent_memory(self):
        """Stage 1 data: memory_mechanisms is None but has_persistent_memory
        is True.  The function should NOT return False -- it should fall back
        to has_persistent_memory as a conservative proxy."""
        profile = _make_profile(has_persistent_memory=True)
        assert profile.memory_mechanisms is None  # Stage 1 data
        assert _has_vector_store(profile) is True

    def test_returns_false_when_memory_mechanisms_none_and_no_persistent_memory(self):
        """Stage 1 data with no persistent memory -- correctly returns False."""
        profile = _make_profile(has_persistent_memory=False)
        assert profile.memory_mechanisms is None
        assert _has_vector_store(profile) is False

    def test_returns_true_with_vector_store_mechanism(self):
        """Stage 2 data with an explicit vector_store mechanism."""
        profile = _make_profile(
            has_persistent_memory=True,
            memory_mechanisms=[
                MemoryMechanism(
                    type=MemoryType.vector_store,
                    scope=MemoryScope.per_user,
                    persistence=MemoryPersistence.long_term,
                    writable_by_agent=False,
                ),
            ],
        )
        assert _has_vector_store(profile) is True

    def test_returns_false_with_non_vector_store_mechanisms(self):
        """Stage 2 data with mechanisms but none are vector_store."""
        profile = _make_profile(
            has_persistent_memory=True,
            memory_mechanisms=[
                MemoryMechanism(
                    type=MemoryType.conversation_history,
                    scope=MemoryScope.per_user,
                    persistence=MemoryPersistence.session,
                    writable_by_agent=True,
                ),
            ],
        )
        assert _has_vector_store(profile) is False

    def test_returns_false_with_empty_mechanisms_list(self):
        """Stage 2 explicitly said no memory mechanisms (empty list)."""
        profile = _make_profile(
            has_persistent_memory=True,
            memory_mechanisms=[],
        )
        assert _has_vector_store(profile) is False


# ---------------------------------------------------------------------------
# _has_shared_writable_memory -- same fallback pattern
# ---------------------------------------------------------------------------


class TestHasSharedWritableMemory:
    """Verify _has_shared_writable_memory handles Stage 1 vs Stage 2 data."""

    def test_returns_true_when_memory_mechanisms_none_and_has_persistent_memory(self):
        profile = _make_profile(has_persistent_memory=True)
        assert profile.memory_mechanisms is None
        assert _has_shared_writable_memory(profile) is True

    def test_returns_false_when_memory_mechanisms_none_and_no_persistent_memory(self):
        profile = _make_profile(has_persistent_memory=False)
        assert _has_shared_writable_memory(profile) is False

    def test_returns_true_with_shared_writable_mechanism(self):
        profile = _make_profile(
            has_persistent_memory=True,
            memory_mechanisms=[
                MemoryMechanism(
                    type=MemoryType.key_value_store,
                    scope=MemoryScope.shared,
                    persistence=MemoryPersistence.long_term,
                    writable_by_agent=True,
                ),
            ],
        )
        assert _has_shared_writable_memory(profile) is True

    def test_returns_false_with_shared_readonly_mechanism(self):
        profile = _make_profile(
            has_persistent_memory=True,
            memory_mechanisms=[
                MemoryMechanism(
                    type=MemoryType.key_value_store,
                    scope=MemoryScope.shared,
                    persistence=MemoryPersistence.long_term,
                    writable_by_agent=False,
                ),
            ],
        )
        assert _has_shared_writable_memory(profile) is False


# ---------------------------------------------------------------------------
# _filter_attack_patterns
# ---------------------------------------------------------------------------


class TestFilterAttackPatterns:
    """Verify data-driven attack-pattern filtering."""

    def test_ap_t2_05_not_filtered_with_stage1_persistent_memory(self):
        """AP-T2-05 requires vector_store; with Stage 1 data (memory_mechanisms
        is None), has_persistent_memory=True acts as conservative proxy and
        preserves AP-T2-05."""
        profile = _make_profile(has_persistent_memory=True)
        patterns = [_AP_T2_01, _AP_T2_04, _AP_T2_05]
        result = _filter_attack_patterns(patterns, profile)
        assert "AP-T2-05" in result
        assert "AP-T2-04" in result

    def test_ap_t2_05_filtered_when_no_persistent_memory(self):
        """When has_persistent_memory is False, AP-T2-04 and AP-T2-05 are
        filtered by their prerequisite_capabilities (require memory zone)."""
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T2_01, _AP_T2_04, _AP_T2_05]
        result = _filter_attack_patterns(patterns, profile)
        assert "AP-T2-04" not in result
        assert "AP-T2-05" not in result

    def test_ap_t1_04_not_filtered_with_stage1_persistent_memory(self):
        """AP-T1-04 requires shared writable memory; with Stage 1 data and
        has_persistent_memory=True, the fallback proxy keeps it."""
        profile = _make_profile(
            has_persistent_memory=True,
            multi_agent=True,
        )
        patterns = [_AP_T1_01, _AP_T1_04]
        result = _filter_attack_patterns(patterns, profile)
        assert "AP-T1-04" in result

    def test_unrelated_patterns_pass_all_with_matching_zones(self):
        """AP-T6 patterns only need input+reasoning zones, which the default
        profile provides, so nothing is filtered."""
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T6_01, _AP_T6_02]
        result = _filter_attack_patterns(patterns, profile)
        assert result == ["AP-T6-01", "AP-T6-02"]


# ---------------------------------------------------------------------------
# Logging of gating decisions
# ---------------------------------------------------------------------------


class TestGatingLogging:
    """Verify that all gating decisions produce log messages."""

    def test_filter_attack_patterns_logs_ap_t2_05_pass(self, caplog):
        """When AP-T2-05 passes the gate, an info log is emitted."""
        profile = _make_profile(has_persistent_memory=True)
        patterns = [_AP_T2_01, _AP_T2_05]
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            _filter_attack_patterns(patterns, profile)

        ap_t2_05_logs = [r for r in caplog.records if "AP-T2-05" in r.message]
        assert len(ap_t2_05_logs) >= 1, (
            "Expected at least one log message about AP-T2-05"
        )
        assert any("PASSED" in r.message for r in ap_t2_05_logs)

    def test_filter_attack_patterns_logs_ap_t2_05_filtered(self, caplog):
        """When AP-T2-05 is filtered out, a warning log is emitted."""
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T2_01, _AP_T2_05]
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            _filter_attack_patterns(patterns, profile)

        ap_t2_05_logs = [r for r in caplog.records if "AP-T2-05" in r.message]
        assert len(ap_t2_05_logs) >= 1, (
            "Expected at least one log message about AP-T2-05"
        )
        assert any(r.levelno == logging.WARNING for r in ap_t2_05_logs)

    def test_filter_attack_patterns_logs_ap_t1_04_filtered(self, caplog):
        """When AP-T1-04 is filtered out, a warning log is emitted."""
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T1_01, _AP_T1_04]
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            _filter_attack_patterns(patterns, profile)

        ap_t1_04_logs = [r for r in caplog.records if "AP-T1-04" in r.message]
        assert len(ap_t1_04_logs) >= 1
        assert any("FILTERED" in r.message for r in ap_t1_04_logs)

    def test_determine_threat_scope_logs_in_scope(self, caplog):
        """In-scope threats produce info-level log messages."""
        profile = _make_profile(has_persistent_memory=True)
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            determine_threat_scope(profile)

        in_scope_logs = [r for r in caplog.records if "IN SCOPE" in r.message]
        assert len(in_scope_logs) > 0, "Expected IN SCOPE log messages"
        # T6 is always in scope
        t6_logs = [r for r in in_scope_logs if "T6" in r.message]
        assert len(t6_logs) >= 1

    def test_determine_threat_scope_logs_out_of_scope(self, caplog):
        """Out-of-scope threats produce warning-level log messages."""
        # Profile with no multi_agent, so T12-T14 should be out of scope
        profile = _make_profile(has_persistent_memory=False, multi_agent=False)
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            determine_threat_scope(profile)

        out_scope_logs = [r for r in caplog.records if "OUT OF SCOPE" in r.message]
        assert len(out_scope_logs) > 0, "Expected OUT OF SCOPE log messages"
        assert any(r.levelno == logging.WARNING for r in out_scope_logs)

    def test_determine_threat_scope_logs_dropped_attack_patterns(self, caplog):
        """When attack patterns are dropped, the in-scope log mentions them."""
        # has_persistent_memory=False means AP-T2-04 and AP-T2-05 get filtered
        # But T2 is only in scope if zone 3 is active (default in _make_profile)
        # and memory-gated threats (T1) require has_persistent_memory
        # So we need zone 3 active but no persistent memory
        profile = _make_profile(has_persistent_memory=False)
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            determine_threat_scope(profile)

        # T2 should be in scope (zone 3 active) but with AP-T2-04/AP-T2-05 dropped
        t2_in_scope = [
            r for r in caplog.records if "T2" in r.message and "IN SCOPE" in r.message
        ]
        assert len(t2_in_scope) >= 1
        assert any("dropped" in r.message for r in t2_in_scope)
