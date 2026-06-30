"""Tests for threat gating logic.

Covers:
  - Logging of all gating decisions (silent filtering fix)
  - _has_vector_store fallback behaviour (premature gating fix)
  - _has_shared_writable_memory fallback behaviour
  - Sub-scenario filtering with Stage 1 vs Stage 2 data
"""

from __future__ import annotations

import logging

from scenario_forge.data.threat_gating import (
    _filter_sub_scenarios,
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
# _has_vector_store — premature gating fix
# ---------------------------------------------------------------------------


class TestHasVectorStore:
    """Verify _has_vector_store handles Stage 1 (None) vs Stage 2 data."""

    def test_returns_true_when_memory_mechanisms_none_and_has_persistent_memory(self):
        """Stage 1 data: memory_mechanisms is None but has_persistent_memory
        is True.  The function should NOT return False — it should fall back
        to has_persistent_memory as a conservative proxy."""
        profile = _make_profile(has_persistent_memory=True)
        assert profile.memory_mechanisms is None  # Stage 1 data
        assert _has_vector_store(profile) is True

    def test_returns_false_when_memory_mechanisms_none_and_no_persistent_memory(self):
        """Stage 1 data with no persistent memory — correctly returns False."""
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
# _has_shared_writable_memory — same fallback pattern
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
# _filter_sub_scenarios
# ---------------------------------------------------------------------------


class TestFilterSubScenarios:
    """Verify sub-scenario filtering with Stage 1 data (the common case)."""

    def test_t2_s5_not_filtered_with_stage1_persistent_memory(self):
        """The key bug: T2-S5 was always filtered because memory_mechanisms
        was None.  With the fix, has_persistent_memory=True preserves T2-S5."""
        profile = _make_profile(has_persistent_memory=True)
        all_subs = ["T2-S1", "T2-S2", "T2-S3", "T2-S4", "T2-S5", "T2-S6"]
        result = _filter_sub_scenarios("T2", all_subs, profile)
        assert "T2-S5" in result
        assert "T2-S4" in result

    def test_t2_s5_filtered_when_no_persistent_memory(self):
        """When has_persistent_memory is False, both T2-S4 and T2-S5 are
        correctly filtered."""
        profile = _make_profile(has_persistent_memory=False)
        all_subs = ["T2-S1", "T2-S2", "T2-S3", "T2-S4", "T2-S5", "T2-S6"]
        result = _filter_sub_scenarios("T2", all_subs, profile)
        assert "T2-S4" not in result
        assert "T2-S5" not in result

    def test_t1_s4_not_filtered_with_stage1_persistent_memory(self):
        """T1-S4 should be kept when has_persistent_memory is True and
        memory_mechanisms is None (Stage 1 fallback)."""
        profile = _make_profile(has_persistent_memory=True)
        all_subs = ["T1-S1", "T1-S2", "T1-S3", "T1-S4"]
        result = _filter_sub_scenarios("T1", all_subs, profile)
        assert "T1-S4" in result

    def test_unrelated_threat_id_passes_all(self):
        """Threats without sub-scenario rules pass everything through."""
        profile = _make_profile(has_persistent_memory=False)
        all_subs = ["T6-S1", "T6-S2"]
        result = _filter_sub_scenarios("T6", all_subs, profile)
        assert result == all_subs


# ---------------------------------------------------------------------------
# Logging of gating decisions
# ---------------------------------------------------------------------------


class TestGatingLogging:
    """Verify that all gating decisions produce log messages."""

    def test_filter_sub_scenarios_logs_t2_s5_pass(self, caplog):
        """When T2-S5 passes the gate, an info log is emitted."""
        profile = _make_profile(has_persistent_memory=True)
        all_subs = ["T2-S1", "T2-S5"]
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            _filter_sub_scenarios("T2", all_subs, profile)

        t2_s5_logs = [r for r in caplog.records if "T2-S5" in r.message]
        assert len(t2_s5_logs) >= 1, "Expected at least one log message about T2-S5"
        assert any("PASSED" in r.message for r in t2_s5_logs)

    def test_filter_sub_scenarios_logs_t2_s5_filtered(self, caplog):
        """When T2-S5 is filtered out, a warning log is emitted."""
        profile = _make_profile(has_persistent_memory=False)
        all_subs = ["T2-S1", "T2-S5"]
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            _filter_sub_scenarios("T2", all_subs, profile)

        t2_s5_logs = [r for r in caplog.records if "T2-S5" in r.message]
        assert len(t2_s5_logs) >= 1, "Expected at least one log message about T2-S5"
        assert any(r.levelno == logging.WARNING for r in t2_s5_logs)

    def test_filter_sub_scenarios_logs_t1_s4_filtered(self, caplog):
        """When T1-S4 is filtered out, a warning log is emitted."""
        profile = _make_profile(has_persistent_memory=False)
        all_subs = ["T1-S1", "T1-S4"]
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            _filter_sub_scenarios("T1", all_subs, profile)

        t1_s4_logs = [r for r in caplog.records if "T1-S4" in r.message]
        assert len(t1_s4_logs) >= 1
        assert any("FILTERED" in r.message for r in t1_s4_logs)

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

    def test_determine_threat_scope_logs_dropped_sub_scenarios(self, caplog):
        """When sub-scenarios are dropped, the in-scope log mentions them."""
        # has_persistent_memory=False means T2-S4 and T2-S5 get filtered
        # But T2 is only in scope if zone 3 is active (default in _make_profile)
        # and memory-gated threats (T1) require has_persistent_memory
        # So we need zone 3 active but no persistent memory
        profile = _make_profile(has_persistent_memory=False)
        with caplog.at_level(logging.DEBUG, logger="scenario_forge.data.threat_gating"):
            determine_threat_scope(profile)

        # T2 should be in scope (zone 3 active) but with T2-S4/S5 dropped
        t2_in_scope = [r for r in caplog.records if "T2" in r.message and "IN SCOPE" in r.message]
        assert len(t2_in_scope) >= 1
        assert any("dropped" in r.message for r in t2_in_scope)
