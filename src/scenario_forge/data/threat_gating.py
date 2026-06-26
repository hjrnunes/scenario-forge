"""Threat gating logic for scenario-forge.

Determines which OWASP Agentic Threats are in scope for a given
capability profile, based on the threat_scope_mapping rules defined
in data/schemas/capability-profile.yaml.

Gating categories:
  - Always in scope: T6, T7, T8, T15
  - Memory-gated (has_persistent_memory): T1, T5
  - Tool-execution-gated (zone 3 active): T2, T3, T4, T11, T16, T17
  - Auth-gated (zone 3 active): T9
  - HITL-gated (hitl=true): T10
  - Multi-agent-gated (multi_agent=true): T12, T13, T14

Sub-scenario filtering applies additional checks within gated threats
(e.g. T1-S4 requires shared writable memory, T2-S4 requires persistent
memory, T2-S5 requires a vector store).
"""

from __future__ import annotations

import logging
from pathlib import Path
from pydantic import BaseModel, Field

from scenario_forge.data.loaders import load_agentic_threats
from scenario_forge.models import CapabilityProfile, MemoryScope, MemoryType

logger = logging.getLogger(__name__)

# Default path to OWASP Agentic Threats data
_DEFAULT_THREATS_PATH = Path(__file__).resolve().parents[3] / "data" / "taxonomies" / "owasp-agentic-threats" / "owasp-agentic-threats-v1.1.yaml"


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


class ThreatScopeEntry(BaseModel):
    """A threat that is in scope for the assessed system."""

    threat_id: str = Field(description="Threat ID (e.g. 'T2')")
    threat_name: str = Field(description="Human-readable threat name")
    applicable_sub_scenarios: list[str] = Field(
        default_factory=list,
        description="Sub-scenario IDs applicable to this system (e.g. ['T2-S1', 'T2-S3'])",
    )
    gating_reason: str = Field(
        description="Why this threat is in scope (e.g. 'always in scope', 'has_persistent_memory is true')",
    )


class OutOfScopeEntry(BaseModel):
    """A group of threats that are out of scope, with the reason."""

    threat_ids: list[str] = Field(description="Threat IDs that are out of scope")
    reason: str = Field(description="Why these threats are out of scope")


class ThreatScope(BaseModel):
    """The complete threat scope determination for a capability profile."""

    in_scope: list[ThreatScopeEntry] = Field(default_factory=list)
    out_of_scope: list[OutOfScopeEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Gating categories
# ---------------------------------------------------------------------------

_ALWAYS_IN_SCOPE = ["T6", "T7", "T8", "T15"]
_MEMORY_GATED = ["T1", "T5"]
_TOOL_EXECUTION_GATED = ["T2", "T3", "T4", "T11", "T16", "T17"]
_AUTH_GATED = ["T9"]
_HITL_GATED = ["T10"]
_MULTI_AGENT_GATED = ["T12", "T13", "T14"]


# ---------------------------------------------------------------------------
# Sub-scenario filtering helpers
# ---------------------------------------------------------------------------


def _has_shared_writable_memory(profile: CapabilityProfile) -> bool:
    """Check if the profile has shared memory that the agent can write to.

    Like ``_has_vector_store``, falls back to ``has_persistent_memory``
    when ``memory_mechanisms`` is ``None`` (Stage 1 data only) to avoid
    premature filtering.
    """
    if profile.memory_mechanisms is None:
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        return False
    return any(
        m.scope == MemoryScope.shared and m.writable_by_agent
        for m in profile.memory_mechanisms
    )


def _has_vector_store(profile: CapabilityProfile) -> bool:
    """Check if the profile includes a vector_store memory mechanism.

    When ``memory_mechanisms`` is populated (Stage 2 data), this performs
    an exact check for a ``vector_store`` entry.  When it is ``None``
    (Stage 1 data only, where the LLM prompt explicitly forbids
    populating Stage 2 fields), the function falls back to
    ``has_persistent_memory`` as a conservative proxy: if the system has
    persistent memory at all, a vector store is plausible and we should
    not silently filter out the sub-scenario.  This avoids the premature-
    gating bug where ``memory_mechanisms`` was always ``None`` after
    Stage 1, causing ``_has_vector_store()`` to always return ``False``
    and silently dropping sub-scenarios like T2-S5.
    """
    if profile.memory_mechanisms is None:
        # Stage 1 only — no detailed memory data yet.
        # Fall back to the broad has_persistent_memory flag so we don't
        # prematurely filter sub-scenarios that require a vector store.
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        # Explicitly empty list (Stage 2 said "no memory mechanisms")
        return False
    return any(m.type == MemoryType.vector_store for m in profile.memory_mechanisms)


def _get_all_sub_scenarios(threat: dict) -> list[str]:
    """Extract all sub-scenario IDs from a threat dict."""
    scenarios = threat.get("scenarios", [])
    return [s["id"] for s in scenarios]


def _filter_sub_scenarios(
    threat_id: str,
    all_sub_scenarios: list[str],
    profile: CapabilityProfile,
) -> list[str]:
    """Apply sub-scenario gating rules for specific threats.

    Rules:
      - T1-S4: only if shared writable memory exists
      - T2-S4: only if has_persistent_memory is true
      - T2-S5: only if vector_store is in memory_mechanisms
    """
    excluded: set[str] = set()

    if threat_id == "T1":
        has_swm = _has_shared_writable_memory(profile)
        if not has_swm:
            excluded.add("T1-S4")
            logger.warning(
                "Gating FILTERED T1-S4: _has_shared_writable_memory=False "
                "(memory_mechanisms=%s, has_persistent_memory=%s)",
                "present" if profile.memory_mechanisms is not None else "None",
                profile.has_persistent_memory,
            )
        else:
            logger.info(
                "Gating PASSED T1-S4: _has_shared_writable_memory=True "
                "(memory_mechanisms=%s, has_persistent_memory=%s)",
                "present" if profile.memory_mechanisms is not None else "None",
                profile.has_persistent_memory,
            )

    elif threat_id == "T2":
        if not profile.has_persistent_memory:
            excluded.add("T2-S4")
            logger.warning(
                "Gating FILTERED T2-S4: has_persistent_memory=False",
            )
        else:
            logger.info(
                "Gating PASSED T2-S4: has_persistent_memory=True",
            )

        has_vs = _has_vector_store(profile)
        if not has_vs:
            excluded.add("T2-S5")
            logger.warning(
                "Gating FILTERED T2-S5: _has_vector_store=False "
                "(memory_mechanisms=%s, has_persistent_memory=%s)",
                "present" if profile.memory_mechanisms is not None else "None",
                profile.has_persistent_memory,
            )
        else:
            logger.info(
                "Gating PASSED T2-S5: _has_vector_store=True "
                "(memory_mechanisms=%s, has_persistent_memory=%s)",
                "present" if profile.memory_mechanisms is not None else "None",
                profile.has_persistent_memory,
            )

    return [s for s in all_sub_scenarios if s not in excluded]


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------


def determine_threat_scope(
    profile: CapabilityProfile,
    threats_path: str | Path | None = None,
) -> ThreatScope:
    """Determine which threats are in scope for a given capability profile.

    Loads the OWASP Agentic Threats YAML to get threat names and
    sub-scenarios, then applies the gating rules from the capability
    profile schema.

    Args:
        profile: The capability profile to evaluate.
        threats_path: Path to the agentic threats YAML. Defaults to the
            bundled data file.

    Returns:
        ThreatScope with in_scope and out_of_scope entries.
    """
    path = Path(threats_path) if threats_path else _DEFAULT_THREATS_PATH
    threats = load_agentic_threats(path)

    in_scope: list[ThreatScopeEntry] = []
    out_of_scope_groups: dict[str, list[str]] = {}

    zone_3_active = 3 in profile.zones_active

    def _add_in_scope(threat_id: str, reason: str) -> None:
        threat = threats[threat_id]
        all_subs = _get_all_sub_scenarios(threat)
        filtered_subs = _filter_sub_scenarios(threat_id, all_subs, profile)
        dropped = set(all_subs) - set(filtered_subs)
        logger.info(
            "Threat %s (%s) IN SCOPE: %s — %d/%d sub-scenarios kept%s",
            threat_id,
            threat["name"],
            reason,
            len(filtered_subs),
            len(all_subs),
            f" (dropped: {sorted(dropped)})" if dropped else "",
        )
        in_scope.append(
            ThreatScopeEntry(
                threat_id=threat_id,
                threat_name=threat["name"],
                applicable_sub_scenarios=filtered_subs,
                gating_reason=reason,
            )
        )

    def _add_out_of_scope(threat_ids: list[str], reason: str) -> None:
        logger.warning(
            "Threats %s OUT OF SCOPE: %s",
            threat_ids,
            reason,
        )
        out_of_scope_groups[reason] = threat_ids

    # --- Always in scope ---
    for tid in _ALWAYS_IN_SCOPE:
        _add_in_scope(tid, "always in scope — any LLM/agent system with zones [1, 2]")

    # --- Memory-gated ---
    if profile.has_persistent_memory:
        for tid in _MEMORY_GATED:
            _add_in_scope(tid, "has_persistent_memory is true")
    else:
        _add_out_of_scope(
            _MEMORY_GATED,
            "has_persistent_memory is false — no memory to poison or cascade hallucinations into",
        )

    # --- Tool-execution-gated ---
    if zone_3_active:
        for tid in _TOOL_EXECUTION_GATED:
            _add_in_scope(tid, "zone 3 (Tool Execution) is active")
    else:
        _add_out_of_scope(
            _TOOL_EXECUTION_GATED,
            "zone 3 not active — no tool execution capability",
        )

    # --- Auth-gated (T9 — separated for future auth-awareness refinement) ---
    if zone_3_active:
        for tid in _AUTH_GATED:
            _add_in_scope(tid, "zone 3 (Tool Execution) is active — auth-gated threat")
    else:
        _add_out_of_scope(
            _AUTH_GATED,
            "zone 3 not active — no tool execution for auth-related threats",
        )

    # --- HITL-gated ---
    if profile.hitl:
        for tid in _HITL_GATED:
            _add_in_scope(tid, "hitl is true — human-in-the-loop checkpoints exist")
    else:
        _add_out_of_scope(
            _HITL_GATED,
            "hitl is false — no human-in-the-loop to overwhelm",
        )

    # --- Multi-agent-gated ---
    if profile.multi_agent:
        for tid in _MULTI_AGENT_GATED:
            _add_in_scope(tid, "multi_agent is true — inter-agent communication exists")
    else:
        _add_out_of_scope(
            _MULTI_AGENT_GATED,
            "multi_agent is false — no inter-agent communication",
        )

    # Build out_of_scope list
    out_of_scope = [
        OutOfScopeEntry(threat_ids=ids, reason=reason)
        for reason, ids in out_of_scope_groups.items()
    ]

    return ThreatScope(in_scope=in_scope, out_of_scope=out_of_scope)
