"""Stage 3 — Technology context block (deterministic, no LLM calls).

Reads a :class:`CapabilityProfile` and emits a structured text block
describing implementation-specific failure modes relevant to the
system's capabilities. This is the mechanism by which AI-specific
threats enter the enumeration without compromising the control
structure's solution-neutrality.

Same ``CapabilityProfile`` always produces the same technology context
block.
"""

from __future__ import annotations

from collections.abc import Callable

from scenario_forge.models.capability_profile import CapabilityProfile

__all__ = ["build_technology_context"]

# Zone-based failure mode templates.
_ZONE_FAILURE_MODES: dict[str, str] = {
    "input": (
        "- Has user-facing input → susceptible to prompt injection, "
        "jailbreaking, input manipulation"
    ),
    "tool_execution": (
        "- Has tool invocation → susceptible to parameter injection, "
        "tool result fabrication, unauthorized tool use"
    ),
    "memory": (
        "- Has persistent memory → susceptible to memory poisoning, "
        "cross-session state manipulation, stale state exploitation"
    ),
    "inter_agent": (
        "- Has inter-agent communication → susceptible to agent "
        "impersonation, message tampering, coordination desynchronization"
    ),
}

# KC sub-code failure mode rules: each entry is (predicate, failure-mode text).
# The predicate receives the set of active KC sub-codes and returns True when
# the rule applies.  This table replaces a chain of if-statements so the
# function's cyclomatic complexity stays low even as new rules are added.
_KC_FAILURE_MODE_RULES: list[tuple[Callable[[set[str]], bool], str]] = [
    (
        lambda kc: "KC6.3.3" in kc,
        "- Uses RAG → susceptible to retrieval poisoning, "
        "knowledge base injection, retrieval manipulation",
    ),
    (
        lambda kc: any(k.startswith("KC4.3") for k in kc),
        "- Has cross-session memory → susceptible to persistent "
        "context poisoning, cross-user data leakage",
    ),
    (
        lambda kc: "KC2.3" in kc or "KCX-MAGENT" in kc,
        "- Has multi-agent collaboration → susceptible to agent "
        "rogue behavior, conflicting directives, shared state corruption",
    ),
    (
        lambda kc: "KCX-HITL" in kc,
        "- Has human-in-the-loop → susceptible to alert fatigue, "
        "escalation bypass, human manipulation",
    ),
    (
        lambda kc: any(k.startswith("KC6.2") for k in kc),
        "- Has code execution → susceptible to arbitrary code "
        "execution, sandbox escape",
    ),
]


def build_technology_context(profile: CapabilityProfile) -> str:
    """Derive implementation-specific failure modes from a capability profile.

    Produces a multi-line text block with:
    - Zone-based failure modes (input, tool_execution, memory, inter_agent)
    - KC sub-code specific failure modes (RAG, HITL, multi-agent, etc.)
    - Entry point specific failure modes (indirect controllability, bidirectional)
    - Tool inventory per-tool failure modes

    Args:
        profile: The capability profile to derive failure modes from.

    Returns:
        A text block of failure mode descriptions, one per line.
        If no relevant capabilities are found, returns a default message.
    """
    lines: list[str] = []

    _emit_zone_failure_modes(lines, profile)
    _emit_kc_failure_modes(lines, profile)
    _emit_entry_point_failure_modes(lines, profile)
    _emit_tool_inventory_failure_modes(lines, profile)

    if not lines:
        return "- No specific technology context identified."
    return "\n".join(lines)


def _emit_zone_failure_modes(lines: list[str], profile: CapabilityProfile) -> None:
    """Emit failure modes for each active zone."""
    zones = set(profile.zones_active)
    for zone, text in _ZONE_FAILURE_MODES.items():
        if zone in zones:
            lines.append(text)


def _emit_kc_failure_modes(lines: list[str], profile: CapabilityProfile) -> None:
    """Emit failure modes based on KC sub-codes.

    Iterates over the ``_KC_FAILURE_MODE_RULES`` table and appends the
    failure-mode text for each rule whose predicate matches the profile's
    active KC sub-codes.
    """
    kc = set(profile.kc_subcodes)
    for predicate, text in _KC_FAILURE_MODE_RULES:
        if predicate(kc):
            lines.append(text)


def _emit_entry_point_failure_modes(
    lines: list[str], profile: CapabilityProfile
) -> None:
    """Emit failure modes for entry points with special properties."""
    for ep in profile.entry_points:
        if ep.effective_controllability == "indirect":
            lines.append(
                f"- Has indirect entry point '{ep.name}' → susceptible "
                f"to supply chain content manipulation"
            )
        if ep.direction == "bidirectional":
            lines.append(
                f"- Has bidirectional entry point '{ep.name}' → "
                f"susceptible to bidirectional data exfiltration"
            )


def _emit_tool_inventory_failure_modes(
    lines: list[str], profile: CapabilityProfile
) -> None:
    """Emit per-tool failure modes from the tool inventory."""
    if not profile.tool_inventory:
        return
    for tool in profile.tool_inventory:
        lines.append(
            f"- Tool '{tool.name}': {tool.description} → "
            f"susceptible to parameter manipulation, output fabrication"
        )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T00:25:25Z","module_hash":"5e5b4039c9d6ea0d57675832aafa606c76ab3e68b454c62fab744c8b12207fa9","functions":[{"id":"func/build_technology_context","name":"build_technology_context","line":74,"end_line":99,"hash":"8635b66655e37525365de7b4d7ffda7dfd888f6d2c6b7359e96fd06a5f911b99"},{"id":"func/_emit_zone_failure_modes","name":"_emit_zone_failure_modes","line":102,"end_line":107,"hash":"bd88a9c679ee0285671255a2653c85ec37fb3d71e51a631ddca9f51e8fc9944e"},{"id":"func/_emit_kc_failure_modes","name":"_emit_kc_failure_modes","line":110,"end_line":120,"hash":"49b0651a494ef5c76f46015379d4ae1ed50c6095fe224b74ffb5661bf90bb4a5"},{"id":"func/_emit_entry_point_failure_modes","name":"_emit_entry_point_failure_modes","line":123,"end_line":137,"hash":"b007dad48da85924be6041f9c517082d0dda3e5fc84301a24f90d8e56ec93d88"},{"id":"func/_emit_tool_inventory_failure_modes","name":"_emit_tool_inventory_failure_modes","line":140,"end_line":150,"hash":"eab800ce106a8b37ef541b98132069501df3402c6a0ab0919d44128e40fcf90f"}]}
# mutate4py-manifest-end
