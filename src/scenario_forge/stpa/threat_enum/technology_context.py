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
    """Emit failure modes based on KC sub-codes."""
    kc = set(profile.kc_subcodes)

    if "KC6.3.3" in kc:
        lines.append(
            "- Uses RAG → susceptible to retrieval poisoning, "
            "knowledge base injection, retrieval manipulation"
        )
    if any(k.startswith("KC4.3") for k in kc):
        lines.append(
            "- Has cross-session memory → susceptible to persistent "
            "context poisoning, cross-user data leakage"
        )
    if "KC2.3" in kc or "KCX-MAGENT" in kc:
        lines.append(
            "- Has multi-agent collaboration → susceptible to agent "
            "rogue behavior, conflicting directives, shared state corruption"
        )
    if "KCX-HITL" in kc:
        lines.append(
            "- Has human-in-the-loop → susceptible to alert fatigue, "
            "escalation bypass, human manipulation"
        )
    if any(k.startswith("KC6.2") for k in kc):
        lines.append(
            "- Has code execution → susceptible to arbitrary code "
            "execution, sandbox escape"
        )


def _emit_entry_point_failure_modes(
    lines: list[str], profile: CapabilityProfile
) -> None:
    """Emit failure modes for entry points with special properties."""
    for ep in profile.entry_points:
        if ep.controllability == "indirect":
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
