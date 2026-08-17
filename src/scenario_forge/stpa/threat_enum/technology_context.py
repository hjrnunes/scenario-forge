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

import re
from collections.abc import Callable

from scenario_forge.models.capability_profile import CapabilityProfile

__all__ = ["build_technology_context", "context_for"]

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
#
# Predicates are named functions (not lambdas) so that coverage tools and
# mutation testers can track their execution at the line/function level.


def _has_rag(kc: set[str]) -> bool:
    """True when the profile uses RAG (KC6.3.3)."""
    return "KC6.3.3" in kc


def _has_cross_session_memory(kc: set[str]) -> bool:
    """True when the profile has cross-session memory (KC4.3*)."""
    return any(k.startswith("KC4.3") for k in kc)


def _has_multi_agent(kc: set[str]) -> bool:
    """True when the profile has multi-agent collaboration (KC2.3 or KCX-MAGENT)."""
    return "KC2.3" in kc or "KCX-MAGENT" in kc


def _has_hitl(kc: set[str]) -> bool:
    """True when the profile has human-in-the-loop (KCX-HITL)."""
    return "KCX-HITL" in kc


def _has_code_execution(kc: set[str]) -> bool:
    """True when the profile has code execution (KC6.2*)."""
    return any(k.startswith("KC6.2") for k in kc)


_KC_FAILURE_MODE_RULES: list[tuple[Callable[[set[str]], bool], str]] = [
    (
        _has_rag,
        "- Uses RAG → susceptible to retrieval poisoning, "
        "knowledge base injection, retrieval manipulation",
    ),
    (
        _has_cross_session_memory,
        "- Has cross-session memory → susceptible to persistent "
        "context poisoning, cross-user data leakage",
    ),
    (
        _has_multi_agent,
        "- Has multi-agent collaboration → susceptible to agent "
        "rogue behavior, conflicting directives, shared state corruption",
    ),
    (
        _has_hitl,
        "- Has human-in-the-loop → susceptible to alert fatigue, "
        "escalation bypass, human manipulation",
    ),
    (
        _has_code_execution,
        "- Has code execution → susceptible to arbitrary code "
        "execution, sandbox escape",
    ),
]

# ---------------------------------------------------------------------------
# Tool intent classification
# ---------------------------------------------------------------------------

# Write/execute intent has priority when both read and write verbs are present
# in a tool description (e.g. "Reads logs and writes audit entries").
_WRITE_VERB_PATTERN = re.compile(
    r"\b(?:writ\w*|send\w*|execut\w*|run\w*|updat\w*|modif\w*|delet\w*|"
    r"creat\w*|insert\w*|process\w*|post\w*|save\w*|upload\w*|"
    r"submit\w*|grant\w*|revok\w*|remov\w*|disabl\w*|enabl\w*|deploy\w*|"
    r"trigger\w*|assign\w*|approv\w*|reject\w*|block\w*|commit\w*|push\w*|"
    r"put\w*|apply\w*)\b",
    re.IGNORECASE,
)

_READ_VERB_PATTERN = re.compile(
    r"\b(?:read\w*|retriev\w*|quer\w*|fetch\w*|get\w*|search\w*|lookup\w*|"
    r"scan\w*|view\w*|inspect\w*|monitor\w*|collect\w*|gather\w*)\b",
    re.IGNORECASE,
)

_WRITE_FAILURE_SUFFIX = (
    "susceptible to parameter manipulation, unauthorized state change"
)
_READ_FAILURE_SUFFIX = "susceptible to output fabrication, data exfiltration"
_UNKNOWN_FAILURE_SUFFIX = (
    "susceptible to unexpected behavior from malformed input or output manipulation"
)


def _classify_tool_failure_mode(description: str) -> str:
    """Classify a tool description and return the appropriate failure-mode suffix.

    Write/execute intent has priority when both read and write verbs are
    present.  Read/retrieval intent emits read-specific failure modes.
    Unknown tools get a conservative fallback.
    """
    if _WRITE_VERB_PATTERN.search(description):
        return _WRITE_FAILURE_SUFFIX
    if _READ_VERB_PATTERN.search(description):
        return _READ_FAILURE_SUFFIX
    return _UNKNOWN_FAILURE_SUFFIX


def context_for(profile: CapabilityProfile | None) -> str | None:
    """Return the technology-context block, or None when no profile is given.

    Prompt assemblers pass the result straight into templates.  A None
    value omits the section; a profile always yields the same block as
    :func:`build_technology_context`.
    """
    if profile is None:
        return None
    return build_technology_context(profile)


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
    """Emit per-tool failure modes from the tool inventory.

    Each tool is classified by its description into write/execute,
    read/retrieval, or unknown intent, and receives a category-specific
    failure-mode suffix.
    """
    if not profile.tool_inventory:
        return
    for tool in profile.tool_inventory:
        suffix = _classify_tool_failure_mode(tool.description)
        lines.append(f"- Tool '{tool.name}': {tool.description} → {suffix}")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-14T09:06:34Z","module_hash":"2b29783b0d5ad6c11eb66f697cc68cf1a5af38e7a6337382981f0ac1e9fa4a0b","functions":[{"id":"func/_has_rag","name":"_has_rag","line":51,"end_line":53,"hash":"0cac04b0fcf1e2abc0dd93ec3efc3d8414141d50fadd6515284cf0a73ca225e2"},{"id":"func/_has_cross_session_memory","name":"_has_cross_session_memory","line":56,"end_line":58,"hash":"dc7f3d4b41eeda83e7dcdd0f7da0a7aa8a98b52dee09d1e7ee2ecc99bc3e7660"},{"id":"func/_has_multi_agent","name":"_has_multi_agent","line":61,"end_line":63,"hash":"a324b39add1f27ba122364a02f89ff2b5b210d1863691958d352b54b16c69c13"},{"id":"func/_has_hitl","name":"_has_hitl","line":66,"end_line":68,"hash":"af2921c248d197d32dd3f065cb05609ef59fa7441017d97481072eb77773c59a"},{"id":"func/_has_code_execution","name":"_has_code_execution","line":71,"end_line":73,"hash":"8a7323f5e6b335eb64bef8e33abc770f09e8d6ec3b85b5c9caf108b35e1cc234"},{"id":"func/_classify_tool_failure_mode","name":"_classify_tool_failure_mode","line":135,"end_line":146,"hash":"32004062807f345992bc3430c9fa428ba8ada34929dca3b9c3923f41fff958e8"},{"id":"func/context_for","name":"context_for","line":149,"end_line":158,"hash":"9aaf315092e54071e5a5fbd5efa13799817c5c08e94a71da0a800e6d54a44458"},{"id":"func/build_technology_context","name":"build_technology_context","line":161,"end_line":186,"hash":"8635b66655e37525365de7b4d7ffda7dfd888f6d2c6b7359e96fd06a5f911b99"},{"id":"func/_emit_zone_failure_modes","name":"_emit_zone_failure_modes","line":189,"end_line":194,"hash":"bd88a9c679ee0285671255a2653c85ec37fb3d71e51a631ddca9f51e8fc9944e"},{"id":"func/_emit_kc_failure_modes","name":"_emit_kc_failure_modes","line":197,"end_line":207,"hash":"49b0651a494ef5c76f46015379d4ae1ed50c6095fe224b74ffb5661bf90bb4a5"},{"id":"func/_emit_entry_point_failure_modes","name":"_emit_entry_point_failure_modes","line":210,"end_line":224,"hash":"b007dad48da85924be6041f9c517082d0dda3e5fc84301a24f90d8e56ec93d88"},{"id":"func/_emit_tool_inventory_failure_modes","name":"_emit_tool_inventory_failure_modes","line":227,"end_line":242,"hash":"bac03455735d253aa7dd04b8bf8d2c467529a540fe69f0d5384f17d2e9bfb037"}]}
# mutate4py-manifest-end
