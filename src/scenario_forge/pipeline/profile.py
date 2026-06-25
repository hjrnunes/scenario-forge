"""Stage 1: Capability Profile Inference via LLM."""

from __future__ import annotations

from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models import CapabilityProfile

_SYSTEM_PROMPT = """\
You are a security architect analysing an AI/LLM system description.
Extract a capability profile that captures the system's structural properties.

## Schneider zones
- Zone 1 (Input Surfaces): always active — every system has user/data inputs.
- Zone 2 (Planning & Reasoning): always active — every LLM system reasons.
- Zone 3 (Tool Execution): active if the system can invoke tools, APIs, \
external actions, run code, or interact with external services.
- Zone 4 (Memory & State): active if the system has persistent memory, \
session state, databases, knowledge graphs, or vector stores. \
When zone 4 is active, has_persistent_memory MUST be true.
- Zone 5 (Inter-Agent Communication): active if multiple AI agents \
coordinate or communicate. When zone 5 is active, multi_agent MUST be true.

## Rules
- zones_active must always include 1 and 2.
- has_persistent_memory: true if the system stores state across sessions \
or interactions (implies zone 4 should be active).
- multi_agent: true if multiple AI agents coordinate (implies zone 5).
- hitl: true if humans review, approve, or intervene in the workflow.
- entry_points: list of attack surfaces as short strings, each annotated \
with its zone, e.g. "user prompts via chat widget (zone 1)".
- confidence: "high" if the description is detailed, "medium" if moderate, \
"low" if vague or minimal.

Return a valid CapabilityProfile with only the Stage 1 fields. \
Do NOT populate Stage 2 fields (tool_types, data_flows, etc.).\
"""


def infer_capability_profile(
    use_case: str,
    client: LLMClient,
) -> tuple[CapabilityProfile, LLMResult]:
    """Call the LLM to extract a CapabilityProfile from a free-text use case.

    Args:
        use_case: Free-text description of the AI system.
        client: Configured LLM client.

    Returns:
        Tuple of (parsed CapabilityProfile, LLMResult with telemetry).
    """
    result = client.complete(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=use_case,
        response_format=CapabilityProfile,
    )
    return result.content, result
