"""Stage 1: Capability Profile Inference via LLM."""

from __future__ import annotations

from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models import CapabilityProfile
from scenario_forge.models.capability_profile import Stage1Profile
from scenario_forge.prompts import render_prompt


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
        system_prompt=render_prompt("profile_system.j2"),
        user_prompt=render_prompt("profile_user.j2", use_case=use_case),
        response_format=Stage1Profile,
    )
    profile = result.content.to_capability_profile()
    return profile, result
