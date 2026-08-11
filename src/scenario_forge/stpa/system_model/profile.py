"""Stage 1b — Capability Profile inference.

Single LLM call extracts a capability profile from the use-case
description.  No loss-analysis context is provided — Stage 1b has
zero dependency on Stage 1a.  Produces Stage1Profile which is promoted
to CapabilityProfile via to_capability_profile(). The --profile flag
skips this stage (loads a pre-built profile).
"""

from __future__ import annotations

from pathlib import Path

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    inject_kc_subcodes_display,
)
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import StageError, safe_llm_call
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

STAGE = "stage_1b"
STEP = "capability_profile"
DEFAULT_TEMPERATURE = 0.4


def derive_capability_profile(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> CapabilityProfile:
    """Run Stage 1b: derive capability profile from use-case text.

    Makes a single LLM call producing a Stage1Profile, promotes it to a
    CapabilityProfile, logs the call, writes the output to
    capability-profile.yaml, and returns the validated model.

    Stage 1b has zero dependency on Stage 1a — no loss analysis context
    is passed to the prompt.

    Args:
        llm_client: LLM client for making the completion call.
        use_case_text: Free-text use-case description.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        Validated CapabilityProfile model.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("stage1b_system.j2")
    user_prompt = loader.render_prompt(
        "stage1b_user.j2",
        use_case_text=use_case_text,
    )

    stage1_profile, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=Stage1Profile,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP,
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=STEP, message=error_msg)

    capability_profile = stage1_profile.to_capability_profile()
    write_yaml(
        capability_profile,
        run_dir / "capability-profile.yaml",
        post_process=inject_kc_subcodes_display,
    )
    return capability_profile


def load_capability_profile(profile_path: Path) -> CapabilityProfile:
    """Load a pre-built capability profile from a YAML file.

    Used when the --profile flag is provided to skip Stage 1b.

    Args:
        profile_path: Path to capability-profile.yaml.

    Returns:
        Validated CapabilityProfile model.
    """
    return read_yaml(profile_path, CapabilityProfile)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T13:27:21Z","module_hash":"9d74283244fdd5b0b4a102888721e83cd5c7afe89e59b70fc595e0e1739527a4","functions":[{"id":"func/derive_capability_profile","name":"derive_capability_profile","line":30,"end_line":89,"hash":"42508df14a55fd6c10b781ca826717e6c08b96838a5ede3aff00fd69cf89c0a4"},{"id":"func/load_capability_profile","name":"load_capability_profile","line":92,"end_line":103,"hash":"879c915a125131af1cfb241df23ef326e72ed0742affe7d456dfc8ecb9658f89"}]}
# mutate4py-manifest-end
