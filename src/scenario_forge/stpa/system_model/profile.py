"""Stage 1b — Capability Profile inference.

New STPA-conditioned prompt for capability profile inference. Receives
LossAnalysis from Stage 1a as context. Produces Stage1Profile which is
promoted to CapabilityProfile via to_capability_profile(). The --profile
flag skips this stage (loads a pre-built profile).
"""

from __future__ import annotations

from pathlib import Path

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import log_llm_call, parse_llm_result
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

STAGE = "stage_1b"
STEP = "capability_profile"
DEFAULT_TEMPERATURE = 0.4


def derive_capability_profile(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> CapabilityProfile:
    """Run Stage 1b: derive capability profile from use-case text and loss analysis.

    Makes a single LLM call producing a Stage1Profile, promotes it to a
    CapabilityProfile, logs the call, writes the output to
    capability-profile.yaml, and returns the validated model.

    Args:
        llm_client: LLM client for making the completion call.
        use_case_text: Free-text use-case description.
        loss_analysis: LossAnalysis from Stage 1a.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        Validated CapabilityProfile model.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("stage1b_system.j2")
    all_losses = loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    user_prompt = loader.render_prompt(
        "stage1b_user.j2",
        use_case_text=use_case_text,
        loss_analysis=loss_analysis,
        all_losses=all_losses,
    )

    result = llm_client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=Stage1Profile,
        temperature=temperature,
    )

    stage1_profile = parse_llm_result(result, Stage1Profile)
    capability_profile = stage1_profile.to_capability_profile()
    log_llm_call(result, llm_client.model, run_dir, STAGE, STEP)
    write_yaml(capability_profile, run_dir / "capability-profile.yaml")
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
# {"version":1,"tested_at":"2026-08-08T14:39:05Z","module_hash":"f9b20182c8f4f98aa32e057faefc20e8acccc613e6c45c1cf6397947ecba8902","functions":[{"id":"func/derive_capability_profile","name":"derive_capability_profile","line":29,"end_line":77,"hash":"eebef01256c14a524b11d90c528e049b0251d4f5b3b5789f01e8132d814fd471"},{"id":"func/load_capability_profile","name":"load_capability_profile","line":80,"end_line":91,"hash":"879c915a125131af1cfb241df23ef326e72ed0742affe7d456dfc8ecb9658f89"}]}
# mutate4py-manifest-end
