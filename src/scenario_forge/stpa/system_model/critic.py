"""Completeness critic and revision for Stage 2.

The critic is a single LLM call with three probes:
  1. Generic checklist (input validation, authorization, etc.)
  2. Taxonomy-derived probes (conditioned on CapabilityProfile KC sub-codes)
  3. Adversarial probe (3 most obvious attack paths)

Revision is a single LLM call (not a loop) if the critic finds unjustified gaps.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import log_llm_call, parse_llm_result
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model import PROMPTS_DIR
from scenario_forge.stpa.system_model.heuristics import run_heuristics

STAGE = "stage_2"
STEP_CRITIC = "critic"
STEP_REVISION = "revision"
DEFAULT_TEMPERATURE = 0.4


# ---------------------------------------------------------------------------
# Internal models
# ---------------------------------------------------------------------------


class CriticGap(BaseModel):
    """A gap identified by the completeness critic."""

    gap_type: Literal["missing_responsibility", "missing_feedback", "missing_pm_part"]
    description: str
    related_attack_path: str
    suggested_remedy: str


class CriticFindings(BaseModel):
    """Findings from the completeness critic."""

    gaps: list[CriticGap] = []
    checklist_results: dict[str, str] = {}
    taxonomy_probe_results: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Completeness critic
# ---------------------------------------------------------------------------


def run_completeness_critic(
    *,
    llm_client: LLMClient,
    control_structure: ControlStructure,
    capability_profile: CapabilityProfile,
    use_case_text: str,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> CriticFindings:
    """Run the completeness critic on the control structure.

    Makes a single LLM call with three probes. Logs the call and returns
    the CriticFindings.

    Args:
        llm_client: LLM client for making the completion call.
        control_structure: The derived control structure to critique.
        capability_profile: The capability profile for taxonomy probes.
        use_case_text: Free-text use-case description.
        run_dir: Directory for call logging.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        CriticFindings model with gaps, checklist results, and taxonomy probe results.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    taxonomy_probes = _build_taxonomy_probes(capability_profile)

    system_prompt = loader.render_prompt(
        "critic_system.j2",
        taxonomy_probes=taxonomy_probes,
    )
    user_prompt = loader.render_prompt(
        "critic_user.j2",
        use_case_text=use_case_text,
        control_structure=control_structure,
        capability_profile=capability_profile,
        taxonomy_probes=taxonomy_probes,
    )

    result = llm_client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=CriticFindings,
        temperature=temperature,
    )

    findings = parse_llm_result(result, CriticFindings)
    log_llm_call(result, llm_client.model, run_dir, STAGE, STEP_CRITIC)
    return findings


def has_unjustified_gaps(findings: CriticFindings) -> bool:
    """Check whether the critic findings contain any unjustified gaps.

    Revision is triggered if any checklist result is ``absent_unjustified``.

    Args:
        findings: The critic findings to check.

    Returns:
        True if revision should be triggered, False otherwise.
    """
    return any(
        status == "absent_unjustified"
        for status in findings.checklist_results.values()
    )


# ---------------------------------------------------------------------------
# Revision
# ---------------------------------------------------------------------------


def run_revision(
    *,
    llm_client: LLMClient,
    control_structure: ControlStructure,
    critic_findings: CriticFindings,
    use_case_text: str,
    run_dir: Path,
    loss_analysis: LossAnalysis | None = None,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> tuple[ControlStructure, list[str]]:
    """Run a single revision attempt on the control structure.

    This is NOT a loop — one revision attempt maximum. After revision,
    structural heuristics are re-run. If structural errors remain, they
    are returned as warnings (the pipeline proceeds).

    Args:
        llm_client: LLM client for making the completion call.
        control_structure: The current control structure to revise.
        critic_findings: The gaps identified by the critic.
        use_case_text: Free-text use-case description.
        run_dir: Directory for call logging.
        loss_analysis: Optional loss analysis for heuristic hazard tracing.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        A tuple of (revised ControlStructure, post-revision heuristic warnings).
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("revision_system.j2")
    user_prompt = loader.render_prompt(
        "revision_user.j2",
        use_case_text=use_case_text,
        control_structure=control_structure,
        critic_findings=critic_findings,
    )

    result = llm_client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=ControlStructure,
        temperature=temperature,
    )

    revised_cs = parse_llm_result(result, ControlStructure)
    log_llm_call(result, llm_client.model, run_dir, STAGE, STEP_REVISION)

    # Re-run structural heuristics after revision
    post_revision = run_heuristics(revised_cs, loss_analysis)
    post_warnings = post_revision.errors + post_revision.warnings

    return revised_cs, post_warnings


# ---------------------------------------------------------------------------
# Taxonomy probe builder
# ---------------------------------------------------------------------------

# Each entry: (predicate, probe text).  Predicates are kept as small
# standalone functions so the builder itself stays a simple loop.
_PROBE_TEXT_RAG = (
    "RAG retrieval integrity: Is there a responsibility governing "
    "retrieval content validation and source integrity?"
)
_PROBE_TEXT_TOOL = (
    "Tool parameter validation: Is there a responsibility governing "
    "parameter validation for tool invocations?"
)
_PROBE_TEXT_MEMORY = (
    "Memory integrity: Is there a responsibility governing "
    "persistent memory integrity and access control?"
)
_PROBE_TEXT_MULTI_AGENT = (
    "Multi-agent coordination: Are there coordination responsibilities "
    "for inter-agent communication?"
)
_PROBE_TEXT_HITL = (
    "Human-in-the-loop escalation: Is there a responsibility for "
    "escalation to human review when needed?"
)


def _needs_rag_probe(profile: CapabilityProfile) -> bool:
    """True when the profile includes RAG capabilities."""
    kc_set = set(profile.kc_subcodes)
    return "KC6.3.3" in kc_set or any(
        "rag" in ep.name.lower() for ep in profile.entry_points
    )


def _needs_tool_probe(profile: CapabilityProfile) -> bool:
    """True when the profile includes tool-invocation capabilities."""
    kc_set = set(profile.kc_subcodes)
    return any(kc.startswith("KC5.") or kc.startswith("KC6.") for kc in kc_set)


def _build_taxonomy_probes(profile: CapabilityProfile) -> list[str]:
    """Build taxonomy-derived probes based on the capability profile.

    Each probe is gated by a small predicate so this function stays a
    simple loop instead of a chain of independent ``if`` blocks.

    Args:
        profile: The capability profile.

    Returns:
        A list of probe descriptions.
    """
    gated_probes: list[tuple[Any, str]] = [
        (_needs_rag_probe, _PROBE_TEXT_RAG),
        (_needs_tool_probe, _PROBE_TEXT_TOOL),
        (lambda p: p.has_persistent_memory, _PROBE_TEXT_MEMORY),
        (lambda p: p.multi_agent, _PROBE_TEXT_MULTI_AGENT),
        (lambda p: p.hitl, _PROBE_TEXT_HITL),
    ]
    return [text for predicate, text in gated_probes if predicate(profile)]
