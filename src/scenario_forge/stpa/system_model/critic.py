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
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
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
    return any(status == "absent_unjustified" for status in findings.checklist_results.values())


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
    if "KC6.3.3" in kc_set:
        return True
    return any("rag" in ep.name.lower() for ep in profile.entry_points)


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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:42:29Z","module_hash":"476189601cdc78899e3e435f7474de196b2e14e11e3dee90199445f166822ec4","functions":[{"id":"func/run_completeness_critic","name":"run_completeness_critic","line":60,"end_line":112,"hash":"bfc981ab2a6bfac94b63dcab451345a76659b6c339d8237cfb38b0a618ff9606"},{"id":"func/has_unjustified_gaps","name":"has_unjustified_gaps","line":115,"end_line":126,"hash":"76f218e93aab136e25ece616eec638dc88c7f8470197c6367a99ddf7da3df23d"},{"id":"func/run_revision","name":"run_revision","line":134,"end_line":188,"hash":"5c8ba32b4b8f1ac8b00ec3e463938c1e2199c4976e1e646dfcb280034b8f0407"},{"id":"func/_needs_rag_probe","name":"_needs_rag_probe","line":219,"end_line":224,"hash":"21a1da1f408fbabedfcb35fdc68747a0d4fdd19ad3842eba865b650245f6c655"},{"id":"func/_needs_tool_probe","name":"_needs_tool_probe","line":227,"end_line":230,"hash":"e77a0b8f2d8e69fc6b955acd6055b0ad45817d5082dce6c4b4fc03010fd7e8fe"},{"id":"func/_build_taxonomy_probes","name":"_build_taxonomy_probes","line":233,"end_line":252,"hash":"5704e40354a3852b42874470d153d96f5524ef91ba324800c90cf2cdc3d6a699"}]}
# mutate4py-manifest-end
