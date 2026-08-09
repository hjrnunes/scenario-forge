"""Completeness critic and revision for Stage 2.

The critic is a single LLM call with three probes:
  1. Generic checklist (input validation, authorization, etc.)
  2. Taxonomy-derived probes (conditioned on CapabilityProfile KC sub-codes)
  3. Adversarial probe (3 most obvious attack paths)

Revision is a single LLM call (not a loop) if the critic finds unjustified gaps.
The revision uses a RevisionDelta schema — only new and modified elements —
which is merged programmatically into the existing ControlStructure.
"""

from __future__ import annotations

import copy
import logging
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    Responsibility,
)
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
from scenario_forge.stpa.system_model.heuristics import run_heuristics

STAGE = "stage_2"
STEP_CRITIC = "critic"
STEP_REVISION = "revision"
DEFAULT_TEMPERATURE = 0.4
REVISION_MAX_COMPLETION_TOKENS = 4096
logger = logging.getLogger(__name__)


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


class RevisionDelta(BaseModel):
    """Delta schema for the revision LLM call.

    Instead of restating the entire ControlStructure, the LLM returns
    only the new and modified elements. These are merged programmatically
    into the existing ControlStructure.
    """

    new_responsibilities: list[Responsibility] = []
    new_controlled_processes: list[ControlledProcess] = []
    new_coordination_links: list[CoordinationLink] = []
    modified_responsibilities: list[Responsibility] = []


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
        Returns empty CriticFindings if the LLM call fails.
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

    findings, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=CriticFindings,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_CRITIC,
        temperature=temperature,
    )
    if error_msg is not None:
        return CriticFindings()

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
# Critic ID sanitization
# ---------------------------------------------------------------------------

# Conforming ID patterns (valid format, non-zero):
# RESP-N, PM-X-Y, CA-X-Y, FB-X-Y, CP-N, CL-N, RC-X-Y
_CONFORMING_PATTERNS = [
    re.compile(r"^RESP-\d+$"),
    re.compile(r"^PM-\d+-\d+$"),
    re.compile(r"^CA-\d+-\d+$"),
    re.compile(r"^FB-\d+-\d+$"),
    re.compile(r"^CP-\d+$"),
    re.compile(r"^CL-\d+$"),
    re.compile(r"^RC-\d+-\d+$"),
]

# Any ID-like token (for detection): RESP-*, PM-*, CA-*, FB-*, CP-*, CL-*, RC-*
_ID_LIKE_PATTERN = re.compile(
    r"\b(?:RESP|PM|CA|FB|CP|CL|RC)-\d+(?:-\d+)?\b"
)

# Generic descriptions for non-conforming ID prefixes, used as replacements
# in suggested_remedy strings so the revision model never sees invalid IDs.
_ID_REPLACEMENTS: dict[str, str] = {
    "PM": "a new PM part",
    "RESP": "a new responsibility",
    "CA": "a new control action",
    "FB": "a new feedback channel",
    "CP": "a new controlled process",
    "CL": "a new coordination link",
    "RC": "a new responsibility constraint",
}


def _is_conforming_id(token: str) -> bool:
    """Check whether an ID-like token matches a valid format and is non-zero."""
    return any(p.match(token) for p in _CONFORMING_PATTERNS)


def _replace_non_conforming_ids(remedy: str) -> str:
    """Replace non-conforming ID tokens in a suggested_remedy string.

    Replaces zero-based IDs (PM-0, RESP-0, CA-0, FB-0, and multi-part
    variants like PM-0-1) with generic descriptions. Also replaces
    any ID-like token that does not match a conforming format.
    """
    def _replacer(match: re.Match) -> str:
        token = match.group()
        if _is_conforming_id(token):
            return token
        # Non-conforming: determine replacement
        prefix = token.split("-")[0]
        return _ID_REPLACEMENTS.get(prefix, "a new element")

    return _ID_LIKE_PATTERN.sub(_replacer, remedy)


def sanitize_critic_ids(findings: CriticFindings) -> CriticFindings:
    """Sanitize non-conforming IDs in critic suggested_remedy strings.

    The completeness critic's ``suggested_remedy`` field is free-text and
    may contain non-conforming IDs (e.g., ``PM-0``, ``RESP-0``, or
    IDs that don't match the standard format). These are passed verbatim
    into the revision user prompt, causing the revision LLM to use invalid
    IDs and trigger Pydantic ValidationError on the RevisionDelta output.

    This function replaces non-conforming IDs with generic descriptions
    (e.g., ``PM-0`` → ``a new PM part``) so the revision model receives
    only valid or descriptive text.

    Args:
        findings: The CriticFindings from the completeness critic.

    Returns:
        A new CriticFindings with sanitized suggested_remedy strings.
        ``checklist_results`` and ``taxonomy_probe_results`` are preserved
        unchanged.
    """
    sanitized_gaps = []
    for gap in findings.gaps:
        sanitized_remedy = _replace_non_conforming_ids(gap.suggested_remedy)
        sanitized_gaps.append(
            CriticGap(
                gap_type=gap.gap_type,
                description=gap.description,
                related_attack_path=gap.related_attack_path,
                suggested_remedy=sanitized_remedy,
            )
        )
    return CriticFindings(
        gaps=sanitized_gaps,
        checklist_results=findings.checklist_results,
        taxonomy_probe_results=findings.taxonomy_probe_results,
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

    Requests a :class:`RevisionDelta` from the LLM (only new/modified
    elements) and merges it programmatically into the existing
    ControlStructure. After the merge, ``strip_empty_responsibilities``
    runs as a safety net, and structural heuristics are re-run.

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
        On LLM failure, returns (pre-revision ControlStructure, [warning]).
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    next_ids = _compute_next_ids(control_structure)

    system_prompt = loader.render_prompt(
        "revision_system.j2",
        control_structure=control_structure,
        **next_ids,
    )
    user_prompt = loader.render_prompt(
        "revision_user.j2",
        use_case_text=use_case_text,
        control_structure=control_structure,
        critic_findings=critic_findings,
    )

    revision_delta, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=RevisionDelta,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_REVISION,
        temperature=temperature,
        max_completion_tokens=REVISION_MAX_COMPLETION_TOKENS,
    )
    if error_msg is not None:
        return control_structure, [f"Revision failed: {error_msg}"]
    if revision_delta is None:
        return control_structure, ["Revision failed: unexpected None response"]

    # Merge the delta into the existing ControlStructure
    revised_cs = _merge_revision_delta(control_structure, revision_delta)

    # Strip empty responsibilities as a safety net
    revised_cs, strip_warnings = strip_empty_responsibilities(revised_cs)

    # Re-run structural heuristics after revision
    post_revision = run_heuristics(revised_cs, loss_analysis)
    post_warnings = list(post_revision.errors) + list(post_revision.warnings)
    post_warnings.extend(strip_warnings)

    return revised_cs, post_warnings


def _compute_next_ids(
    cs: ControlStructure,
) -> dict[str, int]:
    """Compute next-available ID numbers from an existing ControlStructure.

    Returns a dict of template variables for the revision system prompt:
    ``next_resp_num``, ``next_cl_num``, ``next_cp_num``.
    """
    return {
        "next_resp_num": _next_num_from(cs.responsibilities, lambda r: r.resp_id),
        "next_cl_num": _next_num_from(cs.coordination_links, lambda cl: cl.link_id),
        "next_cp_num": _next_num_from(cs.controlled_processes, lambda cp: cp.cp_id),
    }


def _next_num_from(items: list, id_getter: Any) -> int:
    """Return the next-available number from a list of items.

    Extracts numeric suffixes from each item's ID via *id_getter* and
    returns ``max(found) + 1``, or 1 when the list is empty.
    """
    nums = [_extract_num(id_getter(item)) for item in items]
    valid_nums = [n for n in nums if n is not None]
    return max(valid_nums, default=0) + 1


def _extract_num(id_str: str) -> int | None:
    """Extract the numeric suffix from an ID like 'RESP-3' or 'CL-1'.

    For multi-part IDs like 'PM-1-2', returns the first number (1).
    """
    match = re.search(r"\d+", id_str)
    return int(match.group()) if match else None


def _add_new_items(
    existing: list,
    new_items: list,
    existing_ids: set,
    id_getter: Any,
) -> list:
    """Append new_items to a deep-copied existing list, skipping duplicate IDs.

    Mutates *existing_ids* by adding each newly inserted item's ID.
    """
    merged = [copy.deepcopy(item) for item in existing]
    for new_item in new_items:
        item_id = id_getter(new_item)
        if item_id not in existing_ids:
            merged.append(copy.deepcopy(new_item))
            existing_ids.add(item_id)
        else:
            logger.warning("Skipping duplicate item %s from revision delta", item_id)
    return merged


def _replace_modified_resps(
    resps: list[Responsibility],
    modified: list[Responsibility],
) -> list[Responsibility]:
    """Replace responsibilities whose resp_id appears in *modified*.

    Responsibilities not in the modified set are deep-copied as-is.
    """
    modified_map = {r.resp_id: r for r in modified}
    return [
        copy.deepcopy(modified_map.get(r.resp_id, r))
        for r in resps
    ]


def _merge_revision_delta(
    cs: ControlStructure,
    delta: RevisionDelta,
) -> ControlStructure:
    """Merge a RevisionDelta into an existing ControlStructure.

    - Replaces ``modified_responsibilities`` by resp_id.
    - Adds ``new_responsibilities`` (skipping duplicate resp_ids).
    - Adds ``new_controlled_processes`` (skipping duplicate cp_ids).
    - Adds ``new_coordination_links`` (skipping duplicate link_ids).
    - Validates the merged ControlStructure.
    """
    existing_resp_ids = {r.resp_id for r in cs.responsibilities}
    existing_cp_ids = {cp.cp_id for cp in cs.controlled_processes}
    existing_cl_ids = {cl.link_id for cl in cs.coordination_links}

    merged_resps = _replace_modified_resps(
        cs.responsibilities, delta.modified_responsibilities
    )
    merged_resps = _add_new_items(
        merged_resps, delta.new_responsibilities,
        existing_resp_ids, lambda r: r.resp_id,
    )

    merged_cps = _add_new_items(
        cs.controlled_processes, delta.new_controlled_processes,
        existing_cp_ids, lambda cp: cp.cp_id,
    )

    merged_cls = _add_new_items(
        cs.coordination_links, delta.new_coordination_links,
        existing_cl_ids, lambda cl: cl.link_id,
    )

    return ControlStructure(
        responsibilities=merged_resps,
        controlled_processes=merged_cps,
        coordination_links=merged_cls,
    )


# ---------------------------------------------------------------------------
# Post-revision strip empty responsibilities
# ---------------------------------------------------------------------------


def _is_responsibility_empty(resp: Responsibility) -> bool:
    """Check if a responsibility has no PM parts, CAs, or FB channels."""
    return not any(
        [resp.process_model_parts, resp.control_actions, resp.feedback_channels]
    )


def strip_empty_responsibilities(
    control_structure: ControlStructure,
) -> tuple[ControlStructure, list[str]]:
    """Strip responsibilities with no PM parts, CAs, or FB channels.

    After revision, the LLM may produce skeleton responsibilities that
    have a description but no process model parts, no control actions,
    and no feedback channels. These would produce downstream heuristic
    errors (every responsibility must have >=1 PM, CA, and FB). This
    function detects and removes them.

    A responsibility is considered empty when **all three** of
    ``process_model_parts``, ``control_actions``, and
    ``feedback_channels`` are empty. ``responsibility_constraints`` alone
    do not prevent stripping.

    Args:
        control_structure: The (possibly revised) control structure.

    Returns:
        A tuple of (stripped ControlStructure, list of warning strings).
        Each warning includes the resp_id and description of the
        stripped responsibility.
    """
    kept: list[Responsibility] = []
    warnings: list[str] = []

    for resp in control_structure.responsibilities:
        if _is_responsibility_empty(resp):
            warnings.append(
                f"Stripped empty responsibility {resp.resp_id} "
                f"({resp.description}) after revision: no PM parts, "
                f"control actions, or feedback channels."
            )
        else:
            kept.append(resp)

    if len(kept) == len(control_structure.responsibilities):
        return control_structure, warnings

    stripped_cs = control_structure.model_copy(
        update={"responsibilities": kept},
    )
    return stripped_cs, warnings


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
# {"version":1,"tested_at":"2026-08-09T20:02:49Z","module_hash":"2d3ea19a535dea2b750d74f7b45cc1883c0c18945adce08185727aff769f3670","functions":[{"id":"func/run_completeness_critic","name":"run_completeness_critic","line":86,"end_line":143,"hash":"02ee0d6f8dd93f9f1f4ac45260e050c1d2c2eb2e571904d3a1c0026e65d838ae"},{"id":"func/has_unjustified_gaps","name":"has_unjustified_gaps","line":146,"end_line":157,"hash":"76f218e93aab136e25ece616eec638dc88c7f8470197c6367a99ddf7da3df23d"},{"id":"func/run_revision","name":"run_revision","line":165,"end_line":244,"hash":"0b604cd556b9cd93a1f645c93a84765a148624217c28bda86b5f70bcd3c760b6"},{"id":"func/_compute_next_ids","name":"_compute_next_ids","line":247,"end_line":259,"hash":"81a219ed24c1f3c420e4e47b0df9c72460d06c11c65398935fd419320b2f9e89"},{"id":"func/_next_num_from","name":"_next_num_from","line":262,"end_line":270,"hash":"7604f4ce687e1ec1d459143ec2b37c8b317573cbfd7b3eee0aaf78075c5cbe2a"},{"id":"func/_extract_num","name":"_extract_num","line":273,"end_line":279,"hash":"5762f14fc8d7f27355617700b71ae9cc6dfed5ee691c3315c44ca384557315d3"},{"id":"func/_add_new_items","name":"_add_new_items","line":282,"end_line":300,"hash":"7b74c64c23b3e02748224a960fc7e5475a3d38781676e87d6e5785e242fb7004"},{"id":"func/_replace_modified_resps","name":"_replace_modified_resps","line":303,"end_line":315,"hash":"a7c3f7893c5e003f2a8bbcff960066069363b6a1ef59e4837a93adccf815f728"},{"id":"func/_merge_revision_delta","name":"_merge_revision_delta","line":318,"end_line":356,"hash":"cd3df3b2870c18cae0a822f4b185fb8959e228945b6a9c1261e943ebdcc62c6f"},{"id":"func/_is_responsibility_empty","name":"_is_responsibility_empty","line":364,"end_line":368,"hash":"f0e3af6c54ff18f8eb0421cb7c1166cfc694589549bba28429d7791561eb4551"},{"id":"func/strip_empty_responsibilities","name":"strip_empty_responsibilities","line":371,"end_line":414,"hash":"0d28f4118b8fe01b7675c720794f49fb3d9425b3bf0afcb045e96e6521c7f336"},{"id":"func/_needs_rag_probe","name":"_needs_rag_probe","line":445,"end_line":450,"hash":"21a1da1f408fbabedfcb35fdc68747a0d4fdd19ad3842eba865b650245f6c655"},{"id":"func/_needs_tool_probe","name":"_needs_tool_probe","line":453,"end_line":456,"hash":"e77a0b8f2d8e69fc6b955acd6055b0ad45817d5082dce6c4b4fc03010fd7e8fe"},{"id":"func/_build_taxonomy_probes","name":"_build_taxonomy_probes","line":459,"end_line":478,"hash":"5704e40354a3852b42874470d153d96f5524ef91ba324800c90cf2cdc3d6a699"}]}
# mutate4py-manifest-end
