"""Stage 1a — Loss Analysis derivation (two sequential LLM calls).

Call 1 (risk_derivation): derives losses, hazards, and security constraints
from organizational risk cards.

Call 2 (gap_analysis): reviews the use-case description against Call 1's
output to find missing adversary-actionable losses.  Receives the capability
profile as additional input for systematic coverage checking.

IDs (loss/hazard/SC) continue sequentially across the two calls with no
duplicates; cross-references stay valid after merge.
"""

from __future__ import annotations

import re
from pathlib import Path

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import StageError, safe_llm_call
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

STAGE = "stage_1a"
STEP_RISK = "risk_derivation"
STEP_GAP = "gap_analysis"
DEFAULT_TEMPERATURE = 0.4


def derive_loss_analysis(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    capability_profile: CapabilityProfile | None = None,
) -> LossAnalysis:
    """Run Stage 1a: derive loss analysis via two sequential LLM calls.

    Call 1 (risk_derivation) derives losses/hazards/constraints from
    organizational risk cards.  Call 2 (gap_analysis) reviews the use-case
    for missing adversary-actionable losses, receiving Call 1's output and
    the capability profile as context.

    The two drafts are merged with sequential ID renumbering so that
    cross-references remain valid and no IDs are duplicated.

    Args:
        llm_client: LLM client for making the completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        capability_profile: Optional capability profile from Stage 1b,
            passed to the gap analysis call for systematic coverage checking.

    Returns:
        Validated LossAnalysis model.

    Raises:
        StageError: If either LLM call fails or the merged result fails
            validation.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    # --- Call 1: risk_derivation ---
    risk_draft = _run_stage1a_call(
        llm_client=llm_client,
        loader=loader,
        system_template="stage1a_risk_system.j2",
        user_template="stage1a_risk_user.j2",
        run_dir=run_dir,
        step=STEP_RISK,
        temperature=temperature,
        use_case_text=use_case_text,
        risk_cards=risk_cards,
    )

    # --- Compute next IDs for gap analysis ---
    next_loss_num = _max_id_num(
        [loss.loss_id for loss in risk_draft.risk_card_losses + risk_draft.use_case_losses],
        "L-",
    ) + 1
    next_hazard_num = _max_id_num([h.hazard_id for h in risk_draft.hazards], "H-") + 1
    next_sc_num = _max_id_num(
        [sc.constraint_id for sc in risk_draft.security_constraints], "SC-"
    ) + 1

    # --- Call 2: gap_analysis ---
    existing_losses = risk_draft.risk_card_losses + risk_draft.use_case_losses
    kc_subcodes = capability_profile.kc_subcodes if capability_profile else []

    gap_draft = _run_stage1a_call(
        llm_client=llm_client,
        loader=loader,
        system_template="stage1a_gap_system.j2",
        user_template="stage1a_gap_user.j2",
        run_dir=run_dir,
        step=STEP_GAP,
        temperature=temperature,
        use_case_text=use_case_text,
        existing_losses=existing_losses,
        existing_hazards=risk_draft.hazards,
        existing_constraints=risk_draft.security_constraints,
        next_loss_num=next_loss_num,
        next_hazard_num=next_hazard_num,
        next_sc_num=next_sc_num,
        kc_subcodes=kc_subcodes,
    )

    # --- Merge and validate ---
    merged = _merge_drafts(risk_draft, gap_draft)
    write_yaml(merged, run_dir / "loss-analysis.yaml")
    return merged


def _run_stage1a_call(
    *,
    llm_client: LLMClient,
    loader: TemplateLoader,
    system_template: str,
    user_template: str,
    run_dir: Path,
    step: str,
    temperature: float,
    **template_vars: object,
) -> LossAnalysisDraft:
    """Render prompts, call the LLM, and return a validated draft.

    Shared by the risk_derivation and gap_analysis calls.  Raises
    :class:`StageError` if the LLM call fails.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = loader.render_prompt(user_template, **template_vars)

    draft, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=LossAnalysisDraft,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=step, message=error_msg)

    assert draft is not None  # safe_llm_call guarantees this on success
    return draft


def _max_id_num(ids: list[str], prefix: str) -> int:
    """Return the maximum numeric suffix among IDs with the given prefix.

    Returns 0 if the list is empty or no IDs match the prefix.
    """
    max_num = 0
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    for id_str in ids:
        match = pattern.match(id_str)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
    return max_num


def _merge_drafts(
    risk_draft: LossAnalysisDraft,
    gap_draft: LossAnalysisDraft,
) -> LossAnalysis:
    """Merge risk derivation and gap analysis drafts into a final LossAnalysis.

    Concatenates losses, hazards, and security constraints from both drafts.
    Renumbers all IDs sequentially to guarantee no duplicates and valid
    cross-references.
    """
    all_risk_losses = list(risk_draft.risk_card_losses)
    all_uc_losses = list(gap_draft.use_case_losses)
    all_hazards = list(risk_draft.hazards) + list(gap_draft.hazards)
    all_constraints = (
        list(risk_draft.security_constraints) + list(gap_draft.security_constraints)
    )

    # --- Renumber loss IDs (risk losses first, then use-case losses) ---
    loss_id_map = _renumber_items(all_risk_losses, "loss_id", "L-")
    loss_id_map.update(
        _renumber_items(all_uc_losses, "loss_id", "L-", start=len(all_risk_losses) + 1)
    )

    # --- Renumber hazard and constraint IDs ---
    hazard_id_map = _renumber_items(all_hazards, "hazard_id", "H-")
    _renumber_items(all_constraints, "constraint_id", "SC-")

    # --- Update cross-references ---
    _remap_references(all_hazards, "related_losses", loss_id_map)
    _remap_references(all_constraints, "related_hazards", hazard_id_map)

    return LossAnalysis(
        risk_card_losses=all_risk_losses,
        use_case_losses=all_uc_losses,
        hazards=all_hazards,
        security_constraints=all_constraints,
    )


def _renumber_items(
    items: list[object],
    id_attr: str,
    prefix: str,
    *,
    start: int = 1,
) -> dict[str, str]:
    """Renumber items sequentially, returning an old-ID → new-ID map.

    Mutates each item's ``id_attr`` in place to ``{prefix}{index}`` where
    index starts at *start* and increments by 1.
    """
    id_map: dict[str, str] = {}
    for i, item in enumerate(items, start):
        old_id = getattr(item, id_attr)
        new_id = f"{prefix}{i}"
        id_map[old_id] = new_id
        setattr(item, id_attr, new_id)
    return id_map


def _remap_references(
    items: list[object],
    ref_attr: str,
    id_map: dict[str, str],
) -> None:
    """Replace each cross-reference in ``ref_attr`` using ``id_map``.

    References not found in the map are preserved unchanged.
    """
    for item in items:
        refs = getattr(item, ref_attr)
        setattr(item, ref_attr, [id_map.get(ref, ref) for ref in refs])


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-11T11:50:53Z","module_hash":"06e356214430b4d9828468d3816ed3e24981490c507a106b3705abc29c8211fc","functions":[{"id":"func/derive_loss_analysis","name":"derive_loss_analysis","line":37,"end_line":124,"hash":"21c908533bc79b6d01657c6c6335cf95eb7c544a19bad2903de0e205dc5e1959"},{"id":"func/_run_stage1a_call","name":"_run_stage1a_call","line":127,"end_line":160,"hash":"37aad383f7dbea5e5024505d7cccd7f3b80ce9d0b597e22eb644775b3cf9221a"},{"id":"func/_max_id_num","name":"_max_id_num","line":163,"end_line":176,"hash":"6a33fe3dc4ff93f3d1859511ae0bdbec836b0ca731d6dcef08e7e0ed2bb487cb"},{"id":"func/_merge_drafts","name":"_merge_drafts","line":179,"end_line":215,"hash":"78acb5779c3bb0725d26d07091b065d434d296125cb4e524ca2f9cb34315912f"},{"id":"func/_renumber_items","name":"_renumber_items","line":218,"end_line":236,"hash":"5d4dfbcc96950022de526a41235bddac53174e3a916c2445c78b74eccad5c43b"},{"id":"func/_remap_references","name":"_remap_references","line":239,"end_line":250,"hash":"f0a6f06c65cc019b9471cc1339e2ab13e037dd073f592adfb160d29787e64545"}]}
# mutate4py-manifest-end
