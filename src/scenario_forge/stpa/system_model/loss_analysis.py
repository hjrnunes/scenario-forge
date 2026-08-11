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
    risk_system = loader.render_prompt("stage1a_risk_system.j2")
    risk_user = loader.render_prompt(
        "stage1a_risk_user.j2",
        use_case_text=use_case_text,
        risk_cards=risk_cards,
    )

    risk_draft, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=risk_system,
        user_prompt=risk_user,
        response_format=LossAnalysisDraft,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_RISK,
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=STEP_RISK, message=error_msg)

    assert risk_draft is not None  # safe_llm_call guarantees this on success

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

    gap_system = loader.render_prompt("stage1a_gap_system.j2")
    gap_user = loader.render_prompt(
        "stage1a_gap_user.j2",
        use_case_text=use_case_text,
        existing_losses=existing_losses,
        existing_hazards=risk_draft.hazards,
        existing_constraints=risk_draft.security_constraints,
        next_loss_num=next_loss_num,
        next_hazard_num=next_hazard_num,
        next_sc_num=next_sc_num,
        kc_subcodes=kc_subcodes,
    )

    gap_draft, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=gap_system,
        user_prompt=gap_user,
        response_format=LossAnalysisDraft,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_GAP,
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=STEP_GAP, message=error_msg)

    assert gap_draft is not None

    # --- Merge and validate ---
    merged = _merge_drafts(risk_draft, gap_draft)
    write_yaml(merged, run_dir / "loss-analysis.yaml")
    return merged


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

    # --- Renumber loss IDs ---
    loss_id_map: dict[str, str] = {}
    for i, loss in enumerate(all_risk_losses, 1):
        loss_id_map[loss.loss_id] = f"L-{i}"
        loss.loss_id = f"L-{i}"
    offset = len(all_risk_losses)
    for i, loss in enumerate(all_uc_losses, 1):
        loss_id_map[loss.loss_id] = f"L-{offset + i}"
        loss.loss_id = f"L-{offset + i}"

    # --- Renumber hazard IDs ---
    hazard_id_map: dict[str, str] = {}
    for i, hazard in enumerate(all_hazards, 1):
        hazard_id_map[hazard.hazard_id] = f"H-{i}"
        hazard.hazard_id = f"H-{i}"

    # --- Renumber constraint IDs ---
    for i, sc in enumerate(all_constraints, 1):
        sc.constraint_id = f"SC-{i}"

    # --- Update cross-references ---
    for hazard in all_hazards:
        hazard.related_losses = [
            loss_id_map.get(ref, ref) for ref in hazard.related_losses
        ]

    for sc in all_constraints:
        sc.related_hazards = [
            hazard_id_map.get(ref, ref) for ref in sc.related_hazards
        ]

    return LossAnalysis(
        risk_card_losses=all_risk_losses,
        use_case_losses=all_uc_losses,
        hazards=all_hazards,
        security_constraints=all_constraints,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T13:27:21Z","module_hash":"6fbc1bb66686e3d234e6793037cfe366e7474d06e8e8bb49eaa4787708df5ca6","functions":[{"id":"func/derive_loss_analysis","name":"derive_loss_analysis","line":26,"end_line":78,"hash":"d4cb1ff4ffaa970b84b08020c7af05605109aadb8080ed9e8c06cd0036acae9d"}]}
# mutate4py-manifest-end
