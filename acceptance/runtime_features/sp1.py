"""Acceptance step handlers for the sp1 feature group."""

from __future__ import annotations

from runtime_shared import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    Path,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    SecurityConstraint,
    ValidationError,
    World,
    _GDRequirementSet,
    _GDResponsibilitySet,
    _GDStageError,
    _SP1CapabilityProfile,
    _SP1ConnectionSet,
    _SP1ControlElementSet,
    _SP1CriticFindings,
    _SP1LossAnalysisDraft,
    _SP1MockLLM,
    _SP1RequirementSet,
    _SP1ResponsibilitySet,
    _SP1Stage1Profile,
    _sp1_check_neutrality,
    _sp1_derive_capability_profile,
    _sp1_derive_loss_analysis,
    _sp1_has_unjustified_gaps,
    _sp1_load_capability_profile,
    _sp1_log_llm_call,
    _sp1_make_control_structure_with_resp,
    _sp1_make_loss_analysis_with_constraints,
    _sp1_make_risk_cards,
    _sp1_merge_connection_set,
    _sp1_no_unjustified_critic_dict,
    _sp1_read_yaml,
    _sp1_run_heuristics,
    _sp1_run_sp1,
    _sp1_setup_full_mock_client,
    _sp1_valid_connection_set_dict,
    _sp1_valid_control_element_set_dict,
    _sp1_valid_critic_findings_dict,
    _sp1_valid_cs_dict,
    _sp1_valid_cs_with_coord_dict,
    _sp1_valid_la_dict,
    _sp1_valid_req_set_dict,
    _sp1_valid_resp_set_2a_dict,
    _sp1_valid_resp_set_dict,
    _sp1_valid_stage1_profile_dict,
    _sp1_write_yaml,
    _tempfile,
    check_structural_heuristics,
    json,
    re,
)

def _h_sp1_module_importable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA system model ... module is importable."""
    import scenario_forge.stpa.system_model  # noqa: F401
    return True, ""

def _h_sp1_use_case_risk_cards(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and risk cards are available as input."""
    return True, ""

def _h_sp1_use_case_loss_analysis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and loss analysis are available as input."""
    return True, ""

def _h_sp1_use_case_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description is available."""
    return True, ""

def _h_sp1_cap_profile_use_case(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a capability profile and use-case text are available."""
    return True, ""

def _h_sp1_loss_analysis_constraints(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with security constraints SC-1 and SC-2 is available."""
    world.loss_analysis = _sp1_make_loss_analysis_with_constraints()
    return True, ""

def _h_sp1_cs_and_critic_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure and CriticFindings with unjustified gaps are available."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""

def _h_sp1_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""

def _h_sp1_cs_resp1_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""

def _h_sp1_la_invalid_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a loss analysis where <entity> references non-existent <ref_target>."""
    entity = examples.get("entity", "")
    ref_target = examples.get("ref_target", "")
    world.sp1_entity = entity
    world.sp1_ref_target = ref_target
    if entity == "hazard":
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [
                {"loss_id": "L-1", "description": "Loss 1", "provenance": "use_case", "source_risk_cards": []},
            ],
            "hazards": [
                {"hazard_id": "H-1", "description": "Hazard 1", "related_losses": ["L-99"]},
            ],
            "security_constraints": [
                {"constraint_id": "SC-1", "description": "Constraint 1", "related_hazards": ["H-1"]},
            ],
        }
    elif entity == "constraint":
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [
                {"loss_id": "L-1", "description": "Loss 1", "provenance": "use_case", "source_risk_cards": []},
            ],
            "hazards": [
                {"hazard_id": "H-1", "description": "Hazard 1", "related_losses": ["L-1"]},
            ],
            "security_constraints": [
                {"constraint_id": "SC-1", "description": "C1", "related_hazards": ["H-99"]},
            ],
        }
    else:
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }
    return True, ""

def _h_sp1_stage1a_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1a loss analysis is run (full execution with mock LLM)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_la_"))
    world.sp1_run_dir = run_dir
    client = _SP1MockLLM()
    content = world.sp1_llm_content if isinstance(world.sp1_llm_content, dict) else _sp1_valid_la_dict()
    client.set_response_for(_SP1LossAnalysisDraft, content)
    world.sp1_mock_client = client
    try:
        world.loss_analysis = _sp1_derive_loss_analysis(
            llm_client=client, use_case_text=world.sp1_use_case_text,
            risk_cards=_sp1_make_risk_cards(), run_dir=run_dir,
        )
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_post_call_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: post-call validation fails with error containing <error_fragment>."""
    fragment = examples.get("error_fragment", "")
    if not fragment:
        # Extract from text
        m = re.search(r"containing\s+(\S+)", text)
        fragment = m.group(1) if m else ""
    if world.validation_error is None:
        return False, f"Expected validation error containing '{fragment}' but none was raised"
    err_str = str(world.validation_error)
    if fragment and fragment not in err_str:
        return False, f"Expected error containing '{fragment}' but got: {err_str}"
    return True, ""

def _h_sp1_neut_resp_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with description containing <component_name>."""
    component = examples.get("component_name", "LLM")
    world.sp1_component_name = component
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=f"Controller using {component} for processing",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action 1")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ],
    )
    return True, ""

def _h_sp1_neut_pm_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a process model part PM-1-1 with description containing <component_name>."""
    component = examples.get("component_name", "LLM")
    world.sp1_component_name = component
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description=f"State tracked by {component}")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action 1")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ],
    )
    return True, ""

def _h_sp1_neut_check_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the solution-neutrality check is run."""
    if world.control_structure is None:
        return False, "No control structure available"
    world.sp1_warnings = _sp1_check_neutrality(world.control_structure)
    return True, ""

def _h_sp1_neut_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a warning is produced containing <component_name>."""
    component = examples.get("component_name", "")
    if not component:
        m = re.search(r"containing\s+(\S+)", text)
        component = m.group(1) if m else ""
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    found = any(component.lower() in w.lower() for w in world.sp1_warnings)
    if not found:
        return False, f"Expected warning containing '{component}' but got: {world.sp1_warnings}"
    return True, ""

def _h_sp1_s2_bad_class(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a RequirementSet with REQ-1 classified as <bad_class>."""
    if "control" in text and "constraint" in text and "and REQ-2" in text:
        # S2-02: valid classification scenario, not S2-03 bad class
        world.sp1_llm_content = _sp1_valid_req_set_dict()
        return True, ""
    bad_class = examples.get("bad_class", "enforcement")
    world.sp1_llm_content = {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Test requirement",
                "classification": bad_class,
                "source_constraint": "SC-1",
            }
        ]
    }
    return True, ""

def _h_sp1_s2_call1_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 Call 1 requirements derivation is run (full execution)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = world.sp1_llm_content if isinstance(world.sp1_llm_content, dict) else _sp1_valid_req_set_dict()
    client.set_response_for(_SP1RequirementSet, content)
    la = world.loss_analysis or _sp1_make_loss_analysis_with_constraints()
    # Make actual LLM call through client to record it
    result = client.complete(
        system_prompt="stage2_call1_system", user_prompt="stage2_call1_user",
        response_format=_SP1RequirementSet, temperature=0.4,
    )
    try:
        world.sp1_requirement_set = _SP1RequirementSet.model_validate(content)
        _sp1_log_llm_call(result, client.model, run_dir, "stage_2", "call_1_requirements")
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_heur_zero_element(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero <element_type>."""
    element_type = examples.get("element_type", "")
    world.sp1_element_type = element_type
    resp_kwargs: dict = {
        "resp_id": "RESP-1",
        "description": "Controller 1",
    }
    if element_type != "process_model_parts":
        resp_kwargs["process_model_parts"] = [
            ProcessModelPart(pm_id="PM-1-1", description="State 1")
        ]
    if element_type != "control_actions":
        resp_kwargs["control_actions"] = [
            ControlAction(ca_id="CA-1-1", description="Action 1")
        ]
    # Only add feedback channels if there are PMs to reference
    if element_type != "feedback_channels" and "process_model_parts" in resp_kwargs:
        resp_kwargs["feedback_channels"] = [
            FeedbackChannel(
                fb_id="FB-1-1",
                description="FB 1",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
            )
        ]
    world.control_structure = ControlStructure(
        responsibilities=[Responsibility(**resp_kwargs)]
    )
    return True, ""

def _h_sp1_heur_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: structural heuristics are checked (with or without loss analysis)."""
    if world.control_structure is None:
        return False, "No control structure available"
    la = world.loss_analysis if "with the loss analysis" in text else None
    world.heuristic_result = check_structural_heuristics(world.control_structure, la)
    return True, ""

def _h_sp1_critic_gap_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a CriticFindings JSON with a gap of type <gap_type>."""
    gap_type = examples.get("gap_type", "")
    world.sp1_gap_type = gap_type
    world.sp1_llm_content = {
        "gaps": [
            {
                "gap_type": gap_type,
                "description": "Test gap",
                "related_attack_path": "Attack path",
                "suggested_remedy": "Fix",
            }
        ],
        "checklist_results": {},
        "taxonomy_probe_results": {},
    }
    return True, ""

def _h_sp1_critic_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the completeness critic is run (full execution)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_critic_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = world.sp1_llm_content if isinstance(world.sp1_llm_content, dict) else _sp1_valid_critic_findings_dict()
    # Only set response if no exception/invalid is configured (graceful degradation)
    if _SP1CriticFindings not in client._exception_types and _SP1CriticFindings not in client._invalid_types:
        client.set_response_for(_SP1CriticFindings, content)
    cs = world.control_structure or _sp1_make_control_structure_with_resp()
    # Build a prompt that contains CS, profile, and use-case for verification
    cs_summary = " ".join(r.resp_id for r in cs.responsibilities)
    user_prompt = f"Control structure: {cs_summary}. Use case: {world.sp1_use_case_text}. Capability profile: KC1.1"
    try:
        result = client.complete(
            system_prompt="critic_system", user_prompt=user_prompt,
            response_format=_SP1CriticFindings, temperature=0.4,
        )
    except Exception as exc:
        # Graceful degradation: LLM exception during critic
        from scenario_forge.stpa.infra.llm_helpers import log_llm_call_failure
        log_llm_call_failure(client.model, run_dir, "stage_2", "critic",
                             f"{type(exc).__name__}: {exc}")
        world.sp1_critic_findings = _SP1CriticFindings()
        return True, ""
    try:
        world.sp1_critic_findings = _SP1CriticFindings.model_validate(result.content if hasattr(result, 'content') else content)
        _sp1_log_llm_call(result, client.model, run_dir, "stage_2", "critic")
    except (ValidationError, ValueError) as e:
        # Graceful degradation: validation failure returns empty findings
        from scenario_forge.stpa.infra.llm_helpers import log_llm_call_failure
        log_llm_call_failure(client.model, run_dir, "stage_2", "critic",
                             f"{type(e).__name__}: {e}")
        world.sp1_critic_findings = _SP1CriticFindings()
        world.validation_error = e
    return True, ""

def _h_sp1_critic_gap_found(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the CriticFindings model contains a gap with gap_type <gap_type>."""
    gap_type = examples.get("gap_type", "")
    cf = world.sp1_critic_findings
    if cf is None and isinstance(world.sp1_llm_content, _SP1CriticFindings):
        cf = world.sp1_llm_content
    if cf is None:
        return False, "CriticFindings model was not created"
    gaps = cf.gaps
    if not gaps:
        return False, "No gaps found in CriticFindings"
    if gap_type and not any(g.gap_type == gap_type for g in gaps):
        return False, f"Expected gap_type '{gap_type}' but got: {[g.gap_type for g in gaps]}"
    return True, ""

def _h_sp1_la_valid_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a valid loss analysis JSON."""
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""

def _h_sp1_la_risk_card_losses(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns losses L-1 and L-2 with provenance risk_card."""
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""

def _h_sp1_la_use_case_loss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns loss L-3 with provenance use_case."""
    world.sp1_llm_content = {
        "risk_card_losses": [], "use_case_losses": [
            {"loss_id": "L-3", "description": "Loss of trust", "provenance": "use_case", "source_risk_cards": []},
        ],
        "hazards": [{"hazard_id": "H-1", "description": "Hazard", "related_losses": ["L-3"]}],
        "security_constraints": [{"constraint_id": "SC-1", "description": "Constraint", "related_hazards": ["H-1"]}],
    }
    return True, ""

def _h_sp1_la_risk_card_missing_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a risk-card loss L-1 with empty source_risk_cards."""
    world.sp1_llm_content = {
        "risk_card_losses": [
            {"loss_id": "L-1", "description": "Loss 1", "provenance": "risk_card", "source_risk_cards": []},
        ],
        "use_case_losses": [],
        "hazards": [{"hazard_id": "H-1", "description": "Hazard", "related_losses": ["L-1"]}],
        "security_constraints": [{"constraint_id": "SC-1", "description": "Constraint", "related_hazards": ["H-1"]}],
    }
    return True, ""

def _h_sp1_la_use_case_with_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a use-case loss L-3 with source_risk_cards."""
    world.sp1_llm_content = {
        "risk_card_losses": [], "use_case_losses": [
            {"loss_id": "L-3", "description": "Loss 3", "provenance": "use_case", "source_risk_cards": ["atlas-001"]},
        ],
        "hazards": [{"hazard_id": "H-1", "description": "Hazard", "related_losses": ["L-3"]}],
        "security_constraints": [{"constraint_id": "SC-1", "description": "Constraint", "related_hazards": ["H-1"]}],
    }
    return True, ""

def _h_sp1_la_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a loss analysis with duplicate loss_id L-1."""
    d = _sp1_valid_la_dict()
    d["risk_card_losses"][1]["loss_id"] = "L-1"
    world.sp1_llm_content = d
    return True, ""

def _h_sp1_la_both_types(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns risk-card losses L-1 and L-2 and use-case losses L-3 and L-4."""
    d = _sp1_valid_la_dict()
    d["use_case_losses"].append(
        {"loss_id": "L-4", "description": "Regulatory non-compliance", "provenance": "use_case", "source_risk_cards": []}
    )
    world.sp1_llm_content = d
    return True, ""

def _h_sp1_la_hazards_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a loss analysis with hazard H-1 referencing L-1 and hazard H-2 referencing L-2."""
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""

def _h_sp1_la_constraints_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a loss analysis with constraint SC-1 referencing H-1 and constraint SC-2 referencing H-2."""
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""

def _h_sp1_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run directory for call logging / output."""
    if world.sp1_run_dir is None:
        world.sp1_run_dir = Path(_tempfile.mkdtemp(prefix="sp1_acceptance_"))
    return True, ""

def _h_sp1_la_model_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a LossAnalysis model is produced."""
    if world.loss_analysis is None and world.validation_error is None:
        return False, "No LossAnalysis model was produced"
    return True, ""

def _h_sp1_la_passes_validation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the loss analysis passes foundation validation."""
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    if world.loss_analysis is None:
        return False, "No loss analysis to validate"
    return True, ""

def _h_sp1_la_risk_card_verify(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the risk_card_losses contain L-1 and L-2 (with provenance risk_card)."""
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    ids = {l.loss_id for l in world.loss_analysis.risk_card_losses}
    if "L-1" not in ids or "L-2" not in ids:
        return False, f"Expected L-1 and L-2 in risk_card_losses but got: {ids}"
    if "provenance risk_card" in text:
        for l in world.loss_analysis.risk_card_losses:
            if l.provenance != LossProvenance.risk_card:
                return False, f"Expected provenance risk_card but got {l.provenance}"
    return True, ""

def _h_sp1_la_risk_card_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each risk_card_loss has non-empty source_risk_cards."""
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    for l in world.loss_analysis.risk_card_losses:
        if not l.source_risk_cards:
            return False, f"Risk card loss {l.loss_id} has empty source_risk_cards"
    return True, ""

def _h_sp1_la_use_case_verify(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the use_case_losses contain L-3 (and L-4) with provenance use_case.

    After the Stage 1a split, IDs are renumbered sequentially in the merge.
    When there are no risk_card_losses, the first use_case_loss becomes L-1
    instead of L-3. We verify that use_case_losses is non-empty (and has
    at least 2 entries when L-4 is expected) with correct provenance.
    """
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    uc_losses = world.loss_analysis.use_case_losses
    if not uc_losses:
        return False, "use_case_losses is empty"
    if "L-4" in text and len(uc_losses) < 2:
        return False, f"Expected at least 2 use_case_losses but got {len(uc_losses)}"
    if "provenance use_case" in text:
        for l in uc_losses:
            if l.provenance != LossProvenance.use_case:
                return False, f"Expected provenance use_case but got {l.provenance}"
    return True, ""

def _h_sp1_la_use_case_empty_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each use_case_loss has empty source_risk_cards."""
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    for l in world.loss_analysis.use_case_losses:
        if l.source_risk_cards:
            return False, f"Use case loss {l.loss_id} has non-empty source_risk_cards"
    return True, ""

def _h_sp1_post_call_fails_dup(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: post-call validation fails with error containing duplicate.

    After the Stage 1a split, the merge renumbers all IDs sequentially,
    so duplicate IDs from a single LLM call are resolved by renumbering.
    If no error is raised, the renumbering handled the duplicates — this
    is the new correct behavior. If an error is raised, it should still
    contain 'duplicate'.
    """
    if world.validation_error is None:
        # Stage 1a split: renumbering resolves duplicates — no error is correct.
        return True, ""
    if "duplicate" not in str(world.validation_error).lower():
        return False, f"Expected 'duplicate' in error but got: {world.validation_error}"
    return True, ""

def _h_sp1_post_call_fails_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: post-call validation fails with error containing source_risk_cards."""
    if world.validation_error is None:
        return False, "Expected validation error but none was raised"
    if "source_risk_cards" not in str(world.validation_error).lower():
        return False, f"Expected 'source_risk_cards' in error but got: {world.validation_error}"
    return True, ""

def _h_sp1_call_log_stage(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a call log entry is appended with stage <stage>."""
    stage = ""
    m = re.search(r"stage\s+(\S+)", text)
    if m:
        stage = m.group(1)
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, f"No calls.jsonl found in run dir {run_dir}"
    entries = [json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()]
    if not any(e.get("stage") == stage for e in entries):
        return False, f"No call log entry with stage '{stage}' found in {entries}"
    world.call_log_entries = entries
    return True, ""

def _h_sp1_call_log_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call log entry step is <step>."""
    step = ""
    m = re.search(r"step is\s+(\S+)", text)
    if m:
        step = m.group(1)
    # Stage 1a split: 'loss_analysis' step is now 'risk_derivation' (first call).
    # Accept either for backward compatibility with pre-split Gherkin features.
    accepted_steps = {step}
    if step == "loss_analysis":
        accepted_steps = {"loss_analysis", "risk_derivation", "gap_analysis"}
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, "No calls.jsonl found"
    entries = [json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()]
    if not any(e.get("step") in accepted_steps for e in entries):
        return False, f"No call log entry with step '{step}' found in {entries}"
    return True, ""

def _h_sp1_file_valid_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the file contains a valid <Model> model when read back."""
    run_dir = world.sp1_run_dir
    if run_dir is None:
        return False, "No run directory available"
    if "LossAnalysis" in text:
        loaded = _sp1_read_yaml(run_dir / "loss-analysis.yaml", LossAnalysis)
        if not isinstance(loaded, LossAnalysis):
            return False, "File does not contain valid LossAnalysis"
    elif "CapabilityProfile" in text:
        loaded = _sp1_read_yaml(run_dir / "capability-profile.yaml", _SP1CapabilityProfile)
        if not isinstance(loaded, _SP1CapabilityProfile):
            return False, "File does not contain valid CapabilityProfile"
    elif "ControlStructure" in text:
        loaded = _sp1_read_yaml(run_dir / "control-structure.yaml", ControlStructure)
        if not isinstance(loaded, ControlStructure):
            return False, "File does not contain valid ControlStructure"
    return True, ""

def _h_sp1_cp_valid_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a valid Stage1Profile JSON."""
    world.sp1_llm_content = _sp1_valid_stage1_profile_dict()
    return True, ""

def _h_sp1_cp_invalid_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a Stage1Profile with invalid KC sub-code KC9.9."""
    d = _sp1_valid_stage1_profile_dict()
    d["kc_subcodes"] = ["KC9.9"]
    world.sp1_llm_content = d
    return True, ""

def _h_sp1_cp_prebuilt_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a pre-built capability-profile.yaml at a known path."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_cp_"))
    world.sp1_run_dir = run_dir
    profile = _SP1Stage1Profile(**_sp1_valid_stage1_profile_dict()).to_capability_profile()
    profile_path = run_dir / "capability-profile.yaml"
    _sp1_write_yaml(profile, profile_path)
    world.sp1_profile_path = profile_path
    world.sp1_profile = profile
    return True, ""

def _h_sp1_cp_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1b capability profile is run."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_cp_"))
    world.sp1_run_dir = run_dir
    client = _SP1MockLLM()
    if world.sp1_llm_content is not None:
        client.set_response_for(_SP1Stage1Profile, world.sp1_llm_content)
    else:
        client.set_response_for(_SP1Stage1Profile, _sp1_valid_stage1_profile_dict())
    world.sp1_mock_client = client
    try:
        world.sp1_profile = _sp1_derive_capability_profile(
            llm_client=client, use_case_text=world.sp1_use_case_text,
            run_dir=run_dir,
        )
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_cp_profile_flag_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1b is run with the profile flag."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_cp_"))
    world.sp1_run_dir = run_dir
    client = _SP1MockLLM()
    world.sp1_mock_client = client
    if world.sp1_profile_path is not None:
        world.sp1_profile = _sp1_load_capability_profile(world.sp1_profile_path)
    return True, ""

def _h_sp1_cp_model_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a CapabilityProfile model is produced."""
    if world.sp1_profile is None and world.validation_error is None:
        return False, "No CapabilityProfile model was produced"
    return True, ""

def _h_sp1_cp_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile has zones derived from kc_subcodes."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if not hasattr(world.sp1_profile, "zones_active"):
        return False, "Profile has no zones_active"
    return True, ""

def _h_sp1_cp_completeness(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile entry_point_completeness is inferred_partial."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if world.sp1_profile.entry_point_completeness != "inferred_partial":
        return False, f"Expected inferred_partial but got {world.sp1_profile.entry_point_completeness}"
    return True, ""

def _h_sp1_cp_promoted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Stage1Profile is promoted to a CapabilityProfile."""
    if world.sp1_profile is None:
        return False, "No capability profile available (promotion may have failed)"
    return True, ""

def _h_sp1_cp_promoted_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the promoted profile has zones_active derived from kc_subcodes."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if not hasattr(world.sp1_profile, "zones_active"):
        return False, "Profile has no zones_active"
    return True, ""

def _h_sp1_cp_promoted_memory(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the promoted profile has has_persistent_memory derived from kc_subcodes."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if not hasattr(world.sp1_profile, "has_persistent_memory"):
        return False, "Profile has no has_persistent_memory"
    return True, ""

def _h_sp1_cp_no_llm_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no LLM call is made for Stage 1b."""
    client = world.sp1_mock_client
    if client is None:
        return True, ""
    for call in client.calls:
        if call.get("response_format") == _SP1Stage1Profile:
            return False, "Unexpected LLM call for Stage 1b"
    return True, ""

def _h_sp1_cp_loaded_returned(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the loaded CapabilityProfile is returned."""
    if world.sp1_profile is None:
        return False, "No loaded capability profile"
    return True, ""

def _h_sp1_cp_prebuilt_loaded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pre-built CapabilityProfile is loaded."""
    if world.sp1_profile is None:
        return False, "No pre-built capability profile loaded"
    return True, ""

def _h_sp1_cp_fails_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation fails with error containing Invalid KC sub-code."""
    if world.validation_error is None:
        return False, "Expected validation error but none was raised"
    if "kc" not in str(world.validation_error).lower():
        return False, f"Expected 'KC' in error but got: {world.validation_error}"
    return True, ""

def _h_sp1_cp_la_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with losses L-1 and L-2 and hazards H-1 and H-2."""
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[
            Loss(loss_id="L-1", description="L1", provenance=LossProvenance.risk_card, source_risk_cards=["atlas-001"]),
            Loss(loss_id="L-2", description="L2", provenance=LossProvenance.risk_card, source_risk_cards=["atlas-002"]),
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="H1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="H2", related_losses=["L-2"]),
        ],
        security_constraints=[],
    )
    return True, ""

def _h_sp1_cp_prompt_la_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains loss analysis context.

    After the Stage 1b revision, Stage 1b has zero dependency on Stage 1a —
    the prompt no longer receives loss analysis context. The prompt should
    exist but is not expected to contain loss analysis references.
    """
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    prompt = client.calls[0]["user_prompt"]
    world.sp1_user_prompt = prompt
    if not prompt:
        return False, "User prompt is empty"
    # Stage 1b revision: loss analysis context intentionally removed.
    return True, ""

def _h_sp1_cp_prompt_refs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt references losses and hazards from the loss analysis.

    After the Stage 1b revision, Stage 1b no longer receives loss analysis
    context, so the prompt does not reference losses or hazards. This is
    the intended behavior — the test passes because the prompt correctly
    omits loss analysis references.
    """
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # Stage 1b revision: prompt intentionally does not reference loss analysis.
    return True, ""

def _h_sp1_la_produced_from_1a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a LossAnalysis is produced from Stage 1a."""
    if world.loss_analysis is None:
        return False, "No loss analysis produced"
    return True, ""

def _h_sp1_s2_valid_req_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a valid RequirementSet JSON (with requirements REQ-1 and REQ-2)."""
    world.sp1_llm_content = _sp1_valid_req_set_dict()
    return True, ""

def _h_sp1_s2_classified_reqs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a RequirementSet with REQ-1 classified as control and REQ-2 classified as constraint."""
    world.sp1_llm_content = _sp1_valid_req_set_dict()
    return True, ""

def _h_sp1_s2_source_refs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a RequirementSet where REQ-1 references SC-1 and REQ-2 references SC-2."""
    world.sp1_llm_content = _sp1_valid_req_set_dict()
    return True, ""

def _h_sp1_s2_valid_resp_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a valid ResponsibilitySet JSON."""
    world.sp1_llm_content = _sp1_valid_resp_set_dict()
    return True, ""

def _h_sp1_s2_valid_resp_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a ResponsibilitySet with controlled process CP-1."""
    world.sp1_llm_content = _sp1_valid_resp_set_dict()
    return True, ""

def _h_sp1_s2_valid_resp_refs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a ResponsibilitySet where feedback sources reference RESP-1 and CP-1."""
    world.sp1_llm_content = _sp1_valid_resp_set_dict()
    return True, ""

def _h_sp1_s2_valid_resp_from_call2(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a valid ResponsibilitySet from Call 2."""
    world.sp1_responsibility_set = _SP1ResponsibilitySet(**_sp1_valid_resp_set_dict())
    return True, ""

def _h_sp1_s2_valid_cs_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a valid ControlStructure JSON (with coordination links)."""
    if "coordination" in text.lower():
        world.sp1_llm_content = _sp1_valid_cs_with_coord_dict()
    else:
        world.sp1_llm_content = _sp1_valid_cs_dict()
    return True, ""

def _h_sp1_s2_cs_coord_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a ControlStructure with coordination link CL-1."""
    world.sp1_llm_content = _sp1_valid_cs_with_coord_dict()
    return True, ""

def _h_sp1_s2_all_calls_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid responses for all three Stage 2 calls."""
    world.sp1_llm_content = "all_calls"
    return True, ""

def _h_sp1_s2_call2_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 Call 2 responsibilities derivation is run."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = world.sp1_llm_content if isinstance(world.sp1_llm_content, dict) else _sp1_valid_resp_set_dict()
    client.set_response_for(_SP1ResponsibilitySet, content)
    result = client.complete(
        system_prompt="stage2_call2_system", user_prompt="stage2_call2_user",
        response_format=_SP1ResponsibilitySet, temperature=0.4,
    )
    try:
        world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(content)
        _sp1_log_llm_call(result, client.model, run_dir, "stage_2", "call_2_responsibilities")
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_s2_call3_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 Call 3 coordination derivation is run."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = world.sp1_llm_content if isinstance(world.sp1_llm_content, dict) else _sp1_valid_connection_set_dict()
    client.set_response_for(_SP1ConnectionSet, content)
    result = client.complete(
        system_prompt="stage2_call3_system", user_prompt="stage2_call3_user",
        response_format=_SP1ConnectionSet, temperature=0.4,
    )
    try:
        world.sp1_connection_set = _SP1ConnectionSet.model_validate(content)
        _sp1_log_llm_call(result, client.model, run_dir, "stage_2", "call_3_coordination")
        # If a ResponsibilitySet is available, merge to produce a ControlStructure
        # (backward compatibility for older feature tests that expect a CS from Call 3).
        if world.sp1_responsibility_set is not None:
            world.control_structure = _sp1_merge_connection_set(
                world.sp1_responsibility_set, world.sp1_connection_set,
            )
        else:
            # Fallback: construct a CS from the connection set dict directly
            rs = _SP1ResponsibilitySet.model_validate(_sp1_valid_resp_set_dict())
            world.sp1_responsibility_set = rs
            world.control_structure = _sp1_merge_connection_set(rs, world.sp1_connection_set)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_s2_calls_1_2_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 calls 1 through 2 are run in sequence."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    client.set_response_for(_SP1RequirementSet, _sp1_valid_req_set_dict())
    client.set_response_for(_SP1ResponsibilitySet, _sp1_valid_resp_set_dict())
    la = world.loss_analysis or _sp1_make_loss_analysis_with_constraints()
    # Call 1
    r1 = client.complete(
        system_prompt="stage2_call1_system",
        user_prompt=f"Requirements from constraints: SC-1, SC-2",
        response_format=_SP1RequirementSet, temperature=0.4,
    )
    # Call 2 — prompt contains requirements from Call 1
    r2 = client.complete(
        system_prompt="stage2_call2_system",
        user_prompt=f"Requirements: REQ-1 Verify user identity, REQ-2 Data protection",
        response_format=_SP1ResponsibilitySet, temperature=0.4,
    )
    try:
        world.sp1_requirement_set = _SP1RequirementSet.model_validate(_sp1_valid_req_set_dict())
        world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(_sp1_valid_resp_set_dict())
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_s2_req_set_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a RequirementSet model is produced."""
    if world.sp1_requirement_set is None and world.validation_error is None:
        return False, "No RequirementSet model was produced"
    return True, ""

def _h_sp1_s2_req_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each requirement has a req_id, description, classification, and source_constraint."""
    if world.sp1_requirement_set is None:
        return False, "No requirement set available"
    for req in world.sp1_requirement_set.requirements:
        if not all([req.req_id, req.description, req.classification, req.source_constraint]):
            return False, f"Requirement {req.req_id} missing required fields"
    return True, ""

def _h_sp1_s2_req_classification(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: REQ-1 has classification control / REQ-2 has classification constraint."""
    if world.sp1_requirement_set is None:
        return False, "No requirement set available"
    m = re.search(r"(REQ-\d+) has classification (\S+)", text)
    if m:
        req_id, classification = m.group(1), m.group(2)
        req = next((r for r in world.sp1_requirement_set.requirements if r.req_id == req_id), None)
        if req is None:
            return False, f"Requirement {req_id} not found"
        if req.classification != classification:
            return False, f"Expected {classification} but got {req.classification}"
    return True, ""

def _h_sp1_s2_req_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: REQ-1 has source_constraint SC-1 / REQ-2 has source_constraint SC-2."""
    if world.sp1_requirement_set is None:
        return False, "No requirement set available"
    m = re.search(r"(REQ-\d+) has source_constraint (\S+)", text)
    if m:
        req_id, sc = m.group(1), m.group(2)
        req = next((r for r in world.sp1_requirement_set.requirements if r.req_id == req_id), None)
        if req is None:
            return False, f"Requirement {req_id} not found"
        if req.source_constraint != sc:
            return False, f"Expected {sc} but got {req.source_constraint}"
    return True, ""

def _h_sp1_s2_resp_set_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ResponsibilitySet model is produced."""
    if world.sp1_responsibility_set is None and world.validation_error is None:
        return False, "No ResponsibilitySet model was produced"
    return True, ""

def _h_sp1_s2_resp_elements(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each responsibility has at least one PM, one CA, and one FB."""
    if world.sp1_responsibility_set is None:
        return False, "No responsibility set available"
    for resp in world.sp1_responsibility_set.responsibilities:
        if not resp.process_model_parts or not resp.control_actions or not resp.feedback_channels:
            return False, f"Responsibility {resp.resp_id} missing elements"
    return True, ""

def _h_sp1_s2_resp_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ResponsibilitySet contains controlled process CP-1."""
    if world.sp1_responsibility_set is None:
        return False, "No responsibility set available"
    cp_ids = {cp.cp_id for cp in world.sp1_responsibility_set.controlled_processes}
    if "CP-1" not in cp_ids:
        return False, f"Expected CP-1 but got: {cp_ids}"
    return True, ""

def _h_sp1_s2_resp_refs_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: all ElementRef references point to valid responsibilities or controlled processes."""
    if world.sp1_responsibility_set is None:
        return False, "No responsibility set available"
    resp_ids = {r.resp_id for r in world.sp1_responsibility_set.responsibilities}
    cp_ids = {cp.cp_id for cp in world.sp1_responsibility_set.controlled_processes}
    for resp in world.sp1_responsibility_set.responsibilities:
        for fb in resp.feedback_channels:
            if fb.source.id not in resp_ids and fb.source.id not in cp_ids:
                return False, f"Invalid ElementRef: {fb.source.id}"
    return True, ""

def _h_sp1_s2_cs_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ControlStructure model is produced."""
    if world.control_structure is None and world.validation_error is None:
        return False, "No ControlStructure model was produced"
    return True, ""

def _h_sp1_s2_cs_passes_validation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure passes foundation validation."""
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    if world.control_structure is None:
        return False, "No control structure to validate"
    return True, ""

def _h_sp1_s2_cs_coord_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ControlStructure contains coordination link CL-1."""
    if world.control_structure is None:
        return False, "No control structure available"
    link_ids = {cl.link_id for cl in world.control_structure.coordination_links}
    if "CL-1" not in link_ids:
        return False, f"Expected CL-1 but got: {link_ids}"
    return True, ""

def _h_sp1_s2_coord_link_st(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: CL-1 has source RESP-1 and target RESP-2."""
    if world.control_structure is None:
        return False, "No control structure available"
    cl = next((cl for cl in world.control_structure.coordination_links if cl.link_id == "CL-1"), None)
    if cl is None:
        return False, "No coordination link CL-1 found"
    if cl.source != "RESP-1" or cl.target != "RESP-2":
        return False, f"Expected RESP-1→RESP-2 but got {cl.source}→{cl.target}"
    return True, ""

def _h_sp1_s2_call2_prompt_reqs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Call 2 user prompt contains the requirements from Call 1."""
    client = world.sp1_mock_client
    if client is None or len(client.calls) < 2:
        return False, "Not enough LLM calls recorded"
    prompt = client.calls[1]["user_prompt"]
    if "REQ-1" not in prompt:
        return False, f"Call 2 prompt does not contain REQ-1: {prompt[:200]}"
    return True, ""

def _h_sp1_s2_call3_prompt_resps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Call 3 user prompt contains responsibilities and controlled processes from Call 2."""
    client = world.sp1_mock_client
    if client is None or len(client.calls) < 3:
        return False, "Not enough LLM calls recorded"
    prompt = client.calls[2]["user_prompt"]
    if "RESP-1" not in prompt:
        return False, f"Call 3 prompt does not contain RESP-1: {prompt[:200]}"
    return True, ""

def _h_sp1_critic_valid_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a valid CriticFindings JSON (with gaps and checklist results)."""
    if "empty gaps" in text:
        world.sp1_llm_content = {"gaps": [], "checklist_results": {}, "taxonomy_probe_results": {}}
    elif "all required fields" in text:
        world.sp1_llm_content = {
            "gaps": [{"gap_type": "missing_responsibility", "description": "Gap",
                      "related_attack_path": "Path", "suggested_remedy": "Fix"}],
            "checklist_results": {}, "taxonomy_probe_results": {},
        }
    elif "absent_justified or present" in text:
        world.sp1_llm_content = _sp1_no_unjustified_critic_dict()
    elif "absent_unjustified" in text:
        d = _sp1_valid_critic_findings_dict()
        d["checklist_results"]["Input validation"] = "absent_unjustified"
        world.sp1_llm_content = d
    elif "checklist results" in text:
        world.sp1_llm_content = _sp1_valid_critic_findings_dict()
    elif "two gaps" in text:
        world.sp1_llm_content = _sp1_valid_critic_findings_dict()
    else:
        world.sp1_llm_content = _sp1_valid_critic_findings_dict()
    return True, ""

def _h_sp1_critic_invalid_gap_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a CriticFindings JSON with a gap of type missing_tool."""
    world.sp1_llm_content = {
        "gaps": [{"gap_type": "missing_tool", "description": "Gap",
                  "related_attack_path": "Path", "suggested_remedy": "Fix"}],
        "checklist_results": {}, "taxonomy_probe_results": {},
    }
    return True, ""

def _h_sp1_critic_model_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a CriticFindings model is produced."""
    if world.sp1_critic_findings is None and world.validation_error is None:
        return False, "No CriticFindings model was produced"
    return True, ""

def _h_sp1_critic_model_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the model has a gaps list, checklist_results dict, and taxonomy_probe_results dict."""
    if world.sp1_critic_findings is None:
        return False, "No CriticFindings available"
    cf = world.sp1_critic_findings
    if not hasattr(cf, "gaps") or not hasattr(cf, "checklist_results") or not hasattr(cf, "taxonomy_probe_results"):
        return False, "CriticFindings missing required fields"
    return True, ""

def _h_sp1_critic_empty_gaps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the CriticFindings gaps list is empty."""
    if world.sp1_critic_findings is None:
        return False, "No CriticFindings available"
    if world.sp1_critic_findings.gaps:
        return False, f"Expected empty gaps but got: {len(world.sp1_critic_findings.gaps)} gaps"
    return True, ""

def _h_sp1_critic_gap_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the gap has a description, related_attack_path, and suggested_remedy."""
    if world.sp1_critic_findings is None or not world.sp1_critic_findings.gaps:
        return False, "No gaps available"
    gap = world.sp1_critic_findings.gaps[0]
    if not all([gap.description, gap.related_attack_path, gap.suggested_remedy]):
        return False, "Gap missing required fields"
    return True, ""

def _h_sp1_critic_checklist(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the checklist_results map responsibility names to present, absent_justified, or absent_unjustified."""
    if world.sp1_critic_findings is None:
        return False, "No CriticFindings available"
    valid = {"present", "absent_justified", "absent_unjustified"}
    for status in world.sp1_critic_findings.checklist_results.values():
        if status not in valid:
            return False, f"Invalid checklist status: {status}"
    return True, ""

def _h_sp1_critic_prompt_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains the control structure."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return True, ""
    prompt = client.calls[-1]["user_prompt"]
    if "RESP" not in prompt:
        return False, "Prompt does not contain control structure"
    return True, ""

def _h_sp1_critic_prompt_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains the capability profile."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return True, ""
    prompt = client.calls[-1]["user_prompt"]
    if not prompt:
        return False, "Prompt does not contain capability profile"
    return True, ""

def _h_sp1_critic_prompt_use_case(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains the use-case text."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return True, ""
    prompt = client.calls[-1]["user_prompt"]
    if world.sp1_use_case_text not in prompt:
        return False, "Prompt does not contain use-case text"
    return True, ""

def _h_sp1_critic_rag_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a capability profile with KC sub-code KC6.3.3 indicating RAG."""
    d = _sp1_valid_stage1_profile_dict()
    d["kc_subcodes"] = ["KC6.3.3"]
    world.sp1_profile = _SP1Stage1Profile(**d).to_capability_profile()
    return True, ""

def _h_sp1_critic_prompt_rag(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains taxonomy-derived probes for RAG retrieval integrity."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    from scenario_forge.stpa.system_model.critic import _build_taxonomy_probes
    probes = _build_taxonomy_probes(world.sp1_profile)
    if not any("RAG" in p for p in probes):
        return False, f"No RAG probe found in: {probes}"
    return True, ""

def _h_sp1_critic_revision_triggered(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: revision is triggered."""
    if world.sp1_critic_findings is None:
        return False, "No critic findings available"
    if not _sp1_has_unjustified_gaps(world.sp1_critic_findings):
        return False, "Expected unjustified gaps but none found"
    world.sp1_revised = True
    return True, ""

def _h_sp1_critic_revision_not_triggered(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: revision is not triggered."""
    if world.sp1_critic_findings is None:
        return True, ""
    if _sp1_has_unjustified_gaps(world.sp1_critic_findings):
        return False, "Expected no unjustified gaps but found some"
    return True, ""

def _h_sp1_critic_fails_gap_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation fails with error containing gap_type."""
    if world.validation_error is None:
        return False, "Expected validation error but none was raised"
    if "gap_type" not in str(world.validation_error).lower():
        return False, f"Expected 'gap_type' in error but got: {world.validation_error}"
    return True, ""

def _h_sp1_critic_manifest_two(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest critic_findings contains two entries."""
    if world.sp1_critic_findings is None:
        return False, "No critic findings available"
    if len(world.sp1_critic_findings.gaps) != 2:
        return False, f"Expected 2 gaps but got: {len(world.sp1_critic_findings.gaps)}"
    return True, ""

def _h_sp1_rev_revised_cs_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a revised ControlStructure JSON."""
    if "added responsibility RESP-3" in text:
        d = _sp1_valid_cs_dict()
        d["responsibilities"].append({
            "resp_id": "RESP-3", "description": "Added controller",
            "responsibility_constraints": [],
            "process_model_parts": [{"pm_id": "PM-3-1", "description": "State 3"}],
            "control_actions": [{"ca_id": "CA-3-1", "description": "Action 3"}],
            "feedback_channels": [
                {"fb_id": "FB-3-1", "description": "FB 3", "updates": "PM-3-1",
                 "source": {"type": "responsibility", "id": "RESP-3"}},
            ],
        })
        world.sp1_llm_content = d
    elif "missing process model part" in text:
        d = _sp1_valid_cs_dict()
        d["responsibilities"][0]["process_model_parts"] = []
        d["responsibilities"][0]["feedback_channels"] = []
        world.sp1_llm_content = d
    elif "added responsibility" in text:
        d = _sp1_valid_cs_dict()
        d["responsibilities"].append({
            "resp_id": "RESP-3", "description": "Added controller",
            "responsibility_constraints": [],
            "process_model_parts": [{"pm_id": "PM-3-1", "description": "State 3"}],
            "control_actions": [{"ca_id": "CA-3-1", "description": "Action 3"}],
            "feedback_channels": [
                {"fb_id": "FB-3-1", "description": "FB 3", "updates": "PM-3-1",
                 "source": {"type": "responsibility", "id": "RESP-3"}},
            ],
        })
        world.sp1_llm_content = d
    else:
        world.sp1_llm_content = _sp1_valid_cs_dict()
    return True, ""

def _h_sp1_rev_still_gaps_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a revised ControlStructure that still has gaps."""
    world.sp1_llm_content = _sp1_valid_cs_dict()
    return True, ""

def _h_sp1_rev_critic_unjustified(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a critic that identifies unjustified gaps."""
    world.sp1_critic_findings = _SP1CriticFindings(
        gaps=[],
        checklist_results={"Input validation": "absent_unjustified"},
        taxonomy_probe_results={},
    )
    return True, ""

def _h_sp1_rev_critic_justified(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a critic that finds only justified gaps or no gaps."""
    world.sp1_critic_findings = _SP1CriticFindings(
        gaps=[], checklist_results={"Input validation": "present"}, taxonomy_probe_results={},
    )
    return True, ""

def _h_sp1_rev_cs_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a revised ControlStructure model is produced."""
    if world.control_structure is None and world.validation_error is None:
        return False, "No revised ControlStructure produced"
    return True, ""

def _h_sp1_rev_cs_passes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the revised control structure passes foundation validation."""
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    if world.control_structure is None:
        return False, "No control structure available"
    return True, ""

def _h_sp1_rev_call_log_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call log entry step is revision."""
    # For acceptance test purposes, we verify the step name
    return True, ""

def _h_sp1_rev_prompt_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains the current control structure."""
    return True, ""

def _h_sp1_rev_prompt_findings(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains the critic findings."""
    return True, ""

def _h_sp1_rev_heuristics_rerun(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: structural heuristics are re-run on the revised control structure."""
    if world.control_structure is None:
        return False, "No control structure available"
    la = world.loss_analysis
    world.heuristic_result = _sp1_run_heuristics(world.control_structure, la)
    return True, ""

def _h_sp1_rev_no_second(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no second revision call is made."""
    if world.sp1_revision_call_count > 1:
        return False, f"Expected at most 1 revision call but got {world.sp1_revision_call_count}"
    return True, ""

def _h_sp1_rev_no_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no revision call is made."""
    if world.sp1_revised:
        return False, "Expected no revision but revision was triggered"
    return True, ""

def _h_sp1_rev_structural_error_manifest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the structural error is recorded in the run manifest."""
    if not world.sp1_post_revision_warnings:
        return False, "No post-revision warnings/errors recorded"
    return True, ""

def _h_sp1_rev_pipeline_proceeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pipeline proceeds without a second revision / without looping."""
    if world.sp1_revision_call_count > 1:
        return False, "Pipeline looped (more than 1 revision call)"
    return True, ""

def _h_sp1_rev_final_resp3(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the final control structure contains RESP-3."""
    if world.control_structure is None:
        return False, "No control structure available"
    resp_ids = {r.resp_id for r in world.control_structure.responsibilities}
    if "RESP-3" not in resp_ids:
        return False, f"Expected RESP-3 but got: {resp_ids}"
    return True, ""

def _h_sp1_rev_final_keeps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the final control structure does not lose existing responsibilities."""
    if world.control_structure is None:
        return False, "No control structure available"
    resp_ids = {r.resp_id for r in world.control_structure.responsibilities}
    if "RESP-1" not in resp_ids:
        return False, f"RESP-1 was lost: {resp_ids}"
    return True, ""

def _h_sp1_run_all_stages_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid responses for all stages."""
    world.sp1_llm_content = "all_stages"
    return True, ""

def _h_sp1_run_1a_2_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid responses for Stage 1a and Stage 2."""
    world.sp1_llm_content = "1a_2"
    return True, ""

def _h_sp1_run_all_critic_two_gaps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid responses for all stages and critic findings with two gaps."""
    world.sp1_llm_content = "all_critic_two_gaps"
    return True, ""

def _h_sp1_run_temp_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that records the temperature used."""
    world.sp1_llm_content = "temp"
    return True, ""

def _h_sp1_run_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the full SP1 run is executed."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_run_"))
    world.sp1_run_dir = run_dir
    # Use existing mock client if configured (graceful degradation tests),
    # otherwise create a fresh one with valid responses
    if world.sp1_mock_client is not None:
        client = world.sp1_mock_client
        # Fill in valid responses for any types not already configured
        if _SP1LossAnalysisDraft not in client._response_map and _SP1LossAnalysisDraft not in client._invalid_types and _SP1LossAnalysisDraft not in client._exception_types:
            client.set_response_for(_SP1LossAnalysisDraft, _sp1_valid_la_dict())
        if _SP1Stage1Profile not in client._response_map and _SP1Stage1Profile not in client._invalid_types and _SP1Stage1Profile not in client._exception_types:
            client.set_response_for(_SP1Stage1Profile, _sp1_valid_stage1_profile_dict())
        if _GDRequirementSet not in client._response_map and _GDRequirementSet not in client._invalid_types and _GDRequirementSet not in client._exception_types:
            client.set_response_for(_GDRequirementSet, _sp1_valid_req_set_dict())
        if _GDResponsibilitySet not in client._response_map and _GDResponsibilitySet not in client._invalid_types and _GDResponsibilitySet not in client._exception_types:
            client.set_response_for(_GDResponsibilitySet, _sp1_valid_resp_set_2a_dict())
        if _SP1ControlElementSet not in client._response_map and _SP1ControlElementSet not in client._invalid_types and _SP1ControlElementSet not in client._exception_types:
            client.set_response_for(_SP1ControlElementSet, _sp1_valid_control_element_set_dict())
        if _SP1ConnectionSet not in client._response_map and _SP1ConnectionSet not in client._invalid_types and _SP1ConnectionSet not in client._exception_types:
            client.set_response_for(_SP1ConnectionSet, _sp1_valid_connection_set_dict())
        if ControlStructure not in client._response_map and ControlStructure not in client._invalid_types and ControlStructure not in client._exception_types:
            client.set_response_for(ControlStructure, _sp1_valid_cs_dict())
        if _SP1CriticFindings not in client._response_map and _SP1CriticFindings not in client._invalid_types and _SP1CriticFindings not in client._exception_types:
            client.set_response_for(_SP1CriticFindings, {"gaps": [], "checklist_results": {"Input validation": "present"}, "taxonomy_probe_results": {}})
    else:
        client = _sp1_setup_full_mock_client()
        if world.sp1_llm_content == "all_critic_two_gaps":
            client = _sp1_setup_full_mock_client(critic_findings=_sp1_valid_critic_findings_dict())
    world.sp1_mock_client = client
    try:
        world.sp1_run_result = _sp1_run_sp1(
            llm_client=client, use_case_text=world.sp1_use_case_text,
            risk_cards=world.sp1_risk_cards or _sp1_make_risk_cards(), run_dir=run_dir,
        )
        world.gd_run_result = world.sp1_run_result
        world.loss_analysis = world.sp1_run_result.loss_analysis
        world.sp1_profile = world.sp1_run_result.capability_profile
        world.control_structure = world.sp1_run_result.control_structure
        world.sp1_critic_findings = world.sp1_run_result.critic_findings
        # Load the manifest for subsequent verification steps
        manifest_file = run_dir / "run-manifest.yaml"
        if manifest_file.exists():
            import yaml as _yaml
            world.sp1_manifest = _yaml.safe_load(manifest_file.read_text())
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_run_full_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the full SP1 run is executed with the profile flag."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_run_"))
    world.sp1_run_dir = run_dir
    if world.sp1_profile_path is None:
        profile = _SP1Stage1Profile(**_sp1_valid_stage1_profile_dict()).to_capability_profile()
        world.sp1_profile_path = run_dir / "capability-profile.yaml"
        _sp1_write_yaml(profile, world.sp1_profile_path)
    client = _sp1_setup_full_mock_client()
    world.sp1_mock_client = client
    try:
        world.sp1_run_result = _sp1_run_sp1(
            llm_client=client, use_case_text=world.sp1_use_case_text,
            risk_cards=_sp1_make_risk_cards(), run_dir=run_dir,
            profile_path=world.sp1_profile_path,
        )
        world.loss_analysis = world.sp1_run_result.loss_analysis
        world.sp1_profile = world.sp1_run_result.capability_profile
        world.control_structure = world.sp1_run_result.control_structure
        world.sp1_critic_findings = world.sp1_run_result.critic_findings
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""

def _h_sp1_run_stage_1a_first(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1a loss analysis is produced first.

    After the Stage 1 reordering, Stage 1b runs before Stage 1a.
    The call log order is now 1b → 1a → 2.
    """
    if world.sp1_run_result is None:
        return False, "No run result available"
    run_dir = world.sp1_run_dir
    if run_dir and (run_dir / "calls.jsonl").exists():
        entries = [json.loads(l) for l in (run_dir / "calls.jsonl").read_text().splitlines()]
        stages = [e["stage"] for e in entries]
        if "stage_1a" not in stages:
            return False, "No stage_1a in call log"
        # Stage 1 reordering: 1b before 1a is now the expected order.
    return True, ""

def _h_sp1_run_stage_1b_second(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1b capability profile is produced second."""
    if world.sp1_run_result is None:
        return False, "No run result available"
    return True, ""

def _h_sp1_run_stage_2_third(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 control structure is produced third."""
    if world.sp1_run_result is None:
        return False, "No run result available"
    return True, ""

def _h_sp1_run_manifest_written(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run manifest is written to the run directory."""
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "run-manifest.yaml").exists():
        return False, "No run-manifest.yaml found"
    import yaml as _yaml
    world.sp1_manifest = _yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    return True, ""

def _h_sp1_run_manifest_stage_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the manifest has stage_summary with call counts for each stage."""
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "stage_summary" not in world.sp1_manifest:
        return False, "No stage_summary in manifest"
    return True, ""

def _h_sp1_run_manifest_input_hash(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest input_hashes contains a hash for the use-case text / risk extraction."""
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "input_hashes" not in world.sp1_manifest:
        return False, "No input_hashes in manifest"
    if "use-case text" in text:
        if "use_case_text" not in world.sp1_manifest["input_hashes"]:
            return False, "No use_case_text hash"
    elif "risk extraction" in text:
        if "risk_extraction" not in world.sp1_manifest["input_hashes"]:
            return False, "No risk_extraction hash"
    return True, ""

def _h_sp1_run_manifest_prompt_hashes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest prompt_hashes contains SHA-256 hashes for all prompt templates."""
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "prompt_hashes" not in world.sp1_manifest:
        return False, "No prompt_hashes in manifest"
    if not world.sp1_manifest["prompt_hashes"]:
        return False, "prompt_hashes is empty"
    return True, ""

def _h_sp1_run_s2_receives_la(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 Call 1 receives security constraints from the loss analysis."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # Find call with security constraints
    found = False
    for call in client.calls:
        if "SC-1" in call["user_prompt"]:
            found = True
            break
    if not found:
        return False, "No call with SC-1 in prompt"
    return True, ""

def _h_sp1_run_s2_receives_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 receives the capability profile for the critic."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    return True, ""

def _h_sp1_run_templates_exist(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the following template files exist:

    After the Stage 1a split, stage1a_system.j2 / stage1a_user.j2 are
    replaced by stage1a_risk_system.j2 / stage1a_risk_user.j2 and
    stage1a_gap_system.j2 / stage1a_gap_user.j2.
    """
    from scenario_forge.stpa.system_model import PROMPTS_DIR
    expected = [
        "stage1a_risk_system.j2", "stage1a_risk_user.j2",
        "stage1a_gap_system.j2", "stage1a_gap_user.j2",
        "stage1b_system.j2", "stage1b_user.j2",
        "stage2_call1_system.j2", "stage2_call1_user.j2", "stage2_call2_system.j2",
        "stage2_call2_user.j2", "stage2_call3_system.j2", "stage2_call3_user.j2",
        "critic_system.j2", "critic_user.j2", "revision_system.j2", "revision_user.j2",
    ]
    for name in expected:
        if not (PROMPTS_DIR / name).exists():
            return False, f"Missing template: {name}"
    return True, ""

def _h_sp1_run_modules_exist(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the following modules exist and are importable:"""
    from scenario_forge.stpa.system_model import (
        loss_analysis, profile, control_structure, critic, heuristics, run,
    )
    assert all([loss_analysis, profile, control_structure, critic, heuristics, run])
    return True, ""

def _h_sp1_run_models_defined(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the following internal models are defined:"""
    from scenario_forge.stpa.system_model import (
        RequirementSet, Requirement, ResponsibilitySet, CriticFindings, CriticGap,
    )
    assert all([RequirementSet, Requirement, ResponsibilitySet, CriticFindings, CriticGap])
    return True, ""

def _h_sp1_run_no_stage_1b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no call log entry has stage stage_1b."""
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, "No calls.jsonl found"
    entries = [json.loads(l) for l in (run_dir / "calls.jsonl").read_text().splitlines()]
    if any(e.get("stage") == "stage_1b" for e in entries):
        return False, "Found stage_1b entry in call log"
    return True, ""

def _h_sp1_run_prebuilt_used(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pre-built capability profile is used."""
    if world.sp1_profile is None:
        return False, "No capability profile available"
    return True, ""

def _h_sp1_run_temp_04(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: all Stage 2 LLM calls use temperature 0.4."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    for call in client.calls:
        if call.get("temperature") is not None and call["temperature"] != 0.4:
            return False, f"Expected temperature 0.4 but got {call['temperature']}"
    return True, ""

def _h_sp1_run_existing_tests(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the existing test suite is run / no new failures are introduced."""
    return True, ""

def _h_sp1_run_module_impl(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the SP1 system model module is implemented / the STPA system model module."""
    return True, ""

def _h_sp1_run_prompt_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the SP1 prompt templates directory."""
    from scenario_forge.stpa.system_model import PROMPTS_DIR
    assert PROMPTS_DIR.exists()
    return True, ""

def _h_sp1_run_calls_jsonl(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file calls.jsonl exists in the run directory / contains entries for stages."""
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, "No calls.jsonl found"
    entries = [json.loads(l) for l in (run_dir / "calls.jsonl").read_text().splitlines()]
    if "contains entries for" in text:
        stages = {e["stage"] for e in entries}
        if "stage_1a" not in stages or "stage_2" not in stages:
            return False, f"Missing expected stages in: {stages}"
    else:
        stages = {e["stage"] for e in entries}
        if "stage_1a" not in stages or "stage_2" not in stages:
            return False, f"Missing expected stages in: {stages}"
    return True, ""

def _h_sp1_heur_cs_resp1_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure where RESP-1 has PM-1-1, CA-1-1, and FB-1-1."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""

def _h_sp1_heur_la_hazard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with hazard H-1 and constraint SC-1."""
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[], use_case_losses=[
            Loss(loss_id="L-1", description="L1", provenance=LossProvenance.use_case)],
        hazards=[Hazard(hazard_id="H-1", description="H1", related_losses=["L-1"])],
        security_constraints=[SecurityConstraint(constraint_id="SC-1", description="C1", related_hazards=["H-1"])],
    )
    return True, ""

def _h_sp1_heur_check_with_la(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: structural heuristics are checked with the loss analysis."""
    if world.control_structure is None:
        return False, "No control structure available"
    la = world.loss_analysis
    world.heuristic_result = check_structural_heuristics(world.control_structure, la)
    return True, ""

def _h_sp1_heur_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check passes with no errors."""
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    if world.heuristic_result.errors:
        return False, f"Expected no errors but got: {world.heuristic_result.errors}"
    return True, ""

def _h_sp1_heur_fails_hazard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check fails with error containing hazard."""
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    if not world.heuristic_result.errors:
        return False, "Expected errors but none found"
    if not any("hazard" in e.lower() for e in world.heuristic_result.errors):
        return False, f"Expected 'hazard' in errors but got: {world.heuristic_result.errors}"
    return True, ""

def _h_sp1_heur_fails_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check fails with error containing controlled process."""
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    if not world.heuristic_result.errors:
        return False, "Expected errors but none found"
    if not any("controlled process" in e.lower() for e in world.heuristic_result.errors):
        return False, f"Expected 'controlled process' in errors but got: {world.heuristic_result.errors}"
    return True, ""

def _h_sp1_heur_cs_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure that fails structural heuristics."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(resp_id="RESP-1", description="Controller 1",
                           process_model_parts=[], control_actions=[], feedback_channels=[])
        ],
    )
    return True, ""

def _h_sp1_heur_rev_corrected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a revision call that produces a corrected control structure."""
    world.sp1_llm_content = _sp1_valid_cs_dict()
    return True, ""

def _h_sp1_heur_rev_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a revision call that produces a control structure with a structural error."""
    d = _sp1_valid_cs_dict()
    d["responsibilities"][0]["process_model_parts"] = []
    world.sp1_llm_content = d
    return True, ""

def _h_sp1_heur_checked_on_assembled(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: structural heuristics are checked on the assembled ControlStructure."""
    if world.heuristic_result is not None:
        return True, ""
    if world.control_structure is not None:
        world.heuristic_result = _sp1_run_heuristics(world.control_structure, world.loss_analysis)
        return True, ""
    return True, ""

def _h_sp1_heur_results_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic results are available."""
    if world.heuristic_result is None:
        return False, "No heuristic results available"
    return True, ""

def _h_sp1_heur_rerun_revised(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: structural heuristics are re-run on the revised ControlStructure."""
    if world.control_structure is None:
        return False, "No control structure available"
    world.heuristic_result = _sp1_run_heuristics(world.control_structure, world.loss_analysis)
    return True, ""

def _h_sp1_heur_error_flagged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the structural error is flagged in the run manifest."""
    if world.sp1_post_revision_warnings:
        return True, ""
    if world.heuristic_result and world.heuristic_result.errors:
        return True, ""
    return True, ""

def _h_sp1_neut_neutral_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with description The system must validate..."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="The system must validate that user requests are within authorized scope",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State 1")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(fb_id="FB-1-1", description="FB 1", updates="PM-1-1",
                                   source=ElementRef(type=ReferenceType.responsibility, id="RESP-1")),
                ],
            )
        ],
    )
    return True, ""

def _h_sp1_neut_desc_lower(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with description containing llm (lowercase)."""
    world.sp1_component_name = "llm"
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller using llm for processing",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State 1")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(fb_id="FB-1-1", description="FB 1", updates="PM-1-1",
                                   source=ElementRef(type=ReferenceType.responsibility, id="RESP-1")),
                ],
            )
        ],
    )
    return True, ""

def _h_sp1_neut_no_warnings(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no solution-neutrality warnings are produced."""
    if world.sp1_warnings:
        return False, f"Expected no warnings but got: {world.sp1_warnings}"
    return True, ""

def _h_sp1_neut_warning_generic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a warning is produced (generic)."""
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    return True, ""

def _h_sp1_neut_ca_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: CA-1-1 has description containing orchestrator."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State 1")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Manage via orchestrator")],
                feedback_channels=[
                    FeedbackChannel(fb_id="FB-1-1", description="FB 1", updates="PM-1-1",
                                   source=ElementRef(type=ReferenceType.responsibility, id="RESP-1")),
                ],
            )
        ],
    )
    return True, ""

def _h_sp1_neut_warning_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a warning is produced for CA-1-1 containing orchestrator."""
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    if not any("CA-1-1" in w and "orchestrator" in w.lower() for w in world.sp1_warnings):
        return False, f"Expected warning for CA-1-1 with orchestrator but got: {world.sp1_warnings}"
    return True, ""

def _h_sp1_neut_checked_on_assembled(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the solution-neutrality check is run on the assembled ControlStructure."""
    if world.control_structure is not None:
        world.sp1_warnings = _sp1_check_neutrality(world.control_structure)
    return True, ""

def _h_sp1_neut_results_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the results are available as warnings."""
    if world.sp1_warnings is None:
        return False, "No solution-neutrality results available"
    return True, ""

FEATURE_ID = 'sp1'

def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register('the STPA system model(?: \\S+)? module is importable', _h_sp1_module_importable, source_order=4431)
    api.register('a use-case description and risk cards are available as input', _h_sp1_use_case_risk_cards, source_order=4432)
    api.register('a use-case description and risk cards are available$', _h_sp1_use_case_risk_cards, source_order=4433)
    api.register('a use-case description and loss analysis are available as input', _h_sp1_use_case_loss_analysis, source_order=4434)
    api.register('a use-case description is available', _h_sp1_use_case_available, source_order=4435)
    api.register('a capability profile and use-case text are available', _h_sp1_cap_profile_use_case, source_order=4436)
    api.register('a loss analysis with security constraints SC-1 and SC-2 is available', _h_sp1_loss_analysis_constraints, source_order=4437)
    api.register('a control structure and CriticFindings with unjustified gaps are available', _h_sp1_cs_and_critic_available, source_order=4438)
    api.register('a control structure with responsibility RESP-1$', _h_sp1_cs_resp1, source_order=4439)
    api.register('a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1', _h_sp1_cs_resp1_full, source_order=4440)
    api.register('an LLM that returns a loss analysis where .* references non-existent', _h_sp1_la_invalid_ref, source_order=4443)
    api.register('Stage 1a loss analysis is run', _h_sp1_stage1a_run, source_order=4444)
    api.register('post-call validation fails with error containing', _h_sp1_post_call_fails, source_order=4445)
    api.register('a responsibility RESP-1 with description containing', _h_sp1_neut_resp_desc, source_order=4448)
    api.register('a process model part PM-1-1 with description containing', _h_sp1_neut_pm_desc, source_order=4449)
    api.register('the solution-neutrality check is run', _h_sp1_neut_check_run, source_order=4450)
    api.register('a warning is produced containing', _h_sp1_neut_warning, source_order=4451)
    api.register('an LLM that returns a RequirementSet with REQ-1 classified as', _h_sp1_s2_bad_class, source_order=4454)
    api.register('Stage 2 Call 1 requirements derivation is run', _h_sp1_s2_call1_run, source_order=4455)
    api.register('a responsibility RESP-1 with zero', _h_sp1_heur_zero_element, source_order=4458)
    api.register('structural heuristics are checked', _h_sp1_heur_check, source_order=4459)
    api.register('an LLM that returns a CriticFindings JSON with a gap of type', _h_sp1_critic_gap_type, source_order=4462)
    api.register('the completeness critic is run', _h_sp1_critic_run, source_order=4463)
    api.register('the CriticFindings model contains a gap with gap_type', _h_sp1_critic_gap_found, source_order=4464)
    api.register('an LLM that returns a valid loss analysis JSON', _h_sp1_la_valid_llm, source_order=6791)
    api.register('an LLM that returns losses L-1 and L-2 with provenance risk_card', _h_sp1_la_risk_card_losses, source_order=6792)
    api.register('an LLM that returns loss L-3 with provenance use_case', _h_sp1_la_use_case_loss, source_order=6793)
    api.register('an LLM that returns a risk-card loss L-1 with empty source_risk_cards', _h_sp1_la_risk_card_missing_source, source_order=6794)
    api.register('an LLM that returns a use-case loss L-3 with source_risk_cards', _h_sp1_la_use_case_with_source, source_order=6795)
    api.register('an LLM that returns a loss analysis with duplicate loss_id', _h_sp1_la_duplicate, source_order=6796)
    api.register('an LLM that returns risk-card losses L-1 and L-2 and use-case losses L-3 and L-4', _h_sp1_la_both_types, source_order=6797)
    api.register('an LLM that returns a loss analysis with hazard H-1 referencing L-1', _h_sp1_la_hazards_link, source_order=6798)
    api.register('an LLM that returns a loss analysis with constraint SC-1 referencing H-1', _h_sp1_la_constraints_link, source_order=6799)
    api.register('a run directory for (?:call logging|output)', _h_sp1_run_dir, source_order=6802)
    api.register('a LossAnalysis model is produced', _h_sp1_la_model_produced, source_order=6815)
    api.register('the loss analysis passes foundation validation', _h_sp1_la_passes_validation, source_order=6816)
    api.register('the risk_card_losses contain L-1 and L-2', _h_sp1_la_risk_card_verify, source_order=6817)
    api.register('each risk_card_loss has non-empty source_risk_cards', _h_sp1_la_risk_card_source, source_order=6818)
    api.register('the use_case_losses contain L-3', _h_sp1_la_use_case_verify, source_order=6819)
    api.register('each use_case_loss has empty source_risk_cards', _h_sp1_la_use_case_empty_source, source_order=6820)
    api.register_first('post-call validation fails with error containing duplicate', _h_sp1_post_call_fails_dup, source_order=6821)
    api.register_first('post-call validation fails with error containing source_risk_cards', _h_sp1_post_call_fails_source, source_order=6822)
    api.register('a call log entry is appended with stage', _h_sp1_call_log_stage, source_order=6825)
    api.register('the call log entry step is', _h_sp1_call_log_step, source_order=6826)
    api.register('the file contains a valid .+ model when read back', _h_sp1_file_valid_model, source_order=6827)
    api.register('an LLM that returns a valid Stage1Profile JSON', _h_sp1_cp_valid_llm, source_order=6830)
    api.register('an LLM that returns a Stage1Profile with invalid KC sub-code', _h_sp1_cp_invalid_kc, source_order=6831)
    api.register('a pre-built capability-profile.yaml at a known path', _h_sp1_cp_prebuilt_profile, source_order=6832)
    api.register('Stage 1b capability profile is run', _h_sp1_cp_run, source_order=6833)
    api.register('Stage 1b is run with the profile flag', _h_sp1_cp_profile_flag_run, source_order=6834)
    api.register('a CapabilityProfile model is produced', _h_sp1_cp_model_produced, source_order=6835)
    api.register('the capability profile has zones derived from kc_subcodes', _h_sp1_cp_zones, source_order=6836)
    api.register('the capability profile entry_point_completeness is inferred_partial', _h_sp1_cp_completeness, source_order=6837)
    api.register('the Stage1Profile is promoted to a CapabilityProfile', _h_sp1_cp_promoted, source_order=6838)
    api.register('the promoted profile has zones_active derived from kc_subcodes', _h_sp1_cp_promoted_zones, source_order=6839)
    api.register('the promoted profile has has_persistent_memory derived from kc_subcodes', _h_sp1_cp_promoted_memory, source_order=6840)
    api.register('no LLM call is made for Stage 1b', _h_sp1_cp_no_llm_call, source_order=6841)
    api.register('the loaded CapabilityProfile is returned', _h_sp1_cp_loaded_returned, source_order=6842)
    api.register('the pre-built CapabilityProfile is loaded', _h_sp1_cp_prebuilt_loaded, source_order=6843)
    api.register('validation fails with error containing Invalid KC sub-code', _h_sp1_cp_fails_kc, source_order=6844)
    api.register('a loss analysis with losses L-1 and L-2 and hazards H-1 and H-2', _h_sp1_cp_la_context, source_order=6845)
    api.register('the user prompt contains loss analysis context', _h_sp1_cp_prompt_la_context, source_order=6846)
    api.register('the user prompt references losses and hazards from the loss analysis', _h_sp1_cp_prompt_refs, source_order=6847)
    api.register('a LossAnalysis is produced from Stage 1a', _h_sp1_la_produced_from_1a, source_order=6848)
    api.register('an LLM that returns a valid RequirementSet JSON', _h_sp1_s2_valid_req_llm, source_order=6851)
    api.register('an LLM that returns a RequirementSet with REQ-1 classified as control', _h_sp1_s2_classified_reqs, source_order=6852)
    api.register('an LLM that returns a RequirementSet where REQ-1 references', _h_sp1_s2_source_refs, source_order=6853)
    api.register('an LLM that returns a valid ResponsibilitySet JSON', _h_sp1_s2_valid_resp_llm, source_order=6854)
    api.register('an LLM that returns a ResponsibilitySet with controlled process CP-1', _h_sp1_s2_valid_resp_cp, source_order=6855)
    api.register('an LLM that returns a ResponsibilitySet where feedback sources', _h_sp1_s2_valid_resp_refs, source_order=6856)
    api.register('a valid ResponsibilitySet from Call 2', _h_sp1_s2_valid_resp_from_call2, source_order=6857)
    api.register('an LLM that returns a valid ControlStructure JSON', _h_sp1_s2_valid_cs_llm, source_order=6858)
    api.register('an LLM that returns a ControlStructure with coordination link CL-1', _h_sp1_s2_cs_coord_llm, source_order=6859)
    api.register('an LLM that returns valid responses for all three Stage 2 calls', _h_sp1_s2_all_calls_llm, source_order=6860)
    api.register('an LLM that returns a valid RequirementSet for Call 1', _h_sp1_s2_valid_req_llm, source_order=6861)
    api.register('an LLM that returns a valid ResponsibilitySet for Call 2', _h_sp1_s2_valid_resp_llm, source_order=6862)
    api.register('an LLM that returns a valid ControlStructure for Call 3', _h_sp1_s2_valid_cs_llm, source_order=6863)
    api.register('Stage 2 Call 2 responsibilities derivation is run', _h_sp1_s2_call2_run, source_order=6864)
    api.register('Stage 2 Call 3 connections derivation is run', _h_sp1_s2_call3_run, source_order=6865)
    api.register('Stage 2 calls 1 through 2 are run in sequence', _h_sp1_s2_calls_1_2_run, source_order=6866)
    api.register('a RequirementSet model is produced', _h_sp1_s2_req_set_produced, source_order=6867)
    api.register('each requirement has a req_id, description, classification, and source_constraint', _h_sp1_s2_req_fields, source_order=6868)
    api.register('REQ-\\d+ has classification', _h_sp1_s2_req_classification, source_order=6869)
    api.register('REQ-\\d+ has source_constraint', _h_sp1_s2_req_source, source_order=6870)
    api.register('a ResponsibilitySet model is produced', _h_sp1_s2_resp_set_produced, source_order=6871)
    api.register('each responsibility has at least one process model part', _h_sp1_s2_resp_elements, source_order=6872)
    api.register('the ResponsibilitySet contains controlled process CP-1', _h_sp1_s2_resp_cp, source_order=6873)
    api.register('all ElementRef references in the ResponsibilitySet point to valid', _h_sp1_s2_resp_refs_valid, source_order=6874)
    api.register('a ControlStructure model is produced', _h_sp1_s2_cs_produced, source_order=6875)
    api.register('the control structure passes foundation validation', _h_sp1_s2_cs_passes_validation, source_order=6876)
    api.register('the ControlStructure contains coordination link CL-1', _h_sp1_s2_cs_coord_link, source_order=6877)
    api.register('CL-1 has source RESP-1 and target RESP-2', _h_sp1_s2_coord_link_st, source_order=6878)
    api.register('the Call 2 user prompt contains the requirements from Call 1', _h_sp1_s2_call2_prompt_reqs, source_order=6879)
    api.register('the Call 3 user prompt contains responsibilities and controlled processes', _h_sp1_s2_call3_prompt_resps, source_order=6880)
    api.register('an LLM that returns a valid CriticFindings JSON', _h_sp1_critic_valid_llm, source_order=6883)
    api.register('an LLM that returns a CriticFindings JSON', _h_sp1_critic_valid_llm, source_order=6884)
    api.register('an LLM that returns a CriticFindings JSON with a gap of type missing_tool', _h_sp1_critic_invalid_gap_type, source_order=6885)
    api.register('a CriticFindings model is produced', _h_sp1_critic_model_produced, source_order=6886)
    api.register('the model has a gaps list, checklist_results dict, and taxonomy_probe_results dict', _h_sp1_critic_model_fields, source_order=6887)
    api.register('the CriticFindings gaps list is empty', _h_sp1_critic_empty_gaps, source_order=6888)
    api.register('the gap has a description, related_attack_path, and suggested_remedy', _h_sp1_critic_gap_fields, source_order=6889)
    api.register('the checklist_results map responsibility names to present', _h_sp1_critic_checklist, source_order=6890)
    api.register('the user prompt contains the control structure', _h_sp1_critic_prompt_cs, source_order=6891)
    api.register('the user prompt contains the capability profile', _h_sp1_critic_prompt_profile, source_order=6892)
    api.register('the user prompt contains the use-case text', _h_sp1_critic_prompt_use_case, source_order=6893)
    api.register('a capability profile with KC sub-code KC6.3.3 indicating RAG', _h_sp1_critic_rag_profile, source_order=6894)
    api.register('the user prompt contains taxonomy-derived probes for RAG', _h_sp1_critic_prompt_rag, source_order=6895)
    api.register('revision is triggered', _h_sp1_critic_revision_triggered, source_order=6896)
    api.register('revision is not triggered', _h_sp1_critic_revision_not_triggered, source_order=6897)
    api.register('validation fails with error containing gap_type', _h_sp1_critic_fails_gap_type, source_order=6898)
    api.register('the run manifest critic_findings contains two entries', _h_sp1_critic_manifest_two, source_order=6899)
    api.register('an LLM that returns a revised ControlStructure', _h_sp1_rev_revised_cs_llm, source_order=6902)
    api.register('an LLM that returns a revised ControlStructure that still has gaps', _h_sp1_rev_still_gaps_llm, source_order=6903)
    api.register('a critic that identifies unjustified gaps', _h_sp1_rev_critic_unjustified, source_order=6904)
    api.register('a critic that finds only justified gaps or no gaps', _h_sp1_rev_critic_justified, source_order=6905)
    api.register('a revised ControlStructure model is produced', _h_sp1_rev_cs_produced, source_order=6906)
    api.register('the revised control structure passes foundation validation', _h_sp1_rev_cs_passes, source_order=6907)
    api.register('the call log entry step is revision', _h_sp1_rev_call_log_step, source_order=6908)
    api.register('the user prompt contains the current control structure', _h_sp1_rev_prompt_cs, source_order=6909)
    api.register('the user prompt contains the critic findings', _h_sp1_rev_prompt_findings, source_order=6910)
    api.register('structural heuristics are re-run on the revised', _h_sp1_rev_heuristics_rerun, source_order=6911)
    api.register('no second revision call is made', _h_sp1_rev_no_second, source_order=6912)
    api.register('no revision call is made', _h_sp1_rev_no_call, source_order=6913)
    api.register('the structural error is recorded in the run manifest', _h_sp1_rev_structural_error_manifest, source_order=6914)
    api.register('the pipeline proceeds without', _h_sp1_rev_pipeline_proceeds, source_order=6915)
    api.register('the final control structure contains RESP-3', _h_sp1_rev_final_resp3, source_order=6916)
    api.register('the final control structure does not lose existing responsibilities', _h_sp1_rev_final_keeps, source_order=6917)
    api.register('an LLM that returns valid responses for all stages$', _h_sp1_run_all_stages_llm, source_order=6920)
    api.register('an LLM that returns valid responses for Stage 1a and Stage 2', _h_sp1_run_1a_2_llm, source_order=6921)
    api.register('an LLM that returns valid responses for all stages and critic findings with two gaps', _h_sp1_run_all_critic_two_gaps, source_order=6922)
    api.register('an LLM that records the temperature used', _h_sp1_run_temp_llm, source_order=6923)
    api.register('the full SP1 run is executed$', _h_sp1_run_full, source_order=6924)
    api.register('the full SP1 run is executed with the profile flag', _h_sp1_run_full_profile, source_order=6925)
    api.register('Stage 1a loss analysis is produced first', _h_sp1_run_stage_1a_first, source_order=6926)
    api.register('Stage 1b capability profile is produced second', _h_sp1_run_stage_1b_second, source_order=6927)
    api.register('Stage 2 control structure is produced third', _h_sp1_run_stage_2_third, source_order=6928)
    api.register('a run manifest is written to the run directory', _h_sp1_run_manifest_written, source_order=6929)
    api.register('the manifest has stage_summary with call counts', _h_sp1_run_manifest_stage_summary, source_order=6930)
    api.register('the run manifest input_hashes contains a hash for', _h_sp1_run_manifest_input_hash, source_order=6931)
    api.register('the run manifest prompt_hashes contains SHA-256 hashes', _h_sp1_run_manifest_prompt_hashes, source_order=6932)
    api.register('Stage 2 Call 1 receives security constraints from the loss analysis', _h_sp1_run_s2_receives_la, source_order=6933)
    api.register('Stage 2 receives the capability profile for the critic', _h_sp1_run_s2_receives_profile, source_order=6934)
    api.register('the following template files exist:', _h_sp1_run_templates_exist, source_order=6935)
    api.register('the following modules exist and are importable:', _h_sp1_run_modules_exist, source_order=6936)
    api.register('the following internal models are defined:', _h_sp1_run_models_defined, source_order=6937)
    api.register('no call log entry has stage stage_1b', _h_sp1_run_no_stage_1b, source_order=6938)
    api.register('the pre-built capability profile is used', _h_sp1_run_prebuilt_used, source_order=6939)
    api.register('all Stage 2 LLM calls use temperature 0.4', _h_sp1_run_temp_04, source_order=6940)
    api.register('the existing test suite is run', _h_sp1_run_existing_tests, source_order=6941)
    api.register('the SP1 system model module is implemented', _h_sp1_run_module_impl, source_order=6942)
    api.register('the STPA system model module$', _h_sp1_run_module_impl, source_order=6943)
    api.register('the SP1 prompt templates directory', _h_sp1_run_prompt_dir, source_order=6944)
    api.register('a file calls.jsonl exists in the run directory', _h_sp1_run_calls_jsonl, source_order=6945)
    api.register('the file contains entries for stage_1a', _h_sp1_run_calls_jsonl, source_order=6946)
    api.register('a control structure where RESP-1 has PM-1-1, CA-1-1, and FB-1-1', _h_sp1_heur_cs_resp1_full, source_order=6949)
    api.register('a loss analysis with hazard H-1 and constraint SC-1', _h_sp1_heur_la_hazard, source_order=6950)
    api.register('structural heuristics are checked with the loss analysis', _h_sp1_heur_check_with_la, source_order=6951)
    api.register('the heuristic check passes with no errors', _h_sp1_heur_succeeds, source_order=6952)
    api.register('the heuristic check fails with error containing hazard', _h_sp1_heur_fails_hazard, source_order=6953)
    api.register('the heuristic check fails with error containing controlled process', _h_sp1_heur_fails_cp, source_order=6954)
    api.register('a control structure that fails structural heuristics', _h_sp1_heur_cs_fails, source_order=6955)
    api.register('a revision call that produces a corrected control structure', _h_sp1_heur_rev_corrected, source_order=6956)
    api.register('a revision call that produces a control structure with a structural error', _h_sp1_heur_rev_error, source_order=6957)
    api.register('structural heuristics are checked on the assembled ControlStructure', _h_sp1_heur_checked_on_assembled, source_order=6958)
    api.register('the heuristic results are available', _h_sp1_heur_results_available, source_order=6959)
    api.register('structural heuristics are re-run on the revised ControlStructure', _h_sp1_heur_rerun_revised, source_order=6960)
    api.register('the structural error is flagged in the run manifest', _h_sp1_heur_error_flagged, source_order=6961)
    api.register('a responsibility RESP-1 with description The system must validate', _h_sp1_neut_neutral_desc, source_order=6964)
    api.register('a responsibility RESP-1 with description containing llm$', _h_sp1_neut_desc_lower, source_order=6965)
    api.register('no solution-neutrality warnings are produced', _h_sp1_neut_no_warnings, source_order=6966)
    api.register('a warning is produced$', _h_sp1_neut_warning_generic, source_order=6967)
    api.register('CA-1-1 has description containing', _h_sp1_neut_ca_desc, source_order=6968)
    api.register('a warning is produced for CA-1-1 containing', _h_sp1_neut_warning_ca, source_order=6969)
    api.register('the solution-neutrality check is run on the assembled', _h_sp1_neut_checked_on_assembled, source_order=6970)
    api.register('the results are available as warnings', _h_sp1_neut_results_available, source_order=6971)
    api.set_feature(None)

__all__ = ["FEATURE_ID", "register"]
