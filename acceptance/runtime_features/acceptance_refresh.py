"""Acceptance step handlers for the acceptance_refresh feature group."""

from __future__ import annotations

from runtime_shared import (
    ControlStructure,
    ElementRef,
    LossAnalysis,
    ReferenceType,
    TemplateLoader,
    World,
    _PQF_PROMPTS_DIR,
    _SP1ControlElementSet,
    _SP1CoordinationAnalysis,
    _SP1RequirementSet,
    _SP1ResponsibilitySet,
    _ar_client,
    _ar_run_dir,
    _ar_stage2_defaults,
    _sp1_add_coordination_links,
    _sp1_assemble_with_fallback,
    _sp1_derive_control_structure,
    _sp1_valid_control_element_set_dict,
    _sp1_valid_coordination_analysis_dict,
    _sp1_valid_cs_dict,
    _sp1_valid_la_dict,
    _sp1_valid_req_set_dict,
    _sp1_valid_resp_set_2a_dict,
    json,
    re,
)

def _h_ar_module_export(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from scenario_forge.stpa.system_model import control_structure
    match = re.search(r"module (does not )?exports? `([^`]+)`", text)
    if not match:
        return False, f"Could not parse symbol from: {text}"
    absent, symbol = match.groups()
    exported = hasattr(control_structure, symbol)
    if bool(absent) == exported:
        expectation = "not be exported" if absent else "be exported"
        return False, f"Expected {symbol} to {expectation}"
    return True, ""

def _h_ar_model_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"`CoordinationAnalysis` model (does not )?declare `([^`]+)`", text)
    if not match:
        return False, f"Could not parse model field from: {text}"
    absent, field = match.groups()
    declared = field in _SP1CoordinationAnalysis.model_fields
    if bool(absent) == declared:
        expectation = "not be declared" if absent else "be declared"
        return False, f"Expected {field} to {expectation}"
    return True, ""

def _h_ar_responsibility_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    ids = re.findall(r"RESP-\d+", text)
    response = _sp1_valid_resp_set_2a_dict()
    response["responsibilities"] = [
        responsibility for responsibility in response["responsibilities"]
        if responsibility["resp_id"] in ids
    ]
    world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(response)
    _ar_client(world).set_response_for(_SP1ResponsibilitySet, response)
    return True, ""

def _h_ar_valid_responsibility_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
        _sp1_valid_resp_set_2a_dict()
    )
    # Handle combined step: "a valid ResponsibilitySet from Call 2a with
    # responsibility RESP-1 and a ControlElementSet from Call 2b with
    # controlled process CP-1"
    if "ControlElementSet from Call 2b" in text:
        if world.sp1_control_element_set is None:
            world.sp1_control_element_set = _SP1ControlElementSet.model_validate(
                _sp1_valid_control_element_set_dict()
            )
        _ar_client(world).set_response_for(
            _SP1ControlElementSet, world.sp1_control_element_set.model_dump()
        )
    return True, ""

def _h_ar_control_element_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_control_element_set is not None:
        # Preserve modifications from a prior sanitize step (e.g. a CA or
        # FB with an invalid ElementRef) and apply the unresolvable
        # feedback source on top of the existing set.  Target FB-2-1
        # (not FB-1-1) so that step-2 modifications to FB-1-1 are
        # preserved.
        existing = world.sp1_control_element_set
        if "unresolvable feedback source reference" in text:
            for fb in existing.feedback_channels:
                if fb.fb_id == "FB-2-1":
                    fb.source = ElementRef(type=ReferenceType.controlled_process, id="CP-404")
        _ar_client(world).set_response_for(
            _SP1ControlElementSet, existing.model_dump()
        )
        return True, ""
    response = _sp1_valid_control_element_set_dict()
    if "unresolvable feedback source reference" in text:
        response["feedback_channels"][1]["source"] = {
            "type": "controlled_process", "id": "CP-404",
        }
    world.sp1_control_element_set = _SP1ControlElementSet.model_validate(response)
    _ar_client(world).set_response_for(_SP1ControlElementSet, response)
    return True, ""

def _h_ar_coordination_analysis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    response = _sp1_valid_coordination_analysis_dict()
    if "integrity finding" in text:
        response = {
            "coordination_links": [],
            "integrity_findings": ["Controlled process CP-404 is unreferenced"],
        }
    elif "non-existent responsibility" in text:
        response["coordination_links"][0]["source"] = "RESP-404"
    world.sp1_connection_set = _SP1CoordinationAnalysis.model_validate(response)
    _ar_client(world).set_response_for(_SP1CoordinationAnalysis, response)
    return True, ""

def _h_ar_stage2_calls_ready(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _ar_stage2_defaults(world)
    return True, ""

def _h_ar_call3_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from scenario_forge.stpa.system_model.control_structure import _call_3_coordination
    _ar_stage2_defaults(world)
    run_dir = _ar_run_dir(world)
    control_structure = ControlStructure.model_validate(_sp1_valid_cs_dict())
    world.sp1_connection_set = _call_3_coordination(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        control_structure=control_structure,
        run_dir=run_dir,
        loader=TemplateLoader(_PQF_PROMPTS_DIR),
        temperature=0.4,
    )
    return True, ""

def _h_ar_assemble(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _ar_stage2_defaults(world)
    responsibility_set = world.sp1_responsibility_set or _SP1ResponsibilitySet.model_validate(
        _sp1_valid_resp_set_2a_dict()
    )
    control_elements = world.sp1_control_element_set or _SP1ControlElementSet.model_validate(
        _sp1_valid_control_element_set_dict()
    )
    world.control_structure, world.sp1_warnings = _sp1_assemble_with_fallback(
        responsibility_set, control_elements, _ar_run_dir(world), "test-model"
    )
    world.san_merge_warnings = list(world.sp1_warnings)
    return True, ""

def _h_ar_add_coordination(world: World, text: str, examples: dict) -> tuple[bool, str]:
    control_structure = world.control_structure or ControlStructure.model_validate(_sp1_valid_cs_dict())
    analysis = world.sp1_connection_set or _SP1CoordinationAnalysis.model_validate(
        _sp1_valid_coordination_analysis_dict()
    )
    world.control_structure, world.sp1_warnings = _sp1_add_coordination_links(
        control_structure, analysis, _ar_run_dir(world), "test-model"
    )
    return True, ""

def _h_ar_stage2_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _ar_stage2_defaults(world)
    template_loader = TemplateLoader(_PQF_PROMPTS_DIR)
    world.template_loader = template_loader
    world.control_structure, world.sp1_warnings = _sp1_derive_control_structure(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        loss_analysis=LossAnalysis.model_validate(_sp1_valid_la_dict()),
        run_dir=_ar_run_dir(world),
        template_loader=template_loader,
        temperature=0.4,
    )
    return True, ""

def _h_ar_call2a_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from scenario_forge.stpa.system_model.control_structure import _call_2a_responsibilities
    _ar_stage2_defaults(world)
    world.sp1_responsibility_set = _call_2a_responsibilities(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        requirement_set=_SP1RequirementSet.model_validate(_sp1_valid_req_set_dict()),
        capability_profile=None,
        run_dir=_ar_run_dir(world),
        loader=TemplateLoader(_PQF_PROMPTS_DIR),
        temperature=0.4,
    )
    return True, ""

def _h_ar_call2b_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from scenario_forge.stpa.system_model.control_structure import _call_2b_control_elements
    _ar_stage2_defaults(world)
    world.sp1_control_element_set = _call_2b_control_elements(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        responsibility_set=world.sp1_responsibility_set or _SP1ResponsibilitySet.model_validate(
            _sp1_valid_resp_set_2a_dict()
        ),
        run_dir=_ar_run_dir(world),
        loader=TemplateLoader(_PQF_PROMPTS_DIR),
        temperature=0.4,
    )
    return True, ""

def _h_ar_call_log_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"step (\S+)", text)
    step = match.group(1) if match else ""
    path = _ar_run_dir(world) / "calls.jsonl"
    entries = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    if not any(entry.get("step") == step for entry in entries):
        return False, f"No {step} entry in call log"
    return True, ""

def _h_ar_call_sequence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _h_ar_stage2_run(world, text, examples)

def _h_ar_coordination_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if not isinstance(world.sp1_connection_set, _SP1CoordinationAnalysis):
        return False, "No CoordinationAnalysis model was produced"
    return True, ""

def _h_ar_coordination_contains_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    analysis = world.sp1_connection_set
    if analysis is None or not any(link.link_id == "CL-1" for link in analysis.coordination_links):
        return False, "CoordinationAnalysis does not contain CL-1"
    return True, ""

def _h_ar_integrity_findings(world: World, text: str, examples: dict) -> tuple[bool, str]:
    analysis = world.sp1_connection_set
    if analysis is None or not analysis.integrity_findings:
        return False, "CoordinationAnalysis integrity_findings is empty"
    return True, ""

def _h_ar_no_coordination_links(world: World, text: str, examples: dict) -> tuple[bool, str]:
    analysis = world.sp1_connection_set
    if analysis is None:
        analysis = world.control_structure
    if analysis is None or analysis.coordination_links:
        return False, "Expected no coordination links"
    return True, ""

def _h_ar_control_structure_element(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No ControlStructure available"
    match = re.search(r"contains (responsibility|controlled process) (RESP-\d+|CP-\d+)", text)
    if not match:
        return False, f"Could not parse control structure element: {text}"
    kind, element_id = match.groups()
    values = (
        [item.resp_id for item in world.control_structure.responsibilities]
        if kind == "responsibility"
        else [item.cp_id for item in world.control_structure.controlled_processes]
    )
    if element_id not in values:
        return False, f"{kind} {element_id} not found in {values}"
    return True, ""

def _h_ar_link_source_target(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No ControlStructure available"
    link = next((item for item in world.control_structure.coordination_links if item.link_id == "CL-1"), None)
    if link is None or link.source != "RESP-1" or link.target != "RESP-2":
        return False, "CL-1 does not connect RESP-1 to RESP-2"
    return True, ""

def _h_ar_call3_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    calls = _ar_client(world).calls
    prompt = next(
        (call["user_prompt"] for call in reversed(calls)
         if call["response_format"] is _SP1CoordinationAnalysis),
        "",
    )
    if "RESP-1" not in prompt or "CP-1" not in prompt:
        return False, "Call 3 prompt lacks assembled responsibilities or controlled processes"
    return True, ""

def _h_ar_warnings_include(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"naming step (\S+)", text)
    step = match.group(1) if match else ""
    if not any(step in warning for warning in world.sp1_warnings):
        return False, f"No warning names {step}: {world.sp1_warnings}"
    return True, ""

def _h_ar_no_assembly_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_warnings:
        return False, f"Unexpected assembly warnings: {world.sp1_warnings}"
    return True, ""

def _h_ar_no_log_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _KNOWN_RETIRED_STEPS = frozenset({
        "call_2_responsibilities",
        "call_3_connections",
        "merge_connection_set",
    })
    match = re.search(r"step (\S+)", text)
    if not match:
        return False, "Could not parse step name from step text"
    step = match.group(1)
    if step not in _KNOWN_RETIRED_STEPS:
        return False, f"'{step}' is not a recognized retired step name"
    run_dir = _ar_run_dir(world)
    entries = [
        json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()
    ] if (run_dir / "calls.jsonl").exists() else []
    if any(entry.get("step") == step for entry in entries):
        return False, f"Unexpected {step} entry in call log"
    return True, ""

def _h_ar_sp1_assembly_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = world.gd_run_result or world.sp1_run_result
    errors = getattr(result, "stage_errors", []) if result is not None else []
    if not any("assemble_control_structure" in error for error in errors):
        return False, f"No assemble_control_structure error in {errors}"
    return True, ""

def _h_ar_named_prompts_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"the (SP2|SP3) prompts directory contains `([^`]+)`", text)
    if not match:
        return False, f"Could not parse prompt directory step: {text}"
    stage, template = match.groups()
    if stage == "SP2":
        from scenario_forge.stpa.threat_enum._constants import PROMPTS_DIR
    else:
        from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR
    if not (PROMPTS_DIR / template).exists():
        return False, f"Missing {stage} template: {template}"
    return True, ""

def _h_ar_render_call2a_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    loader = TemplateLoader(_PQF_PROMPTS_DIR)
    profile = world.sp1_profile
    world.template_rendered = loader.render_prompt(
        "stage2_call2a_user.j2",
        use_case_text=world.sp1_use_case_text,
        requirements=_SP1RequirementSet.model_validate(_sp1_valid_req_set_dict()).requirements,
        capability_profile=profile,
    )
    return True, ""

def _h_ar_responsibility_shape(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_responsibility_set is None:
        return False, "No ResponsibilitySet available"
    for responsibility in world.sp1_responsibility_set.responsibilities:
        if not responsibility.responsibility_constraints or not responsibility.process_model_parts:
            return False, f"Incomplete responsibility: {responsibility.resp_id}"
    return True, ""

def _h_ar_responsibility_no_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _KNOWN_CONTROL_ELEMENT_FIELDS = frozenset({
        "control_actions",
        "feedback_channels",
        "controlled_processes",
    })
    field = re.search(r"does not declare `([^`]+)`", text)
    if not field:
        return False, "Could not parse field name from step text"
    fname = field.group(1)
    if fname in _SP1ResponsibilitySet.model_fields:
        return False, f"ResponsibilitySet declares {fname}"
    if fname not in _KNOWN_CONTROL_ELEMENT_FIELDS:
        return False, f"'{fname}' is not a recognized control element field"
    return True, ""

def _h_ar_control_elements_produced(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (True, "") if world.sp1_control_element_set is not None else (False, "No ControlElementSet available")

def _h_ar_control_elements_contains_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    elements = world.sp1_control_element_set
    if elements is None or not any(cp.cp_id == "CP-1" for cp in elements.controlled_processes):
        return False, "ControlElementSet does not contain CP-1"
    return True, ""

def _h_ar_prior_prompt_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = "requirements" if "2a" in text else "responsibilities"
    if not any(expected in call["user_prompt"].lower() for call in _ar_client(world).calls):
        return False, f"No prompt contains {expected}"
    return True, ""

FEATURE_ID = 'acceptance_refresh'

def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.set_feature('acceptance_refresh')
    api.register_first('the `CoordinationAnalysis` model (?:does not )?declare', _h_ar_model_field, source_order=21826)
    api.register_first('(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis', _h_ar_coordination_analysis, source_order=21827)
    api.register_first('Stage 2 Call 3 coordination derivation is run', _h_ar_call3_run, source_order=21828)
    api.register_first('the Stage 2 coordination link addition with fallback is executed', _h_ar_add_coordination, source_order=21829)
    api.register_first('a CoordinationAnalysis model is produced', _h_ar_coordination_produced, source_order=21830)
    api.register_first('the CoordinationAnalysis contains coordination link CL-1', _h_ar_coordination_contains_link, source_order=21831)
    api.register_first('the CoordinationAnalysis integrity_findings list is not empty', _h_ar_integrity_findings, source_order=21832)
    api.register_first('the CoordinationAnalysis contains no coordination links', _h_ar_no_coordination_links, source_order=21833)
    api.register_first('the ControlStructure contains (?:responsibility|controlled process)', _h_ar_control_structure_element, source_order=21834)
    api.register_first('CL-1 has source RESP-1 and target RESP-2', _h_ar_link_source_target, source_order=21835)
    api.register_first('the warnings list includes a warning naming step', _h_ar_warnings_include, source_order=21836)
    api.register_first('no assembly failure is logged', _h_ar_no_assembly_failure, source_order=21837)
    api.register_first('the SP1RunResult stage_errors contains the assemble_control_structure failure', _h_ar_sp1_assembly_error, source_order=21838)
    api.set_feature(None)
    api.register_first('the control_structure module (?:does not )?exports?', _h_ar_module_export, source_order=21916)
    api.register_first('the SP2 prompts directory contains', _h_ar_named_prompts_contains, source_order=21917)
    api.register_first('the SP3 prompts directory contains', _h_ar_named_prompts_contains, source_order=21918)
    api.register_first('the Call 2a user prompt is rendered with the capability profile', _h_ar_render_call2a_prompt, source_order=21919)
    api.register_first('(?:an LLM that returns a )?ControlElementSet from Call 2b with', _h_ar_control_element_set, source_order=21920)
    api.register_first('a valid ResponsibilitySet from Call 2a', _h_ar_valid_responsibility_set, source_order=21921)
    api.register_first('a ResponsibilitySet from Call 2a with responsibilities', _h_ar_responsibility_set, source_order=21922)
    api.register_first('an LLM that returns valid responses for (?:Stage 2 calls 1, 2a, and 2b|all four Stage 2 calls|Stage 2 calls 1 and 2a)', _h_ar_stage2_calls_ready, source_order=21923)
    api.register_first('the Stage 2 assembly with fallback is executed', _h_ar_assemble, source_order=21924)
    api.register_first('Stage 2 control structure derivation is run', _h_ar_stage2_run, source_order=21925)
    api.register_first('Stage 2 calls 1 through 3 are run in sequence', _h_ar_call_sequence, source_order=21926)
    api.register_first('Stage 2 Call 2a responsibilities derivation is run', _h_ar_call2a_run, source_order=21927)
    api.register_first('Stage 2 Call 2b control elements derivation is run', _h_ar_call2b_run, source_order=21928)
    api.register_first('Stage 2 calls 1 through 2[ab] are run in sequence', _h_ar_stage2_run, source_order=21929)
    api.register_first('an LLM that returns a valid ControlElementSet JSON', _h_ar_control_element_set, source_order=21930)
    api.register_first('an LLM that returns a valid CoordinationAnalysis', _h_ar_coordination_analysis, source_order=21931)
    api.register_first('a CoordinationAnalysis with', _h_ar_coordination_analysis, source_order=21932)
    api.register_first('a call log entry exists with step', _h_ar_call_log_exists, source_order=21933)
    api.register_first('no call log entry has step', _h_ar_no_log_step, source_order=21934)
    api.register_first('each responsibility has at least one responsibility constraint and one process model part', _h_ar_responsibility_shape, source_order=21935)
    api.register_first('the `ResponsibilitySet` model does not declare', _h_ar_responsibility_no_field, source_order=21936)
    api.register_first('a ControlElementSet model is produced', _h_ar_control_elements_produced, source_order=21937)
    api.register_first('the ControlElementSet contains controlled process CP-1', _h_ar_control_elements_contains_cp, source_order=21938)
    api.register_first('the Call 2[ab] user prompt contains', _h_ar_prior_prompt_contains, source_order=21939)
    api.register_first('the Call 3 user prompt contains the assembled responsibilities and controlled processes', _h_ar_call3_prompt, source_order=21940)
    api.set_feature(None)

__all__ = ["FEATURE_ID", "register"]
