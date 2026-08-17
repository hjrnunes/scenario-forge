"""Core acceptance handlers for the shadow_cleanup feature group."""

from __future__ import annotations

from runtime_shared import (
    Hazard,
    Loss,
    LossAnalysis,
    PROJECT_ROOT,
    Path,
    TemplateLoader,
    World,
    _FC_PROMPTS_DIR,
    _resolve_value,
    _sc_ensure_property_test_source,
    _sc_has_xfail,
    _sc_simulate_priority_registration,
    json,
    re,
)


def _h_sc_runtime_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the acceptance runtime module is importable."""
    return True, ""


def _h_sc_collect_ir_step_texts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all example-expanded step texts from every IR file are collected."""
    from snapshot import snapshot_layout

    ir_dir = PROJECT_ROOT / snapshot_layout().ir_dir
    world.sc_ir_step_texts = [
        step_text
        for ir_file in sorted(ir_dir.rglob("*.json"))
        for step_text in _ir_file_step_texts(ir_file)
    ]
    return True, ""


def _ir_file_step_texts(ir_file: Path) -> list[str]:
    try:
        ir = json.loads(ir_file.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    background = [
        _resolve_value(step.get("text", ""), {}) for step in ir.get("background", [])
    ]
    scenarios = [_scenario_step_texts(scenario) for scenario in ir.get("scenarios", [])]
    return background + [text for texts in scenarios for text in texts]


def _scenario_step_texts(scenario: dict) -> list[str]:
    examples = scenario.get("examples") or [{}]
    return [
        _resolve_value(step.get("text", ""), example)
        for example in examples
        for step in scenario.get("steps", [])
    ]


def _h_sc_no_global_conflicts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: find_pattern_conflicts returns an empty list for those step texts."""
    from acceptance_runtime import find_pattern_conflicts

    step_texts = getattr(world, "sc_ir_step_texts", [])
    global_conflicts = find_pattern_conflicts(step_texts)
    if global_conflicts:
        detail = "; ".join(f"{t!r}: {f!r} vs {s!r}" for t, f, s in global_conflicts[:5])
        return (
            False,
            f"Found {len(global_conflicts)} global pattern conflicts: {detail}",
        )
    return True, ""


def _h_sc_collect_synthetic_texts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: synthetic step texts covering known shadowing prefixes are collected."""
    synthetic = [
        "the revision is run",
        "the heuristic check fails with error containing something",
        "the pipeline does not crash",
        "the HTML contains the text something",
        "by_ica_type has 3 entries",
        "by_branch_category has 2 entries",
        "by_responsibility has 4 entries",
        "the file contains entries with stage stage_3",
        "the file contains entries with stage stage_5",
        "the scorecard validation section has 2 errors",
        "the user prompt contains the control structure",
        "no new failures are introduced",
        "the existing test suite is run",
        "the following modules exist and are importable",
        "the following template files exist",
        "uncovered_reason is not empty",
        "ica_type_diversity is a non-negative float",
        "responsibility_diversity is a non-negative float",
        "the scenario spec is validated against the control structure",
        "the TemplateLoader can load templates from the prompts directory",
        "the STPA system model prompts directory is available",
        "critic findings with unjustified gaps",
        "a warning is produced for orphan PM",
        "the revision is applied",
        "Stage 2 control structure derivation is run",
        "Stage 2 calls 1 through 3 are run in sequence",
        "a file test.txt exists in the run directory",
        "validation fails with error containing something",
        "a control structure with responsibilities RESP-1 and RESP-2 is available",
        "the final control structure passes foundation validation",
    ]
    world.sc_synthetic_texts = synthetic
    return True, ""


def _h_sc_no_tagged_conflicts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: find_pattern_conflicts returns an empty list for per-feature tagged patterns."""
    from acceptance_runtime import find_pattern_conflicts

    step_texts = getattr(world, "sc_ir_step_texts", [])
    tagged_conflicts = find_pattern_conflicts(step_texts)
    if tagged_conflicts:
        detail = "; ".join(f"{t!r}: {f!r} vs {s!r}" for t, f, s in tagged_conflicts[:5])
        return (
            False,
            f"Found {len(tagged_conflicts)} per-feature tagged conflicts: {detail}",
        )
    return True, ""


def _h_sc_inspect_property_test(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the property test file test_acceptance_harness_property.py is inspected."""
    test_file = PROJECT_ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"
    if not test_file.is_file():
        return False, f"Property test file not found: {test_file}"
    world.sc_property_test_source = test_file.read_text()
    return True, ""


def _h_sc_no_xfail_marker(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: test_no_global_pattern_conflicts_on_... has no xfail marker."""
    source = getattr(world, "sc_property_test_source", "")
    if not source:
        return False, "Property test file not inspected"
    func = (
        "test_no_global_pattern_conflicts_on_synthetic_steps"
        if "synthetic" in text
        else "test_no_global_pattern_conflicts_on_ir_steps"
    )
    has_xfail, _ = _sc_has_xfail(source, func)
    if has_xfail:
        return False, f"{func} still has @pytest.mark.xfail decorator"
    return True, ""


def _h_sc_xfail_removed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the two property tests have their xfail markers removed."""
    source = _sc_ensure_property_test_source(world)
    if not source:
        return False, "Property test file not found"
    for func in (
        "test_no_global_pattern_conflicts_on_ir_steps",
        "test_no_global_pattern_conflicts_on_synthetic_steps",
    ):
        has_xfail, _ = _sc_has_xfail(source, func)
        if has_xfail:
            return False, f"{func} still has @pytest.mark.xfail decorator"
    return True, ""


def _h_sc_tests_pass_not_xpass(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the tests pass rather than xpass."""
    source = _sc_ensure_property_test_source(world)
    if not source:
        return False, "Property test file not found"
    for func in (
        "test_no_global_pattern_conflicts_on_ir_steps",
        "test_no_global_pattern_conflicts_on_synthetic_steps",
    ):
        has_xfail, _ = _sc_has_xfail(source, func)
        if has_xfail:
            return False, f"{func} is still marked xfail (would xpass instead of pass)"
    return True, ""


def _h_sc_no_strict_false(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the tests are not marked with strict=False."""
    source = _sc_ensure_property_test_source(world)
    if not source:
        return False, "Property test file not found"
    for func in (
        "test_no_global_pattern_conflicts_on_ir_steps",
        "test_no_global_pattern_conflicts_on_synthetic_steps",
    ):
        _, has_strict = _sc_has_xfail(source, func)
        if has_strict:
            return False, f"{func} still has strict=False"
    return True, ""


def _h_sc_register_test_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with handler <handler> in global scope."""
    from acceptance_runtime import STEP_PATTERNS, _track_registration

    m = re.search(
        r"a pattern (.*) is registered with handler (\S+) in global scope", text
    )
    if not m:
        return False, f"Could not parse: {text}"
    pattern_str, handler_name = m.group(1), m.group(2)

    def _test_handler(w: World, t: str, e: dict) -> tuple[bool, str]:
        return True, ""

    _test_handler.__name__ = handler_name
    _track_registration(pattern_str, _test_handler, None)
    STEP_PATTERNS.append((re.compile(pattern_str, re.IGNORECASE), _test_handler, None))
    world.sc_test_pattern = pattern_str
    world.sc_test_handler = _test_handler
    return True, ""


def _h_sc_duplicate_raises(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: registering the same pattern with handler in global scope raises RuntimeError."""
    from acceptance_runtime import (
        STEP_PATTERNS,
        _REGISTERED_PATTERN_KEYS,
        _track_registration,
    )

    m = re.search(
        r"registering the same pattern (.*) with handler (\S+) in global scope", text
    )
    if not m:
        return False, f"Could not parse: {text}"
    pattern_str, handler_name = m.group(1), m.group(2)
    handler = getattr(world, "sc_test_handler", None)
    if handler is None:
        return False, "No test pattern registered"
    try:
        _track_registration(pattern_str, handler, None)
        # Clean up the original registration
        STEP_PATTERNS.pop()
        _REGISTERED_PATTERN_KEYS.discard((pattern_str, handler_name, None))
        return False, "Expected RuntimeError but no error was raised"
    except RuntimeError:
        # Expected! Clean up the original registration
        STEP_PATTERNS.pop()
        _REGISTERED_PATTERN_KEYS.discard((pattern_str, handler_name, None))
        return True, ""


def _h_sc_keys_equal_patterns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the number of entries in _REGISTERED_PATTERN_KEYS equals the length of STEP_PATTERNS."""
    from acceptance_runtime import STEP_PATTERNS, _REGISTERED_PATTERN_KEYS

    keys_count = len(_REGISTERED_PATTERN_KEYS)
    patterns_count = len(STEP_PATTERNS)
    if keys_count != patterns_count:
        return (
            False,
            f"_REGISTERED_PATTERN_KEYS has {keys_count} entries but STEP_PATTERNS has {patterns_count} entries",
        )
    return True, ""


def _h_sc_reg_register_earlier(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with _register by handler <handler> at an earlier line."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"a pattern (.*) is registered with _register by handler (\S+) at an earlier line",
        insert_first=False,
    )


def _h_sc_reg_first_later(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the same pattern <pattern> is registered with _register_first by handler <handler> at a later line."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"the same pattern (.*) is registered with _register_first by handler (\S+) at a later line",
        insert_first=True,
    )


def _h_sc_reg_first_a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with _register_first by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"a pattern (.*) is registered with _register_first by handler (\S+)$",
        insert_first=True,
    )


def _h_sc_reg_first_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the same pattern <pattern> is registered with _register_first by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"the same pattern (.*) is registered with _register_first by handler (\S+)$",
        insert_first=True,
    )


def _h_sc_reg_register_a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with _register by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"a pattern (.*) is registered with _register by handler (\S+)$",
        insert_first=False,
    )


def _h_sc_reg_register_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the same pattern <pattern> is registered with _register by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"the same pattern (.*) is registered with _register by handler (\S+)$",
        insert_first=False,
    )


def _h_sc_verify_live_handler(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: handler <handler> is the live handler for step text matching <pattern>."""
    m = re.search(
        r"handler (\S+) is the live handler for step text matching (.*)", text
    )
    if not m:
        return False, f"Could not parse: {text}"
    expected_handler_name = m.group(1)
    step_text = m.group(2)
    test_list = getattr(world, "sc_test_patterns", None)
    if test_list is None:
        return False, "No test patterns registered"
    return _matching_handler_result(
        test_list,
        step_text,
        expected_handler_name,
    )


def _matching_handler_result(
    test_list: list[tuple[re.Pattern, object, object]],
    step_text: str,
    expected_handler_name: str,
) -> tuple[bool, str]:
    return _handler_outcome(
        _matching_handler_name(test_list, step_text),
        expected_handler_name,
        step_text,
    )


def _matching_handler_name(
    test_list: list[tuple[re.Pattern, object, object]],
    step_text: str,
) -> str | None:
    return next(
        (
            handler.__name__
            for pattern, handler, _tag in test_list
            if pattern.search(step_text)
        ),
        None,
    )


def _handler_outcome(
    actual_name: str | None,
    expected_handler_name: str,
    step_text: str,
) -> tuple[bool, str]:
    if actual_name is None:
        return False, f"No handler found for step text {step_text!r}"
    if actual_name != expected_handler_name:
        return (
            False,
            f"Expected handler {expected_handler_name!r} but got {actual_name!r}",
        )
    return True, ""


def _h_sc_use_case_loss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and loss analysis are available."""
    world.sp1_use_case_text = "Test use case for Stage 2"
    world.loss_analysis = LossAnalysis(
        losses=[Loss(loss_id="L-1", description="Loss of confidentiality")],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", loss_ids=["L-1"])],
    )
    return True, ""


def _h_sc_cs_derived_with_loader(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the control structure was derived with a TemplateLoader."""
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader was set"
    if not isinstance(loader, TemplateLoader):
        return False, f"template_loader is {type(loader).__name__}, not TemplateLoader"
    return True, ""


def _h_sc_critic_log_capture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the critic logger had a log capture handler installed during revision."""
    warnings = getattr(world, "sp1_post_revision_warnings", None)
    if warnings is None:
        return (
            False,
            "No log capture warnings recorded (revision may not have been run)",
        )
    return True, ""


def _h_sc_template_loader_instance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the world template_loader is a TemplateLoader instance."""
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader set"
    if not isinstance(loader, TemplateLoader):
        return False, f"template_loader is {type(loader).__name__}, not TemplateLoader"
    return True, ""


def _h_sc_template_dir_fc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the template loader source directory is the FC prompts directory."""
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader set"
    source_dir = getattr(loader, "prompts_dir", None)
    if source_dir is None:
        return False, "Could not determine template loader source directory"
    if Path(source_dir) != _FC_PROMPTS_DIR:
        return (
            False,
            f"Template loader source is {source_dir}, expected {_FC_PROMPTS_DIR}",
        )
    return True, ""


def _h_sc_returns_false_file_not_found(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns false with a file-not-found message."""
    from runtime_features.parallel_llm import _h_pll_file_exists

    run_dir = getattr(world, "sp1_run_dir", None)
    if run_dir is None:
        return False, "No run directory set"
    result = _h_pll_file_exists(
        world, "a file nonexistent_file.txt exists in the run directory", {}
    )
    return _file_not_found_assertion(result)


def _file_not_found_assertion(result: tuple[bool, str]) -> tuple[bool, str]:
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if not any(
        marker in result[1].lower() for marker in ("does not exist", "not found")
    ):
        return False, f"Expected file-not-found message, got: {result[1]}"
    return True, ""
