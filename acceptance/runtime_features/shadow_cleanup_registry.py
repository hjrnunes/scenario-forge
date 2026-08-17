"""Registration adapter for the shadow_cleanup acceptance handlers."""

from runtime_features.shadow_cleanup_core import (
    _h_sc_runtime_importable,
    _h_sc_collect_ir_step_texts,
    _h_sc_no_global_conflicts,
    _h_sc_collect_synthetic_texts,
    _h_sc_no_tagged_conflicts,
    _h_sc_inspect_property_test,
    _h_sc_no_xfail_marker,
    _h_sc_xfail_removed,
    _h_sc_tests_pass_not_xpass,
    _h_sc_no_strict_false,
    _h_sc_register_test_pattern,
    _h_sc_duplicate_raises,
    _h_sc_keys_equal_patterns,
    _h_sc_reg_register_earlier,
    _h_sc_reg_first_later,
    _h_sc_reg_first_a,
    _h_sc_reg_first_b,
    _h_sc_reg_register_a,
    _h_sc_reg_register_b,
    _h_sc_verify_live_handler,
    _h_sc_use_case_loss,
    _h_sc_cs_derived_with_loader,
    _h_sc_critic_log_capture,
    _h_sc_template_loader_instance,
    _h_sc_template_dir_fc,
    _h_sc_returns_false_file_not_found,
)
from runtime_features.shadow_cleanup_observations import (
    _h_sc_heuristic_passed,
    _h_sc_returns_false_heuristic_passed,
    _h_sc_cs_resp1_available,
    _h_sc_world_cs_resp1,
    _h_sc_cs_sp1_helper,
    _h_sc_sp1_no_calls,
    _h_sc_returns_true_no_calls,
    _h_sc_returns_true_unconditional,
    _h_sc_ets_empty_uncovered,
    _h_sc_returns_false_uncovered_empty,
    _h_sc_scorecard_validation,
    _h_sc_returns_true,
    _h_sc_not_manual_mock,
)

FEATURE_ID = "shadow_cleanup"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.set_feature("shadow_cleanup")
    api.register_first(
        "a pattern (.*) is registered with _register by handler (\\S+) at an earlier line",
        _h_sc_reg_register_earlier,
        source_order=23107,
    )
    api.register_first(
        "the same pattern (.*) is registered with _register_first by handler (\\S+) at a later line",
        _h_sc_reg_first_later,
        source_order=23108,
    )
    api.register_first(
        "a pattern (.*) is registered with _register_first by handler (\\S+)$",
        _h_sc_reg_first_a,
        source_order=23109,
    )
    api.register_first(
        "the same pattern (.*) is registered with _register_first by handler (\\S+)$",
        _h_sc_reg_first_b,
        source_order=23110,
    )
    api.register_first(
        "a pattern (.*) is registered with _register by handler (\\S+)$",
        _h_sc_reg_register_a,
        source_order=23111,
    )
    api.register_first(
        "the same pattern (.*) is registered with _register by handler (\\S+)$",
        _h_sc_reg_register_b,
        source_order=23112,
    )
    api.register_first(
        "handler (\\S+) is the live handler for step text matching (.*)",
        _h_sc_verify_live_handler,
        source_order=23113,
    )
    api.set_feature(None)
    api.register(
        "the acceptance runtime module is importable",
        _h_sc_runtime_importable,
        source_order=23118,
    )
    api.register(
        "all example-expanded step texts from every IR file are collected",
        _h_sc_collect_ir_step_texts,
        source_order=23119,
    )
    api.register(
        "find_pattern_conflicts returns an empty list for those step texts",
        _h_sc_no_global_conflicts,
        source_order=23120,
    )
    api.register(
        "synthetic step texts covering known shadowing prefixes are collected",
        _h_sc_collect_synthetic_texts,
        source_order=23121,
    )
    api.register(
        "find_pattern_conflicts returns an empty list for per-feature tagged patterns",
        _h_sc_no_tagged_conflicts,
        source_order=23122,
    )
    api.register(
        "the property test file test_acceptance_harness_property\\.py is inspected",
        _h_sc_inspect_property_test,
        source_order=23123,
    )
    api.register(
        "test_no_global_pattern_conflicts_on_ir_steps has no xfail marker",
        _h_sc_no_xfail_marker,
        source_order=23124,
    )
    api.register(
        "test_no_global_pattern_conflicts_on_synthetic_steps has no xfail marker",
        _h_sc_no_xfail_marker,
        source_order=23125,
    )
    api.register(
        "the two property tests have their xfail markers removed",
        _h_sc_xfail_removed,
        source_order=23126,
    )
    api.register(
        "the tests pass rather than xpass",
        _h_sc_tests_pass_not_xpass,
        source_order=23127,
    )
    api.register(
        "the tests are not marked with strict=False",
        _h_sc_no_strict_false,
        source_order=23128,
    )
    api.register(
        "a pattern (.*) is registered with handler (\\S+) in global scope",
        _h_sc_register_test_pattern,
        source_order=23129,
    )
    api.register(
        "registering the same pattern (.*) with handler (\\S+) in global scope raises RuntimeError",
        _h_sc_duplicate_raises,
        source_order=23130,
    )
    api.register(
        "the number of entries in _REGISTERED_PATTERN_KEYS equals the length of STEP_PATTERNS",
        _h_sc_keys_equal_patterns,
        source_order=23131,
    )
    api.register(
        "a use-case description and loss analysis are available",
        _h_sc_use_case_loss,
        source_order=23132,
    )
    api.register(
        "the control structure was derived with a TemplateLoader",
        _h_sc_cs_derived_with_loader,
        source_order=23133,
    )
    api.register(
        "the critic logger had a log capture handler installed during revision",
        _h_sc_critic_log_capture,
        source_order=23134,
    )
    api.register(
        "the world template_loader is a TemplateLoader instance",
        _h_sc_template_loader_instance,
        source_order=23135,
    )
    api.register(
        "the template loader source directory is the FC prompts directory",
        _h_sc_template_dir_fc,
        source_order=23136,
    )
    api.register(
        "the handler returns false with a file-not-found message$",
        _h_sc_returns_false_file_not_found,
        source_order=23137,
    )
    api.register(
        "the handler returns false because the heuristic passed$",
        _h_sc_returns_false_heuristic_passed,
        source_order=23138,
    )
    api.register(
        "a heuristic result that passed", _h_sc_heuristic_passed, source_order=23139
    )
    api.register(
        "a control structure with responsibility RESP-1 is available",
        _h_sc_cs_resp1_available,
        source_order=23140,
    )
    api.register(
        "the world control structure has responsibility RESP-1",
        _h_sc_world_cs_resp1,
        source_order=23141,
    )
    api.register(
        "the control structure was created by the SP1 helper function",
        _h_sc_cs_sp1_helper,
        source_order=23142,
    )
    api.register(
        "the SP1 mock client has no calls recorded",
        _h_sc_sp1_no_calls,
        source_order=23143,
    )
    api.register(
        "the handler returns true because no calls were made$",
        _h_sc_returns_true_no_calls,
        source_order=23144,
    )
    api.register(
        "the handler returns true unconditionally$",
        _h_sc_returns_true_unconditional,
        source_order=23145,
    )
    api.register(
        "an enriched threat set with an empty uncovered_reason",
        _h_sc_ets_empty_uncovered,
        source_order=23146,
    )
    api.register(
        "the handler returns false because uncovered_reason is empty$",
        _h_sc_returns_false_uncovered_empty,
        source_order=23147,
    )
    api.register(
        "the in-memory scorecard has a validation section with \\d+ stage_local_errors",
        _h_sc_scorecard_validation,
        source_order=23148,
    )
    api.register("^the handler returns true$", _h_sc_returns_true, source_order=23149)
    api.register(
        "the control structure is not produced by manual mock call sequencing",
        _h_sc_not_manual_mock,
        source_order=23150,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
