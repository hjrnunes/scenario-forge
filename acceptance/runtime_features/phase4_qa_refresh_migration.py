"""Black-box characterization handlers for the Phase 4 QA migration."""

from __future__ import annotations

from .phase4_qa_refresh_migration_generated import (
    _h_endpoint_configuration,
    _h_run_generated,
    _h_source_count,
    _h_source_generated,
    _h_source_no_failures,
    _h_source_same,
)
from .phase4_qa_refresh_migration_process import (
    _h_baseline,
    _h_checks_once,
    _h_endpoint_zero,
    _h_failure_arguments,
    _h_failure_output_removed,
    _h_failure_root,
    _h_failure_status,
    _h_failure_streams,
    _h_failure_standin,
    _h_failure_summary,
    _h_help,
    _h_help_modes,
    _h_help_option,
    _h_identical_checks,
    _h_invalid_invocation,
    _h_invalid_status,
    _h_nested_cwd_unchanged,
    _h_nested_invocation,
    _h_nested_root,
    _h_nested_same,
    _h_nested_static,
    _h_no_pipeline_child,
    _h_opt_in_unset,
    _h_output_contains,
    _h_parent_recorded,
    _h_parent_unchanged,
    _h_run_failure_pipeline,
    _h_run_mode_twice,
    _h_runs_successful,
    _h_standin_count,
    _h_status_zero,
    _h_success_standin,
    _h_summary,
)
from .phase4_qa_refresh_migration_scope import (
    _h_artifacts_untracked,
    _h_completion_change_set,
    _h_config_unchanged,
    _h_generated_paths,
    _h_harness_compatible,
    _h_later_qa_changes_outside_boundary,
    _h_metadata_relative,
    _h_no_src_changes,
    _h_refresh_suite_unchanged,
    _h_refresh_registration_unchanged,
    _h_run_hygiene,
    _h_scope_stable,
    _h_worktree_recorded,
    _h_worktree_unchanged,
)

FEATURE_ID = "phase4_qa_refresh_migration"


def register(api: object) -> None:
    """Register Phase 4 steps, scoping only the overlapping ones."""
    api.set_feature(FEATURE_ID)
    api.register(r'the Phase 4 migration baseline is commit "([^"]+)"', _h_baseline)
    api.register(r"live endpoint opt-in is unset", _h_opt_in_unset)
    api.register(r"acceptance-refresh QA help is requested", _h_help)
    api.register(r"acceptance-refresh QA exits with status 0", _h_status_zero)
    api.register(r'help advertises option "([^"]+)"', _h_help_option)
    api.register(
        r'help identifies "--static", "--pipeline", and "--all" as required mutually exclusive modes',
        _h_help_modes,
    )
    api.register(
        r"a successful local pipeline stand-in supplies the characterized acceptance-refresh artifacts",
        _h_success_standin,
    )
    api.register(
        r'acceptance-refresh QA mode "([^"]+)" is run twice with all input options',
        _h_run_mode_twice,
    )
    api.register(r"both runs exit with status 0", _h_runs_successful)
    api.register(
        r"each recorded check is emitted once in recording order", _h_checks_once
    )
    api.register(r"both runs have identical ordered check results", _h_identical_checks)
    api.register(
        r"each run reports a zero-failure summary matching its ordered checks",
        _h_summary,
    )
    api.register(
        r"the pipeline stand-in is invoked (\d+) time per run", _h_standin_count
    )
    api.register(r"the endpoint contact count remains 0", _h_endpoint_zero)
    api.register(
        r'acceptance-refresh QA is invoked with "([^"]+)"', _h_invalid_invocation
    )
    api.register(r"acceptance-refresh QA exits with status \d+", _h_invalid_status)
    api.register(r'output contains "([^"]+)"', _h_output_contains)
    api.register(r"no pipeline child is started", _h_no_pipeline_child)
    api.register(
        r"a local pipeline stand-in emits distinct standard output and standard error and exits with status 7",
        _h_failure_standin,
    )
    api.register(
        r"the parent environment and working directory are recorded",
        _h_parent_recorded,
    )
    api.register(
        r'acceptance-refresh QA is run in "--pipeline" mode with all input options',
        _h_run_failure_pipeline,
    )
    api.register(
        r"the pipeline child receives the documented stpa-run arguments",
        _h_failure_arguments,
    )
    api.register(r"the pipeline child runs from the repository root", _h_failure_root)
    api.register(
        r"its exit status, standard output, and standard error remain separately observable",
        _h_failure_streams,
    )
    api.register(r'QA command reports "([^"]+)"', _h_failure_summary)
    api.register(r"acceptance-refresh QA exits with status 1", _h_failure_status)
    api.register_first(
        r"^the parent environment and working directory remain unchanged$",
        _h_parent_unchanged,
    )
    api.register(
        r"temporary pipeline output is removed after the run",
        _h_failure_output_removed,
    )
    api.register(
        r"acceptance-refresh QA is invoked by absolute path from a nested temporary directory",
        _h_nested_invocation,
    )
    api.register(r'"--static" mode is run twice', _h_nested_static)
    api.register(r"both runs discover the repository root", _h_nested_root)
    api.register(
        r"both runs emit the same ordered checks and a zero-failure summary",
        _h_nested_same,
    )
    api.register(
        r"neither run changes the caller working directory",
        _h_nested_cwd_unchanged,
    )
    api.register_first(
        r'^the acceptance-refresh source feature "([^"]+)" is generated$',
        _h_source_generated,
    )
    api.register(
        r"endpoint URLs target a local contact sentinel", _h_endpoint_configuration
    )
    api.register(
        r"its generated acceptance test is run twice with live opt-in unset",
        _h_run_generated,
    )
    api.register(
        r"each run reports exactly \d+ distinct scenarios as PASS",
        _h_source_count,
    )
    api.register(
        r"neither run reports an acceptance-refresh scenario as FAIL or SKIP",
        _h_source_no_failures,
    )
    api.register(r"both runs report the same ordered scenario outcomes", _h_source_same)
    api.register(
        r'the Phase 4 completion change set is compared with commit "([^"]+)"',
        _h_completion_change_set,
    )
    api.register(
        r"acceptance-refresh QA behavior is byte-for-byte unchanged from the Phase 4 completion baseline",
        _h_refresh_suite_unchanged,
    )
    api.register(
        r"later independent QA-suite migrations are outside the Phase 4 change boundary",
        _h_later_qa_changes_outside_boundary,
    )
    api.register(
        r"the shared QA harness preserves its check and summary API behavior",
        _h_harness_compatible,
    )
    api.register(
        r"acceptance-refresh runtime registration is byte-for-byte unchanged from the Phase 4 completion baseline",
        _h_refresh_registration_unchanged,
    )
    api.register_first(
        r'^no production path beneath "src/" is added, modified, or deleted$',
        _h_no_src_changes,
    )
    api.register(
        r"acceptance configuration and generation commands are byte-for-byte unchanged",
        _h_config_unchanged,
    )
    api.register(
        r"the complete unrelated worktree status and content are recorded",
        _h_worktree_recorded,
    )
    api.register(
        r"the migrated suite and generated Phase 4 acceptance test are run",
        _h_run_hygiene,
    )
    api.register(
        r"IR, dry reports, generated tests, metadata, coverage, mutation, and QA capture artifacts remain untracked",
        _h_artifacts_untracked,
    )
    api.register(
        r"generated artifacts remain within their configured generated-output paths",
        _h_generated_paths,
    )
    api.register(
        r"generated metadata contains no absolute checkout path", _h_metadata_relative
    )
    api.register(
        r"no source-analysis or generated-output scope changes", _h_scope_stable
    )
    api.register(
        r"every unrelated worktree path retains its original status and content",
        _h_worktree_unchanged,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
