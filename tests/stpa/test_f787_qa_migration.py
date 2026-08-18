from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "sp2_stage3_prompts.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import CheckResult, child_env, find_project_root, run_command  # noqa: E402
from sp2_stage3_prompts import F787QARunner, REGRESSION_MATRIX, _format_f787_result  # noqa: E402

_STATIC_CHECKS = [
    "SP2-PR-static-01: stage3_system.j2 exists",
    "SP2-PR-static-02: stage3_user.j2 exists",
    "SP2-PR-static-03: technology_context.py exists",
    "SP2-PR-static-04: system prompt does not contain STPA-Sec",
    "SP2-PR-static-05: system prompt contains security analyst framing",
    "SP2-PR-static-06: ICA is expanded as Insecure Control Action exactly once",
    "SP2-PR-static-07: system prompt has no standalone UCA in prose",
    "SP2-PR-static-08: system prompt has no 'Unsafe Control Action' phrase",
    "SP2-PR-static-09: system prompt contains uca_type field name",
    "SP2-PR-static-10: user prompt contains uca_type field name",
    "SP2-PR-static-11: user prompt has no standalone UCA in prose",
    "SP2-PR-static-12: user prompt has no 'Unsafe Control Action' phrase",
    "SP2-PR-static-13: system prompt contains ICA type NOT_PROVIDED",
    "SP2-PR-static-13: system prompt contains ICA type INCORRECT",
    "SP2-PR-static-13: system prompt contains ICA type WRONG_TIMING",
    "SP2-PR-static-13: system prompt contains ICA type WRONG_DURATION",
    "SP2-PR-static-14: system prompt contains na_justification field",
    "SP2-PR-static-15: system prompt contains is_na field",
    "SP2-PR-static-16: system prompt requires structural property for N/A",
    "SP2-PR-static-17: user prompt contains Technology Context heading",
    "SP2-PR-static-18: user prompt contains a task directive",
    "SP2-PR-static-19: user prompt references hazards and constraints",
    "SP2-PR-static-20: user prompt contains REQ-*/SC-* mapping note",
    "SP2-PR-static-21: user prompt does not contain 'Four ICA Types' heading",
    "SP2-PR-static-22: user prompt does not contain 'Type 1' definition block",
    "SP2-PR-static-22: user prompt does not contain 'Type 2' definition block",
    "SP2-PR-static-22: user prompt does not contain 'Type 3' definition block",
    "SP2-PR-static-22: user prompt does not contain 'Type 4' definition block",
    "SP2-PR-static-23: user prompt does not contain 'Requirements' heading",
    "SP2-PR-static-24: user prompt template contains variable control_structure_yaml",
    "SP2-PR-static-24: user prompt template contains variable loss_analysis_yaml",
    "SP2-PR-static-24: user prompt template contains variable technology_context",
    "SP2-PR-static-24: user prompt template contains variable slots_yaml",
    "SP2-PR-static-24: user prompt template contains variable resp_id",
    "SP2-PR-static-25: technology context builder has category-specific logic",
    "SP2-PR-static-26: technology context has at least two distinct tool failure-mode suffixes",
]
_DYNAMIC_CHECKS = [
    "SP2-PR-dynamic-00: project imports without error",
    "SP2-PR-dynamic-01: prompts render without error",
    "SP2-PR-dynamic-02: rendered system prompt has no STPA-Sec",
    "SP2-PR-dynamic-03: rendered system prompt has security analyst framing",
    "SP2-PR-dynamic-04: ICA expanded exactly once in rendered system prompt",
    "SP2-PR-dynamic-05: no standalone UCA in rendered system prompt prose",
    "SP2-PR-dynamic-06: uca_type preserved in rendered system prompt",
    "SP2-PR-dynamic-07: rendered system prompt contains NOT_PROVIDED",
    "SP2-PR-dynamic-07: rendered system prompt contains INCORRECT",
    "SP2-PR-dynamic-07: rendered system prompt contains WRONG_TIMING",
    "SP2-PR-dynamic-07: rendered system prompt contains WRONG_DURATION",
    "SP2-PR-dynamic-08: rendered system prompt mentions na_justification",
    "SP2-PR-dynamic-09: rendered system prompt requires structural property for N/A",
    "SP2-PR-dynamic-10: rendered user prompt has no unresolved {{ }}",
    "SP2-PR-dynamic-11: rendered system prompt has no unresolved {{ }}",
    "SP2-PR-dynamic-12: rendered user prompt contains Technology Context",
    "SP2-PR-dynamic-13: rendered user prompt contains the tech context text",
    "SP2-PR-dynamic-14: rendered user prompt contains slot IDs for RESP-1",
    "SP2-PR-dynamic-15: rendered user prompt has a task directive",
    "SP2-PR-dynamic-16: rendered user prompt references H- and SC-",
    "SP2-PR-dynamic-17: rendered user prompt contains REQ-*/SC-* mapping note",
    "SP2-PR-dynamic-18: rendered user prompt has no 'Four ICA Types' heading",
    "SP2-PR-dynamic-19: rendered user prompt has no 'Type 1' block",
    "SP2-PR-dynamic-19: rendered user prompt has no 'Type 2' block",
    "SP2-PR-dynamic-19: rendered user prompt has no 'Type 3' block",
    "SP2-PR-dynamic-19: rendered user prompt has no 'Type 4' block",
    "SP2-PR-dynamic-20: rendered user prompt has no 'Requirements' heading",
    "SP2-PR-dynamic-21: rendered user prompt preserves uca_type field",
    "SP2-PR-dynamic-22: ICASlotFillResult parses with uca_type NOT_PROVIDED",
    "SP2-PR-dynamic-23: filled_slots has correct length",
    "SP2-PR-dynamic-24: slot has uca_type NOT_PROVIDED",
    "SP2-PR-dynamic-25: slot has field slot_id",
    "SP2-PR-dynamic-25: slot has field responsibility",
    "SP2-PR-dynamic-25: slot has field control_action",
    "SP2-PR-dynamic-25: slot has field uca_type",
    "SP2-PR-dynamic-25: slot has field is_na",
    "SP2-PR-dynamic-25: slot has field icas",
    "SP2-PR-dynamic-25: slot has field na_justification",
    "SP2-PR-dynamic-30: read tool 'search-index' emits output fabrication",
    "SP2-PR-dynamic-31: read tool 'search-index' emits exfiltration",
    "SP2-PR-dynamic-30: read tool 'rag-query' emits output fabrication",
    "SP2-PR-dynamic-31: read tool 'rag-query' emits exfiltration",
    "SP2-PR-dynamic-30: read tool 'data-lookup' emits output fabrication",
    "SP2-PR-dynamic-31: read tool 'data-lookup' emits exfiltration",
    "SP2-PR-dynamic-30: read tool 'get-config' emits output fabrication",
    "SP2-PR-dynamic-31: read tool 'get-config' emits exfiltration",
    "SP2-PR-dynamic-32: write tool 'send-email' emits parameter manipulation",
    "SP2-PR-dynamic-33: write tool 'send-email' emits unauthorized state change",
    "SP2-PR-dynamic-32: write tool 'execute-code' emits parameter manipulation",
    "SP2-PR-dynamic-33: write tool 'execute-code' emits unauthorized state change",
    "SP2-PR-dynamic-32: write tool 'update-record' emits parameter manipulation",
    "SP2-PR-dynamic-33: write tool 'update-record' emits unauthorized state change",
    "SP2-PR-dynamic-32: write tool 'file-write' emits parameter manipulation",
    "SP2-PR-dynamic-33: write tool 'file-write' emits unauthorized state change",
    "SP2-PR-dynamic-34: unknown tool 'mystery-tool' emits a failure mode",
    "SP2-PR-dynamic-34: unknown tool 'api-bridge' emits a failure mode",
    "SP2-PR-dynamic-35: read and write tool suffixes are distinct",
    "SP2-PR-dynamic-36: empty tool inventory produces no tool lines",
    "SP2-PR-dynamic-37: overlapping-verb tool classified as write (parameter manipulation present)",
    "SP2-PR-dynamic-38: overlapping-verb tool classified as read (output fabrication present)",
    "SP2-PR-dynamic-50: vacuous system prompt (NOT_PROVIDED removed) fails ICA type check",
    "SP2-PR-dynamic-51: vacuous user prompt (mapping note removed) fails mapping note check",
    "SP2-PR-dynamic-52: read-only tool does not emit write-specific suffix (branches are distinct, not collapsed)",
]
_REGRESSION_CHECKS = [
    (
        "SP2-PR-regression: TestSystemPromptContent::test_four_ica_types_in_system_prompt "
        "(Four ICA type names present in system prompt)"
    ),
    (
        "SP2-PR-regression: TestUserPromptContent::test_user_prompt_contains_required_content "
        "(User prompt has control structure, hazards, tech context, slot IDs)"
    ),
    (
        "SP2-PR-regression: TestStatelessCalls::test_each_call_receives_full_control_structure "
        "(Each call receives full CS; system prompts identical)"
    ),
    (
        "SP2-PR-regression: TestCallLogging::test_calls_jsonl_exists_with_stage_3 "
        "(All LLM calls logged to calls.jsonl with stage_3)"
    ),
    (
        "SP2-PR-regression: TestFillSlotsForResponsibility::test_returns_filled_slots_for_the_responsibility "
        "(Single-responsibility fill returns correct slots)"
    ),
    (
        "SP2-PR-regression: TestCollectFilledSlotsTypeCheck::test_non_icaslotfillresult_is_skipped "
        "(Non-ICASlotFillResult results are skipped)"
    ),
    (
        "SP2-PR-regression: TestCollectFilledSlotsTypeCheck::test_none_result_is_skipped "
        "(None results are skipped)"
    ),
    (
        "SP2-PR-regression: TestCollectFilledSlotsTypeCheck::test_valid_icaslotfillresult_is_collected "
        "(Valid ICASlotFillResult is collected)"
    ),
]
_PIPELINE_CHECKS = [
    "SP2-PR-pipeline-01: slot-fill success rate remains 100% with revised prompts",
    "SP2-PR-pipeline-02: revised prompts produce ICAs that validate against the loss analysis",
    "SP2-PR-pipeline-03: known baseline preserved — unit 5918 passed / 11 expected failures / 15 skipped",
    "SP2-PR-pipeline-04: known baseline preserved — acceptance 72 passed / 9 expected failures",
    "SP2-PR-pipeline-05: source ruff check remains clean",
]
_PIPELINE_SKIP_REASON = (
    "requires SCENARIO_FORGE_QA_PIPELINE=1 and a live LLM endpoint; "
    "no endpoint in this environment"
)
_PIPELINE_MANUAL_PREFIX = "manual review: "


def _run_suite(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(_SUITE), *args],
        cwd=str(cwd or _PROJECT_ROOT),
        env=env or dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
    )


def _check_names(output: str) -> list[str]:
    return [
        line.split("] ", 1)[1] for line in output.splitlines() if line.startswith("  [")
    ]


def test_f787_suite_uses_shared_harness_without_local_framework() -> None:
    tree = ast.parse(_SUITE.read_text(encoding="utf-8"), filename=str(_SUITE))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]

    assert "qa_harness" in imports
    assert not any(
        isinstance(node, ast.ClassDef) and node.name in {"CheckResult", "QARunner"}
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.ClassDef) and node.name == "F787QARunner"
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_command"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        for node in ast.walk(tree)
    )


def test_f787_cli_preserves_modes_and_invalid_invocations() -> None:
    help_result = _run_suite("--help")
    assert help_result.returncode == 0
    assert "--static" in help_result.stdout
    assert "--dynamic" in help_result.stdout
    assert "--regression" in help_result.stdout
    assert "--pipeline" in help_result.stdout
    assert "--all" in help_result.stdout
    assert "--use-case" not in help_result.stdout

    unrecognized = _run_suite("--bogus")
    assert unrecognized.returncode == 2
    assert "unrecognized arguments: --bogus" in unrecognized.stderr
    assert "[PASS]" not in unrecognized.stdout
    assert "[FAIL]" not in unrecognized.stdout
    assert "QA SUMMARY:" not in unrecognized.stdout


def test_f787_static_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--static")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _STATIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert "--- Static checks (source text) ---" in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "--- Regression matrix" not in result.stdout
    assert "--- Pipeline-mode checks" not in result.stdout
    assert (
        "QA SUMMARY: 36/36 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert "ALL 36 EXECUTED CHECK(S) PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 36/36 passed, 0 failed, 0 skipped (not executed)"
    )
    assert first_check > summary


def test_f787_dynamic_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--dynamic")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _DYNAMIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert (
        "--- Dynamic checks (import + render + deterministic builders) ---"
        in result.stdout
    )
    assert "--- Static checks" not in result.stdout
    assert "--- Regression matrix" not in result.stdout
    assert "--- Pipeline-mode checks" not in result.stdout
    assert (
        "QA SUMMARY: 63/63 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert "ALL 63 EXECUTED CHECK(S) PASSED" in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 63/63 passed, 0 failed, 0 skipped (not executed)"
    )
    assert first_check > summary


def test_f787_regression_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--regression")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _REGRESSION_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert (
        "--- Regression matrix (existing stage3 slot-fill tests) ---" in result.stdout
    )
    assert "--- Static checks" not in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "--- Pipeline-mode checks" not in result.stdout
    assert "QA SUMMARY: 8/8 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    assert "ALL 8 EXECUTED CHECK(S) PASSED" in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 8/8 passed, 0 failed, 0 skipped (not executed)"
    )
    assert first_check > summary


def test_f787_pipeline_mode_skips_without_endpoint() -> None:
    result = _run_suite("--pipeline")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _PIPELINE_CHECKS
    assert all(line.startswith("  [SKIP] ") for line in lines)
    assert "--- Pipeline-mode checks (live LLM endpoint) ---" in result.stdout
    assert "--- Static checks" not in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "--- Regression matrix" not in result.stdout
    assert "QA SUMMARY: 0/5 passed, 0 failed, 5 skipped (not executed)" in result.stdout
    assert "NO CHECKS WERE EXECUTED" in result.stdout
    assert (
        "5 CHECK(S) SKIPPED — live LLM endpoint or pipeline run required; see --pipeline."
        in result.stdout
    )
    assert result.stdout.count(_PIPELINE_SKIP_REASON) == 5
    assert "QA suite:" not in result.stdout


def test_f787_pipeline_env_still_skips_as_manual_review() -> None:
    env = dict(os.environ)
    env["SCENARIO_FORGE_QA_PIPELINE"] = "1"
    result = _run_suite("--pipeline", env=env)
    assert result.returncode == 0
    assert _check_names(result.stdout) == _PIPELINE_CHECKS
    assert "QA SUMMARY: 0/5 passed, 0 failed, 5 skipped (not executed)" in result.stdout
    assert "NO CHECKS WERE EXECUTED" in result.stdout
    assert result.stdout.count(_PIPELINE_MANUAL_PREFIX) == 5
    assert _PIPELINE_SKIP_REASON not in result.stdout


@pytest.mark.parametrize("args", [(), ("--all",)])
def test_f787_all_mode_preserves_default_and_explicit_check_order(
    args: tuple[str, ...],
) -> None:
    result = _run_suite(*args)
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == (
        _STATIC_CHECKS + _DYNAMIC_CHECKS + _REGRESSION_CHECKS + _PIPELINE_CHECKS
    )
    assert [line[:8] for line in lines] == (["  [PASS]"] * 107 + ["  [SKIP]"] * 5)
    assert result.stdout.index(
        "--- Static checks (source text) ---"
    ) < result.stdout.index(
        "--- Dynamic checks (import + render + deterministic builders) ---"
    )
    assert result.stdout.index(
        "--- Dynamic checks (import + render + deterministic builders) ---"
    ) < result.stdout.index(
        "--- Regression matrix (existing stage3 slot-fill tests) ---"
    )
    assert result.stdout.index(
        "--- Regression matrix (existing stage3 slot-fill tests) ---"
    ) < result.stdout.index("--- Pipeline-mode checks (live LLM endpoint) ---")
    assert (
        "QA SUMMARY: 107/112 passed, 0 failed, 5 skipped (not executed)"
        in result.stdout
    )
    assert "ALL 107 EXECUTED CHECK(S) PASSED" in result.stdout
    assert (
        "5 CHECK(S) SKIPPED — live LLM endpoint or pipeline run required; see --pipeline."
        in result.stdout
    )
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 107/112 passed, 0 failed, 5 skipped (not executed)"
    )
    assert first_check > summary


def test_f787_static_and_dynamic_flags_are_combinable() -> None:
    result = _run_suite("--static", "--dynamic")
    assert result.returncode == 0
    assert _check_names(result.stdout) == _STATIC_CHECKS + _DYNAMIC_CHECKS
    assert "--- Regression matrix" not in result.stdout
    assert "--- Pipeline-mode checks" not in result.stdout
    assert (
        "QA SUMMARY: 99/99 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert "ALL 99 EXECUTED CHECK(S) PASSED" in result.stdout


def test_f787_adapter_defers_output_and_keeps_legacy_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = F787QARunner()
    runner.check("first", True, "hidden on pass")
    runner.check("second", False, "details")
    runner.skip("pipeline", "no endpoint")

    assert capsys.readouterr().out == ""
    assert runner.summary() == 1
    output = capsys.readouterr().out
    assert output.index(
        "QA SUMMARY: 1/3 passed, 1 failed, 1 skipped (not executed)"
    ) < output.index("[PASS] first")
    assert output.index("[PASS] first") < output.index("[FAIL] second")
    assert output.index("[FAIL] second") < output.index("[SKIP] pipeline")
    assert "hidden on pass" not in output
    assert "         details" in output
    assert "         no endpoint" in output
    assert "1 CHECK(S) FAILED" in output
    assert (
        "1 CHECK(S) SKIPPED — live LLM endpoint or pipeline run required; see --pipeline."
        in output
    )
    assert "QA suite:" not in output


def test_f787_adapter_zero_executed_checks_is_success(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = F787QARunner()
    runner.skip("pipeline", "no endpoint")

    assert runner.summary() == 0
    output = capsys.readouterr().out
    assert "QA SUMMARY: 0/1 passed, 0 failed, 1 skipped (not executed)" in output
    assert "NO CHECKS WERE EXECUTED" in output
    assert "ALL " not in output


def test_f787_result_formatter_hides_pass_details() -> None:
    passed = CheckResult("ok", True, "secret")
    failed = CheckResult("bad", False, "why")
    skipped = CheckResult("later", True, "wait", "SKIP")
    assert _format_f787_result(passed) == "  [PASS] ok"
    assert _format_f787_result(failed) == "  [FAIL] bad\n         why"
    assert _format_f787_result(skipped) == "  [SKIP] later\n         wait"


def test_f787_static_child_isolation_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    parent_environment = dict(os.environ)
    isolated = child_env(parent_environment, QA_PARENT_ONLY=None, CHILD="only")

    result = _run_suite("--static", cwd=nested, env=isolated)

    assert result.returncode == 0
    assert (
        "QA SUMMARY: 36/36 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert parent_environment["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"
    assert find_project_root() == _PROJECT_ROOT


def test_f787_dynamic_child_isolation_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    isolated = child_env(dict(os.environ), QA_PARENT_ONLY=None, CHILD="only")

    result = _run_suite("--dynamic", cwd=nested, env=isolated)

    assert result.returncode == 0
    assert (
        "QA SUMMARY: 63/63 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"


def test_f787_regression_child_is_isolated_and_uses_project_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    seen: list[dict[str, object]] = []

    def fake_run_command(argv, *, cwd=None, env=None, timeout=None, input_text=None):
        seen.append(
            {
                "argv": list(argv),
                "cwd": Path(cwd) if cwd is not None else None,
                "env": dict(env) if env is not None else None,
                "timeout": timeout,
                "input_text": input_text,
                "parent_cwd": Path.cwd(),
            }
        )
        return SimpleNamespace(returncode=0, stdout="PASSED\n", stderr="")

    monkeypatch.setattr("sp2_stage3_prompts.run_command", fake_run_command)
    from sp2_stage3_prompts import run_regression_checks

    runner = F787QARunner()
    run_regression_checks(runner)

    assert len(seen) == len(REGRESSION_MATRIX)
    assert all(call["cwd"] == _PROJECT_ROOT for call in seen)
    assert all(call["timeout"] == 120 for call in seen)
    assert all(call["input_text"] is None for call in seen)
    assert all(call["parent_cwd"] == nested for call in seen)
    assert all(call["env"] is None for call in seen)
    assert seen[0]["argv"][:4] == [
        sys.executable,
        "-m",
        "pytest",
        (
            "tests/stpa/test_sp2_slot_filling.py::TestSystemPromptContent"
            "::test_four_ica_types_in_system_prompt"
        ),
    ]
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert [result.name for result in runner.results] == _REGRESSION_CHECKS
    assert all(result.passed for result in runner.results)


def test_f787_run_command_defaults_to_project_root_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)

    result = run_command(
        [sys.executable, "-c", "from pathlib import Path; print(Path.cwd())"]
    )

    assert result.returncode == 0
    assert result.stdout.strip() == str(_PROJECT_ROOT)
    assert Path.cwd() == nested
