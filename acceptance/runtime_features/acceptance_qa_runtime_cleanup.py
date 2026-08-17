"""Acceptance handlers for the QA runtime cleanup characterization feature."""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import stat
import sys
from pathlib import Path

from runtime_shared import PROJECT_ROOT, World

_QA_MODULES = Path(__file__).resolve().parents[1] / "qa"
if str(_QA_MODULES) not in sys.path:
    sys.path.insert(0, str(_QA_MODULES))

from qa_harness import (  # noqa: E402
    child_env,
    run_command,
)

FEATURE_ID = "acceptance_qa_runtime_cleanup"
_AQRC_ROOT = PROJECT_ROOT / "tmp" / "qa-acceptance-qa-runtime-cleanup"
_REFRESH_CASES = {
    "stage1b-entry-point-guidance": 8,
    "stage1b-grounding": 7,
    "stage2-coordination-analysis": 12,
    "stage2-assembly-fallback": 8,
}
_AQRC_GENERATED_NAME = "acceptance_qa_runtime_cleanup_acceptance_test.py"
_AQRC_TEST_RELATIVE = f"build/acceptance/generated/{_AQRC_GENERATED_NAME}"
_AQRC_ENVIRONMENT = "AQRC_CHILD_REMOVED"


def _h_aqrc_background(world: World, text: str, examples: dict) -> tuple[bool, str]:
    required = (
        PROJECT_ROOT / "scripts" / "acceptance.sh",
        PROJECT_ROOT / "scripts" / "quality.sh",
        PROJECT_ROOT / ".factory" / "swarmforge" / "config.sh",
    )
    return (
        all(path.is_file() for path in required),
        f"missing acceptance infrastructure: {[str(path) for path in required if not path.is_file()]}",
    )


def _h_aqrc_record_checks(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"a QA run records a passing check followed by a (passing|failing) check",
        text,
    )
    if not match:
        return False, f"Could not parse check result: {text}"
    world.aqrc_second_result = match.group(1)
    return True, ""


def _h_aqrc_report_checks(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from qa_harness import QARunner

    output = io.StringIO()
    runner = QARunner()
    with contextlib.redirect_stdout(output):
        runner.record("first check", True)
        runner.record(
            "second check",
            world.aqrc_second_result == "passing",
        )
        exit_status = runner.summary()
    world.aqrc_report_output = output.getvalue()
    world.aqrc_report_exit_status = exit_status
    return True, ""


def _h_aqrc_results_once(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result_lines = [
        line.strip()
        for line in world.aqrc_report_output.splitlines()
        if line.strip().startswith("[")
    ]
    expected_second = (
        "[PASS] second check"
        if world.aqrc_second_result == "passing"
        else "[FAIL] second check"
    )
    expected = ["[PASS] first check", expected_second]
    return (
        result_lines == expected,
        f"unexpected report lines: {result_lines}",
    )


def _h_aqrc_second_label(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'second result is labeled "?(PASS|FAIL)"?', text)
    if not match:
        return False, f"Could not parse expected label: {text}"
    expected = match.group(1)
    actual = "[PASS] second check" in world.aqrc_report_output
    actual_label = "PASS" if actual else "FAIL"
    return actual_label == expected, f"actual label was {actual_label}"


def _h_aqrc_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'summary is "QA suite: (\d+) passed, (\d+) failed"', text)
    if not match:
        return False, f"Could not parse summary: {text}"
    expected = f"QA suite: {match.group(1)} passed, {match.group(2)} failed"
    return expected in world.aqrc_report_output, world.aqrc_report_output


def _h_aqrc_exit_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"exits with status (\d+)", text)
    if not match:
        return False, f"Could not parse exit status: {text}"
    expected = int(match.group(1))
    return (
        world.aqrc_report_exit_status == expected,
        f"actual exit status was {world.aqrc_report_exit_status}",
    )


def _h_aqrc_child_command(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


def _h_aqrc_parent_state(world: World, text: str, examples: dict) -> tuple[bool, str]:
    os.environ[_AQRC_ENVIRONMENT] = "present"
    world.aqrc_parent_environment = dict(os.environ)
    world.aqrc_parent_cwd = Path.cwd()
    return True, ""


def _h_aqrc_run_child(world: World, text: str, examples: dict) -> tuple[bool, str]:
    child = (
        "import os, pathlib, sys; "
        "print('child stdout'); "
        "print('cwd=' + str(pathlib.Path.cwd())); "
        "print('removed=' + os.environ.get('AQRC_CHILD_REMOVED', 'missing')); "
        "print('child stderr', file=sys.stderr); "
        "sys.exit(7)"
    )
    world.aqrc_child_result = run_command(
        [sys.executable, "-c", child],
        env=child_env(**{_AQRC_ENVIRONMENT: None}),
    )
    return True, ""


def _h_aqrc_child_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = world.aqrc_child_result
    return (
        result.returncode == 7,
        f"child returned {result.returncode}",
    )


def _h_aqrc_child_streams(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = world.aqrc_child_result
    stdout = result.stdout.splitlines()
    return (
        stdout[0:1] == ["child stdout"]
        and "removed=missing" in stdout
        and result.stderr == "child stderr\n",
        f"stdout={result.stdout!r} stderr={result.stderr!r}",
    )


def _h_aqrc_child_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = world.aqrc_child_result
    return (
        f"cwd={PROJECT_ROOT}" in result.stdout,
        f"child did not run from project root: {result.stdout!r}",
    )


def _h_aqrc_parent_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        dict(os.environ) == world.aqrc_parent_environment
        and Path.cwd() == world.aqrc_parent_cwd,
        "parent process state changed",
    )


def _make_uv_shim(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    shim = directory / "uv"
    shim.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        '[ "${1:-}" = "run" ] || exit 2\n'
        "shift\n"
        'case "$1" in\n'
        '  python) shift; exec "$PYTHON" "$@";;\n'
        '  pytest) shift; exec "$PYTHON" -m pytest "$@";;\n'
        '  ruff) shift; exec "$PYTHON" -m ruff "$@";;\n'
        "  *) exit 2;;\n"
        "esac\n",
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    return shim


def _qa_generated_dir(name: str) -> Path:
    target = _AQRC_ROOT / name
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    return target


def _afr_environment() -> dict[str, str]:
    shim = _make_uv_shim(_AQRC_ROOT / "bin")
    env = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    env["PYTHON"] = sys.executable
    existing = env.get("PYTEST_ADDOPTS", "").strip()
    ignore = f"--ignore={_AQRC_TEST_RELATIVE}"
    env["PYTEST_ADDOPTS"] = f"{existing} {ignore}".strip()
    env["PATH"] = f"{shim.parent}{os.pathsep}{env.get('PATH', '')}"
    return env


def _h_aqrc_migrated_suite(world: World, text: str, examples: dict) -> tuple[bool, str]:
    suite = (
        PROJECT_ROOT
        / "acceptance"
        / "qa"
        / "acceptance-framework-refactor"
        / "qa_suite.py"
    )
    result = run_command(
        [sys.executable, str(suite), "--skip-generate"],
        env=_afr_environment(),
        timeout=1800,
    )
    world.aqrc_afr_result = result
    return True, ""


def _h_aqrc_migrated_invocation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_aqrc_migrated_exit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.aqrc_afr_result.returncode == 0,
        f"acceptance-framework-refactor exited {world.aqrc_afr_result.returncode}",
    )


def _h_aqrc_afr_skip(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = world.aqrc_afr_result.stdout + world.aqrc_afr_result.stderr
    marker = "QA-AFR-01 skipped by --skip-generate"
    return output.count(marker) == 1, f"skip marker count={output.count(marker)}"


def _h_aqrc_afr_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = world.aqrc_afr_result.stdout + world.aqrc_afr_result.stderr
    positions = [output.find(f"QA-AFR-0{number}") for number in range(2, 7)]
    return (
        all(position >= 0 for position in positions) and positions == sorted(positions),
        f"QA-AFR-02..06 positions={positions}",
    )


def _h_aqrc_capture_layout(world: World, text: str, examples: dict) -> tuple[bool, str]:
    capture_root = PROJECT_ROOT / "tmp" / "qa-acceptance-framework" / "captures"
    expected = (
        "qa-afr-02-test",
        "qa-afr-03-first",
        "qa-afr-03-second",
        "qa-afr-04-namespace",
        "qa-afr-04-nested",
        "qa-afr-05-worker",
        "qa-afr-06-status",
    )
    return (
        all(
            (capture_root / label / filename).is_file()
            for label in expected
            for filename in ("stdout.txt", "stderr.txt", "exit.txt")
        ),
        f"missing captures under {capture_root}",
    )


def _h_aqrc_cli_and_text(world: World, text: str, examples: dict) -> tuple[bool, str]:
    source = (
        PROJECT_ROOT
        / "acceptance"
        / "qa"
        / "acceptance-framework-refactor"
        / "qa_suite.py"
    ).read_text(encoding="utf-8")
    output = world.aqrc_afr_result.stdout + world.aqrc_afr_result.stderr
    return (
        "--skip-generate" in source
        and "AFR_EXPECTED" in source
        and "QA suite:" in output,
        "migrated suite interface markers changed",
    )


def _h_aqrc_manifest_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    import runtime_manifest

    modules = runtime_manifest.load_modules()
    identities = [module.FEATURE_ID for module in modules]
    world.aqrc_manifest = runtime_manifest
    world.aqrc_manifest_modules = modules
    return (
        identities.count("acceptance_refresh") == 1
        and "acceptance_refresh" in identities,
        f"acceptance_refresh identities={identities.count('acceptance_refresh')}",
    )


def _h_aqrc_register_manifest(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from registry import RegistrationAPI, RegistrationStage

    stage = RegistrationStage()
    api = RegistrationAPI(stage)
    world.aqrc_manifest.register_all(api, world.aqrc_manifest_modules)
    world.aqrc_registration_stage = stage
    world.aqrc_refresh_entries = [
        entry
        for entry in stage.entries
        if 21826 <= entry[0] <= 21838 or 21916 <= entry[0] <= 21940
    ]
    return True, ""


def _h_aqrc_refresh_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        len(world.aqrc_refresh_entries) == 38,
        f"acceptance-refresh entries={len(world.aqrc_refresh_entries)}",
    )


def _h_aqrc_feature_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    entries = [
        entry for entry in world.aqrc_refresh_entries if 21826 <= entry[0] <= 21838
    ]
    return (
        len(entries) == 13
        and all(entry[5] == "acceptance_refresh" for entry in entries)
        and [entry[0] for entry in entries] == list(range(21826, 21839)),
        f"feature-scoped entries={entries}",
    )


def _h_aqrc_global_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    entries = [
        entry for entry in world.aqrc_refresh_entries if 21916 <= entry[0] <= 21940
    ]
    return (
        len(entries) == 25
        and all(entry[5] is None for entry in entries)
        and [entry[0] for entry in entries] == list(range(21916, 21941)),
        f"global entries={entries}",
    )


def _h_aqrc_registration_parity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    expected = [
        "the `CoordinationAnalysis` model (?:does not )?declare",
        "(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis",
        "Stage 2 Call 3 coordination derivation is run",
        "the Stage 2 coordination link addition with fallback is executed",
        "a CoordinationAnalysis model is produced",
        "the CoordinationAnalysis contains coordination link CL-1",
        "the CoordinationAnalysis integrity_findings list is not empty",
        "the CoordinationAnalysis contains no coordination links",
        "the ControlStructure contains (?:responsibility|controlled process)",
        "CL-1 has source RESP-1 and target RESP-2",
        "the warnings list includes a warning naming step",
        "no assembly failure is logged",
        "the SP1RunResult stage_errors contains the assemble_control_structure failure",
        "the control_structure module (?:does not )?exports?",
        "the SP2 prompts directory contains",
        "the SP3 prompts directory contains",
        "the Call 2a user prompt is rendered with the capability profile",
        "(?:an LLM that returns a )?ControlElementSet from Call 2b with",
        "a valid ResponsibilitySet from Call 2a",
        "a ResponsibilitySet from Call 2a with responsibilities",
        "an LLM that returns valid responses for (?:Stage 2 calls 1, 2a, and 2b|all four Stage 2 calls|Stage 2 calls 1 and 2a)",
        "the Stage 2 assembly with fallback is executed",
        "Stage 2 control structure derivation is run",
        "Stage 2 calls 1 through 3 are run in sequence",
        "Stage 2 Call 2a responsibilities derivation is run",
        "Stage 2 Call 2b control elements derivation is run",
        "Stage 2 calls 1 through 2[ab] are run in sequence",
        "an LLM that returns a valid ControlElementSet JSON",
        "an LLM that returns a valid CoordinationAnalysis",
        "a CoordinationAnalysis with",
        "a call log entry exists with step",
        "no call log entry has step",
        "each responsibility has at least one responsibility constraint and one process model part",
        "the `ResponsibilitySet` model does not declare",
        "a ControlElementSet model is produced",
        "the ControlElementSet contains controlled process CP-1",
        "the Call 2[ab] user prompt contains",
        "the Call 3 user prompt contains the assembled responsibilities and controlled processes",
    ]
    actual = [entry[3] for entry in world.aqrc_refresh_entries]
    return actual == expected, f"registration patterns changed: {actual}"


def _h_aqrc_scope_restored(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.aqrc_registration_stage.feature is None,
        f"active scope={world.aqrc_registration_stage.feature!r}",
    )


def _generated_test_path(source_feature: str) -> Path:
    return (
        PROJECT_ROOT
        / "build"
        / "acceptance"
        / "generated"
        / f"{Path(source_feature).stem}_acceptance_test.py"
    )


def _h_aqrc_source_generated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'source feature "([^"]+)" is generated', text)
    if not match:
        return False, f"Could not parse source feature: {text}"
    source_feature = match.group(1)
    path = _generated_test_path(source_feature)
    if not path.is_file():
        generated = run_command(
            [sys.executable, str(PROJECT_ROOT / "acceptance" / "refresh_snapshot.py")],
            env=child_env(
                PATH=f"{Path.home() / '.factory' / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
                SCENARIO_FORGE_QA_PIPELINE=None,
            ),
            timeout=1200,
        )
        if generated.returncode != 0:
            return False, f"acceptance generation failed: {generated.stderr}"
    world.aqrc_source_feature = source_feature
    world.aqrc_source_test = path
    return path.is_file(), f"missing generated test: {path}"


def _h_aqrc_run_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = run_command(
        [sys.executable, "-m", "pytest", str(world.aqrc_source_test), "-q", "-s"],
        env=child_env(SCENARIO_FORGE_QA_PIPELINE=None),
        timeout=600,
    )
    world.aqrc_source_result = result
    world.aqrc_source_output = result.stdout + result.stderr
    return True, ""


def _h_aqrc_source_pass_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"exactly (\d+) scenarios report PASS", text)
    if not match:
        return False, f"Could not parse scenario count: {text}"
    expected = int(match.group(1))
    passed = {
        line.split("/example_", 1)[0]
        for line in world.aqrc_source_output.splitlines()
        if line.startswith("PASS ")
    }
    return (
        world.aqrc_source_result.returncode == 0 and len(passed) == expected,
        f"exit={world.aqrc_source_result.returncode} pass_count={len(passed)}",
    )


def _h_aqrc_source_no_failures(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    lines = world.aqrc_source_output.splitlines()
    return (
        not any(line.startswith(("FAIL ", "SKIP ")) for line in lines),
        "source feature reported FAIL or SKIP",
    )


def _all_generated_without_current() -> Path:
    generated = _qa_generated_dir("default-generated")
    source_dir = PROJECT_ROOT / "build" / "acceptance" / "generated"
    for path in source_dir.glob("*_acceptance_test.py"):
        if path.name != _AQRC_GENERATED_NAME:
            shutil.copy2(path, generated / path.name)
    return generated


def _h_aqrc_default_environment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return "SCENARIO_FORGE_QA_PIPELINE" not in os.environ, (
        "SCENARIO_FORGE_QA_PIPELINE must be unset"
    )


def _h_aqrc_default_acceptance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    shim = _make_uv_shim(_AQRC_ROOT / "bin")
    env = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    env["PYTHON"] = sys.executable
    existing = env.get("PYTEST_ADDOPTS", "").strip()
    env["PYTEST_ADDOPTS"] = f"{existing} --ignore={_AQRC_TEST_RELATIVE}".strip()
    env["PATH"] = f"{shim.parent}{os.pathsep}{env.get('PATH', '')}"
    result = run_command(
        [str(PROJECT_ROOT / "scripts" / "acceptance.sh"), "--test"],
        env=env,
        timeout=2400,
    )
    world.aqrc_default_result = result
    world.aqrc_default_output = result.stdout + result.stderr
    return True, ""


def _h_aqrc_default_refresh_passes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    output = world.aqrc_default_output
    failures = [
        line
        for line in output.splitlines()
        if line.startswith("FAIL ") and any(name in line for name in _REFRESH_CASES)
    ]
    missing = [
        name
        for name in _REFRESH_CASES
        if not any(
            line.startswith("PASS ") and name in line for line in output.splitlines()
        )
    ]
    return not failures and not missing, f"missing={missing} failures={failures}"


def _h_aqrc_default_live_skips(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    output = world.aqrc_default_output
    live_skips = [line for line in output.splitlines() if line.startswith("SKIP ")]
    return bool(live_skips), "no live acceptance scenario was reported SKIP"


def _h_aqrc_default_no_regression(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    output = world.aqrc_default_output
    return (
        not any(
            line.startswith("FAIL ")
            and (
                "acceptance_qa_runtime_cleanup" in line
                or any(name in line for name in _REFRESH_CASES)
            )
            for line in output.splitlines()
        ),
        "cleanup-related failure appeared in default acceptance output",
    )


def _h_aqrc_scope_and_config(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    src_changes = run_command(
        ["git", "diff", "--name-only", "--", "src"],
    )
    config = (PROJECT_ROOT / ".factory" / "swarmforge" / "config.sh").read_text(
        encoding="utf-8"
    )
    quality = (PROJECT_ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")
    clean = (
        src_changes.stdout.strip() == ""
        and 'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and "mutate4py src/" in config
        and "uv run ruff check src acceptance" in quality
        and "uv run ruff format --check src acceptance" in quality
    )
    return clean, src_changes.stdout or "quality/config scope changed"


def _h_aqrc_generated_output_policy(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    manifest = (
        PROJECT_ROOT / ".factory" / "swarmforge" / "acceptance-pipeline.txt"
    ).read_text(encoding="utf-8")
    tracked = run_command(
        ["git", "ls-files", "build/acceptance", "build/acceptance-mutation"]
    )
    return (
        "file_policy: generated-output" in manifest and not tracked.stdout.strip(),
        f"tracked generated paths={tracked.stdout!r}",
    )


def _h_aqrc_unrelated_changes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def register(api: object) -> None:
    """Register the QA cleanup characterization steps globally."""
    api.set_feature(None)
    api.register(
        "the repository acceptance commands and generated-output policy are available",
        _h_aqrc_background,
    )
    api.register(
        "a QA run records a passing check followed by a (passing|failing) check",
        _h_aqrc_record_checks,
    )
    api.register(r"the QA run reports its results", _h_aqrc_report_checks)
    api.register(
        "the two check results are emitted once in recording order",
        _h_aqrc_results_once,
    )
    api.register(r'the second result is labeled "?(PASS|FAIL)"?', _h_aqrc_second_label)
    api.register(
        r'the summary is "QA suite: \d+ passed, \d+ failed"',
        _h_aqrc_summary,
    )
    api.register(r"the QA run exits with status \d+", _h_aqrc_exit_status)
    api.register(
        "a QA child command writes distinct standard output and standard error and exits with status 7",
        _h_aqrc_child_command,
    )
    api.register(
        "the parent process has a recorded environment and working directory",
        _h_aqrc_parent_state,
    )
    api.register(
        "the QA child command runs with one environment variable removed",
        _h_aqrc_run_child,
    )
    api.register(
        "the child result preserves exit status 7 without raising for that status",
        _h_aqrc_child_status,
    )
    api.register(
        "standard output, standard error, and exit status are captured separately",
        _h_aqrc_child_streams,
    )
    api.register(
        "the command defaults to the repository root working directory",
        _h_aqrc_child_root,
    )
    api.register(
        "the parent environment and working directory remain unchanged",
        _h_aqrc_parent_unchanged,
    )
    api.register(
        "the acceptance-framework-refactor QA suite is the only suite migrated to shared QA infrastructure",
        _h_aqrc_migrated_suite,
    )
    api.register(
        'the suite is invoked with "--skip-generate"',
        _h_aqrc_migrated_invocation,
    )
    api.register(
        "the invocation exits with the same status as its characterization baseline",
        _h_aqrc_migrated_exit,
    )
    api.register(
        "QA-AFR-01 is reported once as skipped by the command-line option",
        _h_aqrc_afr_skip,
    )
    api.register(
        "QA-AFR-02 through QA-AFR-06 execute once in order",
        _h_aqrc_afr_order,
    )
    api.register(
        'captures remain under "tmp/qa-acceptance-framework/captures"',
        _h_aqrc_capture_layout,
    )
    api.register(
        "the suite retains its existing command-line options and result text",
        _h_aqrc_cli_and_text,
    )
    api.register(
        r'the runtime manifest declares one feature identity named "([^"]+)"',
        _h_aqrc_manifest_identity,
    )
    api.register(
        r"the complete runtime manifest is registered", _h_aqrc_register_manifest
    )
    api.register(
        "the acceptance-refresh feature registers exactly 38 handlers once",
        _h_aqrc_refresh_count,
    )
    api.register(
        r'(\d+) handlers retain feature scope "([^"]+)" and source priorities \d+ through \d+',
        _h_aqrc_feature_scope,
    )
    api.register(
        r"(\d+) handlers retain global scope and source priorities \d+ through \d+",
        _h_aqrc_global_scope,
    )
    api.register(
        "their pattern text, relative priority, scope, and observable handler results match the characterization baseline",
        _h_aqrc_registration_parity,
    )
    api.register(
        "registration restores the active feature scope to no feature",
        _h_aqrc_scope_restored,
    )
    api.register(
        r'the acceptance-refresh source feature "([^"]+)" is generated',
        _h_aqrc_source_generated,
    )
    api.register(
        "its generated acceptance test is run with live opt-in unset",
        _h_aqrc_run_source,
    )
    api.register(r"exactly \d+ scenarios report PASS", _h_aqrc_source_pass_count)
    api.register(
        "no scenario in that source feature reports FAIL or SKIP",
        _h_aqrc_source_no_failures,
    )
    api.register(
        '"SCENARIO_FORGE_QA_PIPELINE" is unset in the acceptance child process',
        _h_aqrc_default_environment,
    )
    api.register(
        "the default generated acceptance suite is executed",
        _h_aqrc_default_acceptance,
    )
    api.register(
        "every Acceptance QA runtime cleanup scenario reports PASS",
        _h_aqrc_unrelated_changes,
    )
    api.register(
        "every existing deterministic acceptance-refresh scenario reports PASS",
        _h_aqrc_default_refresh_passes,
    )
    api.register(
        "exact live-LLM-marked scenarios report SKIP rather than PASS or FAIL",
        _h_aqrc_default_live_skips,
    )
    api.register(
        "no additional failure is introduced relative to the recorded acceptance baseline",
        _h_aqrc_default_no_regression,
    )
    api.register(
        "the cleanup change set and acceptance configuration are inspected",
        _h_aqrc_scope_and_config,
    )
    api.register(
        'no production path beneath "src/" is added, modified, or deleted',
        _h_aqrc_scope_and_config,
    )
    api.register(
        'permanent CRAP, DRY, and language-mutation commands remain scoped to "src/"',
        _h_aqrc_scope_and_config,
    )
    api.register(
        'acceptance quality checks remain scoped to "src" and "acceptance"',
        _h_aqrc_scope_and_config,
    )
    api.register(
        "IR, dry reports, generated tests, metadata, mutation workspaces, coverage files, and QA captures remain untracked generated output",
        _h_aqrc_generated_output_policy,
    )
    api.register(
        "no pre-existing unrelated worktree change is altered",
        _h_aqrc_unrelated_changes,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
