"""Acceptance QA harness characterization handlers."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from runtime_shared import PROJECT_ROOT, World

_AQRC_ROOT = PROJECT_ROOT / "tmp" / "qa-acceptance-qa-runtime-cleanup"
_AQRC_TEST_RELATIVE = (
    "build/acceptance/generated/acceptance_qa_runtime_cleanup_acceptance_test.py"
)
_AQRC_ENVIRONMENT = "AQRC_CHILD_REMOVED"
_QA_DIRECTORY = PROJECT_ROOT / "acceptance" / "qa"


def _run_external_command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one checked-in command without changing this acceptance process."""
    return subprocess.run(
        list(argv),
        cwd=str(cwd or PROJECT_ROOT),
        env=dict(env) if env is not None else None,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _without_live_opt_in() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("SCENARIO_FORGE_QA_PIPELINE", None)
    return environment


def _acceptance_child_environment() -> dict[str, str]:
    """Build the isolated environment shared by the two acceptance checks."""
    shim = _make_uv_shim(_AQRC_ROOT / "bin")
    environment = _without_live_opt_in()
    environment["PYTHON"] = sys.executable
    existing = environment.get("PYTEST_ADDOPTS", "").strip()
    environment["PYTEST_ADDOPTS"] = (
        f"{existing} --ignore={_AQRC_TEST_RELATIVE}"
    ).strip()
    environment["PATH"] = f"{shim.parent}{os.pathsep}{environment.get('PATH', '')}"
    return environment


def _harness_environment(
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Expose the QA-only harness to an isolated test-glue child process."""
    environment = dict(os.environ if base is None else base)
    paths = [str(_QA_DIRECTORY), environment.get("PYTHONPATH", "")]
    environment["PYTHONPATH"] = os.pathsep.join(path for path in paths if path)
    return environment


def _run_harness_script(
    script: str,
    *,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run_external_command(
        [sys.executable, "-c", script],
        env=_harness_environment(env),
    )


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
    script = f"""
from qa_harness import QARunner

runner = QARunner()
runner.record("first check", True)
runner.record("second check", {world.aqrc_second_result == "passing"!r})
raise SystemExit(runner.summary())
"""
    result = _run_harness_script(script)
    world.aqrc_report_output = result.stdout
    world.aqrc_report_exit_status = result.returncode
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
    environment = dict(world.aqrc_parent_environment)
    environment[_AQRC_ENVIRONMENT] = "present"
    script = f"""
import json
import sys

from qa_harness import child_env, run_command

result = run_command(
    [sys.executable, "-c", {child!r}],
    env=child_env(**{{{_AQRC_ENVIRONMENT!r}: None}}),
)
print(json.dumps({{
    "returncode": result.returncode,
    "stdout": result.stdout,
    "stderr": result.stderr,
}}))
"""
    harness_result = _run_harness_script(script, env=environment)
    try:
        captured = json.loads(harness_result.stdout)
        world.aqrc_child_result = subprocess.CompletedProcess(
            [sys.executable],
            captured["returncode"],
            captured["stdout"],
            captured["stderr"],
        )
    except (KeyError, json.JSONDecodeError, TypeError):
        world.aqrc_child_result = subprocess.CompletedProcess(
            [sys.executable],
            harness_result.returncode,
            harness_result.stdout,
            harness_result.stderr,
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


def register_harness_handlers(api: object) -> None:
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


__all__ = ["register_harness_handlers"]
