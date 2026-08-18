"""CLI and successful-mode handlers for the Phase 4 QA migration."""

from __future__ import annotations

import os
import re
import shlex
import subprocess

from runtime_shared import PROJECT_ROOT, World

from .phase4_qa_refresh_migration_support import (
    _OPT_IN,
    _check_lines,
    _cleanup_fixture,
    _finish_sentinel,
    _fixture_environment,
    _input_arguments,
    _invocations,
    _new_temp_root,
    _output,
    _run_qa_suite,
    _start_sentinel,
    _write_pipeline_standin,
)


def _h_baseline(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'commit "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse baseline commit: {text}"
    expected = match.group(1)
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", expected, "HEAD"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0, f"baseline {expected} is not an ancestor of HEAD"


def _h_opt_in_unset(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _OPT_IN not in os.environ, f"{_OPT_IN} is set"


def _h_help(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p4qrm_help_result = _run_qa_suite(["--help"])
    return True, ""


def _h_status_zero(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = getattr(world, "p4qrm_help_result", None)
    if result is None:
        return False, "help was not requested"
    return result.returncode == 0, f"help exited with {result.returncode}"


def _h_help_option(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'help advertises option "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse option: {text}"
    expected = match.group(1)
    output = _output(world.p4qrm_help_result)
    return expected in output, f"help does not contain {expected}"


def _h_help_modes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = _output(world.p4qrm_help_result).replace("\n", " ")
    expected = re.compile(r"\(--static\s*\|\s*--pipeline\s*\|\s*--all\)")
    return bool(expected.search(output)), "required mode group is absent from help"


def _h_success_standin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    world.p4qrm_standin_mode = "success"
    _write_pipeline_standin(root, "success")
    _start_sentinel(world)
    world.p4qrm_runs = []
    world.p4qrm_invocation_counts = []
    return True, ""


def _h_run_mode_twice(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'QA mode "([^"]+)" is run twice', text)
    if match is None:
        return False, f"Could not parse QA mode: {text}"
    mode = match.group(1)
    runs: list[subprocess.CompletedProcess[str]] = []
    counts: list[int] = []
    for _ in range(2):
        before = len(_invocations(world))
        result = _run_qa_suite(
            [mode, *_input_arguments(world)],
            env=_fixture_environment(world),
        )
        after = len(_invocations(world))
        runs.append(result)
        counts.append(after - before)
    world.p4qrm_runs = runs
    world.p4qrm_invocation_counts = counts
    _finish_sentinel(world)
    return True, ""


def _h_runs_successful(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = getattr(world, "p4qrm_runs", None)
    if not runs:
        runs = getattr(world, "p4qrm_nested_runs", [])
    return (
        len(runs) == 2 and all(result.returncode == 0 for result in runs),
        f"run statuses={[result.returncode for result in runs]}",
    )


def _h_checks_once(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = getattr(world, "p4qrm_runs", [])
    if len(runs) != 2:
        return False, "two QA runs were not recorded"
    expected_match = re.search(
        r"QA suite: (\d+) passed, 0 failed",
        str(examples.get("summary", "")),
    )
    expected_count = int(expected_match.group(1)) if expected_match else None
    details = []
    for result in runs:
        lines = _check_lines(_output(result))
        details.append((len(lines), len(set(lines))))
        if (
            expected_count is None
            or len(lines) != expected_count
            or len(lines) != len(set(lines))
            or any("[FAIL]" in line for line in lines)
        ):
            return False, f"check line counts={details}"
    return True, ""


def _h_identical_checks(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = getattr(world, "p4qrm_runs", [])
    if len(runs) != 2:
        return False, "two QA runs were not recorded"
    first = _check_lines(_output(runs[0]))
    second = _check_lines(_output(runs[1]))
    return first == second, "ordered check results differ"


def _h_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'run reports "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse summary: {text}"
    summary = match.group(1)
    return all(_output(result).count(summary) == 1 for result in world.p4qrm_runs), (
        f"summary {summary!r} was not emitted once per run"
    )


def _h_standin_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"invoked (\d+) time per run", text)
    if match is None:
        return False, f"Could not parse stand-in count: {text}"
    expected = int(match.group(1))
    actual = getattr(world, "p4qrm_invocation_counts", [])
    return actual == [expected, expected], f"invocation counts={actual}"


def _h_endpoint_zero(world: World, text: str, examples: dict) -> tuple[bool, str]:
    passed = (
        getattr(world, "p4qrm_endpoint_contacts", -1) == 0,
        f"endpoint contacts={getattr(world, 'p4qrm_endpoint_contacts', None)}",
    )
    _cleanup_fixture(world)
    return passed


def _h_invalid_invocation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    world.p4qrm_standin_mode = "success"
    _write_pipeline_standin(root, "success")
    argument_match = re.search(r'invoked with "([^"]+)"', text)
    if argument_match is None:
        return False, f"Could not parse invocation: {text}"
    raw_arguments = argument_match.group(1)
    arguments = [] if raw_arguments == "none" else shlex.split(raw_arguments)
    world.p4qrm_invalid_result = _run_qa_suite(
        arguments,
        env=_fixture_environment(world),
    )
    return True, ""


def _h_invalid_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"exits with status (\d+)", text)
    if match is None:
        return False, f"Could not parse status: {text}"
    expected = int(match.group(1))
    result = getattr(world, "p4qrm_invalid_result", None)
    if result is None:
        result = getattr(world, "p4qrm_failure_result", None)
    if result is None:
        return False, "no QA result was recorded"
    actual = result.returncode
    return actual == expected, f"actual status={actual}"


def _h_output_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'output contains "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse message: {text}"
    expected = match.group(1)
    return expected in _output(world.p4qrm_invalid_result), (
        f"output does not contain {expected!r}"
    )


def _h_no_pipeline_child(world: World, text: str, examples: dict) -> tuple[bool, str]:
    no_child = not _invocations(world)
    _cleanup_fixture(world)
    return no_child, "pipeline stand-in was invoked"
