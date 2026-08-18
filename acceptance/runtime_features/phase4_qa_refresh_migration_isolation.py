"""Failure and nested-process handlers for the Phase 4 QA migration."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import PROJECT_ROOT, World

from .phase4_qa_refresh_migration_support import (
    _QA_TMP_ROOT,
    _check_lines,
    _cleanup_fixture,
    _fixture_environment,
    _input_arguments,
    _invocations,
    _new_temp_root,
    _output,
    _run_qa_suite,
    _write_pipeline_standin,
)


def _h_failure_standin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    world.p4qrm_standin_mode = "failure"
    _write_pipeline_standin(root, "failure")
    return True, ""


def _h_run_failure_pipeline(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.p4qrm_failure_result = _run_qa_suite(
        ["--pipeline", *_input_arguments(world)],
        env=_fixture_environment(world),
    )
    world.p4qrm_failure_invocations = _invocations(world)
    return True, ""


def _failure_invocation(world: World) -> dict[str, Any] | None:
    entries = getattr(world, "p4qrm_failure_invocations", [])
    return entries[0] if entries else None


def _h_failure_arguments(world: World, text: str, examples: dict) -> tuple[bool, str]:
    invocation = _failure_invocation(world)
    if invocation is None:
        return False, "pipeline stand-in did not receive an invocation"
    argv = invocation.get("argv", [])
    root = world.p4qrm_fixture_root
    required = [
        "--use-case",
        str(root / "use-case.txt"),
        "--risk-extraction",
        str(root / "risks.json"),
        "--profile",
        str(root / "profile.yaml"),
    ]
    return (
        argv[:3] == ["run", "scenario-forge", "stpa-run"]
        and all(value in argv for value in required)
        and "--output-dir" in argv,
        f"stand-in argv={argv}",
    )


def _h_failure_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    invocation = _failure_invocation(world)
    return (
        invocation is not None and invocation.get("cwd") == str(PROJECT_ROOT),
        f"stand-in cwd={invocation.get('cwd') if invocation else None}",
    )


def _h_failure_streams(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = world.p4qrm_failure_result
    invocation = _failure_invocation(world)
    return (
        invocation is not None
        and invocation.get("mode") == "failure"
        and result.returncode == 1
        and (world.p4qrm_fixture_root / "stdout.txt").read_text(encoding="utf-8")
        == "phase4 stand-in stdout\n"
        and (world.p4qrm_fixture_root / "stderr.txt").read_text(encoding="utf-8")
        == "phase4 stand-in stderr\n",
        "pipeline failure streams were not preserved",
    )


def _h_failure_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'QA command reports "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse failure summary: {text}"
    return match.group(1) in _output(world.p4qrm_failure_result), (
        f"missing failure summary in {_output(world.p4qrm_failure_result)!r}"
    )


def _h_failure_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.p4qrm_failure_result.returncode == 1,
        f"QA suite status={world.p4qrm_failure_result.returncode}",
    )


def _h_parent_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    environment = getattr(world, "p4qrm_parent_environment", None)
    cwd = getattr(world, "p4qrm_parent_cwd", None)
    if environment is None or cwd is None:
        return False, "parent environment and working directory were not recorded"
    return (
        dict(os.environ) == environment and Path.cwd() == cwd,
        "parent process state changed",
    )


def _h_parent_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p4qrm_parent_environment = dict(os.environ)
    world.p4qrm_parent_cwd = Path.cwd()
    return True, ""


def _h_failure_output_removed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    invocation = _failure_invocation(world)
    output_dir = Path(invocation["output_dir"]) if invocation else None
    removed = output_dir is not None and not output_dir.exists()
    _cleanup_fixture(world)
    return removed, f"temporary output exists: {output_dir}"


def _h_nested_invocation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _QA_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    tempdir = tempfile.TemporaryDirectory(prefix="nested-", dir=str(_QA_TMP_ROOT))
    nested = Path(tempdir.name) / "a" / "b"
    nested.mkdir(parents=True)
    world.p4qrm_nested_tempdir = tempdir
    world.p4qrm_nested_cwd = nested
    world.p4qrm_caller_cwd = Path.cwd()
    return True, ""


def _h_nested_static(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = [
        _run_qa_suite(["--static"], cwd=world.p4qrm_nested_cwd),
        _run_qa_suite(["--static"], cwd=world.p4qrm_nested_cwd),
    ]
    world.p4qrm_nested_runs = runs
    return True, ""


def _h_nested_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p4qrm_nested_runs
    return (
        len(runs) == 2
        and all(
            result.returncode == 0
            and "QA suite: 519 passed, 0 failed" in _output(result)
            for result in runs
        ),
        f"nested statuses={[result.returncode for result in runs]}",
    )


def _h_nested_same(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p4qrm_nested_runs
    return (
        _check_lines(_output(runs[0])) == _check_lines(_output(runs[1])),
        "nested check order differs",
    )


def _h_nested_cwd_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    unchanged = Path.cwd() == world.p4qrm_caller_cwd
    world.p4qrm_nested_tempdir.cleanup()
    return unchanged, "caller working directory changed"
