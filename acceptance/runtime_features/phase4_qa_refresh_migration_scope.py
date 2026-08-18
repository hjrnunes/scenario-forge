"""Scope and artifact handlers for the Phase 4 QA migration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from runtime_shared import PROJECT_ROOT, World

from .phase4_qa_refresh_migration_support import (
    _BASELINE,
    _DRY_ROOT,
    _GENERATED_ROOT,
    _IR_ROOT,
    _MUTATION_ROOT,
    _content_snapshot,
    _generated_test_path,
    _git_diff_names,
    _git_show,
    _run,
    _run_qa_suite,
    _scope_is_unchanged,
    _status_snapshot,
)


def _h_change_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p4qrm_qa_changes = _git_diff_names("acceptance/qa")
    return True, ""


def _h_only_refresh_suite(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = "acceptance/qa/acceptance-refresh/qa_suite.py"
    suites = [path for path in world.p4qrm_qa_changes if path.endswith("/qa_suite.py")]
    return suites == [expected], f"changed suites={suites}"


def _h_other_suites(world: World, text: str, examples: dict) -> tuple[bool, str]:
    current = sorted(
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "acceptance" / "qa").rglob("qa_suite.py")
    )
    baseline = [
        path
        for path in _git_tree_paths("acceptance/qa")
        if path.endswith("/qa_suite.py")
    ]
    excluded = "acceptance/qa/acceptance-refresh/qa_suite.py"
    current = [path for path in current if path != excluded]
    baseline = [path for path in baseline if path != excluded]
    common = sorted(set(current) & set(baseline))
    return (
        all(_git_show(path) == (PROJECT_ROOT / path).read_bytes() for path in common),
        f"suite sets differ: current={current} baseline={baseline}",
    )


def _git_tree_paths(root: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", _BASELINE, "--", root],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def _h_harness_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    path = "acceptance/qa/qa_harness.py"
    return _git_show(path) == (PROJECT_ROOT / path).read_bytes(), f"{path} changed"


def _h_refresh_registration_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    path = "acceptance/runtime_features/acceptance_refresh.py"
    return _git_show(path) == (PROJECT_ROOT / path).read_bytes(), f"{path} changed"


def _h_no_src_changes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    changes = _git_diff_names("src")
    return not changes, f"source changes={changes}"


def _h_config_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    unchanged, detail = _scope_is_unchanged()
    return unchanged, detail


def _h_worktree_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    status = _status_snapshot()
    world.p4qrm_status_before = status
    world.p4qrm_content_before = _content_snapshot(status)
    return True, ""


def _h_run_hygiene(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if os.environ.get("P4QRM_HYGIENE_CHILD") == "1":
        world.p4qrm_hygiene_result = subprocess.CompletedProcess(
            ["phase4-hygiene-child"], 0, "", ""
        )
        return True, ""
    result = _run_qa_suite(["--static"])
    generated_test = _generated_test_path("phase4_qa_refresh_migration.feature")
    child_environment = dict(os.environ)
    child_environment["P4QRM_HYGIENE_CHILD"] = "1"
    generated_result = _run(
        [sys.executable, "-m", "pytest", str(generated_test), "-q", "-s"],
        env=child_environment,
        timeout=600,
    )
    world.p4qrm_hygiene_result = result
    world.p4qrm_generated_result = generated_result
    return (
        result.returncode == 0 and generated_result.returncode == 0,
        f"migrated suite status={result.returncode}, generated status={generated_result.returncode}",
    )


def _h_artifacts_untracked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    tracked = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "build/acceptance",
            "build/acceptance-mutation",
            "tmp/qa-phase4-qa-refresh-migration",
            "coverage.lcov",
            "lcov.info",
            "lcov_stpa_report.info",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return not tracked.stdout.strip(), f"tracked generated files={tracked.stdout}"


def _h_generated_paths(world: World, text: str, examples: dict) -> tuple[bool, str]:
    allowed = (_IR_ROOT, _DRY_ROOT, _GENERATED_ROOT, _MUTATION_ROOT)
    offenders = []
    for root in (PROJECT_ROOT / "build" / "acceptance", _MUTATION_ROOT):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if not any(path.is_relative_to(base) for base in allowed):
                offenders.append(str(path))
    return not offenders, f"generated path offenders={offenders}"


def _h_metadata_relative(world: World, text: str, examples: dict) -> tuple[bool, str]:
    metadata_root = _GENERATED_ROOT / "metadata"
    offenders = []
    for path in metadata_root.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            offenders.append(str(path))
            continue
        values = [value for value in data.values() if isinstance(value, str)]
        if any(
            Path(value).is_absolute() or str(PROJECT_ROOT) in value for value in values
        ):
            offenders.append(str(path))
    return not offenders, f"absolute metadata paths={offenders}"


def _h_scope_stable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _scope_is_unchanged()


def _h_worktree_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    after = _status_snapshot()
    before_content = world.p4qrm_content_before
    after_content = _content_snapshot(after)
    return (
        after == world.p4qrm_status_before and after_content == before_content,
        "unrelated worktree status or content changed",
    )
