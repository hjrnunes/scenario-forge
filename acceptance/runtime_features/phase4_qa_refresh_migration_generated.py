"""Generated acceptance handlers for the Phase 4 QA migration."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from runtime_shared import PROJECT_ROOT, World

from .phase4_qa_refresh_migration_support import (
    _GENERATED_ROOT,
    _finish_sentinel,
    _outcome_lines,
    _run,
    _start_sentinel,
)


def _generated_test_path(source_feature: str) -> Path:
    return _GENERATED_ROOT / f"{Path(source_feature).stem}_acceptance_test.py"


def _h_source_generated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'source feature "([^"]+)" is generated', text)
    if match is None:
        return False, f"Could not parse source feature: {text}"
    source_feature = match.group(1)
    feature = PROJECT_ROOT / "features" / source_feature
    generated = _generated_test_path(source_feature)
    world.p4qrm_source_feature = source_feature
    world.p4qrm_source_test = generated
    # The acceptance-refresh cleanup feature shares this Given step. Retain
    # its observable state names when this handler wins the overlap.
    world.aqrc_source_feature = source_feature
    world.aqrc_source_test = generated
    return (
        feature.is_file() and generated.is_file(),
        f"missing feature={feature} generated={generated}",
    )


def _h_endpoint_configuration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _start_sentinel(world)
    return True, ""


def _h_run_generated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = [
        _run(
            [sys.executable, "-m", "pytest", str(world.p4qrm_source_test), "-q", "-s"],
            timeout=600,
        ),
        _run(
            [sys.executable, "-m", "pytest", str(world.p4qrm_source_test), "-q", "-s"],
            timeout=600,
        ),
    ]
    world.p4qrm_source_runs = result
    return True, ""


def _h_source_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"exactly (\d+) distinct scenarios as PASS", text)
    if match is None:
        return False, f"Could not parse scenario count: {text}"
    expected = int(match.group(1))
    actual = []
    for result in world.p4qrm_source_runs:
        names = {
            line.split("/example_", 1)[0]
            for line in result.stdout.splitlines()
            if line.startswith("PASS ")
        }
        actual.append((result.returncode, len(names)))
    return all(status == 0 and count == expected for status, count in actual), (
        f"source counts={actual}"
    )


def _h_source_no_failures(world: World, text: str, examples: dict) -> tuple[bool, str]:
    failures = [
        line
        for result in world.p4qrm_source_runs
        for line in _outcome_lines(result.stdout)
        if line.startswith(("FAIL ", "SKIP "))
    ]
    return not failures, f"source failures={failures}"


def _h_source_same(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p4qrm_source_runs
    same = _outcome_lines(runs[0].stdout) == _outcome_lines(runs[1].stdout)
    _finish_sentinel(world)
    return same, "generated scenario outcomes differ"
