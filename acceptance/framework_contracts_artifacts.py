"""Artifact and deterministic snapshot contract handlers."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from snapshot import artifact_paths, snapshot_layout
from runtime_world import World

from framework_contracts_common import (
    _restore_environment,
    _without_layout_overrides,
)


def _h_afr_layout_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the repo-relative layout precondition."""
    layout = snapshot_layout()
    values = (
        layout.features_dir,
        layout.ir_dir,
        layout.dry_dir,
        layout.generated_dir,
        layout.mutation_dir,
    )
    if any(Path(value).is_absolute() for value in values):
        return False, f"acceptance layout contains an absolute path: {values}"
    return True, ""


def _h_afr_artifact_paths(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Request the canonical paths while ignoring caller output overrides."""
    saved = _without_layout_overrides()
    try:
        world.afr_artifact_paths = artifact_paths("features/group/example.feature")
    finally:
        _restore_environment(saved)
    return True, ""


def _h_afr_artifact_path_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.fullmatch(r'the (IR|dry|test|metadata) path is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse artifact assertion: {text}"
    artifact, expected = match.groups()
    field = {
        "IR": "ir_path",
        "dry": "dry_path",
        "test": "test_path",
        "metadata": "metadata_path",
    }[artifact]
    actual = getattr(world.afr_artifact_paths, field, None)
    return actual == expected, f"Unexpected {artifact} path: {actual}"


def _h_afr_snapshot_project(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Create nested features and stale output in intentionally odd order."""
    root = Path(tempfile.mkdtemp(prefix="acceptance-framework-snapshot-"))
    (root / "pyproject.toml").write_text(
        '[project]\nname = "acceptance-framework-fixture"\n',
        encoding="utf-8",
    )
    features = root / "features"
    # Create zeta before alpha; discover_features must still return alpha first.
    (features / "zeta.feature").parent.mkdir(parents=True, exist_ok=True)
    (features / "zeta.feature").write_text(
        "Feature: Zeta\n  Scenario: Zeta scenario\n    Given a supported fixture\n",
        encoding="utf-8",
    )
    (features / "group").mkdir(parents=True)
    (features / "group" / "alpha.feature").write_text(
        "Feature: Alpha\n  Scenario: Alpha scenario\n    Given a supported fixture\n",
        encoding="utf-8",
    )

    build = root / "build" / "acceptance"
    (build / "ir").mkdir(parents=True)
    (build / "generated" / "metadata").mkdir(parents=True)
    (build / "ir" / "group").mkdir(parents=True)
    (build / "ir" / "group" / "stale.json").write_text("{}\n", encoding="utf-8")
    (build / "generated" / "stale_acceptance_test.py").write_text(
        "stale\n", encoding="utf-8"
    )
    (build / "generated" / "metadata" / "stale.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (build / "generated" / "unrelated.txt").write_text(
        "preserve me\n", encoding="utf-8"
    )
    world.afr_snapshot_root = root
    return True, ""


def _h_afr_snapshot_outputs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Refresh the fixture twice and retain the observed processing order."""
    import refresh_snapshot

    root = world.afr_snapshot_root
    saved = _without_layout_overrides()
    processed: list[str] = []
    original_run_tool = refresh_snapshot.run_tool

    def recording_run_tool(command: list[str], cwd: Path | None = None) -> int:
        if command and command[0] == "gherkin-parser":
            processed.append(Path(command[1]).relative_to(root).as_posix())
        return original_run_tool(command, cwd=cwd)

    refresh_snapshot.run_tool = recording_run_tool
    try:
        refresh_snapshot.refresh_snapshot(root)
        first = _afr_snapshot_bytes(root)
        processed_first = list(processed)
        processed.clear()
        refresh_snapshot.refresh_snapshot(root)
        second = _afr_snapshot_bytes(root)
        world.afr_snapshot_processed = processed_first
        world.afr_snapshot_processed_again = processed
        world.afr_snapshot_deterministic = first == second
    except Exception as exc:
        return False, f"snapshot refresh failed: {exc}"
    finally:
        refresh_snapshot.run_tool = original_run_tool
        _restore_environment(saved)
    return True, ""


def _afr_snapshot_bytes(root: Path) -> list[tuple[str, bytes]]:
    """Read only mapped snapshot files, excluding unrelated files."""
    saved = _without_layout_overrides()
    try:
        rows: list[tuple[str, bytes]] = []
        from snapshot import discover_features

        for feature in discover_features(root):
            paths = artifact_paths(feature)
            for relative in (
                paths.ir_path,
                paths.dry_path,
                paths.test_path,
                paths.metadata_path,
            ):
                path = root / relative
                rows.append((relative, path.read_bytes()))
        return rows
    finally:
        _restore_environment(saved)


def _h_afr_snapshot_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = ["features/group/alpha.feature", "features/zeta.feature"]
    actual = getattr(world, "afr_snapshot_processed", [])
    return actual == expected, f"Unexpected feature order: {actual}"


def _h_afr_snapshot_complete(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    root = world.afr_snapshot_root
    saved = _without_layout_overrides()
    try:
        from snapshot import discover_features

        for feature in discover_features(root):
            paths = artifact_paths(feature)
            for relative in (
                paths.ir_path,
                paths.dry_path,
                paths.test_path,
                paths.metadata_path,
            ):
                if not (root / relative).is_file():
                    return False, f"missing mapped artifact: {relative}"
    finally:
        _restore_environment(saved)
    return True, ""


def _h_afr_snapshot_metadata(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    root = world.afr_snapshot_root
    saved = _without_layout_overrides()
    try:
        from snapshot import discover_features

        for feature in discover_features(root):
            paths = artifact_paths(feature)
            metadata = json.loads((root / paths.metadata_path).read_text())
            problem = _metadata_problem(metadata, paths)
            if problem:
                return False, problem
    finally:
        _restore_environment(saved)
    return True, ""


def _metadata_problem(metadata: dict, paths: Any) -> str | None:
    checks = (
        (
            metadata.get("feature_path") != paths.feature_path,
            f"incorrect feature metadata: {metadata}",
        ),
        (
            metadata.get("ir_path") != paths.ir_path,
            f"incorrect IR metadata: {metadata}",
        ),
        (
            any(
                Path(str(metadata.get(field, ""))).is_absolute()
                for field in ("feature_path", "ir_path")
            ),
            f"absolute metadata path: {metadata}",
        ),
    )
    return next((message for failed, message in checks if failed), None)


def _h_afr_snapshot_stale(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = world.afr_snapshot_root
    stale = (
        root / "build" / "acceptance" / "ir" / "group" / "stale.json",
        root / "build" / "acceptance" / "generated" / "stale_acceptance_test.py",
        root / "build" / "acceptance" / "generated" / "metadata" / "stale.json",
    )
    missing = [str(path) for path in stale if path.exists()]
    return not missing, f"stale artifacts remain: {missing}"


def _h_afr_snapshot_unrelated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    path = (
        world.afr_snapshot_root / "build" / "acceptance" / "generated" / "unrelated.txt"
    )
    return path.is_file(), f"unrelated file was removed: {path}"
