#!/usr/bin/env python3
"""Regenerate ignored acceptance artifacts from features/."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from generate_entrypoints import generate
from snapshot import artifact_paths, discover_features, snapshot_layout


def _project_root(start: Path) -> Path:
    for parent in (start, *start.parents):
        if (parent / "pyproject.toml").is_file():
            return parent
    raise FileNotFoundError(f"could not find project root from {start}")


def _is_aps_root(path: Path) -> bool:
    return (path / "bb.edn").is_file() or (path / "bb" / "gherkin-parser").is_dir()


def _aps_root(project_root: Path) -> Path:
    search_roots = (project_root, Path(__file__).resolve().parents[1])
    for root in search_roots:
        for candidate in (
            root / "tmp" / "Acceptance-Pipeline-Specification",
            root / ".factory" / "swarmforge" / "aps",
        ):
            if _is_aps_root(candidate):
                return candidate
    raise FileNotFoundError("Acceptance-Pipeline-Specification clone not found")


def _resolve_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in (
        Path("/opt/homebrew/bin") / name,
        Path("/usr/local/bin") / name,
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def run_tool(command: list[str], cwd: Path | None = None) -> int:
    """Run an APS tool by task name, preferring Babashka."""
    task, *args = command
    bb = _resolve_binary("bb")
    if bb:
        argv = [bb, task, *args]
    else:
        fallback = _resolve_binary(task)
        if fallback is None:
            raise FileNotFoundError(f"neither bb nor {task} is available")
        argv = [fallback, *args]
    result = subprocess.run(argv, cwd=cwd, check=False, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(argv)}")
    return result.returncode


def _write_parents(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _expected_artifacts(root: Path) -> tuple[set[Path], set[Path], set[Path]]:
    ir_files: set[Path] = set()
    test_files: set[Path] = set()
    meta_files: set[Path] = set()
    for feature_path in discover_features(root):
        paths = artifact_paths(feature_path)
        ir_files.add(root / paths.ir_path)
        test_files.add(root / paths.test_path)
        meta_files.add(root / paths.metadata_path)
    return ir_files, test_files, meta_files


def _remove_stale(directory: Path, keep: set[Path], pattern: str) -> None:
    if not directory.exists():
        return
    for path in directory.rglob(pattern):
        if path.is_file() and path not in keep:
            path.unlink()


def refresh_snapshot(root: Path | None = None, run_tests: bool = False) -> int:
    """Parse features, write IR/dry/generated artifacts, and drop orphans."""
    project_root = Path(root) if root is not None else _project_root(Path.cwd())
    layout = snapshot_layout()
    aps_root = _aps_root(project_root)
    features = discover_features(project_root)
    for feature_path in features:
        paths = artifact_paths(feature_path)
        ir_abs = project_root / paths.ir_path
        dry_abs = project_root / paths.dry_path
        _write_parents(ir_abs)
        _write_parents(dry_abs)
        run_tool(
            ["gherkin-parser", str(project_root / feature_path), str(ir_abs)],
            cwd=aps_root,
        )
        run_tool(
            ["gherkin-ir-dry-checker", str(ir_abs), str(dry_abs)],
            cwd=aps_root,
        )
        generate(str(ir_abs), str(project_root / layout.generated_dir), feature_path)

    keep_ir, keep_tests, keep_meta = _expected_artifacts(project_root)
    _remove_stale(project_root / layout.ir_dir, keep_ir, "*.json")
    _remove_stale(
        project_root / layout.generated_dir, keep_tests, "*_acceptance_test.py"
    )
    _remove_stale(project_root / layout.metadata_dir, keep_meta, "*.json")
    if run_tests:
        generated = project_root / layout.generated_dir
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(generated), "-q", "-s"],
            cwd=project_root,
            check=False,
        )
        return result.returncode
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="store_true",
        help="run pytest on the generated acceptance tests after refresh",
    )
    args = parser.parse_args(argv)
    return refresh_snapshot(run_tests=args.run)


if __name__ == "__main__":
    sys.exit(main())
