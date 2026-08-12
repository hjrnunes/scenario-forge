#!/usr/bin/env python3
"""Regenerate the committed acceptance snapshot from features/."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from generate_entrypoints import generate
from snapshot import (
    GENERATED_DIR,
    IR_DIR,
    METADATA_DIR,
    artifact_paths,
    discover_features,
)


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


def _iter_steps(ir: dict):
    background = ir.get("background") or []
    if isinstance(background, dict):
        background = [background]
    for step in background:
        if isinstance(step, dict):
            yield step
    for scenario in ir.get("scenarios") or []:
        if not isinstance(scenario, dict):
            continue
        for step in scenario.get("steps") or []:
            if isinstance(step, dict):
                yield step


def _table_count(ir: dict) -> int:
    return sum(1 for step in _iter_steps(ir) if step.get("data_table"))


def _restore_data_tables(existing: dict, parsed: dict) -> dict:
    """Keep previously parsed step tables when APS omits them."""
    if _table_count(parsed) >= _table_count(existing):
        return parsed
    tables = {
        (step.get("keyword"), step.get("text")): step["data_table"]
        for step in _iter_steps(existing)
        if step.get("data_table")
    }
    for step in _iter_steps(parsed):
        table = tables.get((step.get("keyword"), step.get("text")))
        if table is not None and "data_table" not in step:
            step["data_table"] = table
    return parsed


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


def refresh_snapshot(root: Path | None = None) -> int:
    """Parse features, write IR/dry/generated artifacts, and drop orphans."""
    project_root = Path(root) if root is not None else _project_root(Path.cwd())
    aps_root = _aps_root(project_root)
    features = discover_features(project_root)
    for feature_path in features:
        paths = artifact_paths(feature_path)
        ir_abs = project_root / paths.ir_path
        dry_abs = project_root / paths.dry_path
        _write_parents(ir_abs)
        _write_parents(dry_abs)
        existing_ir = json.loads(ir_abs.read_text()) if ir_abs.is_file() else None
        run_tool(
            ["gherkin-parser", str(project_root / feature_path), str(ir_abs)],
            cwd=aps_root,
        )
        if existing_ir is not None:
            parsed_ir = json.loads(ir_abs.read_text())
            merged = _restore_data_tables(existing_ir, parsed_ir)
            ir_abs.write_text(json.dumps(merged, indent=2) + "\n")
        run_tool(
            ["gherkin-ir-dry-checker", str(ir_abs), str(dry_abs)],
            cwd=aps_root,
        )
        generate(str(ir_abs), str(project_root / GENERATED_DIR), feature_path)

    keep_ir, keep_tests, keep_meta = _expected_artifacts(project_root)
    _remove_stale(project_root / IR_DIR, keep_ir, "*.json")
    _remove_stale(project_root / GENERATED_DIR, keep_tests, "*_acceptance_test.py")
    _remove_stale(project_root / METADATA_DIR, keep_meta, "*.json")
    return 0


if __name__ == "__main__":
    sys.exit(refresh_snapshot())
