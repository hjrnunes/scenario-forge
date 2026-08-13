"""Deterministic source-to-output mapping for the committed acceptance snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class SnapshotError(ValueError):
    """Raised when the snapshot mapping is incomplete or ambiguous."""


@dataclass(frozen=True)
class SnapshotLayout:
    """Repo-relative directories for snapshot inputs and generated output."""

    features_dir: str
    ir_dir: str
    generated_dir: str
    metadata_dir: str
    dry_dir: str
    mutation_dir: str


@dataclass(frozen=True)
class ArtifactPaths:
    """Repo-relative paths for one snapshot feature."""

    feature_path: str
    ir_path: str
    test_path: str
    metadata_path: str
    dry_path: str


def snapshot_layout() -> SnapshotLayout:
    """Return the current snapshot directories, honoring environment overrides."""
    generated_dir = os.environ.get(
        "SWARMFORGE_ACCEPTANCE_GENERATED_DIR", "build/acceptance/generated"
    )
    return SnapshotLayout(
        features_dir=os.environ.get("SWARMFORGE_ACCEPTANCE_FEATURES_DIR", "features"),
        ir_dir=os.environ.get("SWARMFORGE_ACCEPTANCE_IR_DIR", "build/acceptance/ir"),
        generated_dir=generated_dir,
        metadata_dir=f"{generated_dir}/metadata",
        dry_dir=os.environ.get("SWARMFORGE_ACCEPTANCE_DRY_DIR", "build/acceptance/dry"),
        mutation_dir=os.environ.get(
            "SWARMFORGE_ACCEPTANCE_MUTATION_DIR", "build/acceptance-mutation"
        ),
    )


def metadata_name(feature_path: str) -> str:
    """Convert a feature path to its metadata filename."""
    stem = Path(feature_path).stem
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    return f"{slug}.json"


def artifact_paths(feature_path: str) -> ArtifactPaths:
    """Map a repo-relative feature path to IR, test, metadata, and dry paths."""
    layout = snapshot_layout()
    relative = Path(feature_path)
    if relative.parts[:1] != (layout.features_dir,):
        raise ValueError(
            f"feature path must live under {layout.features_dir}/: {feature_path}"
        )
    rel_inside = relative.relative_to(layout.features_dir)
    ir_rel = rel_inside.with_suffix(".json")
    dry_rel = rel_inside.with_suffix(".txt")
    return ArtifactPaths(
        feature_path=relative.as_posix(),
        ir_path=f"{layout.ir_dir}/{ir_rel.as_posix()}",
        test_path=f"{layout.generated_dir}/{relative.stem}_acceptance_test.py",
        metadata_path=f"{layout.metadata_dir}/{metadata_name(feature_path)}",
        dry_path=f"{layout.dry_dir}/{dry_rel.as_posix()}",
    )


def discover_features(root: Path) -> list[str]:
    """Return sorted repo-relative feature paths under features/."""
    features_root = Path(root) / snapshot_layout().features_dir
    found = sorted(
        path.relative_to(root).as_posix()
        for path in features_root.rglob("*.feature")
    )
    stems: dict[str, str] = {}
    for feature_path in found:
        stem = Path(feature_path).stem
        previous = stems.get(stem)
        if previous is not None:
            raise SnapshotError(
                f"duplicate feature stem {stem!r}: {previous} and {feature_path}"
            )
        stems[stem] = feature_path
    return found


def find_step_data_tables(feature_path: Path) -> list[str]:
    """Return problems for `|` rows that are not inside an Examples block."""
    problems: list[str] = []
    in_examples = False
    rel = feature_path.as_posix()
    for line_no, raw in enumerate(feature_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("Examples:"):
            in_examples = True
            continue
        if stripped.startswith(("Feature:", "Background:", "Scenario:", "Scenario Outline:")):
            in_examples = False
        if stripped.startswith("|") and stripped.endswith("|") and not in_examples:
            problems.append(f"step data table in {rel}:{line_no}")
    return problems


_ABS_PATH = re.compile(r"(?:/Users/|/private/|file://)")


def _sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _scan_absolute_paths(root: Path) -> list[str]:
    problems: list[str] = []
    layout = snapshot_layout()
    roots = (
        root / layout.features_dir,
        root / layout.ir_dir,
        root / layout.generated_dir,
    )
    for base in roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".feature", ".json", ".py", ".txt"}:
                continue
            if path.suffix == ".txt" and layout.dry_dir not in path.as_posix():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if _ABS_PATH.search(text):
                problems.append(
                    f"absolute path in {path.relative_to(root).as_posix()}"
                )
    return problems


def _tracked_ignored_files(root: Path) -> list[str]:
    git_dir = root / ".git"
    if not git_dir.exists():
        return []
    result = subprocess.run(
        ["git", "ls-files", "-ci", "--exclude-standard"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return [f"git ls-files failed: {result.stderr.strip()}"]
    return [
        f"tracked ignored file {line.strip()}"
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def _legacy_generated_paths(root: Path) -> list[str]:
    problems: list[str] = []
    git_dir = root / ".git"
    if not git_dir.exists():
        return problems
    result = subprocess.run(
        ["git", "ls-files", "acceptance/ir", "acceptance/generated"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return [f"git ls-files failed: {result.stderr.strip()}"]
    return [
        f"tracked generated artifact {line.strip()}"
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def validate_committed_snapshot(root: Path) -> list[str]:
    """Return problems that belong in the committed tree, not generated output."""
    problems = _tracked_ignored_files(root)
    problems.extend(_legacy_generated_paths(root))
    for feature_path in discover_features(root):
        problems.extend(find_step_data_tables(root / feature_path))
        feature_abs = root / feature_path
        try:
            text = feature_abs.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if _ABS_PATH.search(text):
            problems.append(f"absolute path in {feature_path}")
    return problems


def validate_snapshot(root: Path) -> list[str]:
    """Return problems in generated snapshot artifacts and the committed tree."""
    problems = validate_committed_snapshot(root)
    problems.extend(_scan_absolute_paths(root))
    layout = snapshot_layout()

    expected_ir: set[Path] = set()
    expected_tests: set[Path] = set()
    expected_meta: set[Path] = set()
    for feature_path in discover_features(root):
        paths = artifact_paths(feature_path)
        ir_abs = root / paths.ir_path
        test_abs = root / paths.test_path
        meta_abs = root / paths.metadata_path
        expected_ir.add(ir_abs)
        expected_tests.add(test_abs)
        expected_meta.add(meta_abs)
        if not ir_abs.is_file():
            problems.append(f"missing IR for {feature_path}")
        if not test_abs.is_file():
            problems.append(f"missing generated test for {feature_path}")
        if not meta_abs.is_file():
            problems.append(f"missing metadata for {feature_path}")
            continue
        meta = json.loads(meta_abs.read_text(encoding="utf-8"))
        if meta.get("feature_path") != paths.feature_path:
            problems.append(f"metadata feature_path mismatch in {paths.metadata_path}")
        if meta.get("ir_path") != paths.ir_path:
            problems.append(f"metadata ir_path mismatch in {paths.metadata_path}")
        feature_abs = root / feature_path
        expected_hash = _sha256_file(feature_abs)
        if meta.get("feature_hash") != expected_hash:
            problems.append(f"stale feature_hash in {paths.metadata_path}")
        for key in ("feature_path", "ir_path"):
            pointed = root / str(meta.get(key, ""))
            if not pointed.is_file():
                problems.append(f"metadata points at missing {key} in {paths.metadata_path}")

    ir_root = root / layout.ir_dir
    if ir_root.exists():
        for path in ir_root.rglob("*.json"):
            if path.stem.endswith("_dry"):
                problems.append(f"dry report in IR tree {path.relative_to(root).as_posix()}")
            elif path not in expected_ir:
                problems.append(f"orphan IR {path.relative_to(root).as_posix()}")
    generated_root = root / layout.generated_dir
    if generated_root.exists():
        for path in generated_root.glob("*_acceptance_test.py"):
            if path not in expected_tests:
                problems.append(f"orphan generated test {path.relative_to(root).as_posix()}")
    meta_root = root / layout.metadata_dir
    if meta_root.exists():
        for path in meta_root.glob("*.json"):
            if path not in expected_meta:
                problems.append(f"orphan metadata {path.relative_to(root).as_posix()}")
    return problems
