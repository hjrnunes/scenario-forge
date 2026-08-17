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
        features_dir=os.environ.get(
            "SWARMFORGE_FEATURES_DIR",
            os.environ.get("SWARMFORGE_ACCEPTANCE_FEATURES_DIR", "features"),
        ),
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
        path.relative_to(root).as_posix() for path in features_root.rglob("*.feature")
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


def expected_artifacts(root: Path) -> tuple[set[Path], set[Path], set[Path]]:
    """Return the mapped IR, generated-test, and metadata files for a tree."""
    ir_files: set[Path] = set()
    test_files: set[Path] = set()
    metadata_files: set[Path] = set()
    for feature_path in discover_features(root):
        paths = artifact_paths(feature_path)
        ir_files.add(root / paths.ir_path)
        test_files.add(root / paths.test_path)
        metadata_files.add(root / paths.metadata_path)
    return ir_files, test_files, metadata_files


def find_step_data_tables(feature_path: Path) -> list[str]:
    """Return problems for `|` rows that are not inside an Examples block."""
    problems: list[str] = []
    in_examples = False
    rel = feature_path.as_posix()
    for line_no, raw in enumerate(
        feature_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = raw.strip()
        in_examples = _update_examples_state(stripped, in_examples)
        if _is_step_table(stripped, in_examples):
            problems.append(f"step data table in {rel}:{line_no}")
    return problems


def _update_examples_state(line: str, in_examples: bool) -> bool:
    if line.startswith("Examples:"):
        return True
    if line.startswith(("Feature:", "Background:", "Scenario:", "Scenario Outline:")):
        return False
    return in_examples


def _is_step_table(line: str, in_examples: bool) -> bool:
    return line.startswith("|") and line.endswith("|") and not in_examples


_ABS_PATH = re.compile(r"(?:/Users/|/private/|file://)")


def _sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _scan_absolute_paths(root: Path) -> list[str]:
    problems: list[str] = []
    layout = snapshot_layout()
    for base in _snapshot_roots(root, layout):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            problem = _absolute_path_problem(path, root, layout.dry_dir)
            if problem:
                problems.append(problem)
    return problems


def _snapshot_roots(root: Path, layout: SnapshotLayout) -> tuple[Path, ...]:
    return (
        root / layout.features_dir,
        root / layout.ir_dir,
        root / layout.generated_dir,
    )


def _absolute_path_problem(
    path: Path,
    root: Path,
    dry_dir: str,
) -> str | None:
    if not _is_scannable_file(path, dry_dir):
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    return _absolute_path_message(path, root, text)


def _is_scannable_file(path: Path, dry_dir: str) -> bool:
    if not path.is_file() or path.suffix not in {".feature", ".json", ".py", ".txt"}:
        return False
    return path.suffix != ".txt" or dry_dir in path.as_posix()


def _absolute_path_message(path: Path, root: Path, text: str) -> str | None:
    if not _ABS_PATH.search(text):
        return None
    return f"absolute path in {path.relative_to(root).as_posix()}"


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

    expected_ir, expected_tests, expected_meta = expected_artifacts(root)
    for feature_path in discover_features(root):
        problems.extend(_validate_feature_artifacts(root, feature_path))

    problems.extend(
        _orphan_artifact_problems(
            root,
            layout,
            expected_ir,
            expected_tests,
            expected_meta,
        )
    )
    return problems


def _validate_feature_artifacts(root: Path, feature_path: str) -> list[str]:
    paths = artifact_paths(feature_path)
    mapped = {
        "IR": root / paths.ir_path,
        "generated test": root / paths.test_path,
        "metadata": root / paths.metadata_path,
    }
    problems = [
        f"missing {kind} for {feature_path}"
        for kind, path in mapped.items()
        if not path.is_file()
    ]
    metadata_path = mapped["metadata"]
    if not metadata_path.is_file():
        return problems
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    problems.extend(_metadata_problems(root, feature_path, paths, metadata))
    return problems


def _metadata_problems(
    root: Path,
    feature_path: str,
    paths: ArtifactPaths,
    metadata: dict,
) -> list[str]:
    problems = _metadata_identity_problems(paths, metadata)
    problems.extend(_metadata_source_problems(root, feature_path, paths, metadata))
    return problems


def _metadata_identity_problems(
    paths: ArtifactPaths,
    metadata: dict,
) -> list[str]:
    problems: list[str] = []
    if metadata.get("feature_path") != paths.feature_path:
        problems.append(f"metadata feature_path mismatch in {paths.metadata_path}")
    if metadata.get("ir_path") != paths.ir_path:
        problems.append(f"metadata ir_path mismatch in {paths.metadata_path}")
    return problems


def _metadata_source_problems(
    root: Path,
    feature_path: str,
    paths: ArtifactPaths,
    metadata: dict,
) -> list[str]:
    problems: list[str] = []
    if metadata.get("feature_hash") != _sha256_file(root / feature_path):
        problems.append(f"stale feature_hash in {paths.metadata_path}")
    problems.extend(
        f"metadata points at missing {key} in {paths.metadata_path}"
        for key in ("feature_path", "ir_path")
        if not (root / str(metadata.get(key, ""))).is_file()
    )
    return problems


def _orphan_artifact_problems(
    root: Path,
    layout: SnapshotLayout,
    expected_ir: set[Path],
    expected_tests: set[Path],
    expected_meta: set[Path],
) -> list[str]:
    return (
        _orphan_ir_problems(root, layout, expected_ir)
        + _orphan_generated_problems(root, layout, expected_tests)
        + _orphan_metadata_problems(root, layout, expected_meta)
    )


def _orphan_ir_problems(
    root: Path,
    layout: SnapshotLayout,
    expected_ir: set[Path],
) -> list[str]:
    ir_root = root / layout.ir_dir
    if not ir_root.exists():
        return []
    return [
        problem
        for path in ir_root.rglob("*.json")
        if (problem := _ir_artifact_problem(root, path, expected_ir)) is not None
    ]


def _ir_artifact_problem(
    root: Path,
    path: Path,
    expected_ir: set[Path],
) -> str | None:
    relative = path.relative_to(root).as_posix()
    if path.stem.endswith("_dry"):
        return f"dry report in IR tree {relative}"
    if path not in expected_ir:
        return f"orphan IR {relative}"
    return None


def _orphan_generated_problems(
    root: Path,
    layout: SnapshotLayout,
    expected_tests: set[Path],
) -> list[str]:
    generated_root = root / layout.generated_dir
    if not generated_root.exists():
        return []
    return [
        f"orphan generated test {path.relative_to(root).as_posix()}"
        for path in generated_root.glob("*_acceptance_test.py")
        if path not in expected_tests
    ]


def _orphan_metadata_problems(
    root: Path,
    layout: SnapshotLayout,
    expected_meta: set[Path],
) -> list[str]:
    meta_root = root / layout.metadata_dir
    if not meta_root.exists():
        return []
    return [
        f"orphan metadata {path.relative_to(root).as_posix()}"
        for path in meta_root.glob("*.json")
        if path not in expected_meta
    ]
