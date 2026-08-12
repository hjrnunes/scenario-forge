"""Deterministic source-to-output mapping for the committed acceptance snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


FEATURES_DIR = "features"
IR_DIR = "acceptance/ir"
GENERATED_DIR = "acceptance/generated"
METADATA_DIR = "acceptance/generated/metadata"
DRY_DIR = "acceptance/dry"


class SnapshotError(ValueError):
    """Raised when the snapshot mapping is incomplete or ambiguous."""


@dataclass(frozen=True)
class ArtifactPaths:
    """Repo-relative paths for one snapshot feature."""

    feature_path: str
    ir_path: str
    test_path: str
    metadata_path: str
    dry_path: str


def metadata_name(feature_path: str) -> str:
    """Convert a feature path to its metadata filename."""
    stem = Path(feature_path).stem
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    return f"{slug}.json"


def artifact_paths(feature_path: str) -> ArtifactPaths:
    """Map a repo-relative feature path to IR, test, metadata, and dry paths."""
    relative = Path(feature_path)
    if relative.parts[:1] != (FEATURES_DIR,):
        raise ValueError(f"feature path must live under {FEATURES_DIR}/: {feature_path}")
    rel_inside = relative.relative_to(FEATURES_DIR)
    ir_rel = rel_inside.with_suffix(".json")
    dry_rel = rel_inside.with_suffix(".txt")
    return ArtifactPaths(
        feature_path=relative.as_posix(),
        ir_path=f"{IR_DIR}/{ir_rel.as_posix()}",
        test_path=f"{GENERATED_DIR}/{relative.stem}_acceptance_test.py",
        metadata_path=f"{METADATA_DIR}/{metadata_name(feature_path)}",
        dry_path=f"{DRY_DIR}/{dry_rel.as_posix()}",
    )


def discover_features(root: Path) -> list[str]:
    """Return sorted repo-relative feature paths under features/."""
    features_root = Path(root) / FEATURES_DIR
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


_ABS_PATH = re.compile(r"(?:/Users/|/private/|file://)")


def _sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _scan_absolute_paths(root: Path) -> list[str]:
    problems: list[str] = []
    roots = (
        root / FEATURES_DIR,
        root / IR_DIR,
        root / GENERATED_DIR,
    )
    for base in roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".feature", ".json", ".py", ".txt"}:
                continue
            if path.suffix == ".txt" and DRY_DIR not in path.as_posix():
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


def validate_snapshot(root: Path) -> list[str]:
    """Return human-readable problems in the committed acceptance snapshot."""
    problems = _scan_absolute_paths(root)
    problems.extend(_tracked_ignored_files(root))

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

    ir_root = root / IR_DIR
    if ir_root.exists():
        for path in ir_root.rglob("*.json"):
            if path.stem.endswith("_dry"):
                problems.append(f"dry report in IR tree {path.relative_to(root).as_posix()}")
            elif path not in expected_ir:
                problems.append(f"orphan IR {path.relative_to(root).as_posix()}")
    generated_root = root / GENERATED_DIR
    if generated_root.exists():
        for path in generated_root.glob("*_acceptance_test.py"):
            if path not in expected_tests:
                problems.append(f"orphan generated test {path.relative_to(root).as_posix()}")
    meta_root = root / METADATA_DIR
    if meta_root.exists():
        for path in meta_root.glob("*.json"):
            if path not in expected_meta:
                problems.append(f"orphan metadata {path.relative_to(root).as_posix()}")
    return problems
