"""Immutable run identity, versioned manifest, artifact inventory, and provenance.

This module is the single ownership boundary for:

* Run collection → run directory resolution (sortable, collision-safe)
* Versioned manifest sentinel lifecycle (``started`` → final status)
* Typed artifact inventory with SHA-256 verification and global integrity
* Comprehensive provenance capture (Git, config, inputs, model, prompts)
* Strict manifest inventory resolver shared by eval and report readers

Every invocation creates a new ``<collection>/<run_id>/`` child directory.
Existing run directories are never reused, cleaned, or overwritten.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import subprocess
import tempfile
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Constants and versions
# --------------------------------------------------------------------------- #

MANIFEST_VERSION = "2"
ARTIFACT_SCHEMA_VERSION = "1"
_RUN_ID_TIMESTAMP_LEN = 15  # YYYYMMDDTHHMMSS
_RUN_ID_SEPARATOR = "_"
_RUN_ID_HEX_LEN = 32  # 128 bits of collision-safe entropy
_RUN_ID_TOTAL_LEN = _RUN_ID_TIMESTAMP_LEN + 1 + _RUN_ID_HEX_LEN  # 48
_RUN_ID_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})_([0-9a-f]{32})$")
MANIFEST_FILENAME = "run-manifest.yaml"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class RunStatus(str, Enum):
    """Lifecycle status of a run."""

    STARTED = "started"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"

    @classmethod
    def final_statuses(cls) -> set["RunStatus"]:
        return {cls.COMPLETED, cls.COMPLETED_WITH_ERRORS, cls.FAILED}

    @property
    def is_final(self) -> bool:
        return self in self.final_statuses()

    @property
    def is_authoritative(self) -> bool:
        """Only ``completed`` runs are authoritative."""
        return self == self.COMPLETED


class ArtifactRole(str, Enum):
    """Typed role for every persisted artifact in a run.

    The manifest container file (``run-manifest.yaml``) is **not** an
    artifact entry — it is the sole orphan exception.
    """

    USE_CASE = "use_case"
    CAPABILITY_PROFILE = "capability_profile"
    THREAT_SURFACE = "threat_surface"
    SCENARIO_YAML = "scenario_yaml"
    SCENARIO_FEATURE = "scenario_feature"
    SCENARIO_CALL_LOG = "scenario_call_log"
    PIPELINE_CALL_LOG = "pipeline_call_log"
    COVERAGE_REPORT = "coverage_report"
    EVAL_SCORECARD = "eval_scorecard"
    REPORT = "report"
    PIPELINE_LOG = "pipeline_log"


class AttemptDisposition(str, Enum):
    """Disposition of a generation attempt."""

    ADMITTED = "admitted"
    QUARANTINED = "quarantined"
    FAILED = "failed"


# --------------------------------------------------------------------------- #
# Role metadata
# --------------------------------------------------------------------------- #

# Expected file extension and media type for each role.
_ROLE_METADATA: dict[ArtifactRole, dict[str, str]] = {
    ArtifactRole.USE_CASE: {"extension": ".txt", "media_type": "text/plain"},
    ArtifactRole.CAPABILITY_PROFILE: {
        "extension": ".yaml",
        "media_type": "application/yaml",
    },
    ArtifactRole.THREAT_SURFACE: {
        "extension": ".yaml",
        "media_type": "application/yaml",
    },
    ArtifactRole.SCENARIO_YAML: {
        "extension": ".yaml",
        "media_type": "application/yaml",
    },
    ArtifactRole.SCENARIO_FEATURE: {
        "extension": ".feature",
        "media_type": "text/plain",
    },
    ArtifactRole.SCENARIO_CALL_LOG: {
        "extension": ".jsonl",
        "media_type": "application/jsonl",
    },
    ArtifactRole.PIPELINE_CALL_LOG: {
        "extension": ".jsonl",
        "media_type": "application/jsonl",
    },
    ArtifactRole.COVERAGE_REPORT: {
        "extension": ".json",
        "media_type": "application/json",
    },
    ArtifactRole.EVAL_SCORECARD: {
        "extension": ".yaml",
        "media_type": "application/yaml",
    },
    ArtifactRole.REPORT: {"extension": ".html", "media_type": "text/html"},
    ArtifactRole.PIPELINE_LOG: {
        "extension": ".log",
        "media_type": "text/plain",
    },
}

# Roles that must appear at most once in the inventory.
SINGLETON_ROLES: frozenset[ArtifactRole] = frozenset(
    {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.COVERAGE_REPORT,
        ArtifactRole.EVAL_SCORECARD,
        ArtifactRole.REPORT,
        ArtifactRole.PIPELINE_LOG,
        ArtifactRole.PIPELINE_CALL_LOG,
        ArtifactRole.SCENARIO_CALL_LOG,
    }
)


def required_singleton_roles(*, eval_enabled: bool) -> set[ArtifactRole]:
    """Return the set of singleton roles required for ``completed`` status.

    *report* is always required.  *eval_scorecard* is required only when
    eval is enabled.
    """
    roles: set[ArtifactRole] = {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.COVERAGE_REPORT,
        ArtifactRole.PIPELINE_LOG,
        ArtifactRole.REPORT,
    }
    if eval_enabled:
        roles.add(ArtifactRole.EVAL_SCORECARD)
    return roles


# --------------------------------------------------------------------------- #
# Pydantic models
# --------------------------------------------------------------------------- #


class ArtifactEntry(BaseModel):
    """A single persisted artifact in the run inventory.

    Every entry requires a valid SHA-256 hash, media_type, schema_version,
    canonical role/path, and applicable scenario_id/candidate_id.
    """

    role: ArtifactRole
    path: str  # canonical relative path from run root
    sha256: str
    schema_version: str = ARTIFACT_SCHEMA_VERSION
    media_type: str
    scenario_id: str | None = None
    candidate_id: str | None = None

    model_config = {"use_enum_values": False}


class AttemptRecord(BaseModel):
    """Typed record of a generation attempt keyed by candidate/scenario."""

    candidate_id: str
    scenario_id: str | None = None
    disposition: AttemptDisposition
    failure_evidence: str | None = None

    model_config = {"use_enum_values": False}


class GitProvenance(BaseModel):
    """Git source provenance for reproducibility."""

    commit: str | None = None
    dirty: bool | None = None
    source_diff_digest: str | None = None
    branch: str | None = None
    untracked_files: list[str] = Field(default_factory=list)


class InputHashes(BaseModel):
    """SHA-256 hashes of all effective inputs."""

    use_case_hash: str | None = None
    risk_extraction_hash: str | None = None
    sssom_hash: str | None = None
    cross_taxonomy_hash: str | None = None
    threats_hash: str | None = None
    source_profile_hash: str | None = None
    effective_profile_hash: str | None = None
    attack_patterns_hash: str | None = None
    attack_patterns_sssom_hash: str | None = None
    attack_goals_taxonomy_hash: str | None = None
    threat_goal_affinity_hash: str | None = None


class ModelConfig(BaseModel):
    """Resolved LLM model configuration (effective values, not raw None args)."""

    model: str
    base_url: str
    temperature: float
    max_completion_tokens: int | None = None


class CommandProvenance(BaseModel):
    """Normalized command and options that invoked the run."""

    command: str = "generate"
    options: dict[str, Any] = Field(default_factory=dict)


class Provenance(BaseModel):
    """Full provenance for a run."""

    run_id: str
    command: CommandProvenance = Field(default_factory=CommandProvenance)
    package_version: str = "0.0.0"
    manifest_version: str = MANIFEST_VERSION
    artifact_schema_version: str = ARTIFACT_SCHEMA_VERSION
    timestamp_start: str
    timestamp_end: str | None = None
    model_config_provenance: ModelConfig | None = None
    prompt_template_hashes: dict[str, str] = Field(default_factory=dict)
    input_hashes: InputHashes = Field(default_factory=InputHashes)
    config_digest: str | None = None
    git: GitProvenance = Field(default_factory=GitProvenance)


class RunManifest(BaseModel):
    """The complete versioned run manifest — sentinel and final inventory.

    ``run-manifest.yaml`` is the inventory **container**, not an
    :class:`ArtifactEntry`.  It is the sole orphan exception.
    """

    manifest_version: str = MANIFEST_VERSION
    status: RunStatus = RunStatus.STARTED
    run_id: str
    timestamp_start: str
    timestamp_end: str | None = None
    package_version: str = "0.0.0"
    provenance: Provenance | None = None
    inventory: list[ArtifactEntry] = Field(default_factory=list)
    attempts: list[AttemptRecord] = Field(default_factory=list)
    error: str | None = None

    # Legacy/extension fields from the pipeline manifest
    inputs: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    seeds_generated: int = 0
    funnel: dict[str, Any] = Field(default_factory=dict)
    stage_records: list[dict[str, Any]] = Field(default_factory=list)
    rule_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    scenarios_generated: int = 0
    scenarios_failed: int = 0
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    phantom_validation: dict[str, Any] = Field(default_factory=dict)
    structural_validation: dict[str, Any] = Field(default_factory=dict)
    semantic_validation: dict[str, Any] = Field(default_factory=dict)
    leaf_technique_provenance: dict[str, Any] = Field(default_factory=dict)
    parsimony: dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": False}


# --------------------------------------------------------------------------- #
# Run ID generation and validation
# --------------------------------------------------------------------------- #


def generate_sortable_run_id() -> str:
    """Generate a sortable, collision-safe run ID.

    Format: ``YYYYMMDDTHHMMSS_<32 hex chars>`` (48 chars total).
    The timestamp prefix makes directories sortable by lexical order.
    The 128-bit random suffix prevents collisions within the same second.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    suffix = secrets.token_hex(16)  # 32 hex chars = 128 bits
    return f"{ts}_{suffix}"


def validate_run_id(run_id: str) -> None:
    """Validate that *run_id* follows the canonical sortable format.

    Also accepts the legacy 32-char lowercase hex format (UUID4) for
    reading forensic outputs only — new generation must use the
    canonical sortable format.

    Raises:
        ValueError: If the run_id is invalid.
    """
    if not run_id:
        raise ValueError("run_id must not be empty")

    # Canonical sortable format: YYYYMMDDTHHMMSS_<32hex>
    if _RUN_ID_RE.match(run_id):
        return

    # Legacy format: 32-char lowercase hex (UUID4 without dashes) — forensic read only
    if len(run_id) == 32 and run_id == run_id.lower():
        try:
            int(run_id, 16)
            return
        except ValueError:
            pass

    raise ValueError(
        f"run_id must be a sortable format (YYYYMMDDTHHMMSS_<32hex>) "
        f"or a 32-char hex string, got: '{run_id}' (length {len(run_id)})"
    )


def is_sortable_run_id(run_id: str) -> bool:
    """Check whether *run_id* uses the canonical sortable format."""
    return bool(_RUN_ID_RE.match(run_id))


# --------------------------------------------------------------------------- #
# Collection → run directory resolution
# --------------------------------------------------------------------------- #


def resolve_run_dir(
    collection_dir: Path, run_id: str | None = None
) -> tuple[Path, str]:
    """Resolve and exclusively create a new run directory under *collection_dir*.

    This is the **single ownership boundary** for collection-to-run
    resolution.  No other code should create run directories.

    Raises:
        FileExistsError: If the run directory already exists (collision).
        ValueError: If run_id is invalid.
    """
    if run_id is None:
        run_id = generate_sortable_run_id()
    validate_run_id(run_id)

    collection_dir = Path(collection_dir)
    collection_dir.mkdir(parents=True, exist_ok=True)
    run_dir = collection_dir / run_id

    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir, run_id


# --------------------------------------------------------------------------- #
# File hashing
# --------------------------------------------------------------------------- #


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file's exact bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of exact bytes."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Atomic file writing
# --------------------------------------------------------------------------- #


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> Path:
    """Write text to *path* atomically using temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, suffix=".tmp", prefix=path.name
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path


def atomic_write_yaml(path: Path, data: Any) -> Path:
    """Write YAML atomically."""
    content = yaml.dump(
        data, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
    return atomic_write_text(path, content)


# --------------------------------------------------------------------------- #
# Manifest sentinel and finalization
# --------------------------------------------------------------------------- #


def _get_package_version() -> str:
    try:
        return importlib.metadata.version("scenario-forge")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def write_manifest_sentinel(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    package_version: str | None = None,
) -> Path:
    """Write the initial manifest sentinel before any pipeline work begins.

    The sentinel has status ``started`` and survives every exit path.
    It is later replaced by the final manifest via :func:`finalize_manifest`.
    """
    if package_version is None:
        package_version = _get_package_version()

    sentinel = {
        "manifest_version": MANIFEST_VERSION,
        "status": RunStatus.STARTED.value,
        "run_id": run_id,
        "timestamp_start": timestamp_start,
        "package_version": package_version,
    }
    manifest_path = run_dir / MANIFEST_FILENAME
    return atomic_write_yaml(manifest_path, sentinel)


def finalize_manifest(
    run_dir: Path,
    manifest: RunManifest,
) -> Path:
    """Write the final manifest atomically, replacing the sentinel.

    The manifest must have a final status.
    """
    if not manifest.status.is_final:
        raise ValueError(
            f"Cannot finalize manifest with non-final status: {manifest.status}"
        )
    manifest_path = run_dir / MANIFEST_FILENAME
    data = manifest.model_dump(mode="json", exclude_none=True)
    return atomic_write_yaml(manifest_path, data)


def write_failed_manifest(
    run_dir: Path,
    manifest: RunManifest,
) -> Path:
    """Best-effort write of a ``failed`` manifest with accumulated evidence.

    Called when a fatal error prevents normal finalization.  Updates the
    *existing* manifest in-place with ``status=failed`` and an error
    field, preserving whatever attempts/artifacts/provenance were
    accumulated.  Does **not** replace it with an empty manifest.
    """
    manifest.status = RunStatus.FAILED
    manifest.timestamp_end = manifest.timestamp_end or datetime.now(UTC).isoformat()
    if manifest.provenance is not None:
        manifest.provenance.timestamp_end = manifest.timestamp_end
    data = manifest.model_dump(mode="json", exclude_none=True)
    manifest_path = run_dir / MANIFEST_FILENAME
    try:
        return atomic_write_yaml(manifest_path, data)
    except Exception:
        try:
            manifest_path.write_text(
                yaml.dump(data, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )
        except Exception:
            pass
        return manifest_path


# --------------------------------------------------------------------------- #
# Git provenance
# --------------------------------------------------------------------------- #


def _find_source_repo_root() -> Path | None:
    """Find the Git repository root for the scenario_forge source package."""
    # Walk up from the package directory to find a .git directory.
    pkg_dir = Path(__file__).resolve().parent
    for parent in [pkg_dir, *pkg_dir.parents]:
        if (parent / ".git").is_dir():
            return parent
    return None


def capture_git_provenance(repo_root: Path | None = None) -> GitProvenance:
    """Capture Git commit, dirty state, and source-diff digest.

    Args:
        repo_root: Path to the Git repository root.  If None, finds the
            source repository root for the scenario_forge package.

    Returns:
        GitProvenance with commit hash, dirty flag, source-diff digest
        (including untracked file content), and untracked file list.
        If Git is unavailable or not a repo, all fields are None.
    """
    if repo_root is None:
        repo_root = _find_source_repo_root()
    if repo_root is None:
        return GitProvenance()
    cwd = str(repo_root)

    def _run_git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args],
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return None

    commit = _run_git("rev-parse", "HEAD")
    if commit is None:
        # Git is not available or not a repo — return all None
        return GitProvenance()
    branch = _run_git("rev-parse", "--abbrev-ref", "HEAD")

    # Dirty state: check if working tree has modifications or untracked files
    status = _run_git("status", "--porcelain")
    dirty = bool(status) if status is not None else None

    # Source-diff digest: SHA-256 of tracked diff + deterministic untracked
    # file paths and content hashes.
    diff = _run_git("diff", "HEAD")
    untracked_str = _run_git("ls-files", "--others", "--exclude-standard")
    untracked_files = sorted(
        [f for f in untracked_str.splitlines() if f] if untracked_str else []
    )

    hasher = hashlib.sha256()
    if diff is not None:
        hasher.update(b"--- diff ---\n")
        hasher.update(diff.encode("utf-8"))
    hasher.update(b"\n--- untracked ---\n")
    for f in untracked_files:
        hasher.update(f.encode("utf-8"))
        hasher.update(b"\n")
        fpath = repo_root / f
        if fpath.is_file():
            try:
                hasher.update(hashlib.sha256(fpath.read_bytes()).hexdigest().encode())
                hasher.update(b"\n")
            except OSError:
                hasher.update(b"<unreadable>\n")
    source_diff_digest = hasher.hexdigest()

    return GitProvenance(
        commit=commit,
        dirty=dirty,
        source_diff_digest=source_diff_digest,
        branch=branch,
        untracked_files=untracked_files,
    )


# --------------------------------------------------------------------------- #
# Provenance capture
# --------------------------------------------------------------------------- #


def capture_provenance(
    run_id: str,
    timestamp_start: str,
    command: str = "generate",
    options: dict[str, Any] | None = None,
    model_config: ModelConfig | None = None,
    prompt_template_hashes: dict[str, str] | None = None,
    input_hashes: InputHashes | None = None,
    config_digest: str | None = None,
    repo_root: Path | None = None,
    timestamp_end: str | None = None,
) -> Provenance:
    """Capture comprehensive provenance for a run."""
    pkg_version = _get_package_version()
    git_prov = capture_git_provenance(repo_root)

    return Provenance(
        run_id=run_id,
        command=CommandProvenance(
            command=command,
            options=options or {},
        ),
        package_version=pkg_version,
        manifest_version=MANIFEST_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
        model_config_provenance=model_config,
        prompt_template_hashes=prompt_template_hashes or {},
        input_hashes=input_hashes or InputHashes(),
        config_digest=config_digest,
        git=git_prov,
    )


def compute_config_digest(options: dict[str, Any]) -> str:
    """Compute a canonical SHA-256 digest of the run configuration."""
    canonical = json.dumps(options, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Manifest loading and strict inventory validation
# --------------------------------------------------------------------------- #


class ManifestIntegrityError(Exception):
    """Raised when manifest inventory validation fails."""


class ManifestInventoryResolver:
    """Strict manifest inventory resolver and validator.

    Loads a manifest (from disk or in-memory), validates every inventory
    entry (path, hash, role, duplicates, orphans, singletons, pairing),
    and provides typed access to artifacts by role.

    This is the **single shared resolver** used by both eval and report
    readers.  It never globs the filesystem — it consumes only manifest
    inventory entries.
    """

    def __init__(
        self,
        run_dir: Path,
        manifest: RunManifest,
        check_orphans: bool = True,
    ) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.manifest = manifest
        self.check_orphans = check_orphans
        self._by_role: dict[ArtifactRole, list[ArtifactEntry]] = {}
        self._validate()

    # --- Validation ---

    def _validate(self) -> None:
        """Validate the full inventory integrity globally."""
        seen_canonical: set[str] = set()
        seen_resolved: set[Path] = set()
        singleton_counts: dict[ArtifactRole, int] = {}
        scenario_ids: set[str] = set()
        candidate_ids: set[str] = set()
        yaml_stems: set[str] = set()
        feature_stems: set[str] = set()
        yaml_scenario_ids: dict[str, str] = {}  # stem -> scenario_id from YAML content

        for entry in self.manifest.inventory:
            # --- 1. Role validity ---
            try:
                role = entry.role
            except (ValueError, TypeError):
                raise ManifestIntegrityError(
                    f"Invalid or unknown artifact role: {entry.role!r}"
                ) from None

            # --- 2. Path validation ---
            entry_path = Path(entry.path)
            if entry_path.is_absolute():
                raise ManifestIntegrityError(f"Artifact path is absolute: {entry.path}")
            # Reject non-normalized / dot-dot paths
            normalized = entry_path.as_posix()
            if ".." in entry_path.parts or entry_path.as_posix() != normalized:
                raise ManifestIntegrityError(
                    f"Artifact path is not normalized or contains '..': {entry.path}"
                )
            # --- 2b. Reject symlinks and non-regular files (before resolve) ---
            path_to_check = self.run_dir / entry.path
            if path_to_check.is_symlink():
                raise ManifestIntegrityError(
                    f"Artifact path is a symlink: {entry.path}"
                )
            # Check for symlink components in the path
            current = self.run_dir
            for part in entry_path.parts:
                current = current / part
                if current.is_symlink():
                    raise ManifestIntegrityError(
                        f"Symlink component in artifact path: {entry.path}"
                    )
            resolved = (self.run_dir / entry.path).resolve()
            try:
                resolved.relative_to(self.run_dir)
            except ValueError:
                raise ManifestIntegrityError(
                    f"Artifact path escapes run directory: {entry.path}"
                ) from None

            # --- 3. No duplicate canonical or resolved paths ---
            if entry.path in seen_canonical:
                raise ManifestIntegrityError(
                    f"Duplicate artifact canonical path: {entry.path}"
                )
            seen_canonical.add(entry.path)
            if resolved in seen_resolved:
                raise ManifestIntegrityError(
                    f"Duplicate artifact resolved path: {resolved}"
                )
            seen_resolved.add(resolved)

            # --- 4. File must exist ---
            if not resolved.exists():
                raise ManifestIntegrityError(
                    f"Manifested artifact does not exist: {entry.path}"
                )

            if not resolved.is_file():
                raise ManifestIntegrityError(
                    f"Artifact is not a regular file: {entry.path}"
                )

            # --- 6. Hash verification ---
            if not entry.sha256:
                raise ManifestIntegrityError(
                    f"Missing SHA-256 for artifact: {entry.path}"
                )
            if not _SHA256_RE.match(entry.sha256):
                raise ManifestIntegrityError(
                    f"Malformed SHA-256 for artifact {entry.path}: {entry.sha256}"
                )
            actual_hash = compute_file_sha256(resolved)
            if actual_hash != entry.sha256:
                raise ManifestIntegrityError(
                    f"Hash mismatch for {entry.path}: "
                    f"manifest={entry.sha256}, actual={actual_hash}"
                )

            # --- 7. Role-extension-media-schema validation ---
            meta = _ROLE_METADATA.get(role)
            if meta is not None:
                expected_ext = meta["extension"]
                if not entry.path.endswith(expected_ext):
                    raise ManifestIntegrityError(
                        f"Role {role.value} expects extension {expected_ext}, "
                        f"got: {entry.path}"
                    )
                if not entry.media_type:
                    raise ManifestIntegrityError(
                        f"Missing media_type for artifact: {entry.path}"
                    )
            if not entry.schema_version:
                raise ManifestIntegrityError(
                    f"Missing schema_version for artifact: {entry.path}"
                )

            # --- 8. Singleton cardinality ---
            if role in SINGLETON_ROLES:
                singleton_counts[role] = singleton_counts.get(role, 0) + 1
                if singleton_counts[role] > 1:
                    raise ManifestIntegrityError(
                        f"Duplicate singleton role {role.value}: "
                        f"{singleton_counts[role]} entries"
                    )

            # --- 9. Scenario/candidate ID tracking ---
            # Track scenario IDs per role to allow YAML/feature pairs
            # with the same scenario_id while rejecting duplicates
            # within the same role.
            if entry.scenario_id:
                sid_key = (role, entry.scenario_id)
                if sid_key in scenario_ids:
                    raise ManifestIntegrityError(
                        f"Duplicate scenario_id for role {role.value}: "
                        f"{entry.scenario_id}"
                    )
                scenario_ids.add(sid_key)
            if entry.candidate_id:
                candidate_ids.add(entry.candidate_id)

            # --- 10. Scenario YAML/feature pairing ---
            if role == ArtifactRole.SCENARIO_YAML:
                stem = Path(entry.path).stem
                yaml_stems.add(stem)
                # Verify serialized scenario_id matches inventory scenario_id
                try:
                    data = yaml.safe_load(resolved.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        serialized_sid = data.get("scenario_id")
                        if serialized_sid and entry.scenario_id:
                            if serialized_sid != entry.scenario_id:
                                raise ManifestIntegrityError(
                                    f"Scenario ID mismatch for {entry.path}: "
                                    f"inventory={entry.scenario_id}, "
                                    f"serialized={serialized_sid}"
                                )
                            if serialized_sid != stem:
                                raise ManifestIntegrityError(
                                    f"Filename stem '{stem}' does not match "
                                    f"serialized scenario_id '{serialized_sid}' "
                                    f"in {entry.path}"
                                )
                        yaml_scenario_ids[stem] = entry.scenario_id or ""
                except ManifestIntegrityError:
                    raise
                except Exception as exc:
                    raise ManifestIntegrityError(
                        f"Failed to read scenario YAML {entry.path}: {exc}"
                    ) from exc

            if role == ArtifactRole.SCENARIO_FEATURE:
                stem = Path(entry.path).stem
                feature_stems.add(stem)

            # Index by role
            self._by_role.setdefault(role, []).append(entry)

        # --- 11. Exact YAML/feature pairing ---
        yaml_only = yaml_stems - feature_stems
        feature_only = feature_stems - yaml_stems
        if yaml_only or feature_only:
            parts: list[str] = []
            if yaml_only:
                parts.append(f"YAML without feature: {sorted(yaml_only)}")
            if feature_only:
                parts.append(f"feature without YAML: {sorted(feature_only)}")
            raise ManifestIntegrityError(
                f"Incomplete scenario YAML/feature pairs: {'; '.join(parts)}"
            )

        # --- 12. Orphan detection ---
        if self.check_orphans:
            self._check_orphans(seen_canonical)

    def _check_orphans(self, manifested_paths: set[str]) -> None:
        """Detect unmanifested files inside the run directory.

        The manifest container file (``run-manifest.yaml``) is the sole
        orphan exception — it is the inventory container, not an artifact.
        """
        actual_files: set[str] = set()
        for root, _dirs, files in os.walk(self.run_dir):
            for fname in files:
                full = Path(root) / fname
                rel = full.relative_to(self.run_dir).as_posix()
                actual_files.add(rel)

        allowed_unmanifested = {MANIFEST_FILENAME}
        orphans = actual_files - manifested_paths - allowed_unmanifested
        if orphans:
            raise ManifestIntegrityError(
                f"Unmanifested orphan files in run directory: {sorted(orphans)}"
            )

    # --- Typed accessors ---

    def entries_by_role(self, role: ArtifactRole) -> list[ArtifactEntry]:
        """Return all inventory entries with the given role."""
        return list(self._by_role.get(role, []))

    def entry_by_role(self, role: ArtifactRole) -> ArtifactEntry | None:
        """Return the single entry with the given role, or None."""
        entries = self.entries_by_role(role)
        if len(entries) > 1:
            raise ManifestIntegrityError(
                f"Expected at most 1 entry for role {role}, got {len(entries)}"
            )
        return entries[0] if entries else None

    def resolve_path(self, entry: ArtifactEntry) -> Path:
        """Resolve an inventory entry to an absolute path."""
        return (self.run_dir / entry.path).resolve()

    def read_text(self, entry: ArtifactEntry, encoding: str = "utf-8") -> str:
        """Read the content of an inventory entry as text."""
        return self.resolve_path(entry).read_text(encoding=encoding)

    def read_bytes(self, entry: ArtifactEntry) -> bytes:
        """Read the content of an inventory entry as bytes."""
        return self.resolve_path(entry).read_bytes()

    def read_yaml(self, entry: ArtifactEntry) -> Any:
        """Read and parse a YAML inventory entry."""
        return yaml.safe_load(self.read_text(entry))

    def read_json(self, entry: ArtifactEntry) -> Any:
        """Read and parse a JSON inventory entry."""
        return json.loads(self.read_text(entry))

    def scenario_yaml_entries(self) -> list[ArtifactEntry]:
        """Return all scenario YAML entries, sorted by scenario_id."""
        return sorted(
            self.entries_by_role(ArtifactRole.SCENARIO_YAML),
            key=lambda e: e.scenario_id or e.path,
        )

    def scenario_feature_entries(self) -> list[ArtifactEntry]:
        """Return all scenario feature entries, sorted by scenario_id."""
        return sorted(
            self.entries_by_role(ArtifactRole.SCENARIO_FEATURE),
            key=lambda e: e.scenario_id or e.path,
        )

    def feature_for_scenario(self, scenario_id: str) -> ArtifactEntry | None:
        """Return the feature entry for a given scenario_id, if any."""
        for e in self.entries_by_role(ArtifactRole.SCENARIO_FEATURE):
            if e.scenario_id == scenario_id:
                return e
        return None


def load_manifest(run_dir: Path) -> RunManifest:
    """Load and parse a manifest from a run directory.

    Does not validate inventory — use :func:`load_strict_resolver` for that.
    """
    run_dir = Path(run_dir)
    manifest_path = run_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise ManifestIntegrityError(f"No manifest found in run directory: {run_dir}")
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not data or not isinstance(data, dict):
        raise ManifestIntegrityError(f"Invalid manifest in {manifest_path}: not a dict")
    return RunManifest.model_validate(data)


def load_strict_resolver(
    run_dir: Path,
    require_final: bool = True,
    require_authoritative: bool = False,
) -> ManifestInventoryResolver:
    """Load a manifest from disk and build a strict inventory resolver.

    Args:
        run_dir: Path to a run directory (not a collection).
        require_final: If True, manifest status must be final.
        require_authoritative: If True, manifest status must be ``completed``.

    Raises:
        ManifestIntegrityError: If the manifest is missing, invalid,
            not final (when required), or not authoritative (when required).
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise ManifestIntegrityError(
            f"Run directory does not exist or is not a directory: {run_dir}"
        )

    manifest = load_manifest(run_dir)

    if require_final and not manifest.status.is_final:
        raise ManifestIntegrityError(
            f"Manifest status is not final: {manifest.status} in {run_dir}"
        )

    if require_authoritative and not manifest.status.is_authoritative:
        raise ManifestIntegrityError(
            f"Manifest is not authoritative (status={manifest.status}) in {run_dir}"
        )

    check_orphans = require_final
    return ManifestInventoryResolver(run_dir, manifest, check_orphans=check_orphans)


def build_in_memory_resolver(
    run_dir: Path,
    manifest: RunManifest,
) -> ManifestInventoryResolver:
    """Build a resolver from an in-memory manifest for internal pipeline use.

    Validates inventory entries (paths, hashes, roles) but does **not**
    check for orphans — the run is still in progress and may have files
    not yet inventoried.
    """
    return ManifestInventoryResolver(run_dir, manifest, check_orphans=False)


def is_run_dir(path: Path) -> bool:
    """Check whether *path* is a run directory (contains a manifest)."""
    return (Path(path) / MANIFEST_FILENAME).exists()


def find_run_dir(path: Path) -> Path:
    """Given a path, resolve it to a single unambiguous run directory.

    If *path* is a run directory (contains run-manifest.yaml), return it.
    If *path* is a collection containing **exactly one** run, return that run.
    If the collection contains zero or multiple runs, raise.
    """
    path = Path(path)
    if is_run_dir(path):
        return path

    if path.is_dir():
        run_dirs = sorted(
            [d for d in path.iterdir() if d.is_dir() and is_run_dir(d)],
            key=lambda d: d.name,
        )
        if len(run_dirs) == 1:
            return run_dirs[0]
        if not run_dirs:
            raise ManifestIntegrityError(
                f"No run directory found in collection: {path}"
            )
        raise ManifestIntegrityError(
            f"Collection {path} contains {len(run_dirs)} runs; "
            f"pass a specific run directory to disambiguate. "
            f"Runs: {[d.name for d in run_dirs]}"
        )

    raise ManifestIntegrityError(
        f"Path is neither a run directory nor a collection: {path}"
    )


# --------------------------------------------------------------------------- #
# Inventory builder helpers
# --------------------------------------------------------------------------- #


def build_artifact_entry(
    role: ArtifactRole,
    run_dir: Path,
    rel_path: str,
    scenario_id: str | None = None,
    candidate_id: str | None = None,
) -> ArtifactEntry:
    """Build an ArtifactEntry from a file in the run directory.

    The file must exist — this function raises if it does not, so that
    ``_build_run_inventory`` fails for expected-but-missing outputs
    rather than silently omitting them.
    """
    full_path = run_dir / rel_path
    if not full_path.exists():
        raise ManifestIntegrityError(
            f"Expected artifact missing for role {role.value}: {rel_path}"
        )
    meta = _ROLE_METADATA.get(role, {})
    return ArtifactEntry(
        role=role,
        path=rel_path,
        sha256=compute_file_sha256(full_path),
        scenario_id=scenario_id,
        candidate_id=candidate_id,
        media_type=meta.get("media_type", "application/octet-stream"),
    )


def validate_completed_inventory(
    manifest: RunManifest,
    *,
    eval_enabled: bool,
) -> None:
    """Globally validate role cardinality, singleton requirements, funnel
    equations, and full inventory before atomically committing ``completed``.

    Raises:
        ManifestIntegrityError: If any invariant is violated.
    """
    # Check required singleton roles
    required = required_singleton_roles(eval_enabled=eval_enabled)
    present_roles: set[ArtifactRole] = set()
    for entry in manifest.inventory:
        try:
            present_roles.add(entry.role)
        except (ValueError, TypeError):
            raise ManifestIntegrityError(
                f"Invalid artifact role in inventory: {entry.role!r}"
            ) from None

    missing = required - present_roles
    if missing:
        raise ManifestIntegrityError(
            f"Missing required singleton roles for completed status: "
            f"{sorted(r.value for r in missing)}"
        )

    # Check duplicate singleton roles
    role_counts: dict[ArtifactRole, int] = {}
    for entry in manifest.inventory:
        try:
            role = entry.role
        except (ValueError, TypeError):
            raise ManifestIntegrityError(
                f"Invalid artifact role: {entry.role!r}"
            ) from None
        if role in SINGLETON_ROLES:
            role_counts[role] = role_counts.get(role, 0) + 1
            if role_counts[role] > 1:
                raise ManifestIntegrityError(
                    f"Duplicate singleton role {role.value}: "
                    f"{role_counts[role]} entries"
                )

    # Check unique scenario/candidate IDs among scenario artifacts
    scenario_ids: set[str] = set()
    for entry in manifest.inventory:
        if entry.role in (
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
        ):
            if entry.scenario_id:
                if entry.scenario_id in scenario_ids:
                    raise ManifestIntegrityError(
                        f"Duplicate scenario_id: {entry.scenario_id}"
                    )
                scenario_ids.add(entry.scenario_id)

    # Check funnel/disposition equations from attempts
    if manifest.attempts:
        admitted = sum(
            1 for a in manifest.attempts if a.disposition == AttemptDisposition.ADMITTED
        )
        quarantined = sum(
            1
            for a in manifest.attempts
            if a.disposition == AttemptDisposition.QUARANTINED
        )
        failed = sum(
            1 for a in manifest.attempts if a.disposition == AttemptDisposition.FAILED
        )
        funnel = manifest.funnel
        if funnel:
            funnel_admitted = funnel.get("admitted", 0)
            funnel_quarantined = funnel.get("quarantined", 0)
            funnel_attempted = funnel.get("attempted", 0)
            if admitted != funnel_admitted:
                raise ManifestIntegrityError(
                    f"Funnel admitted mismatch: attempts={admitted}, "
                    f"funnel={funnel_admitted}"
                )
            if quarantined != funnel_quarantined:
                raise ManifestIntegrityError(
                    f"Funnel quarantined mismatch: attempts={quarantined}, "
                    f"funnel={funnel_quarantined}"
                )
            if admitted + quarantined + failed != funnel_attempted:
                raise ManifestIntegrityError(
                    f"Funnel attempted mismatch: "
                    f"attempts(admitted={admitted}+quarantined={quarantined}"
                    f"+failed={failed})={admitted + quarantined + failed}, "
                    f"funnel={funnel_attempted}"
                )

    # Evaluated count must derive from unique typed inventory
    if eval_enabled:
        yaml_count = sum(
            1 for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
        )
        feature_count = sum(
            1 for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_FEATURE
        )
        if yaml_count != feature_count:
            raise ManifestIntegrityError(
                f"Scenario YAML/feature count mismatch: "
                f"yaml={yaml_count}, feature={feature_count}"
            )
