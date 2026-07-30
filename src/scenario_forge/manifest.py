"""Immutable run identity, versioned manifest, artifact inventory, and provenance.

This module is the single ownership boundary for:

* Run collection → run directory resolution (sortable, collision-safe)
* Versioned manifest sentinel lifecycle (``started`` → final status)
* Typed artifact inventory with SHA-256 verification
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


# ---------------------------------------------------------------------------
# Constants and versions
# ---------------------------------------------------------------------------

MANIFEST_VERSION = "2"
ARTIFACT_SCHEMA_VERSION = "1"
_RUN_ID_TIMESTAMP_LEN = 15  # YYYYMMDDTHHMMSS
_RUN_ID_SEPARATOR = "_"
_RUN_ID_HEX_LEN = 16  # 64 bits of collision-safe entropy
_RUN_ID_TOTAL_LEN = _RUN_ID_TIMESTAMP_LEN + 1 + _RUN_ID_HEX_LEN  # 32
_RUN_ID_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})_([0-9a-f]{16})$")
MANIFEST_FILENAME = "run-manifest.yaml"
MANIFEST_SENTINEL_FILENAME = "run-manifest.yaml"  # same file, evolved


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


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
    """Typed role for every persisted artifact in a run."""

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
    RUN_MANIFEST = "run_manifest"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ArtifactEntry(BaseModel):
    """A single persisted artifact in the run inventory."""

    role: ArtifactRole
    path: str  # canonical relative path from run root
    sha256: str | None = None  # None for manifest itself (self-referential)
    schema_version: str = ARTIFACT_SCHEMA_VERSION
    scenario_id: str | None = None
    candidate_id: str | None = None
    media_type: str | None = None

    model_config = {"use_enum_values": False}


class GitProvenance(BaseModel):
    """Git source provenance for reproducibility."""

    commit: str | None = None
    dirty: bool | None = None
    source_diff_digest: str | None = None  # SHA-256 of `git diff` output
    branch: str | None = None


class InputHashes(BaseModel):
    """SHA-256 hashes of all effective inputs."""

    use_case_hash: str | None = None
    risk_extraction_hash: str | None = None
    sssom_hash: str | None = None
    profile_hash: str | None = None
    threats_hash: str | None = None
    cross_taxonomy_hash: str | None = None


class ModelConfig(BaseModel):
    """Resolved LLM model configuration."""

    model: str | None = None
    base_url: str | None = None
    temperature: float | None = None
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
    model_config_provenance: ModelConfig = Field(default_factory=ModelConfig)
    prompt_template_hashes: dict[str, str] = Field(default_factory=dict)
    input_hashes: InputHashes = Field(default_factory=InputHashes)
    config_digest: str | None = None
    git: GitProvenance = Field(default_factory=GitProvenance)


class RunManifest(BaseModel):
    """The complete versioned run manifest — sentinel and final inventory."""

    manifest_version: str = MANIFEST_VERSION
    status: RunStatus = RunStatus.STARTED
    run_id: str
    timestamp_start: str
    timestamp_end: str | None = None
    package_version: str = "0.0.0"
    provenance: Provenance | None = None
    inventory: list[ArtifactEntry] = Field(default_factory=list)

    # Legacy/extension fields from the pipeline manifest
    inputs: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    seeds_generated: int = 0
    funnel: dict[str, Any] = Field(default_factory=dict)
    stage_records: list[dict[str, Any]] = Field(default_factory=list)
    rule_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    scenarios_generated: int = 0
    scenarios_failed: int = 0
    artifacts: list[dict[str, Any]] = Field(
        default_factory=list
    )  # legacy artifact records
    phantom_validation: dict[str, Any] = Field(default_factory=dict)
    structural_validation: dict[str, Any] = Field(default_factory=dict)
    semantic_validation: dict[str, Any] = Field(default_factory=dict)
    leaf_technique_provenance: dict[str, Any] = Field(default_factory=dict)
    parsimony: dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": False}


# ---------------------------------------------------------------------------
# Run ID generation and validation
# ---------------------------------------------------------------------------


def generate_sortable_run_id() -> str:
    """Generate a sortable, collision-safe run ID.

    Format: ``YYYYMMDDTHHMMSS_<16 hex chars>`` (32 chars total).
    The timestamp prefix makes directories sortable by lexical order.
    The 64-bit random suffix prevents collisions within the same second.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    suffix = secrets.token_hex(8)  # 16 hex chars = 64 bits
    return f"{ts}_{suffix}"


def validate_run_id(run_id: str) -> None:
    """Validate that *run_id* follows the sortable format.

    Also accepts the legacy 32-char lowercase hex format (UUID4) for
    backward compatibility with existing cmps.3 tests.

    Raises:
        ValueError: If the run_id is invalid.
    """
    if not run_id:
        raise ValueError("run_id must not be empty")

    # New sortable format: YYYYMMDDTHHMMSS_<16hex>
    if _RUN_ID_RE.match(run_id):
        return

    # Legacy format: 32-char lowercase hex (UUID4 without dashes)
    if len(run_id) == 32 and run_id == run_id.lower():
        try:
            int(run_id, 16)
            return
        except ValueError:
            pass

    raise ValueError(
        f"run_id must be a sortable format (YYYYMMDDTHHMMSS_<16hex>) "
        f"or a 32-char hex string, got: '{run_id}' (length {len(run_id)})"
    )


def is_sortable_run_id(run_id: str) -> bool:
    """Check whether *run_id* uses the new sortable format."""
    return bool(_RUN_ID_RE.match(run_id))


# ---------------------------------------------------------------------------
# Collection → run directory resolution
# ---------------------------------------------------------------------------


def resolve_run_dir(
    collection_dir: Path, run_id: str | None = None
) -> tuple[Path, str]:
    """Resolve and exclusively create a new run directory under *collection_dir*.

    This is the **single ownership boundary** for collection-to-run
    resolution.  No other code should create run directories.

    Args:
        collection_dir: The user-supplied output collection path.
        run_id: Optional pre-generated run ID.  If None, a new sortable
            run ID is generated.

    Returns:
        Tuple of (run_dir_path, run_id).

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

    # Exclusive creation — fails if directory already exists.
    # This is the immutability guard: existing runs are never overwritten.
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir, run_id


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file's exact bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of exact bytes."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Atomic file writing
# ---------------------------------------------------------------------------


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> Path:
    """Write text to *path* atomically using temp file + os.replace.

    The temp file is created in the same directory as *path* to ensure
    the rename is atomic on the same filesystem.
    """
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


# ---------------------------------------------------------------------------
# Manifest sentinel and finalization
# ---------------------------------------------------------------------------


def write_manifest_sentinel(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    package_version: str | None = None,
) -> Path:
    """Write the initial manifest sentinel before pipeline work begins.

    The sentinel has status ``started`` and survives every exit path.
    It is later replaced by the final manifest via :func:`finalize_manifest`.
    """
    if package_version is None:
        try:
            package_version = importlib.metadata.version("scenario-forge")
        except importlib.metadata.PackageNotFoundError:
            package_version = "0.0.0"

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

    The manifest must have a final status (``completed``,
    ``completed_with_errors``, or ``failed``).
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
    run_id: str,
    timestamp_start: str,
    error_message: str,
    package_version: str | None = None,
    timestamp_end: str | None = None,
) -> Path:
    """Best-effort write of a ``failed`` manifest.

    Called when a fatal error prevents normal finalization.
    Preserves evidence and marks the run as non-authoritative.
    """
    if package_version is None:
        try:
            package_version = importlib.metadata.version("scenario-forge")
        except importlib.metadata.PackageNotFoundError:
            package_version = "0.0.0"

    if timestamp_end is None:
        timestamp_end = datetime.now(UTC).isoformat()

    manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.FAILED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
        package_version=package_version,
        provenance=Provenance(
            run_id=run_id,
            package_version=package_version,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        ),
    )
    # Store error in a diagnostic field
    data = manifest.model_dump(mode="json", exclude_none=True)
    data["error"] = error_message
    manifest_path = run_dir / MANIFEST_FILENAME
    try:
        return atomic_write_yaml(manifest_path, data)
    except Exception:
        # Last resort: direct write
        manifest_path.write_text(
            yaml.dump(data, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        return manifest_path


# ---------------------------------------------------------------------------
# Git provenance
# ---------------------------------------------------------------------------


def capture_git_provenance(repo_root: Path | None = None) -> GitProvenance:
    """Capture Git commit, dirty state, and source-diff digest.

    Args:
        repo_root: Path to the Git repository root.  If None, uses cwd.

    Returns:
        GitProvenance with commit hash, dirty flag, and diff digest.
        If Git is unavailable or not a repo, all fields are None.
    """
    cwd = str(repo_root) if repo_root else None

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
    branch = _run_git("rev-parse", "--abbrev-ref", "HEAD")

    # Dirty state: check if working tree has modifications
    status = _run_git("status", "--porcelain")
    dirty = bool(status) if status is not None else None

    # Source-diff digest: SHA-256 of the full diff (staged + unstaged)
    diff = _run_git("diff", "HEAD")
    if diff is None:
        source_diff_digest = None
    else:
        source_diff_digest = hashlib.sha256(diff.encode("utf-8")).hexdigest()

    return GitProvenance(
        commit=commit,
        dirty=dirty,
        source_diff_digest=source_diff_digest,
        branch=branch,
    )


# ---------------------------------------------------------------------------
# Provenance capture
# ---------------------------------------------------------------------------


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
    try:
        pkg_version = importlib.metadata.version("scenario-forge")
    except importlib.metadata.PackageNotFoundError:
        pkg_version = "0.0.0"

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
        model_config_provenance=model_config or ModelConfig(),
        prompt_template_hashes=prompt_template_hashes or {},
        input_hashes=input_hashes or InputHashes(),
        config_digest=config_digest,
        git=git_prov,
    )


def compute_config_digest(options: dict[str, Any]) -> str:
    """Compute a canonical SHA-256 digest of the run configuration."""
    canonical = json.dumps(options, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Manifest loading and strict inventory validation
# ---------------------------------------------------------------------------


class ManifestIntegrityError(Exception):
    """Raised when manifest inventory validation fails."""


class ManifestInventoryResolver:
    """Strict manifest inventory resolver and validator.

    Loads a finalized manifest from a run directory, validates every
    inventory entry (path, hash, role, duplicates, orphans), and provides
    typed access to artifacts by role.

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
        self.run_dir = run_dir.resolve()
        self.manifest = manifest
        self.check_orphans = check_orphans
        self._by_role: dict[ArtifactRole, list[ArtifactEntry]] = {}
        self._by_path: dict[str, ArtifactEntry] = {}
        self._validate()

    def _validate(self) -> None:
        """Validate the full inventory integrity."""
        seen_paths: set[str] = set()

        for entry in self.manifest.inventory:
            # 1. Path must be relative and not escape the run directory
            entry_path = Path(entry.path)
            if entry_path.is_absolute():
                raise ManifestIntegrityError(f"Artifact path is absolute: {entry.path}")
            resolved = (self.run_dir / entry.path).resolve()
            try:
                resolved.relative_to(self.run_dir)
            except ValueError:
                raise ManifestIntegrityError(
                    f"Artifact path escapes run directory: {entry.path}"
                ) from None

            # 2. No duplicate paths
            if entry.path in seen_paths:
                raise ManifestIntegrityError(
                    f"Duplicate artifact path in inventory: {entry.path}"
                )
            seen_paths.add(entry.path)

            # 3. File must exist
            if not resolved.exists():
                raise ManifestIntegrityError(
                    f"Manifested artifact does not exist: {entry.path}"
                )

            # 4. Hash verification (skip for manifest itself and None hashes)
            if entry.sha256 is not None:
                actual_hash = compute_file_sha256(resolved)
                if actual_hash != entry.sha256:
                    raise ManifestIntegrityError(
                        f"Hash mismatch for {entry.path}: "
                        f"manifest={entry.sha256}, actual={actual_hash}"
                    )

        # 5. Orphan detection: every file in run_dir (recursively)
        # must be in the inventory or be the manifest itself.
        # Only for finalized manifests — intermediate (started) manifests
        # may have files not yet inventoried.
        if self.check_orphans:
            self._check_orphans(seen_paths)

    def _check_orphans(self, manifested_paths: set[str]) -> None:
        """Detect unmanifested files inside the run directory."""
        manifest_path = MANIFEST_FILENAME
        # Collect all files in run_dir recursively
        actual_files: set[str] = set()
        for root, _dirs, files in os.walk(self.run_dir):
            for fname in files:
                full = Path(root) / fname
                rel = full.relative_to(self.run_dir).as_posix()
                actual_files.add(rel)

        # The manifest file itself is allowed without an inventory entry
        # (it is the inventory container/sentinel).
        allowed_unmanifested = {manifest_path}

        orphans = actual_files - manifested_paths - allowed_unmanifested
        if orphans:
            raise ManifestIntegrityError(
                f"Unmanifested orphan files in run directory: {sorted(orphans)}"
            )

    # --- Typed accessors ---

    def entries_by_role(self, role: ArtifactRole) -> list[ArtifactEntry]:
        """Return all inventory entries with the given role."""
        return [e for e in self.manifest.inventory if e.role == role]

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
    """Load a manifest and build a strict inventory resolver.

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

    # Only check orphans for finalized manifests — intermediate (started)
    # manifests may have files not yet inventoried (e.g. eval scorecard,
    # report, pipeline.log written during the run).
    check_orphans = require_final

    return ManifestInventoryResolver(run_dir, manifest, check_orphans=check_orphans)


def is_run_dir(path: Path) -> bool:
    """Check whether *path* is a run directory (contains a manifest)."""
    return (Path(path) / MANIFEST_FILENAME).exists()


def find_run_dir(path: Path) -> Path:
    """Given a path, resolve it to a single unambiguous run directory.

    If *path* is a run directory (contains run-manifest.yaml), return it.
    If *path* is a collection containing **exactly one** run, return that run.
    If the collection contains zero or multiple runs, raise — the caller
    must disambiguate by passing the specific run directory.  This enforces
    strict, unambiguous run-directory semantics with no implicit ``latest``
    selection.
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


# ---------------------------------------------------------------------------
# Inventory builder
# ---------------------------------------------------------------------------


def build_artifact_entry(
    role: ArtifactRole,
    run_dir: Path,
    rel_path: str,
    scenario_id: str | None = None,
    candidate_id: str | None = None,
    media_type: str | None = None,
    compute_hash: bool = True,
) -> ArtifactEntry:
    """Build an ArtifactEntry from a file in the run directory."""
    full_path = run_dir / rel_path
    sha256 = (
        compute_file_sha256(full_path) if compute_hash and full_path.exists() else None
    )
    return ArtifactEntry(
        role=role,
        path=rel_path,
        sha256=sha256,
        scenario_id=scenario_id,
        candidate_id=candidate_id,
        media_type=media_type,
    )
