"""Focused lifecycle, immutability, integrity, and provenance tests for cmps.1.

Covers the acceptance contract:
- Immutable two-run collections with sortable, collision-safe run IDs (128-bit)
- Run-local logging that never appends across runs
- Versioned manifest sentinel surviving every exit path
- Final status: completed / completed_with_errors / failed
- Typed artifact inventory with SHA-256, roles, and integrity validation
- Strict eval/report consuming only manifest inventory entries
- Provenance: Git (clean/dirty/untracked), config digest, input hashes, model config
- Standalone CLI eval/report requiring authoritative completed
- Attempt records with admitted/quarantined/failed disposition
- Inventory validation: symlinks, non-regular, duplicate singletons, ID mismatch
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from scenario_forge.manifest import (
    AttemptDisposition,
    AttemptPhase,
    AttemptRecord,
    ArtifactEntry,
    ArtifactRole,
    GitProvenance,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    build_in_memory_resolver,
    compute_config_digest,
    compute_file_sha256,
    find_run_dir,
    generate_sortable_run_id,
    is_run_dir,
    is_sortable_run_id,
    load_manifest,
    load_strict_resolver,
    required_singleton_roles,
    resolve_run_dir,
    validate_completed_inventory,
    validate_attempt_equations,
    validate_run_id,
    write_failed_manifest,
    write_manifest_sentinel,
    finalize_manifest,
    atomic_write_yaml,
    MANIFEST_FILENAME,
    capture_provenance,
)
from tests.manifest_helpers import build_test_run_dir


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_VALID_RUN_ID = "20260101T000000_abcdef0123456789abcdef0123456789"


def _make_scenario(scenario_id: str = "s1") -> dict:
    return {
        "scenario_id": scenario_id,
        "narrative": {
            "title": "Test",
            "summary": "A test",
            "entry_point": "e",
            "zone_sequence": ["input"],
            "steps": [],
        },
        "actor_profile": {
            "actor_type": "external",
            "goal_category": "x",
            "capability_level": "intermediate",
        },
        "attack_tree": {"id": "t", "goal": "g", "root": {}},
    }


def _make_feature(scenario_id: str = "s1") -> str:
    return f"Feature: {scenario_id}\n  Scenario: Attack\n    Given x\n"


# --------------------------------------------------------------------------- #
# 1. Immutable two-run collections
# --------------------------------------------------------------------------- #


class TestImmutableTwoRun:
    """Reusing one output collection twice creates two immutable run dirs."""

    def test_two_runs_create_unique_sortable_dirs(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir_1, run_id_1 = resolve_run_dir(collection)
        run_dir_2, run_id_2 = resolve_run_dir(collection)

        assert run_id_1 != run_id_2
        assert run_dir_1 != run_dir_2
        assert is_sortable_run_id(run_id_1)
        assert is_sortable_run_id(run_id_2)
        assert run_dir_1.parent == collection
        assert run_dir_2.parent == collection

    def test_first_run_unchanged_after_second(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir_1, run_id_1 = resolve_run_dir(collection)
        (run_dir_1 / "use-case.txt").write_text("test use case")
        write_manifest_sentinel(run_dir_1, run_id_1, "2026-01-01T00:00:00+00:00")

        snapshot: dict[str, bytes] = {}
        for f in run_dir_1.rglob("*"):
            if f.is_file():
                snapshot[f.relative_to(run_dir_1).as_posix()] = f.read_bytes()

        run_dir_2, run_id_2 = resolve_run_dir(collection)
        (run_dir_2 / "use-case.txt").write_text("different use case")

        for rel, original_bytes in snapshot.items():
            assert (run_dir_1 / rel).read_bytes() == original_bytes, (
                f"File {rel} in first run was modified by second run"
            )

    def test_existing_run_dir_not_reused(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)
        with pytest.raises(FileExistsError):
            resolve_run_dir(collection, run_id=run_id)

    def test_collection_sibling_stale_files_ignored(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / _VALID_RUN_ID,
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )

        (collection / "stale.yaml").write_text("stale: true")
        (collection / "garbage.json").write_text("{}")

        found = find_run_dir(collection)
        assert found == run_dir

        resolver = load_strict_resolver(run_dir)
        assert len(resolver.scenario_yaml_entries()) == 1


# --------------------------------------------------------------------------- #
# 2. Run-local logging
# --------------------------------------------------------------------------- #


class TestRunLocalLogging:
    """Logs are run-local and never append across runs."""

    def test_log_file_mode_is_write_not_append(self, tmp_path: Path):
        from scenario_forge.log_config import setup_logging
        import logging

        collection = tmp_path / "output"
        run_dir, _ = resolve_run_dir(collection)
        setup_logging(output_dir=run_dir)
        logger = logging.getLogger("scenario_forge")
        logger.info("First run message")

        for h in logger.handlers:
            h.flush()

        log_path = run_dir / "pipeline.log"
        assert log_path.exists()
        content_1 = log_path.read_text()
        assert "First run message" in content_1

        run_dir_2, _ = resolve_run_dir(collection)
        setup_logging(output_dir=run_dir_2)
        logger.info("Second run message")
        for h in logger.handlers:
            h.flush()

        log_path_2 = run_dir_2 / "pipeline.log"
        content_2 = log_path_2.read_text()
        assert "Second run message" in content_2
        assert "First run message" not in content_2


# --------------------------------------------------------------------------- #
# 3. Manifest sentinel and lifecycle
# --------------------------------------------------------------------------- #


class TestManifestSentinel:
    """Versioned manifest sentinel survives every exit path."""

    def test_sentinel_written_before_pipeline_work(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)
        ts = "2026-01-01T00:00:00+00:00"
        write_manifest_sentinel(run_dir, run_id, ts)

        manifest = load_manifest(run_dir)
        assert manifest.status == RunStatus.STARTED
        assert manifest.run_id == run_id
        assert manifest.timestamp_start == ts
        assert manifest.manifest_version == "2"

    def test_failed_manifest_on_fatal_error(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)
        ts = "2026-01-01T00:00:00+00:00"
        write_manifest_sentinel(run_dir, run_id, ts)

        # Build a manifest with some accumulated evidence
        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=ts,
            attempts=[
                AttemptRecord(
                    candidate_id="cand:v1:abc",
                    scenario_id="20240101T120000_abcdef1234567890abcdef1234567890",
                    disposition=AttemptDisposition.FAILED,
                    failure_evidence="boom",
                )
            ],
        )
        manifest.error = "Something went wrong"
        write_failed_manifest(run_dir, manifest)

        loaded = load_manifest(run_dir)
        assert loaded.status == RunStatus.FAILED
        assert loaded.run_id == run_id
        assert loaded.error == "Something went wrong"
        assert len(loaded.attempts) == 1

    def test_finalize_requires_final_status(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)

        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start="2026-01-01T00:00:00+00:00",
        )
        with pytest.raises(ValueError, match="non-final status"):
            finalize_manifest(run_dir, manifest)

    def test_completed_status_is_authoritative(self):
        assert RunStatus.COMPLETED.is_authoritative
        assert not RunStatus.COMPLETED_WITH_ERRORS.is_authoritative
        assert not RunStatus.FAILED.is_authoritative

    def test_final_statuses(self):
        finals = RunStatus.final_statuses()
        assert RunStatus.COMPLETED in finals
        assert RunStatus.COMPLETED_WITH_ERRORS in finals
        assert RunStatus.FAILED in finals
        assert RunStatus.STARTED not in finals


# --------------------------------------------------------------------------- #
# 4. Typed artifact inventory integrity
# --------------------------------------------------------------------------- #


class TestInventoryIntegrity:
    """Manifest inventory validation: missing, duplicate, orphan, hash mismatch."""

    def test_valid_inventory_passes(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )
        resolver = load_strict_resolver(run_dir)
        assert len(resolver.scenario_yaml_entries()) == 1
        assert resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE) is not None

    def test_hash_mismatch_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        (run_dir / "capability-profile.yaml").write_text("tampered: true")
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            load_strict_resolver(run_dir)

    def test_missing_artifact_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        (run_dir / "capability-profile.yaml").unlink()
        with pytest.raises(ManifestIntegrityError, match="does not exist"):
            load_strict_resolver(run_dir)

    def test_orphan_file_in_run_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        (run_dir / "rogue.yaml").write_text("rogue: true")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            load_strict_resolver(run_dir)

    def test_duplicate_path_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt"),
                build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt"),
            ],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Duplicate"):
            load_strict_resolver(run_dir)

    def test_path_escaping_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")
        outside = tmp_path / "outside.txt"
        outside.write_text("outside")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="../../outside.txt",
            sha256=compute_file_sha256(outside),
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(
            ManifestIntegrityError, match="not normalized|escapes|'\\.\\.'"
        ):
            load_strict_resolver(run_dir)

    def test_symlink_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        target = tmp_path / "target.txt"
        target.write_text("target")
        link = run_dir / "link.txt"
        os.symlink(target, link)

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="link.txt",
            sha256=compute_file_sha256(link),
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="symlink"):
            load_strict_resolver(run_dir)

    def test_non_regular_file_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "subdir").mkdir()

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="subdir",
            sha256=compute_file_sha256(run_dir / "use-case.txt")
            if (run_dir / "use-case.txt").exists()
            else "0" * 64,
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="not a regular file"):
            load_strict_resolver(run_dir)

    def test_malformed_hash_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="use-case.txt",
            sha256="not-a-hash",
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Malformed SHA-256"):
            load_strict_resolver(run_dir)

    def test_missing_hash_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="use-case.txt",
            sha256="",
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Missing SHA-256"):
            load_strict_resolver(run_dir)

    def test_duplicate_singleton_role_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "a.txt").write_text("a")
        (run_dir / "b.txt").write_text("b")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                ArtifactEntry(
                    role=ArtifactRole.USE_CASE,
                    path="a.txt",
                    sha256=compute_file_sha256(run_dir / "a.txt"),
                    media_type="text/plain",
                ),
                ArtifactEntry(
                    role=ArtifactRole.USE_CASE,
                    path="b.txt",
                    sha256=compute_file_sha256(run_dir / "b.txt"),
                    media_type="text/plain",
                ),
            ],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(
            ManifestIntegrityError,
            match="Duplicate singleton|must be at 'use-case.txt'",
        ):
            load_strict_resolver(run_dir)

    def test_wrong_extension_for_role_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "profile.txt").write_text("not yaml")

        entry = ArtifactEntry(
            role=ArtifactRole.CAPABILITY_PROFILE,
            path="profile.txt",
            sha256=compute_file_sha256(run_dir / "profile.txt"),
            media_type="application/yaml",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="expects extension"):
            load_strict_resolver(run_dir)

    def test_yaml_feature_pairing_enforced(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        (run_dir / "scenarios" / "s1.yaml").write_text(yaml.dump({"scenario_id": "s1"}))
        # No matching .feature file

        entry = ArtifactEntry(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/s1.yaml",
            sha256=compute_file_sha256(run_dir / "scenarios" / "s1.yaml"),
            media_type="application/yaml",
            scenario_id="s1",
            candidate_id="cand:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="YAML without feature"):
            load_strict_resolver(run_dir)

    def test_feature_only_without_yaml_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        (run_dir / "scenarios" / "orphan.feature").write_text("Feature: orphan")

        entry = ArtifactEntry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/orphan.feature",
            sha256=compute_file_sha256(run_dir / "scenarios" / "orphan.feature"),
            media_type="text/plain",
            scenario_id="orphan",
            candidate_id="cand:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="feature without YAML"):
            load_strict_resolver(run_dir)

    def test_scenario_id_filename_stem_mismatch_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        # Filename stem is "s1" but serialized scenario_id is "s2"
        (run_dir / "scenarios" / "s1.yaml").write_text(yaml.dump({"scenario_id": "s2"}))
        (run_dir / "scenarios" / "s1.feature").write_text("Feature: s1")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                ArtifactEntry(
                    role=ArtifactRole.SCENARIO_YAML,
                    path="scenarios/s1.yaml",
                    sha256=compute_file_sha256(run_dir / "scenarios" / "s1.yaml"),
                    media_type="application/yaml",
                    scenario_id="s2",
                    candidate_id="cand:v1:cccccccccccccccccccccccccccccccc",
                ),
                ArtifactEntry(
                    role=ArtifactRole.SCENARIO_FEATURE,
                    path="scenarios/s1.feature",
                    sha256=compute_file_sha256(run_dir / "scenarios" / "s1.feature"),
                    media_type="text/plain",
                    scenario_id="s2",
                    candidate_id="cand:v1:cccccccccccccccccccccccccccccccc",
                ),
            ],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Filename stem"):
            load_strict_resolver(run_dir)

    def test_absolute_path_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path=str(run_dir / "use-case.txt"),
            sha256=compute_file_sha256(run_dir / "use-case.txt"),
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="absolute"):
            load_strict_resolver(run_dir)

    def test_manifest_container_is_sole_orphan_exception(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        # run-manifest.yaml exists but is not in inventory — should be OK
        resolver = load_strict_resolver(run_dir)
        # No RUN_MANIFEST role in inventory
        assert resolver.entry_by_role(ArtifactRole.REPORT) is not None


# --------------------------------------------------------------------------- #
# 5. Strict eval/report stale file immunity
# --------------------------------------------------------------------------- #


class TestStrictEvalStaleImmunity:
    """Strict eval/report consume only manifest inventory entries."""

    def test_stale_scenario_yaml_rejected_inside_finalized_run(self, tmp_path: Path):
        from scenario_forge.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )

        stale = run_dir / "scenarios" / "stale.yaml"
        stale.write_text(
            yaml.dump({"scenario_id": "stale", "narrative": {"entry_point": "bad"}})
        )

        with pytest.raises(ManifestIntegrityError, match="orphan"):
            run_evaluation(run_dir)

    def test_collection_level_stale_ignored_by_eval(self, tmp_path: Path):
        from scenario_forge.eval.runner import run_evaluation

        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / _VALID_RUN_ID,
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )
        (collection / "stale.yaml").write_text("stale: true")

        scorecard = run_evaluation(run_dir)
        assert scorecard["evaluation"]["scenario_count"] == 1

    def test_stale_feature_only_entry_not_scored_by_eval(self, tmp_path: Path):
        """Eval must not score feature-only entries."""
        from scenario_forge.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )
        # Add an unmanifested stale feature file — orphan check rejects it
        stale_feature = run_dir / "scenarios" / "stale.feature"
        stale_feature.write_text("Feature: stale\n  Scenario: X\n")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            run_evaluation(run_dir)

    def test_non_authoritative_rejected_by_default(self, tmp_path: Path):
        from scenario_forge.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            status=RunStatus.COMPLETED_WITH_ERRORS,
        )
        with pytest.raises(ManifestIntegrityError, match="not authoritative"):
            run_evaluation(run_dir)

    def test_non_authoritative_allowed_with_flag(self, tmp_path: Path):
        from scenario_forge.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            status=RunStatus.COMPLETED_WITH_ERRORS,
        )
        scorecard = run_evaluation(run_dir, allow_non_authoritative=True)
        assert scorecard["evaluation"]["scenario_count"] == 0


# --------------------------------------------------------------------------- #
# 6. Provenance
# --------------------------------------------------------------------------- #


class TestProvenance:
    """Git, config digest, and input hash provenance."""

    def test_config_digest_stable_across_key_order(self):
        opts1 = {"a": 1, "b": 2, "c": 3}
        opts2 = {"c": 3, "a": 1, "b": 2}
        assert compute_config_digest(opts1) == compute_config_digest(opts2)

    def test_config_digest_differs_for_different_values(self):
        assert compute_config_digest({"a": 1}) != compute_config_digest({"a": 2})

    def test_git_provenance_mocked_clean(self, tmp_path: Path):
        from scenario_forge.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        with patch("scenario_forge.manifest.subprocess.run") as mock_run:

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.commit == "abc123"
        assert prov.dirty is False
        assert prov.source_diff_digest is not None

    def test_git_provenance_mocked_dirty(self, tmp_path: Path):
        from scenario_forge.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()

        with patch("scenario_forge.manifest.subprocess.run") as mock_run:

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="def456\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="dev\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=" M file.py\n", stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="diff content\n", stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.commit == "def456"
        assert prov.dirty is True
        assert prov.source_diff_digest is not None

    def test_git_provenance_clean_vs_dirty_differ(self, tmp_path: Path):
        from scenario_forge.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()

        def make_mock(stdout_status, stdout_diff, stdout_untracked=""):
            mock_run = MagicMock()

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=stdout_status, stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout=stdout_diff, stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout=stdout_untracked, stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            return mock_run

        with patch("scenario_forge.manifest.subprocess.run", make_mock("", "")):
            clean_prov = capture_git_provenance(repo)
        with patch(
            "scenario_forge.manifest.subprocess.run", make_mock(" M f\n", "d\n")
        ):
            dirty_prov = capture_git_provenance(repo)

        assert clean_prov.source_diff_digest != dirty_prov.source_diff_digest
        assert clean_prov.dirty is False
        assert dirty_prov.dirty is True

    def test_git_provenance_no_repo(self, tmp_path: Path):
        from scenario_forge.manifest import capture_git_provenance

        prov = capture_git_provenance(tmp_path)
        assert prov.commit is None
        assert prov.dirty is None
        assert prov.source_diff_digest is None

    def test_git_provenance_untracked_in_digest(self, tmp_path: Path):
        from scenario_forge.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "tracked.txt").write_text("tracked")
        (repo / "untracked.txt").write_text("untracked content")

        with patch("scenario_forge.manifest.subprocess.run") as mock_run:

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(
                        returncode=0, stdout="?? untracked.txt\n", stderr=""
                    )
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout="untracked.txt\n", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.dirty is True
        assert "untracked.txt" in prov.untracked_files
        assert prov.source_diff_digest is not None

    def test_git_provenance_tracked_dirty_vs_untracked_dirty_differ(
        self, tmp_path: Path
    ):
        """Tracked-dirty and untracked-dirty states produce distinct digests."""
        from scenario_forge.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()

        def make_mock(status, diff, untracked):
            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=status, stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout=diff, stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout=untracked, stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            return side_effect

        with patch(
            "scenario_forge.manifest.subprocess.run",
            side_effect=make_mock(" M tracked.txt\n", "diff\n", ""),
        ):
            tracked_prov = capture_git_provenance(repo)
        with patch(
            "scenario_forge.manifest.subprocess.run",
            side_effect=make_mock("?? new.txt\n", "", "new.txt\n"),
        ):
            untracked_prov = capture_git_provenance(repo)

        assert tracked_prov.source_diff_digest != untracked_prov.source_diff_digest


# --------------------------------------------------------------------------- #
# 7. Run ID validation (128-bit entropy)
# --------------------------------------------------------------------------- #


class TestRunIdValidation:
    """Sortable run ID format and validation."""

    def test_sortable_format_accepted(self):
        validate_run_id("20260101T120000_abcdef0123456789abcdef0123456789")

    def test_legacy_hex_accepted(self):
        validate_run_id("a" * 32)

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("")

    def test_uppercase_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("A" * 32)

    def test_too_short_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("short")

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("z" * 32)

    def test_old_16hex_format_rejected(self):
        """The old 64-bit suffix format (16 hex) is no longer valid."""
        with pytest.raises(ValueError):
            validate_run_id("20260101T120000_abcdef0123456789")

    def test_generate_produces_valid(self):
        rid = generate_sortable_run_id()
        validate_run_id(rid)
        assert is_sortable_run_id(rid)

    def test_generated_ids_unique(self):
        ids = {generate_sortable_run_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generated_id_has_128_bit_suffix(self):
        """The suffix must be 32 hex chars (128 bits)."""
        rid = generate_sortable_run_id()
        suffix = rid.split("_", 1)[1]
        assert len(suffix) == 32


# --------------------------------------------------------------------------- #
# 8. find_run_dir unambiguous resolution
# --------------------------------------------------------------------------- #


class TestFindRunDir:
    """find_run_dir requires unambiguous resolution — no implicit latest."""

    def test_run_dir_returns_itself(self, tmp_path: Path):
        run_dir = build_test_run_dir(tmp_path / "run")
        assert find_run_dir(run_dir) == run_dir

    def test_collection_with_one_run(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir = build_test_run_dir(collection / _VALID_RUN_ID)
        assert find_run_dir(collection) == run_dir

    def test_collection_with_multiple_runs_ambiguous(self, tmp_path: Path):
        collection = tmp_path / "output"
        build_test_run_dir(collection / _VALID_RUN_ID)
        build_test_run_dir(
            collection / "20260102T000000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        with pytest.raises(ManifestIntegrityError, match="2 runs"):
            find_run_dir(collection)

    def test_empty_collection_raises(self, tmp_path: Path):
        collection = tmp_path / "output"
        collection.mkdir()
        with pytest.raises(ManifestIntegrityError, match="No run"):
            find_run_dir(collection)


# --------------------------------------------------------------------------- #
# 9. Required singleton roles and completed validation
# --------------------------------------------------------------------------- #


class TestRequiredSingletonRoles:
    """Required singleton roles from effective config."""

    def test_report_always_required(self):
        roles = required_singleton_roles(eval_enabled=True)
        assert ArtifactRole.REPORT in roles
        roles = required_singleton_roles(eval_enabled=False)
        assert ArtifactRole.REPORT in roles

    def test_scorecard_required_when_eval_enabled(self):
        roles = required_singleton_roles(eval_enabled=True)
        assert ArtifactRole.EVAL_SCORECARD in roles

    def test_scorecard_not_required_when_eval_disabled(self):
        roles = required_singleton_roles(eval_enabled=False)
        assert ArtifactRole.EVAL_SCORECARD not in roles

    def test_validate_completed_inventory_missing_report_fails(self, tmp_path: Path):
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[],
        )
        with pytest.raises(ManifestIntegrityError, match="Missing required"):
            validate_completed_inventory(manifest, eval_enabled=True)


# --------------------------------------------------------------------------- #
# 10. Attempt records
# --------------------------------------------------------------------------- #


class TestAttemptRecords:
    """Typed attempt records with admitted/quarantined/failed disposition."""

    def test_admitted_attempt(self):
        rec = AttemptRecord(
            candidate_id="cand:v1:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.ADMITTED,
        )
        assert rec.disposition == AttemptDisposition.ADMITTED
        assert rec.failure_evidence is None

    def test_failed_attempt_with_evidence(self):
        rec = AttemptRecord(
            candidate_id="cand:v1:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.FAILED,
            failure_evidence="LLM timeout",
        )
        assert rec.disposition == AttemptDisposition.FAILED
        assert rec.failure_evidence == "LLM timeout"

    def test_quarantined_attempt_with_evidence(self):
        rec = AttemptRecord(
            candidate_id="cand:v1:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.QUARANTINED,
            failure_evidence="phantom capability",
        )
        assert rec.disposition == AttemptDisposition.QUARANTINED


# --------------------------------------------------------------------------- #
# 11. In-memory resolver (no persisted started manifest)
# --------------------------------------------------------------------------- #


class TestInMemoryResolver:
    """Internal eval/report use in-memory resolver, not persisted started manifest."""

    def test_in_memory_resolver_no_orphan_check(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")
        (run_dir / "extra.txt").write_text("extra")  # would be orphan if checked

        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt"),
            ],
        )
        resolver = build_in_memory_resolver(run_dir, manifest)
        # Extra file does not trigger orphan check
        assert resolver.entry_by_role(ArtifactRole.USE_CASE) is not None

    def test_in_memory_resolver_validates_entries(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="use-case.txt",
            sha256="0" * 64,  # wrong hash
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            build_in_memory_resolver(run_dir, manifest)


# --------------------------------------------------------------------------- #
# 12. Pipeline lifecycle integration (mocked)
# --------------------------------------------------------------------------- #


def _mock_write_coverage_report(run_dir):
    """Side effect that actually writes coverage-gaps.json."""
    from scenario_forge.pipeline.io import write_coverage_report as _real

    def _side_effect(*args, **kwargs):
        # Write a minimal coverage file

        path = args[0] if args else kwargs.get("run_dir")
        if path is None:
            # CoverageGaps, run_dir, attacker_diversity signature
            return _real(*args, **kwargs)
        return _real(*args, **kwargs)

    return _side_effect


class TestPipelineLifecycle:
    """Integration tests for pipeline lifecycle with mocked LLM calls."""

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_successful_run_completes(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from scenario_forge.models.capability_profile import CapabilityProfile
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.llm.client import LLMResult
        from scenario_forge.pipeline.runner import run_pipeline

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from scenario_forge.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        # Mock report to actually write report.html
        def _write_report(data, out_dir):
            (Path(out_dir) / "report.html").write_text("<html>mock</html>")
            return Path(out_dir) / "report.html"

        mock_report.side_effect = _write_report

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result = run_pipeline(
            use_case="A chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )

        assert result.run_dir is not None
        assert result.run_id is not None
        manifest = load_manifest(result.run_dir)
        assert manifest.status == RunStatus.COMPLETED

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_fatal_error_writes_failed_manifest(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.pipeline.runner import run_pipeline

        mock_profile.side_effect = RuntimeError("LLM connection failed")
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        with pytest.raises(RuntimeError, match="LLM connection failed"):
            run_pipeline(
                use_case="A chatbot",
                risk_extraction_path=risk_path,
                sssom_path=sssom_path,
                output_dir=collection,
            )

        runs = [d for d in collection.iterdir() if d.is_dir() and is_run_dir(d)]
        assert len(runs) == 1
        manifest = load_manifest(runs[0])
        assert manifest.status == RunStatus.FAILED

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_two_runs_same_collection(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from scenario_forge.models.capability_profile import CapabilityProfile
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.llm.client import LLMResult
        from scenario_forge.pipeline.runner import run_pipeline

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from scenario_forge.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        def _write_report(data, out_dir):
            (Path(out_dir) / "report.html").write_text("<html>mock</html>")
            return Path(out_dir) / "report.html"

        mock_report.side_effect = _write_report

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result1 = run_pipeline(
            use_case="First run",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )
        result2 = run_pipeline(
            use_case="Second run",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )

        assert result1.run_dir != result2.run_dir
        assert result1.run_id != result2.run_id

        m1 = load_manifest(result1.run_dir)
        m2 = load_manifest(result2.run_dir)
        assert m1.status == RunStatus.COMPLETED
        assert m2.status == RunStatus.COMPLETED

        assert (result1.run_dir / "use-case.txt").read_text() == "First run"

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_no_eval_is_completed_with_errors(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from scenario_forge.models.capability_profile import CapabilityProfile
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.llm.client import LLMResult
        from scenario_forge.pipeline.runner import run_pipeline

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from scenario_forge.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        def _write_report(data, out_dir):
            (Path(out_dir) / "report.html").write_text("<html>mock</html>")
            return Path(out_dir) / "report.html"

        mock_report.side_effect = _write_report

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result = run_pipeline(
            use_case="A chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
            eval=False,
        )

        manifest = load_manifest(result.run_dir)
        assert manifest.status == RunStatus.COMPLETED_WITH_ERRORS


# --------------------------------------------------------------------------- #
# Second Mayor review acceptance contract
# --------------------------------------------------------------------------- #


def _mayor_valid_run(run_dir: Path, *, status=RunStatus.COMPLETED) -> RunManifest:
    """Build and load a complete one-scenario run used by adversarial tests."""
    scenario = _make_scenario("s1") | {"candidate_id": "cand-1"}
    build_test_run_dir(
        run_dir,
        use_case="A chatbot",
        profile_data={"zones_active": ["input"]},
        threat_surface_data={"entries": []},
        scenarios=[scenario],
        feature_files={"s1": _make_feature("s1")},
        coverage_data={"gaps": []},
        eval_scorecard={"evaluation": {"scenario_count": 1, "feature_file_count": 1}},
        status=status,
    )
    manifest = load_manifest(run_dir)
    manifest.attempts = [
        AttemptRecord(
            candidate_id="cand-1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
            phase=AttemptPhase.MAIN,
        )
    ]
    manifest.funnel = {
        "attempted": 1,
        "admitted": 1,
        "quarantined": 0,
        "generation_failed": 0,
        "remediation_failed": 0,
    }
    return manifest


class TestCompletedRunWithAdmittedPair:
    def test_completed_run_with_real_admitted_pair(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _mayor_valid_run(run_dir)

        validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)
        ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

        yaml_entries = [
            entry
            for entry in manifest.inventory
            if entry.role == ArtifactRole.SCENARIO_YAML
        ]
        scorecard = yaml.safe_load((run_dir / "eval-scorecard.yaml").read_text())
        assert manifest.status == RunStatus.COMPLETED
        assert scorecard["evaluation"]["scenario_count"] == len(yaml_entries)

    def test_second_real_run_does_not_change_first(self, tmp_path: Path):
        collection = tmp_path / "collection"
        first = collection / _VALID_RUN_ID
        _mayor_valid_run(first)
        before = {
            path.relative_to(first).as_posix(): path.read_bytes()
            for path in first.rglob("*")
            if path.is_file()
        }

        second = collection / "20260101T000001_abcdef0123456789abcdef0123456789"
        _mayor_valid_run(second)
        after = {
            path.relative_to(first).as_posix(): path.read_bytes()
            for path in first.rglob("*")
            if path.is_file()
        }
        assert after == before


class TestAttemptEquations:
    @staticmethod
    def _manifest(attempts, funnel):
        return RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=attempts,
            funnel=funnel,
        )

    @staticmethod
    def _attempt(candidate, scenario, disposition, phase=AttemptPhase.MAIN):
        evidence = (
            "generation error" if disposition != AttemptDisposition.ADMITTED else None
        )
        return AttemptRecord(
            candidate_id=candidate,
            scenario_id=scenario,
            disposition=disposition,
            phase=phase,
            failure_evidence=evidence,
        )

    @pytest.mark.parametrize(
        ("attempts", "funnel"),
        [
            (
                [_attempt.__func__("c1", "s1", AttemptDisposition.ADMITTED)],
                {
                    "attempted": 1,
                    "admitted": 1,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 0,
                },
            ),
            (
                [
                    _attempt.__func__("c1", "s1", AttemptDisposition.ADMITTED),
                    _attempt.__func__(
                        "c2",
                        "s2",
                        AttemptDisposition.ADMITTED,
                        AttemptPhase.REMEDIATION,
                    ),
                ],
                {
                    "attempted": 2,
                    "admitted": 2,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 0,
                },
            ),
            (
                [
                    _attempt.__func__("c1", "s1", AttemptDisposition.ADMITTED),
                    _attempt.__func__(
                        "c2", "s2", AttemptDisposition.FAILED, AttemptPhase.REMEDIATION
                    ),
                ],
                {
                    "attempted": 2,
                    "admitted": 1,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 1,
                },
            ),
            (
                [_attempt.__func__("c1", "s1", AttemptDisposition.QUARANTINED)],
                {
                    "attempted": 1,
                    "admitted": 1,
                    "quarantined": 1,
                    "generation_failed": 0,
                    "remediation_failed": 0,
                },
            ),
            (
                [],
                {
                    "attempted": 0,
                    "admitted": 0,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 0,
                },
            ),
        ],
    )
    def test_valid_equations(self, attempts, funnel):
        validate_attempt_equations(self._manifest(attempts, funnel))

    def test_remediation_success(self):
        attempt = self._attempt(
            "c1", "s1", AttemptDisposition.ADMITTED, AttemptPhase.REMEDIATION
        )
        validate_attempt_equations(
            self._manifest(
                [attempt],
                {
                    "attempted": 1,
                    "admitted": 1,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 0,
                },
            )
        )

    def test_remediation_failure_with_evidence(self):
        attempt = self._attempt(
            "c1", "s1", AttemptDisposition.FAILED, AttemptPhase.REMEDIATION
        )
        assert attempt.failure_evidence
        validate_attempt_equations(
            self._manifest(
                [attempt],
                {
                    "attempted": 1,
                    "admitted": 0,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 1,
                },
            )
        )

    def test_duplicate_attempt_keys_raise(self):
        attempt = self._attempt("c1", "s1", AttemptDisposition.ADMITTED)
        with pytest.raises(ManifestIntegrityError, match="Duplicate attempt"):
            validate_attempt_equations(
                self._manifest([attempt, attempt.model_copy()], {})
            )

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("attempted", 2, "attempted mismatch"),
            ("admitted", 0, "admitted mismatch"),
            ("quarantined", 1, "quarantined mismatch"),
            ("generation_failed", 1, "failed mismatch"),
        ],
    )
    def test_funnel_mismatches_raise(self, field, value, message):
        funnel = {
            "attempted": 1,
            "admitted": 1,
            "quarantined": 0,
            "generation_failed": 0,
            "remediation_failed": 0,
        }
        funnel[field] = value
        attempt = self._attempt("c1", "s1", AttemptDisposition.ADMITTED)
        with pytest.raises(ManifestIntegrityError, match=message):
            validate_attempt_equations(self._manifest([attempt], funnel))


class TestFailedEvidenceRetention:
    @staticmethod
    def _write_failed(run_dir: Path, files):
        inventory = []
        for role, rel_path, content, scenario_id, candidate_id in files:
            path = run_dir / rel_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            inventory.append(
                build_artifact_entry(role, run_dir, rel_path, scenario_id, candidate_id)
            )
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=inventory,
            error="injected failure",
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )

    def test_partial_unpaired_evidence_loads_strictly(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        self._write_failed(
            run_dir,
            [
                (ArtifactRole.USE_CASE, "use-case.txt", "chatbot", None, None),
                (
                    ArtifactRole.CAPABILITY_PROFILE,
                    "capability-profile.yaml",
                    "zones: []\n",
                    None,
                    None,
                ),
                (
                    ArtifactRole.THREAT_SURFACE,
                    "threat-surface.yaml",
                    "entries: []\n",
                    None,
                    None,
                ),
                (
                    ArtifactRole.SCENARIO_YAML,
                    "scenarios/s1.yaml",
                    yaml.safe_dump(_make_scenario("s1")),
                    "s1",
                    "c1",
                ),
            ],
        )
        resolver = load_strict_resolver(run_dir, require_final=True)
        assert resolver.manifest.status == RunStatus.FAILED

    def test_failed_run_inventories_all_forensic_artifacts(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        self._write_failed(
            run_dir,
            [
                (
                    ArtifactRole.SCENARIO_YAML,
                    "scenarios/s1.yaml",
                    yaml.safe_dump(_make_scenario("s1")),
                    "s1",
                    "c1",
                ),
                (
                    ArtifactRole.SCENARIO_FEATURE,
                    "scenarios/s1.feature",
                    _make_feature("s1"),
                    "s1",
                    "c1",
                ),
                (ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl", "{}\n", None, None),
                (ArtifactRole.PIPELINE_LOG, "pipeline.log", "failed\n", None, None),
            ],
        )
        load_strict_resolver(run_dir, require_final=True)


class TestStrictValidationNegativeCases:
    def _base(self, tmp_path):
        run_dir = tmp_path / _VALID_RUN_ID
        return run_dir, _mayor_valid_run(run_dir)

    @pytest.mark.parametrize(
        "bad_path",
        [
            "/etc/passwd",
            "scenarios\\s1.yaml",
            "./use-case.txt",
            "scenarios//s1.yaml",
            "../use-case.txt",
        ],
    )
    def test_noncanonical_paths_raise(self, tmp_path, bad_path):
        run_dir, manifest = self._base(tmp_path)
        manifest.inventory[0].path = bad_path
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_duplicate_canonical_path_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        manifest.inventory.append(manifest.inventory[0].model_copy())
        with pytest.raises(
            ManifestIntegrityError, match="Duplicate artifact canonical"
        ):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_duplicate_singleton_role_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        duplicate = run_dir / "other.txt"
        duplicate.write_text("other")
        manifest.inventory.append(
            build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "other.txt")
        )
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    @pytest.mark.parametrize("field", ["scenario_id", "candidate_id"])
    def test_missing_scenario_identity_raises(self, tmp_path, field):
        run_dir, manifest = self._base(tmp_path)
        entry = next(
            e for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
        )
        setattr(entry, field, None)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_hash_mismatch_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        (run_dir / "use-case.txt").write_text("mutated")
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_malformed_hash_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        manifest.inventory[0].sha256 = "bad"
        with pytest.raises(ManifestIntegrityError, match="Malformed SHA"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    @pytest.mark.parametrize(
        ("field", "value"), [("media_type", "text/xml"), ("schema_version", "99")]
    )
    def test_wrong_metadata_raises(self, tmp_path, field, value):
        run_dir, manifest = self._base(tmp_path)
        entry = next(e for e in manifest.inventory if e.path.endswith("s1.yaml"))
        setattr(entry, field, value)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_wrong_extension_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        entry = next(e for e in manifest.inventory if e.path.endswith("s1.yaml"))
        source = run_dir / entry.path
        target = source.with_suffix(".txt")
        source.rename(target)
        entry.path = "scenarios/s1.txt"
        entry.sha256 = compute_file_sha256(target)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_duplicate_candidate_across_scenarios_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        for suffix, role, content in [
            ("yaml", ArtifactRole.SCENARIO_YAML, yaml.safe_dump(_make_scenario("s2"))),
            ("feature", ArtifactRole.SCENARIO_FEATURE, _make_feature("s2")),
        ]:
            path = run_dir / f"scenarios/s2.{suffix}"
            path.write_text(content)
            manifest.inventory.append(
                build_artifact_entry(
                    role, run_dir, f"scenarios/s2.{suffix}", "s2", "cand-1"
                )
            )
        with pytest.raises(ManifestIntegrityError, match="candidate"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    @pytest.mark.parametrize("defect", ["inventory", "filename", "feature"])
    def test_scenario_identity_mismatches_raise(self, tmp_path, defect):
        run_dir, manifest = self._base(tmp_path)
        yaml_entry = next(
            e for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
        )
        feature_entry = next(
            e for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_FEATURE
        )
        if defect == "inventory":
            yaml_entry.scenario_id = "different"
        elif defect == "feature":
            feature_entry.scenario_id = "different"
        else:
            old = run_dir / yaml_entry.path
            new = old.with_name("different.yaml")
            old.rename(new)
            yaml_entry.path = "scenarios/different.yaml"
            yaml_entry.sha256 = compute_file_sha256(new)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_orphan_file_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        (run_dir / "orphan.txt").write_text("unexpected")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)


class TestProvenanceStartSnapshot:
    def test_input_hashes_remain_start_snapshot(self, tmp_path: Path):
        from scenario_forge.pipeline.runner import _capture_input_hashes

        risk = tmp_path / "risk.json"
        sssom = tmp_path / "mapping.tsv"
        cross = tmp_path / "cross.yaml"
        risk.write_text("original")
        sssom.write_text("mapping")
        cross.write_text("cross")
        hashes = _capture_input_hashes("chatbot", risk, sssom, cross, None, None)
        original = hashes.risk_extraction_hash
        risk.write_text("mutated")
        assert hashes.risk_extraction_hash == original
        assert hashes.risk_extraction_hash != compute_file_sha256(risk)

    def test_capture_provenance_uses_git_state_at_call_time(self, tmp_path: Path):
        with patch("scenario_forge.manifest.capture_git_provenance") as capture:
            capture.return_value = GitProvenance(
                commit="first",
                dirty=False,
                source_diff_digest=None,
                branch="main",
                untracked_files=[],
            )
            provenance = capture_provenance(
                _VALID_RUN_ID, "2026-01-01T00:00:00+00:00", repo_root=tmp_path
            )
        capture.assert_called_with(tmp_path)
        assert provenance.git.commit == "first"


class TestFaultInjection:
    @staticmethod
    def _inputs(tmp_path):
        risk = tmp_path / "risk.json"
        sssom = tmp_path / "sssom.tsv"
        risk.write_text("[]")
        sssom.write_text("")
        return risk, sssom

    def test_client_construction_failure_leaves_failed_manifest(self, tmp_path: Path):
        from scenario_forge.pipeline.runner import run_pipeline

        risk, sssom = self._inputs(tmp_path)
        collection = tmp_path / "output"
        with patch(
            "scenario_forge.pipeline.runner.LLMClient.__init__",
            side_effect=RuntimeError("client failure"),
        ):
            with pytest.raises(RuntimeError, match="client failure"):
                run_pipeline(
                    use_case="chatbot",
                    risk_extraction_path=risk,
                    sssom_path=sssom,
                    output_dir=collection,
                )
        run_dir = next(path for path in collection.iterdir() if path.is_dir())
        assert load_manifest(run_dir).status == RunStatus.FAILED

    def test_use_case_write_failure_keeps_provenance(self, tmp_path: Path):
        from scenario_forge.pipeline.runner import run_pipeline

        risk, sssom = self._inputs(tmp_path)
        collection = tmp_path / "output"
        with patch(
            "scenario_forge.pipeline.runner.write_use_case",
            side_effect=OSError("disk full"),
        ):
            with pytest.raises(OSError, match="disk full"):
                run_pipeline(
                    use_case="chatbot",
                    risk_extraction_path=risk,
                    sssom_path=sssom,
                    output_dir=collection,
                )
        run_dir = next(path for path in collection.iterdir() if path.is_dir())
        manifest = load_manifest(run_dir)
        assert manifest.status == RunStatus.FAILED
        assert manifest.provenance is not None
        assert manifest.provenance.input_hashes.risk_extraction_hash

    def test_finalization_failure_propagates(self, tmp_path: Path):
        from scenario_forge.pipeline.runner import run_pipeline

        risk, sssom = self._inputs(tmp_path)
        with patch(
            "scenario_forge.pipeline.runner.finalize_manifest",
            side_effect=RuntimeError("finalize failure"),
        ):
            with pytest.raises(RuntimeError, match="finalize failure"):
                run_pipeline(
                    use_case="chatbot",
                    risk_extraction_path=risk,
                    sssom_path=sssom,
                    output_dir=tmp_path / "output",
                )

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_client_construction_failure_writes_failed_manifest(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        """Fatal error during client construction writes failed manifest."""
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.pipeline.runner import run_pipeline

        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        with patch(
            "scenario_forge.pipeline.runner.LLMClient",
            side_effect=RuntimeError("bad config"),
        ):
            with pytest.raises(RuntimeError, match="bad config"):
                run_pipeline(
                    use_case="A chatbot",
                    risk_extraction_path=risk_path,
                    sssom_path=sssom_path,
                    output_dir=collection,
                )

        runs = [d for d in collection.iterdir() if d.is_dir() and is_run_dir(d)]
        assert len(runs) == 1
        manifest = load_manifest(runs[0])
        assert manifest.status == RunStatus.FAILED
        assert manifest.error is not None

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_report_failure_is_completed_with_errors(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        """Report generation failure results in completed_with_errors."""
        from scenario_forge.models.capability_profile import CapabilityProfile
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.llm.client import LLMResult
        from scenario_forge.pipeline.runner import run_pipeline

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from scenario_forge.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        mock_report.side_effect = RuntimeError("report rendering failed")

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result = run_pipeline(
            use_case="A chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )

        manifest = load_manifest(result.run_dir)
        assert manifest.status == RunStatus.COMPLETED_WITH_ERRORS
