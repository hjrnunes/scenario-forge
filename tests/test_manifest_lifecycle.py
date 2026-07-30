"""Focused lifecycle, immutability, integrity, and provenance tests for cmps.1.

Covers the acceptance contract:
- Immutable two-run collections with sortable, collision-safe run IDs
- Run-local logging that never appends across runs
- Versioned manifest sentinel surviving every exit path
- Final status: completed / completed_with_errors / failed
- Typed artifact inventory with SHA-256, roles, and integrity validation
- Strict eval/report consuming only manifest inventory entries
- Provenance: Git (clean/dirty), config digest, input hashes, model config
- Standalone CLI eval/report rejecting ambiguous collections
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from scenario_forge.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    compute_config_digest,
    compute_file_sha256,
    find_run_dir,
    generate_sortable_run_id,
    is_run_dir,
    is_sortable_run_id,
    load_manifest,
    load_strict_resolver,
    resolve_run_dir,
    validate_run_id,
    write_failed_manifest,
    write_manifest_sentinel,
    finalize_manifest,
    atomic_write_yaml,
    MANIFEST_FILENAME,
)
from tests.manifest_helpers import build_test_run_dir


# ---------------------------------------------------------------------------
# 1. Immutable two-run collections
# ---------------------------------------------------------------------------


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

        # Snapshot all files in run_dir_1
        snapshot: dict[str, bytes] = {}
        for f in run_dir_1.rglob("*"):
            if f.is_file():
                snapshot[f.relative_to(run_dir_1).as_posix()] = f.read_bytes()

        # Create second run
        run_dir_2, run_id_2 = resolve_run_dir(collection)
        (run_dir_2 / "use-case.txt").write_text("different use case")

        # Verify first run is byte-for-byte unchanged
        for rel, original_bytes in snapshot.items():
            assert (run_dir_1 / rel).read_bytes() == original_bytes, (
                f"File {rel} in first run was modified by second run"
            )

    def test_existing_run_dir_not_reused(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)
        # Attempting to create the same run_id again should fail
        with pytest.raises(FileExistsError):
            resolve_run_dir(collection, run_id=run_id)

    def test_collection_sibling_stale_files_ignored(self, tmp_path: Path):
        """Stale files at the collection level (not in any run dir) cannot
        affect strict manifest-based readers."""
        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / "20260101T000000_aaaaaaaaaaaaaaaa",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[
                {
                    "scenario_id": "s1",
                    "narrative": {
                        "title": "Test",
                        "summary": "A test",
                        "entry_point": "chat",
                        "zone_sequence": ["input"],
                        "steps": [],
                    },
                    "actor_profile": {
                        "actor_type": "external",
                        "goal_category": "data theft",
                        "capability_level": "intermediate",
                    },
                    "attack_tree": {"id": "t1", "goal": "test", "root": {}},
                }
            ],
        )

        # Drop stale files at collection level
        (collection / "stale.yaml").write_text("stale: true")
        (collection / "garbage.json").write_text("{}")

        # find_run_dir should still find the single run
        found = find_run_dir(collection)
        assert found == run_dir

        # Strict resolver should work fine — stale collection files are irrelevant
        resolver = load_strict_resolver(run_dir)
        assert len(resolver.scenario_yaml_entries()) == 1


# ---------------------------------------------------------------------------
# 2. Run-local logging
# ---------------------------------------------------------------------------


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

        # Flush and check content
        for h in logger.handlers:
            h.flush()

        log_path = run_dir / "pipeline.log"
        assert log_path.exists()
        content_1 = log_path.read_text()
        assert "First run message" in content_1

        # Second run in a new dir — log should not contain first run's messages
        run_dir_2, _ = resolve_run_dir(collection)
        setup_logging(output_dir=run_dir_2)
        logger.info("Second run message")
        for h in logger.handlers:
            h.flush()

        log_path_2 = run_dir_2 / "pipeline.log"
        content_2 = log_path_2.read_text()
        assert "Second run message" in content_2
        assert "First run message" not in content_2


# ---------------------------------------------------------------------------
# 3. Manifest sentinel and lifecycle
# ---------------------------------------------------------------------------


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

        write_failed_manifest(run_dir, run_id, ts, "Something went wrong")

        manifest = load_manifest(run_dir)
        assert manifest.status == RunStatus.FAILED
        assert manifest.run_id == run_id

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


# ---------------------------------------------------------------------------
# 4. Typed artifact inventory integrity
# ---------------------------------------------------------------------------


class TestInventoryIntegrity:
    """Manifest inventory validation: missing, duplicate, orphan, hash mismatch."""

    def test_valid_inventory_passes(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[
                {
                    "scenario_id": "s1",
                    "narrative": {
                        "title": "T",
                        "summary": "S",
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
            ],
        )
        resolver = load_strict_resolver(run_dir)
        assert len(resolver.scenario_yaml_entries()) == 1
        assert resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE) is not None

    def test_hash_mismatch_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        # Tamper with the profile file after manifest is written
        (run_dir / "capability-profile.yaml").write_text("tampered: true")
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            load_strict_resolver(run_dir)

    def test_missing_artifact_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        # Delete a file that's in the inventory
        (run_dir / "capability-profile.yaml").unlink()
        with pytest.raises(ManifestIntegrityError, match="does not exist"):
            load_strict_resolver(run_dir)

    def test_orphan_file_in_run_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        # Add an unmanifested file
        (run_dir / "rogue.yaml").write_text("rogue: true")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            load_strict_resolver(run_dir)

    def test_duplicate_path_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id="20260101T000000_aaaaaaaaaaaaaaaa",
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
        # Create a file outside run_dir
        outside = tmp_path / "outside.txt"
        outside.write_text("outside")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="../../outside.txt",
            sha256=compute_file_sha256(outside),
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id="20260101T000000_aaaaaaaaaaaaaaaa",
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="escapes"):
            load_strict_resolver(run_dir)


# ---------------------------------------------------------------------------
# 5. Strict eval/report stale file immunity
# ---------------------------------------------------------------------------


class TestStrictEvalStaleImmunity:
    """Strict eval/report consume only manifest inventory entries."""

    def test_stale_scenario_yaml_ignored_by_eval(self, tmp_path: Path):
        from scenario_forge.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[
                {
                    "scenario_id": "s1",
                    "narrative": {
                        "title": "Real",
                        "summary": "S",
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
            ],
        )

        # Add a stale scenario file NOT in the manifest
        stale = run_dir / "scenarios" / "stale.yaml"
        stale.write_text(
            yaml.dump({"scenario_id": "stale", "narrative": {"entry_point": "bad"}})
        )

        # Eval should only see the manifested scenario, not the stale one.
        # But wait — the orphan check will reject the stale file.
        # This proves stale files inside a finalized run are rejected.
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            run_evaluation(run_dir)

    def test_collection_level_stale_ignored_by_eval(self, tmp_path: Path):
        """Stale files at collection level (outside run dir) are simply not seen."""
        from scenario_forge.eval.runner import run_evaluation

        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / "20260101T000000_aaaaaaaaaaaaaaaa",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[
                {
                    "scenario_id": "s1",
                    "narrative": {
                        "title": "Real",
                        "summary": "S",
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
            ],
        )
        # Stale file at collection level
        (collection / "stale.yaml").write_text("stale: true")

        scorecard = run_evaluation(run_dir)
        assert scorecard["evaluation"]["scenario_count"] == 1


# ---------------------------------------------------------------------------
# 6. Provenance
# ---------------------------------------------------------------------------


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
        (repo / ".git").mkdir()  # fake .git so subprocess calls would work

        with patch("scenario_forge.manifest.subprocess.run") as mock_run:
            # Simulate clean repo
            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.commit == "abc123"
        assert prov.dirty is False
        assert prov.source_diff_digest == hashlib.sha256(b"").hexdigest()

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
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.commit == "def456"
        assert prov.dirty is True
        assert prov.source_diff_digest == hashlib.sha256(b"diff content").hexdigest()

    def test_git_provenance_no_repo(self, tmp_path: Path):
        from scenario_forge.manifest import capture_git_provenance

        # No .git directory — subprocess will fail
        prov = capture_git_provenance(tmp_path)
        assert prov.commit is None
        assert prov.dirty is None
        assert prov.source_diff_digest is None


# ---------------------------------------------------------------------------
# 7. Run ID validation
# ---------------------------------------------------------------------------


class TestRunIdValidation:
    """Sortable run ID format and validation."""

    def test_sortable_format_accepted(self):
        validate_run_id("20260101T120000_abcdef0123456789")

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

    def test_generate_produces_valid(self):
        rid = generate_sortable_run_id()
        validate_run_id(rid)
        assert is_sortable_run_id(rid)

    def test_generated_ids_unique(self):
        ids = {generate_sortable_run_id() for _ in range(100)}
        assert len(ids) == 100


# ---------------------------------------------------------------------------
# 8. find_run_dir unambiguous resolution
# ---------------------------------------------------------------------------


class TestFindRunDir:
    """find_run_dir requires unambiguous resolution — no implicit latest."""

    def test_run_dir_returns_itself(self, tmp_path: Path):
        run_dir = build_test_run_dir(tmp_path / "run")
        assert find_run_dir(run_dir) == run_dir

    def test_collection_with_one_run(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir = build_test_run_dir(collection / "20260101T000000_aaaaaaaaaaaaaaaa")
        assert find_run_dir(collection) == run_dir

    def test_collection_with_multiple_runs_ambiguous(self, tmp_path: Path):
        collection = tmp_path / "output"
        build_test_run_dir(collection / "20260101T000000_aaaaaaaaaaaaaaaa")
        build_test_run_dir(collection / "20260102T000000_bbbbbbbbbbbbbbbb")
        with pytest.raises(ManifestIntegrityError, match="2 runs"):
            find_run_dir(collection)

    def test_empty_collection_raises(self, tmp_path: Path):
        collection = tmp_path / "output"
        collection.mkdir()
        with pytest.raises(ManifestIntegrityError, match="No run"):
            find_run_dir(collection)


# ---------------------------------------------------------------------------
# 9. Pipeline lifecycle integration (mocked)
# ---------------------------------------------------------------------------


class TestPipelineLifecycle:
    """Integration tests for pipeline lifecycle with mocked LLM calls."""

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.write_coverage_report")
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
        mock_coverage_report,
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
        gaps = MagicMock()
        gaps.uncovered_entry_points = []
        mock_gaps.return_value = gaps

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
    @patch("scenario_forge.pipeline.runner.write_coverage_report")
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
        mock_coverage_report,
        mock_report,
        tmp_path: Path,
    ):
        from scenario_forge.pipeline.threats import ThreatSurface
        from scenario_forge.pipeline.runner import run_pipeline

        # Make profile inference raise a fatal error
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

        # The sentinel should exist and be marked failed
        runs = [d for d in collection.iterdir() if d.is_dir() and is_run_dir(d)]
        assert len(runs) == 1
        manifest = load_manifest(runs[0])
        assert manifest.status == RunStatus.FAILED

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.write_coverage_report")
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
        mock_coverage_report,
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
        gaps = MagicMock()
        gaps.uncovered_entry_points = []
        mock_gaps.return_value = gaps

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

        # Both manifests should be COMPLETED
        m1 = load_manifest(result1.run_dir)
        m2 = load_manifest(result2.run_dir)
        assert m1.status == RunStatus.COMPLETED
        assert m2.status == RunStatus.COMPLETED

        # First run's use-case.txt should still say "First run"
        assert (result1.run_dir / "use-case.txt").read_text() == "First run"
