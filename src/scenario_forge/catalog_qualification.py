"""Read-only, content-addressed qualification of the synthetic catalog."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scenario_forge.data.loaders import load_attack_patterns, load_yaml_strict
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.eval.scorecard import ScorecardV1, scorecard_qualification_gates
from scenario_forge.eval.versioned_metrics import evaluate_v3_scorecard
from scenario_forge.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    RunManifest,
    RunStatus,
)
from scenario_forge.models.attack_pattern import Digest, EvaluatedFactEvidence
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import ScenarioEnvelope
from scenario_forge.pipeline.coverage_planning import revalidate_qualified_candidate
from scenario_forge.pipeline.persistence import CoveragePlanV2, FinalizationInventoryV1
from scenario_forge.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectionBudget,
    ProjectionIssue,
    capture_capability_snapshot,
    compute_authoritative_catalog_pin,
    project_authoritative_candidates,
)


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_CANONICAL_PROFILE_IDS = (
    "direct-conversational",
    "influenceable-retrieval",
    "multi-agent-delegation",
    "state-changing-tools",
    "training-tool-supply-chain",
    "writable-persistent-state",
)


def _sorted_unique(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be sorted and unique")
    return values


class ReviewedProfile(_Contract):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    rationale: str = Field(min_length=1)
    profile: CapabilityProfile
    facts: tuple[EvaluatedFactEvidence, ...]
    applicable_pattern_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_collections(self) -> ReviewedProfile:
        _sorted_unique(self.applicable_pattern_ids, "applicable_pattern_ids")
        snapshot = capture_capability_snapshot(self.profile, self.facts)
        if snapshot.facts != self.facts:
            raise ValueError("facts must be sorted by unique authoritative reference")
        return self

    def snapshot(self) -> CapabilityFactSnapshot:
        """Derive the sole profile/fact snapshot; never persist duplicate state."""
        return capture_capability_snapshot(self.profile, self.facts)


class ReviewedProfileMatrixV1(_Contract):
    schema_version: Literal["1"] = "1"
    catalog_sha256: Digest
    catalog_denominator: int = Field(gt=0)
    profiles: tuple[ReviewedProfile, ...] = Field(min_length=6, max_length=6)

    @model_validator(mode="after")
    def validate_profiles(self) -> ReviewedProfileMatrixV1:
        ids = tuple(item.profile_id for item in self.profiles)
        if ids != _CANONICAL_PROFILE_IDS:
            raise ValueError("v1 matrix requires the six canonical focused profiles")
        assignments = [
            pattern_id
            for profile in self.profiles
            for pattern_id in profile.applicable_pattern_ids
        ]
        if len(assignments) != len(set(assignments)):
            raise ValueError("v1 matrix pattern ownership must be disjoint")
        return self


class QualificationRunRef(_Contract):
    profile_id: str
    run_manifest_path: str
    manifest_sha256: Digest

    @field_validator("run_manifest_path")
    @classmethod
    def canonical_manifest_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or ".." in path.parts
            or "." in path.parts
            or "\\" in value
            or path.name != "run-manifest.yaml"
        ):
            raise ValueError(
                "run manifest path must be canonical, safe, relative, and end in run-manifest.yaml"
            )
        return value


class ForensicRunRef(QualificationRunRef):
    pass


class CampaignManifestV1(_Contract):
    schema_version: Literal["1"] = "1"
    catalog_sha256: Digest
    catalog_denominator: int = Field(gt=0)
    matrix_sha256: Digest
    qualification_runs: tuple[QualificationRunRef, ...] = ()
    forensic_runs: tuple[ForensicRunRef, ...] = ()

    @model_validator(mode="after")
    def validate_refs(self) -> CampaignManifestV1:
        for name, refs in (
            ("qualification_runs", self.qualification_runs),
            ("forensic_runs", self.forensic_runs),
        ):
            keys = [(item.profile_id, item.run_manifest_path) for item in refs]
            if keys != sorted(set(keys)):
                raise ValueError(f"{name} must be sorted and duplicate-free")
        qualification_paths = {
            item.run_manifest_path for item in self.qualification_runs
        }
        forensic_paths = {item.run_manifest_path for item in self.forensic_runs}
        if len(qualification_paths) != len(self.qualification_runs):
            raise ValueError("qualification run manifest paths must be unique")
        if len(forensic_paths) != len(self.forensic_runs):
            raise ValueError("forensic run manifest paths must be unique")
        if qualification_paths & forensic_paths:
            raise ValueError("qualification and forensic references must be separate")
        return self


class ProfilePreflight(_Contract):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    reviewed_pattern_ids: tuple[str, ...]
    projected_pattern_ids: tuple[str, ...]
    missing_pattern_ids: tuple[str, ...]
    issues: tuple[ProjectionIssue, ...]

    @model_validator(mode="after")
    def validate_accounting(self) -> ProfilePreflight:
        reviewed = set(
            _sorted_unique(self.reviewed_pattern_ids, "reviewed_pattern_ids")
        )
        projected = set(
            _sorted_unique(self.projected_pattern_ids, "projected_pattern_ids")
        )
        missing = set(_sorted_unique(self.missing_pattern_ids, "missing_pattern_ids"))
        if not projected <= reviewed:
            raise ValueError("projected pattern IDs must be reviewed")
        if missing != reviewed - projected:
            raise ValueError(
                "profile missing pattern IDs must equal reviewed minus projected"
            )
        return self


class ForensicHistoryEntry(_Contract):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    path: str
    status: Literal["completed_with_errors", "failed"]

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or ".." in path.parts
            or "." in path.parts
            or "\\" in value
            or path.name != "run-manifest.yaml"
        ):
            raise ValueError("forensic path must be a canonical run manifest path")
        return value


class QualificationReportV1(_Contract):
    schema_version: Literal["1"] = "1"
    kind: Literal["preflight", "campaign"]
    catalog_sha256: Digest
    catalog_denominator: int = Field(gt=0)
    matrix_sha256: Digest
    campaign_manifest_sha256: Digest | None = None
    preflight: tuple[ProfilePreflight, ...]
    missing_pattern_ids: tuple[str, ...]
    qualified_pattern_ids: tuple[str, ...] = ()
    forensic_history: tuple[ForensicHistoryEntry, ...] = ()

    @model_validator(mode="after")
    def validate_report(self) -> QualificationReportV1:
        profile_ids = tuple(item.profile_id for item in self.preflight)
        if profile_ids != _CANONICAL_PROFILE_IDS:
            raise ValueError("report requires the six canonical profiles in order")
        reviewed_ids = [
            pattern_id
            for profile in self.preflight
            for pattern_id in profile.reviewed_pattern_ids
        ]
        reviewed = set(reviewed_ids)
        if len(reviewed_ids) != len(reviewed):
            raise ValueError("report reviewed pattern ownership must be disjoint")
        if len(reviewed) != self.catalog_denominator:
            raise ValueError("catalog denominator must equal the reviewed universe")
        projected = {
            pattern_id
            for profile in self.preflight
            for pattern_id in profile.projected_pattern_ids
        }
        missing = set(_sorted_unique(self.missing_pattern_ids, "missing_pattern_ids"))
        qualified = set(
            _sorted_unique(self.qualified_pattern_ids, "qualified_pattern_ids")
        )
        if not qualified <= projected:
            raise ValueError("qualified pattern IDs must be projected")
        forensic_keys = [
            (item.profile_id, item.path, item.status) for item in self.forensic_history
        ]
        if forensic_keys != sorted(set(forensic_keys)):
            raise ValueError("forensic history must be canonical and unique")
        forensic_paths = [item.path for item in self.forensic_history]
        if len(forensic_paths) != len(set(forensic_paths)):
            raise ValueError("forensic history paths must be unique")
        if any(
            item.profile_id not in _CANONICAL_PROFILE_IDS
            for item in self.forensic_history
        ):
            raise ValueError("forensic history profile_id is not canonical")
        if self.kind == "preflight":
            if self.campaign_manifest_sha256 is not None:
                raise ValueError("preflight report cannot bind a campaign manifest")
            if qualified or self.forensic_history:
                raise ValueError("preflight report cannot contain campaign results")
            expected_missing = reviewed - projected
        else:
            if self.campaign_manifest_sha256 is None:
                raise ValueError("campaign report requires campaign manifest SHA-256")
            expected_missing = reviewed - qualified
        if missing != expected_missing:
            raise ValueError("top-level missing pattern IDs do not match report kind")
        return self


PersistedContract = ReviewedProfileMatrixV1 | CampaignManifestV1 | QualificationReportV1


def validate_persisted_contract(
    path: Path, contract: Literal["matrix", "campaign", "report"]
) -> PersistedContract:
    """Standalone schema and semantic validation without running qualification."""
    models = {
        "matrix": ReviewedProfileMatrixV1,
        "campaign": CampaignManifestV1,
        "report": QualificationReportV1,
    }
    return models[contract].model_validate(load_yaml_strict(path.read_bytes()))


def _bytes(path: Path) -> bytes:
    return path.read_bytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_matrix(path: Path) -> ReviewedProfileMatrixV1:
    return ReviewedProfileMatrixV1.model_validate(load_yaml_strict(_bytes(path)))


def _fact_key(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _condition_fact_keys(condition: dict | None) -> set[str]:
    if not condition:
        return set()
    keys = set()
    if isinstance(condition.get("fact"), dict):
        keys.add(_fact_key(condition["fact"]))
    for operand in condition.get("operands", []):
        keys.update(_condition_fact_keys(operand))
    keys.update(_condition_fact_keys(condition.get("operand")))
    return keys


def _required_fact_keys(records: list[dict]) -> set[str]:
    keys: set[str] = set()
    for record in records:
        for step in record["canonical_chain"]["steps"]:
            keys.update(_condition_fact_keys(step.get("condition")))
            for precondition in step.get("preconditions", []):
                keys.update(_condition_fact_keys(precondition.get("condition")))
    return keys


def _preflight_matrix(
    matrix: ReviewedProfileMatrixV1,
    raw_bytes: bytes,
    *,
    catalog: dict[str, dict] | None = None,
    resolver: object | None = None,
    catalog_pin: str | None = None,
) -> QualificationReportV1:
    catalog = catalog or load_attack_patterns()
    records = list(catalog.values())
    resolver = resolver or load_taxonomy_resolver()
    pin = catalog_pin or compute_authoritative_catalog_pin(records, resolver)
    if (matrix.catalog_sha256, matrix.catalog_denominator) != (pin, len(catalog)):
        raise ValueError(
            "matrix catalog pin/denominator does not match the live qualified catalog"
        )
    reviewed = tuple(
        pattern_id
        for profile in matrix.profiles
        for pattern_id in profile.applicable_pattern_ids
    )
    if set(reviewed) != set(catalog) or len(reviewed) != len(catalog):
        raise ValueError(
            "matrix must provide an exact disjoint reviewed partition of live patterns"
        )
    results = []
    projected_union: set[str] = set()
    for profile in matrix.profiles:
        selected = [catalog[pid] for pid in profile.applicable_pattern_ids]
        actual_facts = {
            _fact_key(item.fact.model_dump(mode="json")): item for item in profile.facts
        }
        required_facts = _required_fact_keys(selected)
        missing_facts = sorted(required_facts - set(actual_facts))
        unknown_facts = sorted(
            key
            for key in required_facts
            if key in actual_facts and actual_facts[key].status == "unknown"
        )
        if missing_facts or unknown_facts:
            raise ValueError(
                f"profile {profile.profile_id} must provide known explicit readings "
                f"for every applicable condition fact; missing={missing_facts}, "
                f"unknown={unknown_facts}"
            )
        batch = project_authoritative_candidates(
            records,
            resolver,
            profile.snapshot(),
            budget=ProjectionBudget(max_candidates=4096, max_derivation_work=65536),
        )
        projected_candidates = tuple(
            item
            for item in batch.candidates
            if item.pattern_id in profile.applicable_pattern_ids
        )
        if any(item.projection.catalog_pin != pin for item in projected_candidates):
            raise ValueError("preflight projection does not carry the full catalog pin")
        projected = tuple(sorted({item.pattern_id for item in projected_candidates}))
        projected_union.update(projected)
        results.append(
            ProfilePreflight(
                profile_id=profile.profile_id,
                reviewed_pattern_ids=tuple(profile.applicable_pattern_ids),
                projected_pattern_ids=projected,
                missing_pattern_ids=tuple(
                    sorted(set(profile.applicable_pattern_ids) - set(projected))
                ),
                issues=tuple(
                    item
                    for item in batch.infeasibilities
                    if item.pattern_id in profile.applicable_pattern_ids
                ),
            )
        )
    return QualificationReportV1(
        kind="preflight",
        catalog_sha256=pin,
        catalog_denominator=len(catalog),
        matrix_sha256=_sha(raw_bytes),
        preflight=tuple(results),
        missing_pattern_ids=tuple(sorted(set(catalog) - projected_union)),
    )


def preflight_matrix(path: Path) -> QualificationReportV1:
    raw_bytes = _bytes(path)
    matrix = ReviewedProfileMatrixV1.model_validate(load_yaml_strict(raw_bytes))
    return _preflight_matrix(matrix, raw_bytes)


def _safe_relative_read(
    root: Path, relative_path: str
) -> tuple[bytes, tuple[int, int]]:
    """Read one campaign reference without following any symlink component."""
    parts = PurePosixPath(relative_path).parts
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = next_fd
            leaf_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                metadata = os.fstat(leaf_fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ManifestIntegrityError(
                        f"campaign reference is not a regular file: {relative_path}"
                    )
                chunks = []
                while chunk := os.read(leaf_fd, 65536):
                    chunks.append(chunk)
                return b"".join(chunks), (metadata.st_dev, metadata.st_ino)
            finally:
                os.close(leaf_fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ManifestIntegrityError(
            f"cannot safely read campaign reference {relative_path}: {exc}"
        ) from exc


def _resolve_campaign_run(
    base: Path,
    ref: QualificationRunRef,
    *,
    authoritative: bool,
    seen_physical: set[tuple[int, int]],
) -> ManifestInventoryResolver:
    content, physical_id = _safe_relative_read(base, ref.run_manifest_path)
    if physical_id in seen_physical:
        raise ValueError(
            "campaign run manifests must reference distinct physical files"
        )
    seen_physical.add(physical_id)
    if _sha(content) != ref.manifest_sha256:
        raise ValueError(f"manifest hash mismatch: {ref.run_manifest_path}")
    try:
        manifest = RunManifest.model_validate(load_yaml_strict(content))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"invalid pinned run manifest {ref.run_manifest_path}: {exc}"
        ) from exc
    if manifest.manifest_version != "3":
        raise ManifestIntegrityError("catalog qualification requires manifest v3")
    if not manifest.status.is_final:
        raise ManifestIntegrityError("catalog qualification requires a final run")
    if authoritative and manifest.status is not RunStatus.COMPLETED:
        raise ManifestIntegrityError(
            f"qualification run is not authoritative: {manifest.status.value}"
        )
    if not authoritative and manifest.status is RunStatus.COMPLETED:
        raise ManifestIntegrityError(
            "completed authoritative runs belong in qualification_runs"
        )
    return ManifestInventoryResolver(
        base / PurePosixPath(ref.run_manifest_path).parent,
        manifest,
        check_orphans=True,
    )


def aggregate_campaign(matrix_path: Path, campaign_path: Path) -> QualificationReportV1:
    matrix_bytes = _bytes(matrix_path)
    matrix = ReviewedProfileMatrixV1.model_validate(load_yaml_strict(matrix_bytes))
    catalog = load_attack_patterns()
    catalog_records = list(catalog.values())
    taxonomy_resolver = load_taxonomy_resolver()
    catalog_pin = compute_authoritative_catalog_pin(catalog_records, taxonomy_resolver)
    preflight = _preflight_matrix(
        matrix,
        matrix_bytes,
        catalog=catalog,
        resolver=taxonomy_resolver,
        catalog_pin=catalog_pin,
    )
    campaign_bytes = _bytes(campaign_path)
    campaign = CampaignManifestV1.model_validate(load_yaml_strict(campaign_bytes))
    if (
        campaign.catalog_sha256,
        campaign.catalog_denominator,
        campaign.matrix_sha256,
    ) != (
        preflight.catalog_sha256,
        preflight.catalog_denominator,
        preflight.matrix_sha256,
    ):
        raise ValueError(
            "campaign pins do not match the live catalog and exact matrix bytes"
        )
    profiles = {item.profile_id: item for item in matrix.profiles}
    projected_by_profile = {
        item.profile_id: set(item.projected_pattern_ids) for item in preflight.preflight
    }
    qualified: set[str] = set()
    forensic: list[ForensicHistoryEntry] = []
    base = campaign_path.parent
    seen_physical: set[tuple[int, int]] = set()
    for ref in campaign.qualification_runs:
        if ref.profile_id not in profiles:
            raise ValueError(f"unknown matrix profile_id: {ref.profile_id}")
        resolver = _resolve_campaign_run(
            base,
            ref,
            authoritative=True,
            seen_physical=seen_physical,
        )
        score_entry = resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD)
        final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
        profile_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
        plan_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
        if any(
            entry is None
            for entry in (score_entry, final_entry, profile_entry, plan_entry)
        ):
            raise ValueError(
                "qualification run lacks profile, plan, scorecard, or finalization inventory"
            )
        assert score_entry and final_entry and profile_entry and plan_entry
        score = ScorecardV1.model_validate(
            load_yaml_strict(resolver.read_text(score_entry))
        )
        recomputed_score = evaluate_v3_scorecard(resolver)
        if score != recomputed_score:
            raise ValueError(
                "qualification scorecard does not equal canonical resolver evaluation"
            )
        if score.qualification.status.value != "pass":
            raise ValueError("qualification scorecard does not pass canonical gates")
        nonpassing_gates = sorted(
            gate_id
            for gate_id, metric in scorecard_qualification_gates(score).items()
            if metric.status.value != "pass"
        )
        if nonpassing_gates:
            raise ValueError(
                "qualification scorecard has non-passing strict category gates: "
                + ", ".join(nonpassing_gates)
            )
        final = FinalizationInventoryV1.model_validate(
            json.loads(resolver.read_text(final_entry))
        )
        if final.quarantine_inventory or any(
            not item.admitted for item in final.admission_decisions
        ):
            raise ValueError(
                "qualification run contains quarantine or non-admitted decisions"
            )
        expected = profiles[ref.profile_id]
        run_profile = CapabilityProfile.model_validate(
            load_yaml_strict(resolver.read_text(profile_entry))
        )
        if run_profile != expected.profile:
            raise ValueError("run capability profile does not match matrix profile")
        plan = CoveragePlanV2.model_validate_json(resolver.read_text(plan_entry))
        choices = {
            choice.candidate_id: choice
            for target in plan.targets
            for choice in target.ordered_choices
        }
        for entry in resolver.entries_by_role(ArtifactRole.SCENARIO_YAML):
            scenario = ScenarioEnvelope.model_validate(
                load_yaml_strict(resolver.read_text(entry))
            )
            block = scenario.projection
            if block.capability_snapshot != expected.snapshot():
                raise ValueError(
                    "scenario capability snapshot does not match matrix profile"
                )
            if block.projection.catalog_pin != campaign.catalog_sha256:
                raise ValueError("scenario catalog pin does not match campaign")
            pattern_id = block.projection.source_chain.pattern_id
            if pattern_id not in expected.applicable_pattern_ids:
                raise ValueError(
                    "scenario pattern is not reviewed for its matrix profile"
                )
            if pattern_id not in projected_by_profile[ref.profile_id]:
                raise ValueError(
                    "scenario pattern has no valid deterministic matrix projection"
                )
            choice = choices.get(scenario.candidate_id)
            if choice is None:
                raise ValueError(
                    "admitted scenario candidate is absent from coverage plan"
                )
            revalidated = revalidate_qualified_candidate(
                choice.model_dump(mode="json"),
                taxonomy_resolver,
                expected.snapshot(),
                catalog_records,
                expected_catalog_pin=campaign.catalog_sha256,
            ).projected
            if (
                revalidated.candidate_id != scenario.candidate_id
                or revalidated.projection != block.projection
                or revalidated.canonical_ingress != block.canonical_ingress
                or revalidated.ingress_controllability != block.ingress_controllability
                or revalidated.projected_mappings != block.projected_mappings
                or revalidated.execution_requirements != block.execution_requirements
                or revalidated.requirement_derivation_version
                != block.requirement_derivation_version
                or revalidated.execution_requirements_digest
                != block.execution_requirements_digest
            ):
                raise ValueError(
                    "scenario projection does not match authoritative plan candidate"
                )
            qualified.add(pattern_id)
    for ref in campaign.forensic_runs:
        if ref.profile_id not in profiles:
            raise ValueError(f"unknown matrix profile_id: {ref.profile_id}")
        resolver = _resolve_campaign_run(
            base,
            ref,
            authoritative=False,
            seen_physical=seen_physical,
        )
        forensic.append(
            ForensicHistoryEntry(
                profile_id=ref.profile_id,
                path=ref.run_manifest_path,
                status=resolver.manifest.status.value,
            )
        )
    return QualificationReportV1(
        kind="campaign",
        catalog_sha256=preflight.catalog_sha256,
        catalog_denominator=preflight.catalog_denominator,
        matrix_sha256=preflight.matrix_sha256,
        campaign_manifest_sha256=_sha(campaign_bytes),
        preflight=preflight.preflight,
        qualified_pattern_ids=tuple(sorted(qualified)),
        missing_pattern_ids=tuple(
            sorted(
                {pid for p in matrix.profiles for pid in p.applicable_pattern_ids}
                - qualified
            )
        ),
        forensic_history=tuple(forensic),
    )
