"""Loader, semantic validator, and deterministic digest for catalog lineage.

The catalog-lineage artifact
(``data/taxonomies/attack-patterns/catalog-lineage.yaml``) is the final,
versioned, machine-readable record of how each of the 71 legacy
attack-pattern source records maps to resulting authoritative patterns for
the canonical chain-authoring waves.  It is validated against the closed
Draft 2020-12 schema at ``data/schemas/catalog-lineage.yaml`` plus the
semantic gates in :func:`validate_catalog_lineage`:

- exactly the production catalog IDs appear as sources, once each;
- source-entry facts (file, threat, evidence, kill-chain counts) match the
  production loader;
- taxonomy pins match the production resolver (ATLAS-only; LAAF absent);
- every proposed exact ATLAS id exists in the production resolver — with the
  schema requiring nonblank operational-identity rationale and evidence so
  membership alone is never semantic approval;
- disposition/resulting invariants: retired and deferred sources carry no
  resulting record; resulting ids are unique and collision-free against the
  existing catalog unless they continue their own source id; split sources
  map explicitly to two or more resulting ids;
- overlap groups have one explicit resolution covering all members.

The release digest (:func:`compute_catalog_lineage_digest`) is a
deterministic semantic digest: every string is NFC-normalized, object keys
are emitted in sorted order, and every array is framed as a sorted set, so
the digest is insensitive to key order and array order but sensitive to any
content change.  Only ``release.semantic_digest`` itself is excluded.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

_DEFAULT_LINEAGE_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "attack-patterns"
    / "catalog-lineage.yaml"
)
_DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "data" / "schemas" / "catalog-lineage.yaml"
)
_LINEAGE_DOMAIN = "scenario-forge:catalog-lineage:v1"

_FINAL_DISPOSITIONS = frozenset(
    {"retain", "narrow", "split", "supersede", "retire", "defer"}
)


def load_catalog_lineage(path: str | Path | None = None) -> dict[str, Any]:
    """Load the catalog-lineage artifact as a plain dict (no validation)."""
    lineage_path = Path(path) if path is not None else _DEFAULT_LINEAGE_PATH
    with open(lineage_path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise TypeError(f"catalog lineage {lineage_path} is not a mapping")
    return data


def load_catalog_lineage_schema(path: str | Path | None = None) -> dict[str, Any]:
    """Load the closed Draft 2020-12 schema for the artifact."""
    schema_path = Path(path) if path is not None else _DEFAULT_SCHEMA_PATH
    with open(schema_path) as f:
        schema = yaml.safe_load(f)
    if not isinstance(schema, dict):
        raise TypeError(f"catalog lineage schema {schema_path} is not a mapping")
    Draft202012Validator.check_schema(schema)
    return schema


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _normalize(value: Any) -> Any:
    """Recursively NFC-normalize strings and frame arrays as sorted sets.

    Dict key order is handled by the canonical-JSON sort_keys; arrays are
    sorted by the canonical JSON of their normalized elements so the digest
    is independent of authoring order.
    """
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=_canonical_json)
    if isinstance(value, str):
        return _nfc(value)
    return value


def compute_catalog_lineage_digest(artifact: dict[str, Any]) -> str:
    """Deterministic semantic digest over normalized artifact content.

    Excludes only ``release.semantic_digest``.  NFC-normalized; object key
    order and array order are normalized away; framed under a versioned
    domain so the digest never collides with other pinned content.
    """
    if not isinstance(artifact, dict):
        raise TypeError("catalog lineage artifact must be a mapping")
    release = artifact.get("release")
    if not isinstance(release, dict) or "semantic_digest" not in release:
        raise ValueError("catalog lineage artifact lacks release.semantic_digest")
    stripped = {
        **artifact,
        "release": {k: v for k, v in release.items() if k != "semantic_digest"},
    }
    payload = (
        _LINEAGE_DOMAIN.encode()
        + b"\0"
        + _canonical_json(_normalize(stripped)).encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def _split_pattern_id(pattern_id: str) -> tuple[str, int]:
    """Split ``AP-T<fam>-<NN>`` into its threat family and sequence number."""
    fam, _, nn = pattern_id.removeprefix("AP-T").partition("-")
    return fam, int(nn)


def _mapping_ids(resulting: dict[str, Any]) -> list[str]:
    ids = [m["id"] for m in resulting["atlas_chain_mappings"]]
    ids.extend(m["id"] for m in resulting["atlas_step_mappings"])
    return ids


def validate_catalog_lineage(
    artifact: dict[str, Any],
    *,
    patterns: dict[str, dict],
    resolver: Any,
    schema: dict[str, Any] | None = None,
    owners: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Schema-validate and semantically qualify the lineage artifact.

    ``patterns`` is the production catalog from
    :func:`scenario_forge.data.loaders.load_attack_patterns`; ``resolver``
    implements the production ``TaxonomyResolver`` protocol
    (``taxonomy_context`` + ``contains``).  ``owners`` maps every catalog id
    to the attack-patterns file that declares it (per-file loader glob); when
    given, source-file ownership of both source entries and resulting records
    is enforced.  Returns the artifact on success; raises ``ValueError`` (or
    ``jsonschema.ValidationError``) on any breach.
    """
    schema = schema if schema is not None else load_catalog_lineage_schema()
    Draft202012Validator(schema).validate(artifact)

    # Taxonomy pins must match the production resolver exactly.
    context = artifact["taxonomy_context"]
    expected = resolver.taxonomy_context
    if context["laaf"] is not None:
        raise ValueError("catalog lineage taxonomy_context.laaf must be null for v1")
    if (
        context["atlas"]["release"] != expected.atlas.release
        or context["atlas"]["digest"] != expected.atlas.digest
        or context["mapping_set_digest"] != expected.mapping_set_digest
        or expected.laaf is not None
    ):
        raise ValueError(
            "catalog lineage taxonomy pins do not match the production resolver"
        )

    # The disposition vocabulary keys are exactly the closed disposition enum.
    if set(artifact["disposition_vocabulary"]) != _FINAL_DISPOSITIONS:
        raise ValueError(
            "disposition_vocabulary keys diverge from the closed vocabulary"
        )

    sources = artifact["sources"]
    source_ids = [entry["source_pattern_id"] for entry in sources]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("duplicate source_pattern_id in catalog lineage sources")
    if set(source_ids) != set(patterns):
        missing = sorted(set(patterns) - set(source_ids))
        extra = sorted(set(source_ids) - set(patterns))
        raise ValueError(
            f"catalog lineage sources diverge from the production catalog; "
            f"missing={missing} extra={extra}"
        )

    # Source-entry facts must match the production loader records.
    by_id = {entry["source_pattern_id"]: entry for entry in sources}
    for pid, pattern in patterns.items():
        entry = by_id[pid]
        legacy_steps = len(pattern.get("kill_chain") or [])
        evidence = pattern.get("evidence") or []
        tier = (
            "direct_demonstration"
            if any(e.get("type") == "direct_demonstration" for e in evidence)
            else "enrichment"
            if evidence
            else "kill_chain_only"
            if legacy_steps
            else "none"
        )
        mismatches = {
            "threat_id": (entry["threat_id"], pattern["threat_id"]),
            "evidence_tier": (entry["evidence_tier"], tier),
            "evidence_count": (entry["evidence_count"], len(evidence)),
            "legacy_kill_chain_steps": (entry["legacy_kill_chain_steps"], legacy_steps),
        }
        for field, (claimed, actual) in mismatches.items():
            if claimed != actual:
                raise ValueError(
                    f"catalog lineage entry {pid} {field}={claimed!r} "
                    f"does not match the production catalog value {actual!r}"
                )
        if owners is not None and entry["source_file"] != owners[pid]:
            raise ValueError(
                f"catalog lineage entry {pid} source_file={entry['source_file']!r} "
                f"does not match the declaring file {owners[pid]!r}"
            )

    # Overlap groups: unique ids, one resolution, members are sources, and
    # membership is consistent with the per-entry overlap_group references.
    groups = artifact["overlap_groups"]
    group_ids = [g["group_id"] for g in groups]
    if len(set(group_ids)) != len(group_ids):
        raise ValueError("duplicate overlap group_id in catalog lineage")
    member_to_group: dict[str, str] = {}
    for group in groups:
        for member in group["members"]:
            if member not in by_id:
                raise ValueError(
                    f"overlap group {group['group_id']} member {member} is not a source"
                )
            if member in member_to_group:
                raise ValueError(
                    f"overlap member {member} appears in more than one group"
                )
            member_to_group[member] = group["group_id"]
    for entry in sources:
        referenced = entry["overlap_group"]
        pid = entry["source_pattern_id"]
        if referenced is None:
            if pid in member_to_group:
                raise ValueError(
                    f"overlap group {member_to_group[pid]} lists {pid} but the "
                    "source entry references no group"
                )
            continue
        if referenced not in set(group_ids):
            raise ValueError(
                f"source {pid} references unknown overlap group {referenced}"
            )
        if member_to_group.get(pid) != referenced:
            raise ValueError(
                f"source {pid} references overlap group {referenced} but is "
                "not listed as a member"
            )

    # Resulting records: uniqueness, collision-freedom, disposition rules,
    # and resolver membership for every proposed exact ATLAS id.
    catalog_ids = set(patterns)
    resulting_ids: list[str] = []
    for entry in sources:
        pid = entry["source_pattern_id"]
        disposition = entry["disposition"]
        resulting = entry["resulting_patterns"]
        if disposition in ("retire", "defer"):
            if resulting:
                raise ValueError(
                    f"{disposition} source {pid} carries resulting patterns"
                )
            continue
        if disposition in ("retain", "narrow", "supersede"):
            expected_ids = {pid} if disposition != "supersede" else None
            for record in resulting:
                rid = record["pattern_id"]
                if expected_ids is not None and rid != pid:
                    raise ValueError(
                        f"{disposition} source {pid} resulting id {rid} must "
                        "continue its source id"
                    )
        for record in resulting:
            rid = record["pattern_id"]
            if rid in catalog_ids and rid != pid:
                raise ValueError(
                    f"resulting id {rid} from source {pid} collides with an "
                    "existing catalog id"
                )
            if record["source_file"] not in _SOURCE_FILES:
                raise ValueError(f"resulting id {rid} has an unknown source_file")
            if owners is not None and record["source_file"] != owners[pid]:
                raise ValueError(
                    f"resulting id {rid} from source {pid} is owned by "
                    f"{record['source_file']!r}, not the source file {owners[pid]!r}"
                )
            for atlas_id in _mapping_ids(record):
                if not resolver.contains("ATLAS", atlas_id):
                    raise ValueError(
                        f"resulting id {rid} proposes unknown ATLAS id {atlas_id}"
                    )
            resulting_ids.append(rid)
    if len(set(resulting_ids)) != len(resulting_ids):
        raise ValueError("duplicate resulting pattern id across catalog lineage")

    # Split-derived ids must follow the deterministic naming strategy: split
    # sources are processed in ascending source id order; the first resulting
    # record (causal mechanism order) continues the source id; each subsequent
    # record takes the lowest unused NN in the source threat family across the
    # merged catalog plus ids already allocated to earlier splits.
    family_used: dict[str, set[int]] = {}
    for cid in catalog_ids:
        fam, nn = _split_pattern_id(cid)
        family_used.setdefault(fam, set()).add(nn)
    for entry in sorted(sources, key=lambda e: e["source_pattern_id"]):
        if entry["disposition"] != "split":
            continue
        pid = entry["source_pattern_id"]
        fam, _ = _split_pattern_id(pid)
        results = entry["resulting_patterns"]
        if results[0]["pattern_id"] != pid:
            raise ValueError(
                f"split source {pid} first resulting id "
                f"{results[0]['pattern_id']!r} must continue the source id "
                "in causal mechanism order"
            )
        used = family_used[fam]
        for record in results[1:]:
            nn = 1
            while nn in used:
                nn += 1
            expected = f"AP-T{fam}-{nn:02d}"
            if record["pattern_id"] != expected:
                raise ValueError(
                    f"split source {pid} derived id {record['pattern_id']!r} "
                    f"must be the lowest unused family id {expected!r}"
                )
            used.add(nn)

    # Release digest must recompute deterministically.
    recorded = artifact["release"]["semantic_digest"]
    recomputed = compute_catalog_lineage_digest(artifact)
    if recorded != recomputed:
        raise ValueError(
            f"catalog lineage digest mismatch: recorded {recorded} != recomputed {recomputed}"
        )
    return artifact


_SOURCE_FILES = frozenset(
    {
        "attack-patterns.yaml",
        "attack-patterns-agentic-only.yaml",
        "attack-patterns-atlas-derived.yaml",
        "attack-patterns-comms-human-supply.yaml",
        "attack-patterns-halluc-intent.yaml",
        "attack-patterns-memory-tool.yaml",
    }
)
