"""Production taxonomy pins and the pinned ATLAS-backed resolver.

Authority rules:

- ATLAS is the sole initially qualified taxonomy.  Resolver membership comes
  only from identifiers actually present in the pinned bundled source
  (:data:`_DEFAULT_ATLAS_PATH`) — tactics and techniques, where
  sub-techniques are flat technique keys.  Mitigations and case studies are
  never taxonomy mapping targets.
- Every SSSOM ``skos:relatedMatch`` row is unqualified migration provenance.
  Rows are digested as mapping-set content only; they never populate
  resolver membership and never confer ``ExactMapping`` authority.
- LAAF is optional and non-authoritative for v1.  Nothing LAAF is bundled
  or vendored here; a future authoritative LAAF release must be supplied
  explicitly as pin plus identifier membership, with strict coherence.

The resolver performs all I/O at construction time via this module's
loaders; the constructed object is a pure in-memory implementation of the
merged :class:`~scenario_forge.models.attack_pattern.TaxonomyResolver`
protocol.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import yaml

from scenario_forge.data.sssom import load_sssom
from scenario_forge.models.attack_pattern import TaxonomyContext, TaxonomyPin

_DEFAULT_ATLAS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "atlas"
    / "ATLAS-2026.05.yaml"
)
_DEFAULT_MAPPING_SET_DIR = (
    Path(__file__).resolve().parents[3] / "data" / "taxonomies" / "attack-patterns"
)
_MAPPING_SET_GLOB = "attack-patterns*.sssom.tsv"
_MAPPING_SET_DOMAIN = "scenario-forge:mapping-set:v1"

_MAPPING_ROW_FIELDS = (
    "subject_id",
    "subject_source",
    "predicate_id",
    "object_id",
    "object_source",
    "mapping_justification",
)


def load_atlas_pin(path: str | Path | None = None) -> TaxonomyPin:
    """Deterministic SHA-256 pin of the bundled ATLAS release file.

    The digest covers the exact pinned file bytes; the release is read from
    the file's ``collection.version`` so pin and source move together.
    """
    atlas_path = Path(path) if path is not None else _DEFAULT_ATLAS_PATH
    raw = atlas_path.read_bytes()
    try:
        release = yaml.safe_load(raw)["collection"]["version"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise ValueError(
            f"ATLAS source {atlas_path} lacks a collection version"
        ) from exc
    return TaxonomyPin(release=str(release), digest=hashlib.sha256(raw).hexdigest())


def load_atlas_identifiers(path: str | Path | None = None) -> frozenset[str]:
    """Authoritative ATLAS identifiers addressable by taxonomy mappings.

    Membership is drawn only from the pinned source's tactics and techniques
    sections (sub-techniques are flat technique keys).  Mitigation and
    case-study identifiers are deliberately excluded.
    """
    atlas_path = Path(path) if path is not None else _DEFAULT_ATLAS_PATH
    with open(atlas_path) as f:
        data = yaml.safe_load(f)
    identifiers: set[str] = set()
    for section in ("tactics", "techniques"):
        entries = data.get(section) or {}
        for key, entry in entries.items():
            if not isinstance(entry, dict) or entry.get("id") != key:
                raise ValueError(
                    f"ATLAS source {atlas_path} has an incoherent "
                    f"{section} entry: {key}"
                )
            identifiers.add(key)
    if not identifiers:
        raise ValueError(
            f"ATLAS source {atlas_path} contains no tactic/technique identifiers"
        )
    return frozenset(identifiers)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _mapping_set_paths(paths: Iterable[str | Path] | None) -> list[Path]:
    if paths is not None:
        return [Path(p) for p in paths]
    return sorted(_DEFAULT_MAPPING_SET_DIR.glob(_MAPPING_SET_GLOB))


def compute_mapping_set_digest(paths: Iterable[str | Path] | None = None) -> str:
    """Normalized content digest over the attack-pattern SSSOM mapping set.

    Rows are NFC-normalized and framed as a sorted set keyed by canonical
    JSON, so the digest is independent of file layout and row order but
    sensitive to any row addition, removal, or content edit.  Defaults to
    the bundled ``attack-patterns*.sssom.tsv`` files.
    """
    rows = {
        _canonical_json(
            {
                field: unicodedata.normalize("NFC", getattr(mapping, field))
                for field in _MAPPING_ROW_FIELDS
            }
        )
        for path in _mapping_set_paths(paths)
        for mapping in load_sssom(path)
    }
    payload = (
        _MAPPING_SET_DOMAIN.encode()
        + b"\0"
        + _canonical_json(sorted(rows)).encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def _checked_identifiers(identifiers: Iterable[str], *, label: str) -> frozenset[str]:
    values = frozenset(identifiers)
    if not values:
        raise ValueError(f"{label} identifier membership must not be empty")
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{label} identifiers must be non-empty strings")
    return values


class PinnedTaxonomyResolver:
    """No-I/O taxonomy resolver over pinned membership snapshots.

    ATLAS membership and pins come from the bundled pinned source.  An
    ATLAS-only resolver carries no LAAF pin, so ``taxonomy_context``
    equality fails closed against any chain that pins LAAF.  Explicit LAAF
    support requires the caller to supply both the authoritative pin and
    its identifier membership; exact LAAF ids outside that membership fail
    qualification.
    """

    def __init__(
        self,
        *,
        atlas_pin: TaxonomyPin,
        atlas_identifiers: Iterable[str],
        mapping_set_digest: str,
        laaf_pin: TaxonomyPin | None = None,
        laaf_identifiers: Iterable[str] | None = None,
    ) -> None:
        if (laaf_pin is None) != (laaf_identifiers is None):
            raise ValueError(
                "an explicit LAAF pin and its identifier membership must be "
                "supplied together"
            )
        self._atlas_identifiers = _checked_identifiers(atlas_identifiers, label="ATLAS")
        self._laaf_identifiers = (
            _checked_identifiers(laaf_identifiers, label="LAAF")
            if laaf_identifiers is not None
            else frozenset()
        )
        self._taxonomy_context = TaxonomyContext(
            atlas=atlas_pin,
            laaf=laaf_pin,
            mapping_set_digest=mapping_set_digest,
        )

    @property
    def taxonomy_context(self) -> TaxonomyContext:
        return self._taxonomy_context

    def contains(self, taxonomy: Literal["ATLAS", "LAAF"], identifier: str) -> bool:
        if taxonomy == "ATLAS":
            return identifier in self._atlas_identifiers
        return identifier in self._laaf_identifiers


def load_taxonomy_resolver(
    *,
    atlas_path: str | Path | None = None,
    mapping_set_paths: Iterable[str | Path] | None = None,
    laaf_pin: TaxonomyPin | None = None,
    laaf_identifiers: Iterable[str] | None = None,
) -> PinnedTaxonomyResolver:
    """Construct the production resolver from the pinned bundled sources.

    Performs all I/O up front; the returned resolver is purely in-memory.
    The default is ATLAS-only.  LAAF authority is never bundled: callers
    with a future authoritative LAAF release must explicitly supply both
    its pin and its identifier membership.
    """
    return PinnedTaxonomyResolver(
        atlas_pin=load_atlas_pin(atlas_path),
        atlas_identifiers=load_atlas_identifiers(atlas_path),
        mapping_set_digest=compute_mapping_set_digest(mapping_set_paths),
        laaf_pin=laaf_pin,
        laaf_identifiers=laaf_identifiers,
    )
