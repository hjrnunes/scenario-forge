"""Taxonomy data loaders for scenario-forge.

Loads each taxonomy data file into typed structures for use in the
scenario generation pipeline.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from scenario_forge.models import EvidenceSpan, MitigationRef, RiskCard


def load_agentic_threats(path: str | Path) -> dict[str, Any]:
    """Load OWASP Agentic Threats YAML and return threats keyed by ID.

    Args:
        path: Path to owasp-agentic-threats-v1.1.yaml

    Returns:
        Dict mapping threat IDs (e.g. "T2") to their full threat dicts.
    """
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["threats"]


def load_atlas_techniques(path: str | Path) -> dict[str, Any]:
    """Load MITRE ATLAS YAML and return techniques keyed by ID.

    Args:
        path: Path to ATLAS-2026.05.yaml

    Returns:
        Dict mapping technique IDs (e.g. "AML.T0000") to their full dicts.
    """
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["techniques"]


def load_cross_taxonomy_mappings(path: str | Path) -> dict[str, Any]:
    """Load cross-taxonomy-mappings.yaml.

    Args:
        path: Path to cross-taxonomy-mappings.yaml

    Returns:
        The full parsed YAML as a dict.
    """
    with open(path) as f:
        return yaml.safe_load(f)


def _parse_evidence(raw: dict) -> EvidenceSpan:
    """Convert a policy-mapper evidence dict to an EvidenceSpan.

    The policy-mapper format uses 'document' and 'cross_encoder_score'
    while our model uses 'source' and 'relevance'.
    """
    return EvidenceSpan(
        text=raw["text"],
        source=raw.get("document"),
        relevance=raw.get("cross_encoder_score"),
    )


def _parse_mitigation(raw: dict) -> MitigationRef:
    """Convert a policy-mapper mitigation dict to a MitigationRef.

    The policy-mapper format uses 'action_id'/'action_name'/'description'
    while our model uses 'mitigation_id'/'description'.
    """
    return MitigationRef(
        mitigation_id=raw.get("action_id"),
        description=raw.get("description", raw.get("action_name", "")),
        source=raw.get("source"),
    )


def load_risk_extraction(path: str | Path) -> list[RiskCard]:
    """Load a policy-mapper risk-extraction.json, filtering to IBM Risk Atlas.

    Reads the JSON file, filters to entries with taxonomy == "ibm-risk-atlas",
    and returns them as a list of RiskCard Pydantic models.

    Args:
        path: Path to a risk-extraction.json file.

    Returns:
        List of RiskCard instances for ibm-risk-atlas entries only.
    """
    with open(path) as f:
        data = json.load(f)

    risks_raw = data.get("risks", data) if isinstance(data, dict) else data

    cards: list[RiskCard] = []
    for r in risks_raw:
        if r.get("taxonomy") != "ibm-risk-atlas":
            continue

        evidence = [_parse_evidence(e) for e in r.get("evidence", [])]
        mitigations = [_parse_mitigation(m) for m in r.get("mitigations", [])]

        card = RiskCard(
            risk_id=r["risk_id"],
            risk_name=r["risk_name"],
            risk_description=r["risk_description"],
            taxonomy=r["taxonomy"],
            confidence=r["confidence"],
            grounding_confidence=r["grounding_confidence"],
            evidence=evidence,
            scores=r.get("scores"),
            mitigations=mitigations,
            threat=r.get("threat"),
            threat_source=r.get("threat_source"),
            vulnerability=r.get("vulnerability"),
            consequence=r.get("consequence"),
            impact=r.get("impact"),
        )
        cards.append(card)

    return cards


_DEFAULT_ATTACK_PATTERNS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "attack-patterns"
    / "attack-patterns.yaml"
)


def load_attack_patterns(
    path: str | Path | None = None,
) -> dict[str, dict]:
    """Load abstract attack patterns YAML, keyed by pattern ID.

    Returns:
        Dict mapping pattern IDs (e.g. 'AP-T7-01') to their full pattern dicts.
    """
    p = Path(path) if path else _DEFAULT_ATTACK_PATTERNS_PATH
    with open(p) as f:
        data = yaml.safe_load(f)
    return dict(data.get("patterns", {}))


def build_threat_to_patterns_index(
    patterns: dict[str, dict],
) -> dict[str, list[str]]:
    """Build threat_id -> list of pattern IDs index."""
    index: dict[str, list[str]] = defaultdict(list)
    for pid, pattern in patterns.items():
        index[pattern["threat_id"]].append(pid)
    return dict(index)
