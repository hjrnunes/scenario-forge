"""Taxonomy grounding metrics for scenario evaluation.

Validates that threat_ids in attack tree nodes reference valid entries
in the bundled OWASP Agentic Threats data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


# Default path to bundled OWASP agentic threats data
_DEFAULT_THREATS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


def _load_valid_threat_ids(threats_path: Path | None = None) -> set[str]:
    """Load the set of valid threat IDs from the OWASP agentic threats file."""
    path = threats_path or _DEFAULT_THREATS_PATH
    if not path.exists():
        return set()
    with open(path) as f:
        data = yaml.safe_load(f)
    threats = data.get("threats", {})
    return set(threats.keys())


def _collect_tree_threat_ids(node: dict[str, Any]) -> list[str]:
    """Recursively collect all threat_id values from attack tree nodes."""
    ids: list[str] = []
    tid = node.get("threat_id")
    if tid:
        ids.append(tid)
    for child in node.get("children") or []:
        ids.extend(_collect_tree_threat_ids(child))
    return ids


def score_grounding(
    scenarios: list[dict[str, Any]],
    threats_path: Path | None = None,
) -> dict[str, Any]:
    """Compute taxonomy grounding metrics across a batch of scenarios.

    Checks:
    - threat_id validity: fraction of threat_ids that map to known OWASP threats
    - dangling reference count: number of invalid threat_ids

    Args:
        scenarios: List of scenario dicts (parsed YAML).
        threats_path: Optional path to the OWASP agentic threats file.

    Returns:
        Dict with threat_id_validity (float 0-1), dangling_references (int),
        and details about any invalid references.
    """
    valid_ids = _load_valid_threat_ids(threats_path)

    total_refs = 0
    valid_refs = 0
    dangling: list[dict[str, str]] = []

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "unknown")
        tree = scenario.get("attack_tree", {})
        root = tree.get("root", {})
        threat_ids = _collect_tree_threat_ids(root)

        for tid in threat_ids:
            total_refs += 1
            if tid in valid_ids:
                valid_refs += 1
            else:
                dangling.append({
                    "scenario_id": scenario_id,
                    "threat_id": tid,
                })

    validity = valid_refs / total_refs if total_refs > 0 else 1.0

    result: dict[str, Any] = {
        "threat_id_validity": round(validity, 4),
        "dangling_references": len(dangling),
    }
    if dangling:
        result["dangling_details"] = dangling

    return result
