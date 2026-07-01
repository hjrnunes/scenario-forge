"""Stage 3: Deterministic Scenario Seed Expansion.

Enumerates all sub-scenarios from the in-scope threat surface entries,
producing one ScenarioSeed per sub-scenario with full provenance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from scenario_forge.data.loaders import load_agentic_threats, load_attack_patterns
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.threats import ThreatSurface

_DEFAULT_THREATS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


class ScenarioSeed(BaseModel):
    seed_id: str = Field(description="Sub-scenario ID, e.g. 'T2-S1'.")
    threat_id: str = Field(description="Parent threat ID, e.g. 'T2'.")
    threat_name: str
    mechanism_name: str
    mechanism_description: str
    owasp_sub_scenario_ref: str | None = None
    risk_card_ref: RiskCardRef
    contributing_risk_cards: list[RiskCardRef] = Field(
        default_factory=list,
        description="All risk cards that contributed to this seed (including the primary).",
    )
    owasp_llm_ids: list[str]
    agentic_threat_ids: list[str]
    atlas_technique_ids: list[str] = Field(default_factory=list)


def _build_sub_scenario_lookup(
    threats: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build a flat lookup from sub-scenario ID to its metadata + parent threat."""
    lookup: dict[str, dict[str, Any]] = {}
    for threat_id, threat in threats.items():
        for scenario in threat.get("scenarios", []):
            lookup[scenario["id"]] = {
                "name": scenario["name"],
                "description": scenario["description"].strip(),
                "threat_id": threat_id,
                "threat_name": threat["name"],
            }
    return lookup


def expand_seeds(
    threat_surface: ThreatSurface,
    threats_path: str | Path | None = None,
    attack_patterns_path: str | Path | None = None,
) -> list[ScenarioSeed]:
    """Expand threat surface entries into individual scenario seeds.

    Args:
        threat_surface: Output from Stage 2.
        threats_path: Optional path to OWASP agentic threats YAML.
        attack_patterns_path: Optional path to abstract attack patterns YAML.

    Returns:
        List of ScenarioSeed, one per in-scope sub-scenario.
    """
    path = Path(threats_path) if threats_path else _DEFAULT_THREATS_PATH
    threats = load_agentic_threats(path)
    sub_lookup = _build_sub_scenario_lookup(threats)

    # Load abstract attack patterns (if available)
    patterns = load_attack_patterns(attack_patterns_path)
    # Build reverse lookup: owasp_sub_scenario_id -> pattern
    owasp_to_pattern: dict[str, dict] = {}
    for pid, pat in patterns.items():
        ref = pat.get("example_reference", {})
        owasp_id = ref.get("owasp_id")
        if owasp_id:
            owasp_to_pattern[owasp_id] = pat

    seen: dict[str, ScenarioSeed] = {}

    for entry in threat_surface.entries:
        if entry.governance_only:
            continue

        for sub_id in entry.sub_scenarios:
            sub = sub_lookup.get(sub_id)
            if sub is None:
                continue

            # Check if an abstract pattern exists for this sub-scenario
            pattern = owasp_to_pattern.get(sub_id)
            if pattern:
                effective_id = pattern["id"]
                mechanism_name = pattern["name"]
                mechanism_desc = pattern["description"].strip()
                owasp_ref = sub_id
            else:
                effective_id = sub_id
                mechanism_name = sub["name"]
                mechanism_desc = sub["description"]
                owasp_ref = None

            if effective_id in seen:
                # Merge: union taxonomy IDs, collect contributing risk cards
                existing = seen[effective_id]
                merged_owasp = list(
                    dict.fromkeys(existing.owasp_llm_ids + entry.owasp_llm_ids)
                )
                merged_agentic = list(
                    dict.fromkeys(
                        existing.agentic_threat_ids + entry.agentic_threat_ids
                    )
                )
                merged_atlas = list(
                    dict.fromkeys(
                        existing.atlas_technique_ids + entry.atlas_technique_ids
                    )
                )
                # Add the new risk card to contributing list (dedup by risk_id)
                known_ids = {r.risk_id for r in existing.contributing_risk_cards}
                new_contribs = list(existing.contributing_risk_cards)
                if entry.risk_card.risk_id not in known_ids:
                    new_contribs.append(entry.risk_card)

                seen[effective_id] = existing.model_copy(
                    update={
                        "owasp_llm_ids": merged_owasp,
                        "agentic_threat_ids": merged_agentic,
                        "atlas_technique_ids": merged_atlas,
                        "contributing_risk_cards": new_contribs,
                    }
                )
            else:
                seen[effective_id] = ScenarioSeed(
                    seed_id=effective_id,
                    threat_id=sub["threat_id"],
                    threat_name=sub["threat_name"],
                    mechanism_name=mechanism_name,
                    mechanism_description=mechanism_desc,
                    owasp_sub_scenario_ref=owasp_ref,
                    risk_card_ref=entry.risk_card,
                    contributing_risk_cards=[entry.risk_card],
                    owasp_llm_ids=entry.owasp_llm_ids,
                    agentic_threat_ids=entry.agentic_threat_ids,
                    atlas_technique_ids=entry.atlas_technique_ids,
                )

    return list(seen.values())
