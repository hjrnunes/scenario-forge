"""Stage 2: Deterministic Threat Surface Determination.

Three-hop taxonomy chain with no LLM calls:
  Hop 1  Risk Atlas ID  -> OWASP LLM Top 10 IDs  (via SSSOM)
  Hop 2  LLM Top 10 IDs -> OWASP Agentic Threat IDs (via cross-taxonomy, reversed)
  Hop 3  Filter by capability profile (via threat_gating)
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from scenario_forge.data.loaders import load_cross_taxonomy_mappings
from scenario_forge.data.sssom import build_risk_to_llm_index, load_sssom
from scenario_forge.data.threat_gating import determine_threat_scope
from scenario_forge.models import CapabilityProfile, RiskCard
from scenario_forge.models.scenario import RiskCardRef


class ThreatSurfaceEntry(BaseModel):
    risk_card: RiskCardRef
    owasp_llm_ids: list[str]
    agentic_threat_ids: list[str]
    atlas_technique_ids: list[str] = Field(default_factory=list)
    sub_scenarios: list[str]
    governance_only: bool = False


class ThreatSurface(BaseModel):
    entries: list[ThreatSurfaceEntry]
    governance_only: list[ThreatSurfaceEntry]


def _build_llm_to_t_index(cross_taxonomy: dict[str, Any]) -> dict[str, list[str]]:
    """Reverse the t_to_llm section to get LLM ID -> list of T-threat IDs."""
    index: dict[str, list[str]] = defaultdict(list)
    for mapping in cross_taxonomy.get("t_to_llm", []):
        t_id = mapping["source"]
        llm_id = mapping["target"]
        if llm_id not in index or t_id not in index[llm_id]:
            index[llm_id].append(t_id)
    return dict(index)


def _make_risk_card_ref(card: RiskCard) -> RiskCardRef:
    kwargs: dict[str, Any] = dict(
        risk_id=card.risk_id,
        risk_name=card.risk_name,
        risk_description=card.risk_description,
        taxonomy=card.taxonomy,
        confidence=card.confidence,
        grounding_confidence=card.grounding_confidence,
    )
    # Populate causal chain fields from the RiskCard when available
    for field in ("threat", "threat_source", "vulnerability", "consequence", "impact"):
        value = getattr(card, field, None)
        if value is not None:
            kwargs[field] = value
    return RiskCardRef(**kwargs)


def determine_threat_surface(
    profile: CapabilityProfile,
    risk_cards: list[RiskCard],
    sssom_path: str | Path,
    cross_taxonomy_path: str | Path,
    threats_path: str | Path | None = None,
) -> ThreatSurface:
    """Walk the three-hop taxonomy chain to build the threat surface.

    Args:
        profile: System capability profile from Stage 1.
        risk_cards: Risk cards from policy-mapper extraction.
        sssom_path: Path to the SSSOM TSV mapping file.
        cross_taxonomy_path: Path to cross-taxonomy-mappings.yaml.
        threats_path: Optional path to OWASP agentic threats YAML.

    Returns:
        ThreatSurface with actionable entries and governance-only entries.
    """
    # --- Hop 1: Risk Atlas ID -> LLM Top 10 IDs ---
    sssom_mappings = load_sssom(sssom_path)
    risk_to_llm = build_risk_to_llm_index(sssom_mappings)

    # --- Hop 2: LLM Top 10 IDs -> Agentic Threat IDs (reversed t_to_llm) ---
    cross_taxonomy = load_cross_taxonomy_mappings(cross_taxonomy_path)
    llm_to_t = _build_llm_to_t_index(cross_taxonomy)

    # --- Hop 3: Filter by capability profile ---
    threat_scope = determine_threat_scope(profile, threats_path)
    in_scope_ids = {e.threat_id for e in threat_scope.in_scope}
    # Build threat_id -> applicable sub-scenario IDs
    threat_sub_scenarios: dict[str, list[str]] = {
        e.threat_id: e.applicable_sub_scenarios for e in threat_scope.in_scope
    }

    entries: list[ThreatSurfaceEntry] = []
    governance_only: list[ThreatSurfaceEntry] = []

    for card in risk_cards:
        ref = _make_risk_card_ref(card)
        llm_ids = list(dict.fromkeys(risk_to_llm.get(card.risk_id, [])))

        if not llm_ids:
            governance_only.append(
                ThreatSurfaceEntry(
                    risk_card=ref,
                    owasp_llm_ids=[],
                    agentic_threat_ids=[],
                    sub_scenarios=[],
                    governance_only=True,
                )
            )
            continue

        # Collect all T-threats reachable from these LLM IDs
        all_t_ids: list[str] = []
        for llm_id in llm_ids:
            for t_id in llm_to_t.get(llm_id, []):
                if t_id not in all_t_ids:
                    all_t_ids.append(t_id)

        # Filter to in-scope threats only
        scoped_t_ids = [t for t in all_t_ids if t in in_scope_ids]

        if not scoped_t_ids:
            governance_only.append(
                ThreatSurfaceEntry(
                    risk_card=ref,
                    owasp_llm_ids=llm_ids,
                    agentic_threat_ids=[],
                    sub_scenarios=[],
                    governance_only=True,
                )
            )
            continue

        # Collect sub-scenarios from in-scope threats
        all_subs: list[str] = []
        for t_id in scoped_t_ids:
            for sub in threat_sub_scenarios.get(t_id, []):
                if sub not in all_subs:
                    all_subs.append(sub)

        entries.append(
            ThreatSurfaceEntry(
                risk_card=ref,
                owasp_llm_ids=llm_ids,
                agentic_threat_ids=scoped_t_ids,
                sub_scenarios=all_subs,
            )
        )

    return ThreatSurface(entries=entries, governance_only=governance_only)
