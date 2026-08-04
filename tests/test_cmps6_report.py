"""Report rendering coverage for cmps.6 actor access provenance."""

from __future__ import annotations

import pytest

from scenario_forge.models.capability_profile import compute_trust_boundary_id
from scenario_forge.models.scenario import ActorAccessProvenance
from scenario_forge.report.template import _build_actor_profile_block


@pytest.mark.parametrize(
    ("access", "expected_evidence"),
    [
        (
            ActorAccessProvenance(
                initial_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ingress_mode="indirect",
                access_class="supply_chain",
                influence_source="ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                influence_mechanism="A compromised supplier submits documents",
                trust_boundary_id=compute_trust_boundary_id("memory", "input"),
            ),
            [
                "Influence source",
                "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "A compromised supplier submits documents",
                "Trust boundary ID",
                compute_trust_boundary_id("memory", "input"),
            ],
        ),
        (
            ActorAccessProvenance(
                initial_entry_point_id="ep:v1:cccccccccccccccccccccccccccccccc",
                ingress_mode="direct",
                access_class="privileged",
                material_insider_advantage="Can bypass normal approval controls",
            ),
            ["Material insider advantage", "Can bypass normal approval controls"],
        ),
    ],
)
def test_actor_profile_renders_access_provenance(
    access: ActorAccessProvenance, expected_evidence: list[str]
) -> None:
    scenario = {
        "actor_profile": {
            "actor_type": "malicious-insider",
            "capability_level": "advanced",
            "beliefs": [],
            "desires": [],
            "intentions": [],
            "resources": [],
            "access": access.model_dump(),
        }
    }

    html = _build_actor_profile_block(scenario)

    assert "ACCESS PROVENANCE" in html
    assert access.ingress_mode in html
    assert access.access_class in html
    assert access.initial_entry_point_id in html
    for evidence in expected_evidence:
        assert evidence in html
