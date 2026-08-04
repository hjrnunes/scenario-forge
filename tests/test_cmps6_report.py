"""Report rendering coverage for cmps.6 actor access provenance."""

from __future__ import annotations

import pytest

from scenario_forge.report.template import _build_actor_profile_block


@pytest.mark.parametrize(
    ("access", "expected_evidence"),
    [
        (
            {
                "ingress_mode": "indirect",
                "access_class": "third_party",
                "initial_entry_point_id": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "influence_source": "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "influence_mechanism": "A compromised supplier submits documents",
                "trust_boundary": "external->input",
            },
            [
                "Influence source",
                "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "A compromised supplier submits documents",
                "external-&gt;input",
            ],
        ),
        (
            {
                "ingress_mode": "direct",
                "access_class": "privileged",
                "initial_entry_point_id": "ep:v1:cccccccccccccccccccccccccccccccc",
                "material_insider_advantage": "Can bypass normal approval controls",
            },
            ["Material insider advantage", "Can bypass normal approval controls"],
        ),
    ],
)
def test_actor_profile_renders_access_provenance(
    access: dict[str, str], expected_evidence: list[str]
) -> None:
    scenario = {
        "actor_profile": {
            "actor_type": "malicious-insider",
            "capability_level": "advanced",
            "beliefs": [],
            "desires": [],
            "intentions": [],
            "resources": [],
            "access": access,
        }
    }

    html = _build_actor_profile_block(scenario)

    assert "ACCESS PROVENANCE" in html
    assert access["ingress_mode"] in html
    assert access["access_class"] in html
    assert access["initial_entry_point_id"] in html
    for evidence in expected_evidence:
        assert evidence in html
