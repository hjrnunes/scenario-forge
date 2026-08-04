"""Report rendering coverage for cmps.6 actor access provenance.

Tests use schema-valid ``ScenarioEnvelope`` objects serialized via
``model_dump()`` to exercise the real report rendering path, not raw
dicts that bypass model validation.
"""

from __future__ import annotations

import pytest

from scenario_forge.models.capability_profile import compute_trust_boundary_id
from scenario_forge.models.scenario import ActorAccessProvenance
from scenario_forge.report.template import _build_actor_profile_block
from tests.test_actor_entry_point_validation import _make_envelope


def _envelope_with_access(access: ActorAccessProvenance):
    """Build a schema-valid ScenarioEnvelope carrying the given access."""
    return _make_envelope(
        entry_point_id=access.initial_entry_point_id,
        access=access,
    )


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
    """The actor profile block renders structured access provenance fields."""
    envelope = _envelope_with_access(access)
    scenario = envelope.model_dump()

    html = _build_actor_profile_block(scenario)

    assert "ACCESS PROVENANCE" in html
    assert access.ingress_mode in html
    assert access.access_class in html
    assert access.initial_entry_point_id in html
    for evidence in expected_evidence:
        assert evidence in html
