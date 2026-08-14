"""Property tests for output-direction ingress-zone normalization."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from scenario_forge.models.capability_profile import (
    ZONE_NAMES,
    EntryPoint,
    _effective_zone,
    _kept_zone,
    compute_entry_point_id,
    is_attacker_accessible_ingress,
)

st_name = st.text(min_size=1, max_size=24)
st_dir = st.sampled_from(("input", "output", "bidirectional"))
st_zone = st.none() | st.sampled_from(ZONE_NAMES)


@given(st_name, st_dir, st_zone)
@settings(max_examples=60, deadline=None)
def test_output_has_no_zone(name, direction, zone):
    ep = EntryPoint(name=name, direction=direction, ingress_zone=zone)
    assert ep.ingress_zone == _kept_zone(direction, zone)
    assert ep.effective_ingress_zone == _effective_zone(direction, zone)
    assert compute_entry_point_id(
        name, direction, None, zone
    ) == compute_entry_point_id(name, direction, None, ep.ingress_zone)
    if direction == "output":
        assert ep.ingress_zone is None
        assert ep.effective_ingress_zone is None
        assert not is_attacker_accessible_ingress(ep)
