"""Property-based tests for SP1 critic/revision invariants.

Covers five invariant families:

1. **Next-ID collision freedom**: ``_compute_next_ids`` never returns a
   number that collides with an existing ID of that kind.
2. **ID-space independence**: ``next_cm_num`` depends only on ``cm_id``
   values, and ``next_cl_num`` depends only on ``link_id`` values.
3. **has_unjustified_gaps iff**: ``has_unjustified_gaps`` is True iff at
   least one of the three probes (checklist, taxonomy, structural gaps)
   reports something unjustified.
4. **Dismissal visibility**: every ``dismissed_gaps`` entry surfaces in
   the returned warnings from ``run_revision``.
5. **Merge conservation**: when the RevisionDelta contains no
   modifications to existing elements, all existing resp_ids, cp_ids,
   and link_ids survive the merge.
"""

from __future__ import annotations

from hypothesis import HealthCheck, assume, given, settings, strategies as st

from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _compute_next_ids,
    has_unjustified_gaps,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# ControlStructure strategy
# ---------------------------------------------------------------------------

st_description = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=40,
)


def _make_resp(num: int) -> Responsibility:
    """Build a fully-populated responsibility RESP-{num}.

    Every responsibility has at least one PM, one CA, and one FB so
    that structural heuristics pass after revision merge.
    """
    resp_id = f"RESP-{num}"
    return Responsibility(
        resp_id=resp_id,
        description=f"Controller {num}",
        process_model_parts=[
            ProcessModelPart(pm_id=f"PM-{num}-1", description="State")
        ],
        control_actions=[
            ControlAction(ca_id=f"CA-{num}-1", description="Action")
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{num}-1",
                description="Feedback",
                updates=f"PM-{num}-1",
                source=ElementRef(
                    type=ReferenceType.responsibility, id=resp_id
                ),
            )
        ],
    )


def _make_cl(cl_num: int, cm_num: int, resp_a: int, resp_b: int) -> CoordinationLink:
    """Build a coordination link CL-{cl_num} with CM-{cm_num}."""
    return CoordinationLink(
        link_id=f"CL-{cl_num}",
        source=f"RESP-{resp_a}",
        target=f"RESP-{resp_b}",
        shared_pm=f"PM-{resp_a}-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id=f"CM-{cm_num}",
            description="Shared state",
            payload="sync",
        ),
        description="Coordination link",
    )


@st.composite
def st_control_structure(draw) -> ControlStructure:
    """Generate a valid ControlStructure with 1-5 responsibilities.

    Each responsibility is fully populated (PM, CA, FB). When there are
    2+ responsibilities, 0-3 coordination links are added with unique
    link_id and cm_id numbers.
    """
    n_resps = draw(st.integers(min_value=1, max_value=5))
    responsibilities = [_make_resp(i) for i in range(1, n_resps + 1)]

    coordination_links: list[CoordinationLink] = []
    if n_resps >= 2:
        n_links = draw(st.integers(min_value=0, max_value=3))
        cl_nums = draw(
            st.lists(
                st.integers(min_value=1, max_value=20),
                min_size=n_links,
                max_size=n_links,
                unique=True,
            )
        )
        cm_nums = draw(
            st.lists(
                st.integers(min_value=1, max_value=20),
                min_size=n_links,
                max_size=n_links,
                unique=True,
            )
        )
        for cl_num, cm_num in zip(cl_nums, cm_nums):
            coordination_links.append(
                _make_cl(cl_num, cm_num, resp_a=1, resp_b=2)
            )

    return ControlStructure(
        responsibilities=responsibilities,
        coordination_links=coordination_links,
    )


# ---------------------------------------------------------------------------
# 1. Next-ID collision freedom
# ---------------------------------------------------------------------------


class TestNextIdsCollisionFree:
    """_compute_next_ids never returns a number colliding with an existing ID."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_next_resp_num_above_all_existing(self, cs):
        """next_resp_num > max(existing resp_id numbers)."""
        ids = _compute_next_ids(cs)
        existing_resp_nums = {
            int(r.resp_id.split("-")[1]) for r in cs.responsibilities
        }
        assert ids["next_resp_num"] not in existing_resp_nums

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_next_cl_num_above_all_existing(self, cs):
        """next_cl_num > max(existing link_id numbers)."""
        ids = _compute_next_ids(cs)
        existing_cl_nums = {
            int(cl.link_id.split("-")[1]) for cl in cs.coordination_links
        }
        if existing_cl_nums:
            assert ids["next_cl_num"] not in existing_cl_nums
        else:
            assert ids["next_cl_num"] == 1

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_next_cm_num_above_all_existing(self, cs):
        """next_cm_num > max(existing cm_id numbers)."""
        ids = _compute_next_ids(cs)
        existing_cm_nums = {
            int(cl.coordination_mechanism.cm_id.split("-")[1])
            for cl in cs.coordination_links
        }
        if existing_cm_nums:
            assert ids["next_cm_num"] not in existing_cm_nums
        else:
            assert ids["next_cm_num"] == 1

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_next_cp_num_above_all_existing(self, cs):
        """next_cp_num > max(existing cp_id numbers)."""
        ids = _compute_next_ids(cs)
        existing_cp_nums = {
            int(cp.cp_id.split("-")[1]) for cp in cs.controlled_processes
        }
        if existing_cp_nums:
            assert ids["next_cp_num"] not in existing_cp_nums
        else:
            assert ids["next_cp_num"] == 1


# ---------------------------------------------------------------------------
# 2. ID-space independence: next_cm_num depends only on cm_ids,
#    next_cl_num depends only on link_ids
# ---------------------------------------------------------------------------


@st.composite
def st_two_cs_same_link_ids_diff_cm_ids(draw):
    """Two CSs with identical link_id numbers but different cm_id numbers."""
    n_resps = draw(st.integers(min_value=2, max_value=4))

    n_links = draw(st.integers(min_value=1, max_value=3))
    cl_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    cm_nums_a = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    cm_nums_b = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    # Ensure the two cm_id sets differ
    assume(set(cm_nums_a) != set(cm_nums_b))

    cs_a = ControlStructure(
        responsibilities=[_make_resp(i) for i in range(1, n_resps + 1)],
        coordination_links=[
            _make_cl(cl_num, cm_num, 1, 2)
            for cl_num, cm_num in zip(cl_nums, cm_nums_a)
        ],
    )
    cs_b = ControlStructure(
        responsibilities=[_make_resp(i) for i in range(1, n_resps + 1)],
        coordination_links=[
            _make_cl(cl_num, cm_num, 1, 2)
            for cl_num, cm_num in zip(cl_nums, cm_nums_b)
        ],
    )
    return cs_a, cs_b


@st.composite
def st_two_cs_same_cm_ids_diff_link_ids(draw):
    """Two CSs with identical cm_id numbers but different link_id numbers."""
    n_resps = draw(st.integers(min_value=2, max_value=4))

    n_links = draw(st.integers(min_value=1, max_value=3))
    cm_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    cl_nums_a = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    cl_nums_b = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    assume(set(cl_nums_a) != set(cl_nums_b))

    cs_a = ControlStructure(
        responsibilities=[_make_resp(i) for i in range(1, n_resps + 1)],
        coordination_links=[
            _make_cl(cl_num, cm_num, 1, 2)
            for cl_num, cm_num in zip(cl_nums_a, cm_nums)
        ],
    )
    cs_b = ControlStructure(
        responsibilities=[_make_resp(i) for i in range(1, n_resps + 1)],
        coordination_links=[
            _make_cl(cl_num, cm_num, 1, 2)
            for cl_num, cm_num in zip(cl_nums_b, cm_nums)
        ],
    )
    return cs_a, cs_b


class TestIdSpaceIndependence:
    """next_cm_num depends only on cm_ids; next_cl_num depends only on link_ids."""

    @given(pair=st_two_cs_same_link_ids_diff_cm_ids())
    @settings(max_examples=50, deadline=None)
    def test_next_cl_num_independent_of_cm_ids(self, pair):
        """Same link_ids, different cm_ids → next_cl_num is the same."""
        cs_a, cs_b = pair
        ids_a = _compute_next_ids(cs_a)
        ids_b = _compute_next_ids(cs_b)
        assert ids_a["next_cl_num"] == ids_b["next_cl_num"]

    @given(pair=st_two_cs_same_link_ids_diff_cm_ids())
    @settings(max_examples=50, deadline=None)
    def test_next_cm_num_differs_when_cm_ids_differ(self, pair):
        """Same link_ids, different cm_ids → next_cm_num may differ."""
        cs_a, cs_b = pair
        ids_a = _compute_next_ids(cs_a)
        ids_b = _compute_next_ids(cs_b)
        # When cm_id sets differ, next_cm_num is derived from cm_ids only.
        # It might coincidentally be the same if max+1 happens to match,
        # but next_cm_num must be determined solely by the cm_id values.
        expected_a = max(
            (int(cl.coordination_mechanism.cm_id.split("-")[1])
             for cl in cs_a.coordination_links),
            default=0,
        ) + 1
        expected_b = max(
            (int(cl.coordination_mechanism.cm_id.split("-")[1])
             for cl in cs_b.coordination_links),
            default=0,
        ) + 1
        assert ids_a["next_cm_num"] == expected_a
        assert ids_b["next_cm_num"] == expected_b

    @given(pair=st_two_cs_same_cm_ids_diff_link_ids())
    @settings(max_examples=50, deadline=None)
    def test_next_cm_num_independent_of_link_ids(self, pair):
        """Same cm_ids, different link_ids → next_cm_num is the same."""
        cs_a, cs_b = pair
        ids_a = _compute_next_ids(cs_a)
        ids_b = _compute_next_ids(cs_b)
        assert ids_a["next_cm_num"] == ids_b["next_cm_num"]

    @given(pair=st_two_cs_same_cm_ids_diff_link_ids())
    @settings(max_examples=50, deadline=None)
    def test_next_cl_num_differs_when_link_ids_differ(self, pair):
        """Same cm_ids, different link_ids → next_cl_num is determined by link_ids."""
        cs_a, cs_b = pair
        ids_a = _compute_next_ids(cs_a)
        ids_b = _compute_next_ids(cs_b)
        expected_a = max(
            (int(cl.link_id.split("-")[1]) for cl in cs_a.coordination_links),
            default=0,
        ) + 1
        expected_b = max(
            (int(cl.link_id.split("-")[1]) for cl in cs_b.coordination_links),
            default=0,
        ) + 1
        assert ids_a["next_cl_num"] == expected_a
        assert ids_b["next_cl_num"] == expected_b


# ---------------------------------------------------------------------------
# 3. has_unjustified_gaps iff at least one probe reports something unjustified
# ---------------------------------------------------------------------------

st_status = st.sampled_from(
    ["present", "absent_justified", "absent_unjustified"]
)
st_checklist_key = st.sampled_from(
    [
        "Input validation",
        "Authorization",
        "Action selection",
        "Outcome verification",
        "Context management",
        "Multi-agent coordination",
        "Human-in-the-loop",
    ]
)
st_taxonomy_key = st.sampled_from(
    [
        "RAG retrieval integrity",
        "Tool parameter validation",
        "Memory integrity",
        "Multi-agent coordination",
        "Human-in-the-loop escalation",
    ]
)


@st.composite
def st_critic_findings(draw) -> CriticFindings:
    """Generate CriticFindings with random combinations of the three probes."""
    n_checklist = draw(st.integers(min_value=0, max_value=4))
    checklist_keys = draw(
        st.lists(st_checklist_key, min_size=n_checklist, max_size=n_checklist, unique=True)
    )
    checklist_results = {
        key: draw(st_status) for key in checklist_keys
    }

    n_taxonomy = draw(st.integers(min_value=0, max_value=3))
    taxonomy_keys = draw(
        st.lists(st_taxonomy_key, min_size=n_taxonomy, max_size=n_taxonomy, unique=True)
    )
    taxonomy_results = {
        key: draw(st_status) for key in taxonomy_keys
    }

    n_gaps = draw(st.integers(min_value=0, max_value=3))
    gaps = [
        CriticGap(
            gap_type=draw(st.sampled_from(
                ["missing_responsibility", "missing_feedback", "missing_pm_part"]
            )),
            description=f"Gap {i}",
            related_attack_path=f"Attack {i}",
            suggested_remedy=f"Fix {i}",
        )
        for i in range(n_gaps)
    ]

    return CriticFindings(
        gaps=gaps,
        checklist_results=checklist_results,
        taxonomy_probe_results=taxonomy_results,
    )


class TestHasUnjustifiedGapsIff:
    """has_unjustified_gaps is True iff at least one probe is unjustified."""

    @given(findings=st_critic_findings())
    @settings(max_examples=100, deadline=None)
    def test_iff_at_least_one_unjustified(self, findings):
        """has_unjustified_gaps == (structural gaps OR unjustified checklist OR unjustified taxonomy)."""
        has_structural = len(findings.gaps) > 0
        has_checklist_unjustified = any(
            s == "absent_unjustified"
            for s in findings.checklist_results.values()
        )
        has_taxonomy_unjustified = any(
            s == "absent_unjustified"
            for s in findings.taxonomy_probe_results.values()
        )
        expected = (
            has_structural or has_checklist_unjustified or has_taxonomy_unjustified
        )
        assert has_unjustified_gaps(findings) == expected

    @given(findings=st_critic_findings())
    @settings(max_examples=100, deadline=None)
    def test_all_justified_means_false(self, findings):
        """When all probes are justified/present and no gaps, result is False."""
        # Force all statuses to non-unjustified and no gaps
        clean = CriticFindings(
            gaps=[],
            checklist_results={
                k: v if v != "absent_unjustified" else "absent_justified"
                for k, v in findings.checklist_results.items()
            },
            taxonomy_probe_results={
                k: v if v != "absent_unjustified" else "absent_justified"
                for k, v in findings.taxonomy_probe_results.items()
            },
        )
        assert has_unjustified_gaps(clean) is False

    @given(
        checklist=st.dictionaries(st_checklist_key, st_status, min_size=1, max_size=3),
        taxonomy=st.dictionaries(st_taxonomy_key, st_status, min_size=0, max_size=2),
    )
    @settings(max_examples=80, deadline=None)
    def test_only_checklist_unjustified_triggers(self, checklist, taxonomy):
        """A single absent_unjustified in checklist triggers revision (no gaps, clean taxonomy)."""
        clean_taxonomy = {
            k: v if v != "absent_unjustified" else "present"
            for k, v in taxonomy.items()
        }
        findings = CriticFindings(
            gaps=[],
            checklist_results=checklist,
            taxonomy_probe_results=clean_taxonomy,
        )
        expected = any(v == "absent_unjustified" for v in checklist.values())
        assert has_unjustified_gaps(findings) == expected


# ---------------------------------------------------------------------------
# 4. Dismissal visibility: every dismissed_gaps entry appears in warnings
# ---------------------------------------------------------------------------

st_dismissal_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=60,
)


def _make_base_cs() -> ControlStructure:
    """Build a minimal valid CS for revision tests."""
    return ControlStructure(
        responsibilities=[_make_resp(1), _make_resp(2)],
        coordination_links=[_make_cl(1, 1, 1, 2)],
    )


def _make_critic_findings_for_revision() -> CriticFindings:
    """Findings that trigger revision (at least one unjustified gap)."""
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing input validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            ),
        ],
        checklist_results={"Input validation": "absent_unjustified"},
        taxonomy_probe_results={},
    )


class TestDismissalVisibility:
    """Every dismissed_gaps entry surfaces in run_revision warnings."""

    @given(
        dismissals=st.lists(
            st_dismissal_text, min_size=0, max_size=5, unique=True
        )
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_each_dismissal_in_warnings(self, tmp_path, dismissals):
        """Each dismissal string appears in the returned warnings."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": dismissals,
            },
        )
        _, warnings = run_revision(
            llm_client=client,
            control_structure=_make_base_cs(),
            critic_findings=_make_critic_findings_for_revision(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        warning_text = " ".join(warnings)
        for d in dismissals:
            assert d in warning_text, (
                f"Dismissal '{d}' not found in warnings: {warnings}"
            )

    @given(
        dismissals=st.lists(
            st_dismissal_text, min_size=1, max_size=5, unique=True
        )
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_dismissal_warning_count_matches(self, tmp_path, dismissals):
        """The number of dismissal warnings equals len(dismissed_gaps)."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": dismissals,
            },
        )
        _, warnings = run_revision(
            llm_client=client,
            control_structure=_make_base_cs(),
            critic_findings=_make_critic_findings_for_revision(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        dismissal_warnings = [
            w for w in warnings if w.startswith("Revision dismissed finding:")
        ]
        assert len(dismissal_warnings) == len(dismissals)

    def test_empty_dismissals_produce_no_dismissal_warnings(self, tmp_path):
        """When dismissed_gaps is empty, no dismissal warnings appear."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": [],
            },
        )
        _, warnings = run_revision(
            llm_client=client,
            control_structure=_make_base_cs(),
            critic_findings=_make_critic_findings_for_revision(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        dismissal_warnings = [
            w for w in warnings if w.startswith("Revision dismissed finding:")
        ]
        assert len(dismissal_warnings) == 0


# ---------------------------------------------------------------------------
# 5. Merge conservation: existing elements survive when delta has no mods
# ---------------------------------------------------------------------------


@st.composite
def st_cs_with_links(draw) -> ControlStructure:
    """Generate a CS with 2-5 responsibilities and 0-3 coordination links."""
    n_resps = draw(st.integers(min_value=2, max_value=5))
    responsibilities = [_make_resp(i) for i in range(1, n_resps + 1)]

    n_links = draw(st.integers(min_value=0, max_value=3))
    cl_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links, max_size=n_links, unique=True,
        )
    )
    cm_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links, max_size=n_links, unique=True,
        )
    )
    coordination_links = [
        _make_cl(cl_num, cm_num, 1, 2)
        for cl_num, cm_num in zip(cl_nums, cm_nums)
    ]
    return ControlStructure(
        responsibilities=responsibilities,
        coordination_links=coordination_links,
    )


class TestMergeConservation:
    """When the delta has no modifications, all existing elements survive."""

    @given(cs=st_cs_with_links())
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_all_resp_ids_survive(self, tmp_path, cs):
        """Every original resp_id is present after an empty-delta revision."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": [],
            },
        )
        revised, _ = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=_make_critic_findings_for_revision(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        original_resp_ids = {r.resp_id for r in cs.responsibilities}
        revised_resp_ids = {r.resp_id for r in revised.responsibilities}
        assert original_resp_ids <= revised_resp_ids

    @given(cs=st_cs_with_links())
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_all_link_ids_survive(self, tmp_path, cs):
        """Every original link_id is present after an empty-delta revision."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": [],
            },
        )
        revised, _ = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=_make_critic_findings_for_revision(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        original_link_ids = {cl.link_id for cl in cs.coordination_links}
        revised_link_ids = {cl.link_id for cl in revised.coordination_links}
        assert original_link_ids <= revised_link_ids

    @given(cs=st_cs_with_links())
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_resp_count_unchanged_with_empty_delta(self, tmp_path, cs):
        """Empty delta does not add or remove responsibilities."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": [],
            },
        )
        revised, _ = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=_make_critic_findings_for_revision(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert len(revised.responsibilities) == len(cs.responsibilities)
