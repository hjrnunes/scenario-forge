"""Tests for RevisionDelta pattern — RevisionDelta-01 through RevisionDelta-14.

The revision step now uses a RevisionDelta schema (only new/modified elements)
instead of full ControlStructure restate. The delta is merged programmatically
into the existing ControlStructure. The user prompt has a numbered per-finding
checklist, and the system prompt has ID format rules with next-available-ID
template variables.
"""

from __future__ import annotations


import pytest

from scenario_forge.stpa.infra.templates import TemplateLoader
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
    ResponsibilityConstraint,
)
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _compute_next_ids,
    _extract_num,
    _is_responsibility_empty,
    _next_num_from,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_control_structure() -> ControlStructure:
    """Build a control structure with RESP-1 and RESP-2."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action 1")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State 2")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-2-1", description="Action 2")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="FB 2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-2-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Shared state",
                    payload="Payload",
                ),
                description="Coordination link",
            )
        ],
    )


def _make_critic_findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing input validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            ),
            CriticGap(
                gap_type="missing_feedback",
                description="Missing outcome feedback",
                related_attack_path="Attacker exploits unchecked output",
                suggested_remedy="Add outcome verification feedback",
            ),
        ],
        checklist_results={
            "Outcome verification": "absent_unjustified",
        },
        taxonomy_probe_results={},
    )


def _make_new_resp_3() -> Responsibility:
    return Responsibility(
        resp_id="RESP-3",
        description="Input validation controller",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-3-1", description="Input state")
        ],
        control_actions=[
            ControlAction(ca_id="CA-3-1", description="Validate input")
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-3-1",
                description="Validation result",
                updates="PM-3-1",
                source=ElementRef(type=ReferenceType.responsibility, id="RESP-3"),
            )
        ],
    )


def _make_revision_delta_dict(
    *,
    new_responsibilities: list | None = None,
    modified_responsibilities: list | None = None,
    new_controlled_processes: list | None = None,
    new_coordination_links: list | None = None,
) -> dict:
    delta: dict = {
        "new_responsibilities": new_responsibilities or [],
        "new_controlled_processes": new_controlled_processes or [],
        "new_coordination_links": new_coordination_links or [],
        "modified_responsibilities": modified_responsibilities or [],
    }
    return delta


def _load_template_text(name: str) -> str:
    path = PROMPTS_DIR / name
    return path.read_text(encoding="utf-8")


def _render_template(name: str, **kwargs) -> str:
    loader = TemplateLoader(PROMPTS_DIR)
    return loader.render_prompt(name, **kwargs)


# ---------------------------------------------------------------------------
# RevisionDelta-01: schema contains only delta fields
# ---------------------------------------------------------------------------


class TestRevisionDelta01Schema:
    """RevisionDelta-01: RevisionDelta schema contains only delta fields."""

    def test_model_has_delta_fields(self):
        fields = RevisionDelta.model_fields
        assert "new_responsibilities" in fields
        assert "new_controlled_processes" in fields
        assert "new_coordination_links" in fields
        assert "modified_responsibilities" in fields

    def test_model_does_not_have_full_structure_field(self):
        fields = RevisionDelta.model_fields
        assert "responsibilities" not in fields
        assert "controlled_processes" not in fields
        assert "coordination_links" not in fields


# ---------------------------------------------------------------------------
# RevisionDelta-02: run_revision produces RevisionDelta from LLM
# ---------------------------------------------------------------------------


class TestRevisionDelta02UsesRevisionDelta:
    """RevisionDelta-02: run_revision uses RevisionDelta as response format."""

    def test_revision_uses_revision_delta_format(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-3",
                    "description": "Input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        # The LLM call used RevisionDelta as response_format
        assert client.calls[0].response_format == RevisionDelta
        # A revised ControlStructure was produced
        assert isinstance(cs, ControlStructure)


# ---------------------------------------------------------------------------
# RevisionDelta-03: new_responsibilities are merged
# ---------------------------------------------------------------------------


class TestRevisionDelta03MergeNewResponsibilities:
    """RevisionDelta-03: new_responsibilities are merged into existing CS."""

    def test_new_resp_merged(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-3",
                    "description": "Input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids
        assert "RESP-3" in resp_ids


# ---------------------------------------------------------------------------
# RevisionDelta-04: modified_responsibilities replace by resp_id
# ---------------------------------------------------------------------------


class TestRevisionDelta04ModifiedReplace:
    """RevisionDelta-04: modified_responsibilities replace existing ones by resp_id."""

    def test_modified_resp_replaces_existing(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            modified_responsibilities=[
                {
                    "resp_id": "RESP-1",
                    "description": "Updated controller description",
                    "process_model_parts": [
                        {"pm_id": "PM-1-1", "description": "Updated state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-1-1", "description": "Updated action"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-1-1",
                            "description": "Updated FB",
                            "updates": "PM-1-1",
                            "source": {"type": "responsibility", "id": "RESP-1"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp1 = next(r for r in cs.responsibilities if r.resp_id == "RESP-1")
        assert resp1.description == "Updated controller description"
        # RESP-2 should be unchanged
        resp2 = next(r for r in cs.responsibilities if r.resp_id == "RESP-2")
        assert resp2.description == "Controller 2"


# ---------------------------------------------------------------------------
# RevisionDelta-05: new_controlled_processes are merged
# ---------------------------------------------------------------------------


class TestRevisionDelta05MergeNewCps:
    """RevisionDelta-05: new_controlled_processes are merged into CS."""

    def test_new_cp_merged(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_controlled_processes=[
                {"cp_id": "CP-2", "description": "New process"}
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-2" in cp_ids


# ---------------------------------------------------------------------------
# RevisionDelta-06: new_coordination_links are added
# ---------------------------------------------------------------------------


class TestRevisionDelta06MergeNewCoordLinks:
    """RevisionDelta-06: new_coordination_links are added to CS."""

    def test_new_cl_added(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_coordination_links=[
                {
                    "link_id": "CL-2",
                    "source": "RESP-1",
                    "target": "RESP-2",
                    "shared_pm": "PM-1-1",
                    "coordination_mechanism": {
                        "cm_id": "CM-2",
                        "description": "New mechanism",
                        "payload": "Payload 2",
                    },
                    "description": "New coordination link",
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        cl_ids = {cl.link_id for cl in cs.coordination_links}
        assert "CL-2" in cl_ids


# ---------------------------------------------------------------------------
# RevisionDelta-07: revision_user.j2 contains numbered per-finding checklist
# ---------------------------------------------------------------------------


class TestRevisionDelta07UserPromptChecklist:
    """RevisionDelta-07: revision_user.j2 contains numbered per-finding checklist."""

    def test_template_contains_checklist_directive(self):
        text = _load_template_text("revision_user.j2")
        assert "You MUST add at least one element for EACH finding" in text

    def test_template_contains_numbered_list_format(self):
        text = _load_template_text("revision_user.j2")
        # The template should have a for loop with gap_type and suggested_remedy
        assert "gap_type" in text
        assert "suggested_remedy" in text
        assert "loop.index" in text or "{{ loop.index }}" in text


# ---------------------------------------------------------------------------
# RevisionDelta-08: revision_system.j2 contains ID format rules
# ---------------------------------------------------------------------------


class TestRevisionDelta08SystemPromptIdRules:
    """RevisionDelta-08: revision_system.j2 contains ID format rules with next-available numbers."""

    def test_template_contains_id_format_rules(self):
        text = _load_template_text("revision_system.j2")
        assert "ID format rules" in text

    @pytest.mark.parametrize(
        "element_kind, id_format",
        [
            ("New responsibilities", "RESP-{next_resp_num}"),
            ("New PM parts", "PM-{resp_num}-{next_pm_num}"),
            ("New CAs", "CA-{resp_num}-{next_ca_num}"),
            ("New FB channels", "FB-{resp_num}-{next_fb_num}"),
            ("New RCs", "RC-{resp_num}-{next_rc_num}"),
            ("New coordination links", "CL-{next_cl_num}"),
        ],
        ids=[
            "new_resp",
            "new_pm",
            "new_ca",
            "new_fb",
            "new_rc",
            "new_cl",
        ],
    )
    def test_template_contains_id_rule(self, element_kind, id_format):
        text = _load_template_text("revision_system.j2")
        assert element_kind in text
        assert id_format in text


# ---------------------------------------------------------------------------
# RevisionDelta-09: next-available-ID template variables are computed from existing structure
# ---------------------------------------------------------------------------


class TestRevisionDelta09NextAvailableIds:
    """RevisionDelta-09: next-available-ID template variables are computed from existing structure."""

    def test_rendered_prompt_contains_next_numbers(self):
        cs = _make_control_structure()
        rendered = _render_template(
            "revision_system.j2",
            control_structure=cs,
            next_resp_num=3,
            next_cl_num=2,
        )
        assert "3" in rendered  # next available responsibility number
        assert "2" in rendered  # next available coordination link number


# ---------------------------------------------------------------------------
# RevisionDelta-10: RevisionDelta merge validates the final ControlStructure
# ---------------------------------------------------------------------------


class TestRevisionDelta10ValidatesFinal:
    """RevisionDelta-10: RevisionDelta merge validates the final ControlStructure."""

    def test_merged_cs_passes_validation(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-3",
                    "description": "Input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        # If CS was constructed, it passed validation
        assert isinstance(cs, ControlStructure)
        assert len(cs.responsibilities) == 3


# ---------------------------------------------------------------------------
# RevisionDelta-11: strip_empty_responsibilities remains as safety net
# ---------------------------------------------------------------------------


class TestRevisionDelta11StripEmptySafetyNet:
    """RevisionDelta-11: strip_empty_responsibilities remains as safety net."""

    def test_empty_resp_stripped_after_merge(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-4",
                    "description": "Empty responsibility",
                    "process_model_parts": [],
                    "control_actions": [],
                    "feedback_channels": [],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-4" not in resp_ids
        # A warning should be logged about the stripped empty responsibility
        warning_text = " ".join(warnings)
        assert "RESP-4" in warning_text or "empty" in warning_text.lower()


# ---------------------------------------------------------------------------
# RevisionDelta-12: empty delta preserves existing responsibilities
# ---------------------------------------------------------------------------


class TestRevisionDelta12EmptyDeltaPreserves:
    """RevisionDelta-12: empty delta preserves existing responsibilities."""

    def test_empty_delta_preserves_existing(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict()
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids
        assert len(cs.responsibilities) == 2


# ---------------------------------------------------------------------------
# RevisionDelta-13: revision_user.j2 checklist includes each gap with required action
# ---------------------------------------------------------------------------


class TestRevisionDelta13ChecklistEachGap:
    """RevisionDelta-13: revision_user.j2 checklist includes each gap with required action."""

    def test_rendered_checklist_includes_all_gaps(self):
        findings = _make_critic_findings()
        rendered = _render_template(
            "revision_user.j2",
            use_case_text="Test",
            control_structure=_make_control_structure(),
            critic_findings=findings,
        )
        assert "missing_responsibility" in rendered
        assert "missing_feedback" in rendered
        assert "Missing input validation" in rendered
        assert "Missing outcome feedback" in rendered
        assert "Add input validation responsibility" in rendered
        assert "Add outcome verification feedback" in rendered
        # Should have numbered items (1. and 2.)
        assert "1." in rendered
        assert "2." in rendered


# ---------------------------------------------------------------------------
# RevisionDelta-14: revision_system.j2 preserves existing rules
# ---------------------------------------------------------------------------


class TestRevisionDelta14PreservesExistingRules:
    """RevisionDelta-14: revision_system.j2 preserves existing rules."""

    def test_template_preserves_solution_neutrality(self):
        text = _load_template_text("revision_system.j2")
        assert "solution-neutrality" in text

    def test_template_preserves_valid_references_rule(self):
        text = _load_template_text("revision_system.j2")
        assert "ElementRef references must be valid" in text

    def test_template_preserves_feedback_channel_rule(self):
        text = _load_template_text("revision_system.j2")
        assert "feedback channel updates must reference a PM in the same responsibility" in text


# ---------------------------------------------------------------------------
# Mutation hardening: _compute_next_ids / _next_num_from / _extract_num
# ---------------------------------------------------------------------------


class TestComputeNextIds:
    """Verify _compute_next_ids correctly computes next-available ID numbers."""

    def test_next_ids_from_populated_structure(self):
        """RESP-1/RESP-3 -> next_resp_num=4; CL-1 -> next_cl_num=2."""
        cs = _make_control_structure()
        # RESP-1, RESP-2 -> max=2, next=3
        # CL-1 -> max=1, next=2
        ids = _compute_next_ids(cs)
        assert ids["next_resp_num"] == 3
        assert ids["next_cl_num"] == 2
        # No controlled processes -> next_cp_num=1
        assert ids["next_cp_num"] == 1

    def test_next_ids_from_empty_structure(self):
        """Empty lists -> all next numbers are 1 (via _next_num_from directly)."""
        assert _next_num_from([], lambda x: x) == 1

    def test_next_ids_with_high_numbers(self):
        """RESP-10, RESP-25 -> next_resp_num=26."""
        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-10",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-10-1", description="S")
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-10-1", description="A")
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-10-1",
                            description="F",
                            updates="PM-10-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-10"
                            ),
                        )
                    ],
                ),
                Responsibility(
                    resp_id="RESP-25",
                    description="B",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-25-1", description="S")
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-25-1", description="A")
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-25-1",
                            description="F",
                            updates="PM-25-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-25"
                            ),
                        )
                    ],
                ),
            ],
        )
        ids = _compute_next_ids(cs)
        assert ids["next_resp_num"] == 26


class TestNextNumFrom:
    """Verify _next_num_from handles edge cases correctly."""

    def test_numeric_ids(self):
        """Items with numeric IDs return max+1."""
        items = [{"id": "X-1"}, {"id": "X-3"}, {"id": "X-2"}]
        result = _next_num_from(items, lambda item: item["id"])
        assert result == 4  # max(1,2,3)+1

    def test_empty_list_returns_one(self):
        """Empty list returns 1 (default 0 + 1)."""
        result = _next_num_from([], lambda item: item["id"])
        assert result == 1

    def test_non_numeric_ids_filtered(self):
        """Non-numeric IDs are filtered out; only valid numbers used."""
        items = [{"id": "X-5"}, {"id": "FOO"}, {"id": "BAR"}]
        result = _next_num_from(items, lambda item: item["id"])
        assert result == 6  # max(5)+1, FOO/BAR produce None which is filtered

    def test_all_non_numeric_returns_one(self):
        """All non-numeric IDs -> default 0 + 1 = 1."""
        items = [{"id": "FOO"}, {"id": "BAR"}]
        result = _next_num_from(items, lambda item: item["id"])
        assert result == 1

    def test_single_item(self):
        """Single item with number 7 -> next is 8."""
        items = [{"id": "X-7"}]
        result = _next_num_from(items, lambda item: item["id"])
        assert result == 8


class TestExtractNum:
    """Verify _extract_num extracts numeric suffixes correctly."""

    def test_simple_id(self):
        assert _extract_num("RESP-3") == 3

    def test_multi_part_id(self):
        """For 'PM-1-2', returns the first number (1)."""
        assert _extract_num("PM-1-2") == 1

    def test_no_number(self):
        assert _extract_num("FOO") is None

    def test_number_at_start(self):
        assert _extract_num("123abc") == 123

    def test_empty_string(self):
        assert _extract_num("") is None


# ---------------------------------------------------------------------------
# Mutation hardening: _is_responsibility_empty with partial responsibilities
# ---------------------------------------------------------------------------


class TestIsResponsibilityEmpty:
    """Verify _is_responsibility_empty correctly identifies partial vs empty."""

    def test_all_fields_empty(self):
        """All three fields empty -> True."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Empty",
            process_model_parts=[],
            control_actions=[],
            feedback_channels=[],
        )
        assert _is_responsibility_empty(resp) is True

    def test_all_fields_populated(self):
        """All three fields populated -> False."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Full",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="S")
            ],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="F",
                    updates="PM-1-1",
                    source=ElementRef(
                        type=ReferenceType.responsibility, id="RESP-1"
                    ),
                )
            ],
        )
        assert _is_responsibility_empty(resp) is False

    def test_only_pm_populated(self):
        """PM populated, CA and FB empty -> False (not ALL empty)."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Partial PM",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="S")
            ],
            control_actions=[],
            feedback_channels=[],
        )
        assert _is_responsibility_empty(resp) is False

    def test_only_ca_populated(self):
        """CA populated, PM and FB empty -> False."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Partial CA",
            process_model_parts=[],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[],
        )
        assert _is_responsibility_empty(resp) is False

    def test_only_fb_populated(self):
        """FB populated, PM and CA empty -> False."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Partial FB",
            process_model_parts=[],
            control_actions=[],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="F",
                    updates="PM-1-1",
                    source=ElementRef(
                        type=ReferenceType.responsibility, id="RESP-1"
                    ),
                )
            ],
        )
        assert _is_responsibility_empty(resp) is False

    def test_constraints_only_still_empty(self):
        """Responsibility with only constraints but no PM/CA/FB -> True."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Constraints only",
            responsibility_constraints=[
                ResponsibilityConstraint(rc_id="RC-1-1", description="C")
            ],
            process_model_parts=[],
            control_actions=[],
            feedback_channels=[],
        )
        assert _is_responsibility_empty(resp) is True
