"""Mutation hardening tests for SP1 System Model.

These tests target specific mutation sites that survived initial
mutation testing. They are kept in a separate file from unit and
acceptance tests per the hardening protocol.
"""

from __future__ import annotations

import yaml

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    Stage1Profile as _S1P,
)
from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model.control_structure import (
    RequirementSet,
    ResponsibilitySet,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    _build_taxonomy_probes,
    _needs_rag_probe,
    _needs_tool_probe,
    has_unjustified_gaps,
)
from scenario_forge.stpa.system_model.run import SP1RunResult, run_sp1
from tests.stpa.sp1_helpers import MockLLMClient


def _profile(
    kc_subcodes: list[str] | None = None,
    entry_point_names: list[str] | None = None,
    tool_inventory: list[dict] | None = None,
) -> CapabilityProfile:
    """Build a CapabilityProfile with the given parameters.

    Boolean flags (has_persistent_memory, multi_agent, hitl) are computed
    from kc_subcodes by CapabilityProfile, so callers control them by
    choosing appropriate kc_subcodes:
    - has_persistent_memory: include KC4.3–KC4.6 or KCX-PMEM
    - multi_agent: include KC2.3 or KCX-MAGENT
    - hitl: include KCX-HITL
    """
    codes = list(kc_subcodes or ["KC1.1"])
    # Provide a default tool_inventory when tool_execution zone is active
    needs_tools = any(c.startswith("KC5.") or c.startswith("KC6.") for c in codes)
    if needs_tools and tool_inventory is None:
        tool_inventory = [{"name": "tool1", "description": "A tool"}]
    eps = [
        {"name": name, "direction": "input", "controllability": "direct"}
        for name in (entry_point_names or ["User chat"])
    ]
    return Stage1Profile(
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=eps,
        confidence="medium",
        kc_subcodes=codes,
        tool_inventory=tool_inventory or [],
    ).to_capability_profile()


class TestNeedsRagProbe:
    """Mutation hardening for _needs_rag_probe — kills or→and and in→not_in mutants."""

    def test_kc_present_no_rag_entry_point(self):
        """KC6.3.3 in subcodes but no 'rag' in entry point names → True.

        Kills the or→and mutant: True or False = True, but True and False = False.
        Kills the in→not_in mutant: True or False = True, but False or False = False.
        """
        profile = _profile(
            kc_subcodes=["KC1.1", "KC6.3.3"],
            entry_point_names=["User chat"],
        )
        assert _needs_rag_probe(profile) is True

    def test_kc_absent_rag_in_entry_point(self):
        """No KC6.3.3 but 'rag' in entry point name → True.

        Covers the any(...) line and kills the or→and mutant from the
        other side: False or True = True, but False and True = False.
        """
        profile = _profile(
            kc_subcodes=["KC1.1"],
            entry_point_names=["RAG search interface"],
        )
        assert _needs_rag_probe(profile) is True

    def test_neither_kc_nor_rag(self):
        """No KC6.3.3 and no 'rag' in entry points → False."""
        profile = _profile(
            kc_subcodes=["KC1.1"],
            entry_point_names=["User chat"],
        )
        assert _needs_rag_probe(profile) is False

    def test_both_kc_and_rag(self):
        """Both KC6.3.3 and 'rag' in entry points → True."""
        profile = _profile(
            kc_subcodes=["KC1.1", "KC6.3.3"],
            entry_point_names=["RAG search"],
        )
        assert _needs_rag_probe(profile) is True


class TestNeedsToolProbe:
    """Mutation hardening for _needs_tool_probe — kills or→and mutant."""

    def test_kc5_present(self):
        """KC5.* in subcodes → True."""
        profile = _profile(kc_subcodes=["KC1.1", "KC5.2"])
        assert _needs_tool_probe(profile) is True

    def test_kc6_present(self):
        """KC6.* (not KC6.3.3) in subcodes → True."""
        profile = _profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        assert _needs_tool_probe(profile) is True

    def test_no_kc5_or_kc6(self):
        """No KC5.* or KC6.* in subcodes → False."""
        profile = _profile(kc_subcodes=["KC1.1", "KC2.3"])
        assert _needs_tool_probe(profile) is False


class TestBuildTaxonomyProbes:
    """Mutation hardening for _build_taxonomy_probes — verifies probe gating."""

    def test_rag_probe_included_via_kc(self):
        """RAG probe is included when KC6.3.3 is present."""
        profile = _profile(
            kc_subcodes=["KC1.1", "KC6.3.3"],
            entry_point_names=["User chat"],
        )
        probes = _build_taxonomy_probes(profile)
        assert any("RAG retrieval" in p for p in probes)

    def test_rag_probe_included_via_entry_point(self):
        """RAG probe is included when entry point name contains 'rag'."""
        profile = _profile(
            kc_subcodes=["KC1.1"],
            entry_point_names=["RAG search"],
        )
        probes = _build_taxonomy_probes(profile)
        assert any("RAG retrieval" in p for p in probes)

    def test_rag_probe_excluded_when_neither(self):
        """RAG probe is excluded when neither KC6.3.3 nor 'rag' entry point."""
        profile = _profile(
            kc_subcodes=["KC1.1"],
            entry_point_names=["User chat"],
        )
        probes = _build_taxonomy_probes(profile)
        assert not any("RAG retrieval" in p for p in probes)

    def test_memory_probe_included(self):
        """Memory probe included when has_persistent_memory (KC4.3)."""
        profile = _profile(
            kc_subcodes=["KC1.1", "KC4.3"],
        )
        probes = _build_taxonomy_probes(profile)
        assert any("Memory integrity" in p for p in probes)

    def test_memory_probe_excluded(self):
        """Memory probe excluded when no persistent memory."""
        profile = _profile(
            kc_subcodes=["KC1.1"],
        )
        probes = _build_taxonomy_probes(profile)
        assert not any("Memory integrity" in p for p in probes)

    def test_multi_agent_probe_included(self):
        """Multi-agent probe included when multi_agent (KC2.3)."""
        profile = _profile(
            kc_subcodes=["KC1.1", "KC2.3"],
        )
        probes = _build_taxonomy_probes(profile)
        assert any("Multi-agent coordination" in p for p in probes)

    def test_multi_agent_probe_excluded(self):
        """Multi-agent probe excluded when not multi_agent."""
        profile = _profile(
            kc_subcodes=["KC1.1"],
        )
        probes = _build_taxonomy_probes(profile)
        assert not any("Multi-agent coordination" in p for p in probes)

    def test_hitl_probe_included(self):
        """HITL probe included when hitl (KCX-HITL)."""
        profile = _profile(
            kc_subcodes=["KC1.1", "KCX-HITL"],
        )
        probes = _build_taxonomy_probes(profile)
        assert any("Human-in-the-loop" in p for p in probes)

    def test_hitl_probe_excluded(self):
        """HITL probe excluded when not hitl."""
        profile = _profile(
            kc_subcodes=["KC1.1"],
        )
        probes = _build_taxonomy_probes(profile)
        assert not any("Human-in-the-loop" in p for p in probes)

    def test_tool_probe_included_with_kc5(self):
        """Tool probe included when KC5.* present."""
        profile = _profile(kc_subcodes=["KC1.1", "KC5.1"])
        probes = _build_taxonomy_probes(profile)
        assert any("Tool parameter validation" in p for p in probes)

    def test_tool_probe_excluded_without_kc5_or_kc6(self):
        """Tool probe excluded when no KC5.* or KC6.*."""
        profile = _profile(kc_subcodes=["KC1.1", "KC2.3"])
        probes = _build_taxonomy_probes(profile)
        assert not any("Tool parameter validation" in p for p in probes)


class TestHasUnjustifiedGaps:
    """Mutation hardening for has_unjustified_gaps."""

    def test_empty_checklist(self):
        """Empty checklist → no unjustified gaps."""
        findings = CriticFindings(gaps=[], checklist_results={})
        assert has_unjustified_gaps(findings) is False

    def test_all_present(self):
        """All present → no unjustified gaps."""
        findings = CriticFindings(
            gaps=[],
            checklist_results={"a": "present", "b": "present"},
        )
        assert has_unjustified_gaps(findings) is False

    def test_all_absent_justified(self):
        """All absent_justified → no unjustified gaps."""
        findings = CriticFindings(
            gaps=[],
            checklist_results={"a": "absent_justified", "b": "absent_justified"},
        )
        assert has_unjustified_gaps(findings) is False

    def test_mixed_with_one_unjustified(self):
        """Mixed with one absent_unjustified → has unjustified gaps."""
        findings = CriticFindings(
            gaps=[],
            checklist_results={
                "a": "present",
                "b": "absent_justified",
                "c": "absent_unjustified",
            },
        )
        assert has_unjustified_gaps(findings) is True

    def test_only_unjustified(self):
        """All absent_unjustified → has unjustified gaps."""
        findings = CriticFindings(
            gaps=[],
            checklist_results={"a": "absent_unjustified"},
        )
        assert has_unjustified_gaps(findings) is True


# ---------------------------------------------------------------------------
# run.py mutation hardening
# ---------------------------------------------------------------------------


def _make_risk_cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


def _valid_loss_analysis_dict() -> dict:
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [
            {
                "loss_id": "L-2",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended action",
                "related_losses": ["L-1", "L-2"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "description": "Must confirm before action",
                "related_hazards": ["H-1"],
            }
        ],
    }


def _valid_stage1_profile_dict() -> dict:
    return {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [{"name": "tool1", "description": "A tool"}],
    }


def _valid_requirement_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity",
                "classification": "control",
                "source_constraint": "SC-1",
            }
        ]
    }


def _valid_responsibility_set_dict() -> dict:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "responsibility_constraints": [
                    {"rc_id": "SC-1", "description": "Must confirm before action"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-1-1", "description": "Execute action"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Action result",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
            }
        ],
        "controlled_processes": [],
    }


def _valid_control_structure_dict() -> dict:
    rs = _valid_responsibility_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": [],
        "coordination_links": [],
    }


def _no_unjustified_gaps_dict() -> dict:
    return {
        "gaps": [],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
        },
        "taxonomy_probe_results": {},
    }


def _with_unjustified_gaps_dict() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            },
        ],
        "checklist_results": {
            "Input validation": "absent_unjustified",
            "Authorization": "present",
        },
        "taxonomy_probe_results": {},
    }


def _make_mock_client(
    critic_findings: dict | None = None,
    revised_cs: dict | None = None,
) -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all stages.

    When revised_cs is provided, all responses are queued in call order
    because the MockLLMClient checks the queue before the response map.
    """
    client = MockLLMClient()
    findings = critic_findings or _no_unjustified_gaps_dict()

    if revised_cs is not None:
        # Queue all responses in call order for the revision path
        client.set_response_queue([
            _valid_loss_analysis_dict(),       # Stage 1a
            _valid_stage1_profile_dict(),       # Stage 1b
            _valid_requirement_set_dict(),      # Stage 2 Call 1
            _valid_responsibility_set_dict(),   # Stage 2 Call 2
            _valid_control_structure_dict(),    # Stage 2 Call 3
            findings,                           # Critic
            revised_cs,                         # Revision
        ])
    else:
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        client.set_response_for(_S1P, _valid_stage1_profile_dict())
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())
        client.set_response_for(CriticFindings, findings)

    return client


def _make_profile() -> CapabilityProfile:
    return Stage1Profile(
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=[
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        confidence="medium",
        kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
        tool_inventory=[{"name": "tool1", "description": "A tool"}],
    ).to_capability_profile()


class TestSP1RunResultDefault:
    """Mutation hardening for SP1RunResult default field values."""

    def test_revised_defaults_to_false(self):
        """SP1RunResult.revised defaults to False when not specified.

        Kills the False→True mutant on the dataclass default.
        """
        result = SP1RunResult(
            loss_analysis=LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[],
                hazards=[],
                security_constraints=[],
            ),
            capability_profile=_make_profile(),
            control_structure=ControlStructure(responsibilities=[]),
        )
        assert result.revised is False


class TestRunSp1Mutation:
    """Mutation hardening for run_sp1 — kills surviving mutants."""

    def test_nested_run_dir_created(self, tmp_path):
        """run_sp1 creates nested run_dir that doesn't exist yet.

        Kills the parents=True→False mutant on mkdir(parents=True).
        """
        nested = tmp_path / "a" / "b" / "c"
        assert not nested.exists()
        client = _make_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=nested,
        )
        assert nested.exists()
        assert (nested / "loss-analysis.yaml").exists()

    def test_revised_false_when_no_unjustified_gaps(self, tmp_path):
        """result.revised is False when critic finds no unjustified gaps.

        Kills the revised=False→True mutant on the initial assignment.
        """
        client = _make_mock_client(critic_findings=_no_unjustified_gaps_dict())
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert result.revised is False

    def test_revised_true_when_unjustified_gaps(self, tmp_path):
        """result.revised is True when critic finds unjustified gaps.

        Covers the revised=True line and kills the True→False mutant.
        """
        client = _make_mock_client(
            critic_findings=_with_unjustified_gaps_dict(),
            revised_cs=_valid_control_structure_dict(),
        )
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert result.revised is True

    def test_manifest_stage_1b_call_count_zero_when_profile_skipped(self, tmp_path):
        """Manifest stage_1b.call_count is 0 when profile is pre-loaded.

        Kills the 0→1 mutant on stage_1b_calls = 0 if profile_skipped else 1.
        """
        profile = _make_profile()
        profile_path = tmp_path / "capability-profile.yaml"
        write_yaml(profile, profile_path)

        client = _make_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
            profile_path=profile_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_1b"]["call_count"] == 0

    def test_manifest_stage_1b_call_count_one_when_inferred(self, tmp_path):
        """Manifest stage_1b.call_count is 1 when profile is inferred.

        Kills the 1→0 mutant on stage_1b_calls = 0 if profile_skipped else 1.
        """
        client = _make_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_1b"]["call_count"] == 1

    def test_manifest_stage_1a_call_count_one(self, tmp_path):
        """Manifest stage_1a.call_count is 1.

        Covers the constant 1 in stage_summary and kills the 1→0 mutant.
        """
        client = _make_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_1a"]["call_count"] == 1
