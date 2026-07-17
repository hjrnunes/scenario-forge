"""Tests for _validate_actor_type BDI validation, regeneration, and
negligent-insider threat-based exclusion."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from scenario_forge.models.scenario import ActorProfile
from scenario_forge.pipeline.generate import (
    _ADVERSARIAL_ONLY_THREATS,
    GenerationError,
    _validate_actor_type,
    generate_scenario,
)
from scenario_forge.pipeline.seeds import RiskCardRef, ScenarioSeed


def _make_actor(
    actor_type: str = "negligent-insider",
    intentions: list[str] | None = None,
    beliefs: list[str] | None = None,
    desires: list[str] | None = None,
    resources: list[str] | None = None,
) -> ActorProfile:
    return ActorProfile(
        actor_type=actor_type,  # type: ignore[arg-type]
        capability_level="intermediate",
        beliefs=beliefs or ["The system exposes a chat interface."],
        desires=desires or ["I want to access restricted data."],
        intentions=intentions or ["I will accidentally paste secrets."],
        resources=resources or ["Company laptop"],
    )


def _make_llm_result(actor_profile: ActorProfile) -> LLMResult:
    """Create a minimal LLMResult wrapping an actor profile."""
    return LLMResult(
        content=actor_profile,
        prompt_tokens=100,
        completion_tokens=50,
        duration_ms=500,
    )


def _make_seed() -> ScenarioSeed:
    """Create a minimal ScenarioSeed for testing."""
    return ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="Test description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description for risk-1",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=[],
    )


def _make_profile() -> CapabilityProfile:
    """Create a minimal CapabilityProfile for testing."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=["user prompts (input)"],
        confidence=ConfidenceLevel.high,
    )


class TestValidateActorType:
    """Tests for negligent-insider BDI intention validation."""

    def test_genuine_negligent_insider_unchanged(self):
        """A true negligent-insider (no adversarial keywords) passes through."""
        profile = _make_actor(
            intentions=[
                "I will accidentally share credentials in a public channel.",
                "I will misconfigure the access controls due to lack of training.",
            ],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "negligent-insider"

    def test_exploit_keyword_triggers_reassignment(self):
        profile = _make_actor(
            intentions=["I will exploit the prompt to extract sensitive data."],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user"

    def test_jailbreak_keyword_triggers_reassignment(self):
        profile = _make_actor(
            intentions=["I will jailbreak the model's safety filters."],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user"

    def test_bypass_keyword_triggers_reassignment(self):
        profile = _make_actor(
            intentions=["I will bypass authentication using prompt injection."],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user"

    def test_multiple_keywords_still_single_reassignment(self):
        profile = _make_actor(
            intentions=[
                "I will inject malicious prompts to manipulate the output.",
                "I will exfiltrate the training data through the API.",
            ],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user"

    def test_non_negligent_insider_types_skipped(self):
        """Validation only fires for negligent-insider, other types pass through."""
        for actor_type in [
            "adversarial-user",
            "malicious-insider",
            "cybercriminal",
            "nation-state",
        ]:
            profile = _make_actor(
                actor_type=actor_type,
                intentions=["I will exploit the system to steal data."],
            )
            result = _validate_actor_type(profile)
            assert result.actor_type == actor_type

    def test_case_insensitive_matching(self):
        """Keywords are matched case-insensitively."""
        profile = _make_actor(
            intentions=["I will EXPLOIT the system's BYPASS mechanisms."],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user"

    def test_warning_logged_on_reassignment(self, caplog):
        profile = _make_actor(
            intentions=["I will exploit a vulnerability to compromise the system."],
        )
        with caplog.at_level(logging.WARNING):
            _validate_actor_type(profile)
        assert "BDI validation" in caplog.text
        assert "adversarial-user" in caplog.text

    def test_original_profile_fields_preserved(self):
        """Reassignment only changes actor_type; all other fields are kept."""
        profile = _make_actor(
            intentions=["I will inject prompts to hijack the conversation."],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user"
        assert result.capability_level == profile.capability_level
        assert result.beliefs == profile.beliefs
        assert result.desires == profile.desires
        assert result.intentions == profile.intentions
        assert result.resources == profile.resources

    @pytest.mark.parametrize(
        "keyword",
        [
            # original keywords
            "exploit",
            "extract",
            "bypass",
            "fraud",
            "inject",
            "jailbreak",
            "manipulate",
            "exfiltrate",
            "compromise",
            "steal",
            "hijack",
            "confuse",
            "trick",
            "probe",
            "probing",
            "deceive",
            "fool",
            "subvert",
            "circumvent",
            "coerce",
            "impersonate",
            # v16 escapees
            "craft",
            "phishing",
            "destroy",
            "forge",
            "fabricate",
            "sabotage",
            "disrupt",
            "corrupt",
            "undermine",
            "tamper",
            "obfuscate",
            "evade",
            # additional adversarial-only verbs
            "spoof",
            "weaponize",
            "poison",
            "siphon",
            "infiltrate",
            "counterfeit",
        ],
    )
    def test_all_adversarial_keywords_detected(self, keyword):
        """Every keyword in the adversarial set triggers reassignment."""
        profile = _make_actor(
            intentions=[f"I will {keyword} the target system."],
        )
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user", (
            f"keyword '{keyword}' did not trigger reassignment"
        )

    @pytest.mark.parametrize(
        "intention",
        [
            "I will accidentally paste secrets into a public channel.",
            "I will misconfigure the access controls due to lack of training.",
            "I will unintentionally expose sensitive data by using the wrong template.",
            "I will unknowingly share a document with the wrong audience.",
            "I will forget to revoke temporary credentials after testing.",
            "I will inadvertently trigger a data leak by copy-pasting into the chatbot.",
            "I will neglect to follow the data handling policy.",
            "I will carelessly upload a file containing PII to the wrong bucket.",
        ],
    )
    def test_legitimate_negligent_intentions_not_reassigned(self, intention):
        """Genuine negligent-insider language must not trigger reassignment."""
        profile = _make_actor(intentions=[intention])
        result = _validate_actor_type(profile)
        assert result.actor_type == "negligent-insider", (
            f"legitimate intention was wrongly reassigned: {intention!r}"
        )

    @pytest.mark.parametrize(
        ("keyword", "sentence"),
        [
            ("craft", "I will craft output manipulation prompts to alter responses."),
            ("phishing", "I will generate phishing template content via the model."),
            ("destroy", "I will destroy audit evidence to cover my tracks."),
            ("forge", "I will forge authentication tokens using model outputs."),
            ("fabricate", "I will fabricate compliance documents with the AI."),
            ("sabotage", "I will sabotage the training pipeline data."),
            ("disrupt", "I will disrupt the service by flooding it with requests."),
            ("corrupt", "I will corrupt the model's fine-tuning dataset."),
            ("undermine", "I will undermine the safety filters through prompt tricks."),
            ("tamper", "I will tamper with the logging configuration."),
            ("obfuscate", "I will obfuscate my malicious queries to avoid detection."),
            ("evade", "I will evade the content safety classifiers."),
        ],
    )
    def test_v16_escapee_scenarios_now_caught(self, keyword, sentence):
        """Exact v16 QA escapee patterns are now detected."""
        profile = _make_actor(intentions=[sentence])
        result = _validate_actor_type(profile)
        assert result.actor_type == "adversarial-user", (
            f"v16 escapee keyword '{keyword}' in {sentence!r} was not caught"
        )


def _make_narrative_mock():
    """Create a mock narrative with the attributes _assemble_envelope needs."""
    narrative = MagicMock()
    narrative.zone_sequence = ["input", "reasoning"]
    narrative.entry_point = "user prompts (input)"
    return narrative


def _make_tree_mock():
    """Create a mock attack tree with proper root structure."""
    root = MagicMock()
    root.maestro_layer = 3
    root.children = None
    root.threat_id = "T7"
    tree = MagicMock()
    tree.root = root
    return tree


def _make_client_mock():
    """Create a mock LLMClient with the attributes generate_scenario needs."""
    client = MagicMock()
    client.model = "test-model"
    return client


class TestBDIRegeneration:
    """Tests for actor profile regeneration after BDI validation reassignment.

    These tests mock _assemble_envelope (in addition to the LLM call functions)
    to isolate the regeneration logic from Pydantic model assembly.
    """

    _PATCHES = [
        "scenario_forge.pipeline.generate._assemble_envelope",
        "scenario_forge.pipeline.generate._call_attack_tree",
        "scenario_forge.pipeline.generate._call_behavior_spec",
        "scenario_forge.pipeline.generate._call_narrative",
        "scenario_forge.pipeline.generate._call_actor_profile",
    ]

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_regeneration_triggered_on_reassignment(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree, mock_assemble, caplog
    ):
        """When _validate_actor_type reassigns, _call_actor_profile is invoked a second time."""
        adversarial_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will exploit the system to steal data."],
        )
        regen_profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will craft malicious API requests."],
        )

        mock_actor.side_effect = [
            (adversarial_profile, _make_llm_result(adversarial_profile)),
            (regen_profile, _make_llm_result(regen_profile)),
        ]
        mock_narrative.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_assemble.return_value = MagicMock()

        with caplog.at_level(logging.WARNING):
            generate_scenario(
                seed=_make_seed(),
                profile=_make_profile(),
                client=_make_client_mock(),
                use_case="Test AI chatbot",
            )

        assert mock_actor.call_count == 2
        _, second_kwargs = mock_actor.call_args_list[1]
        assert second_kwargs.get("forced_actor_type") == "adversarial-user"
        assert "BDI reassignment: regenerating" in caplog.text

        # _assemble_envelope should receive the regenerated profile
        _, assemble_kwargs = mock_assemble.call_args
        assert assemble_kwargs["actor_profile"].actor_type == "adversarial-user"

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_no_regeneration_when_type_unchanged(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree, mock_assemble
    ):
        """No regeneration when _validate_actor_type does not change the type."""
        genuine_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will accidentally share credentials."],
        )
        mock_actor.return_value = (genuine_profile, _make_llm_result(genuine_profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(genuine_profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(genuine_profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(genuine_profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed(),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
        )

        assert mock_actor.call_count == 1

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_regenerated_profile_has_correct_bdi(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree, mock_assemble
    ):
        """Regenerated profile BDI text matches the corrected actor type."""
        adversarial_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will exploit the system to bypass security."],
        )
        regen_profile = _make_actor(
            actor_type="adversarial-user",
            beliefs=["The target API lacks rate limiting."],
            desires=["I want to extract proprietary training data."],
            intentions=["I will send crafted adversarial queries."],
            resources=["Custom scripts", "GPU cluster"],
        )

        mock_actor.side_effect = [
            (adversarial_profile, _make_llm_result(adversarial_profile)),
            (regen_profile, _make_llm_result(regen_profile)),
        ]
        mock_narrative.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed(),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
        )

        _, assemble_kwargs = mock_assemble.call_args
        actor = assemble_kwargs["actor_profile"]
        assert actor.actor_type == "adversarial-user"
        assert actor.beliefs == regen_profile.beliefs
        assert actor.desires == regen_profile.desires
        assert actor.intentions == regen_profile.intentions
        assert actor.resources == regen_profile.resources

    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_regeneration_failure_raises_generation_error(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree
    ):
        """If regeneration LLM call fails, GenerationError is raised."""
        adversarial_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will exploit the system."],
        )
        mock_actor.side_effect = [
            (adversarial_profile, _make_llm_result(adversarial_profile)),
            RuntimeError("LLM unavailable"),
        ]

        with pytest.raises(GenerationError, match="BDI regeneration failed"):
            generate_scenario(
                seed=_make_seed(),
                profile=_make_profile(),
                client=_make_client_mock(),
                use_case="Test AI chatbot",
            )

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_defence_in_depth_accepts_still_wrong_type(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree, mock_assemble, caplog
    ):
        """If regenerated profile still fails validation, accept it with a warning."""
        adversarial_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will exploit the system to steal data."],
        )
        still_wrong = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will jailbreak the model safety filters."],
        )

        mock_actor.side_effect = [
            (adversarial_profile, _make_llm_result(adversarial_profile)),
            (still_wrong, _make_llm_result(still_wrong)),
        ]
        mock_narrative.return_value = (MagicMock(), _make_llm_result(still_wrong))
        mock_tree.return_value = (MagicMock(), _make_llm_result(still_wrong))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(still_wrong))
        mock_assemble.return_value = MagicMock()

        with caplog.at_level(logging.WARNING):
            generate_scenario(
                seed=_make_seed(),
                profile=_make_profile(),
                client=_make_client_mock(),
                use_case="Test AI chatbot",
            )

        # Re-validation reassigns again; _assemble_envelope gets adversarial-user
        _, assemble_kwargs = mock_assemble.call_args
        assert assemble_kwargs["actor_profile"].actor_type == "adversarial-user"

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_non_negligent_insider_no_regeneration(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree, mock_assemble
    ):
        """Adversarial-user profiles pass through without regeneration."""
        profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will exploit the system to steal data."],
        )
        mock_actor.return_value = (profile, _make_llm_result(profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed(),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
        )

        assert mock_actor.call_count == 1

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_regeneration_passes_forced_not_preferred(
        self, mock_actor, mock_narrative, mock_behavior, mock_tree, mock_assemble
    ):
        """Regeneration uses forced_actor_type, not preferred_actor_type."""
        adversarial_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will exploit the system."],
        )
        regen_profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will send crafted queries."],
        )
        mock_actor.side_effect = [
            (adversarial_profile, _make_llm_result(adversarial_profile)),
            (regen_profile, _make_llm_result(regen_profile)),
        ]
        mock_narrative.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(regen_profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed(),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
            preferred_actor_type="negligent-insider",
        )

        _, second_kwargs = mock_actor.call_args_list[1]
        assert second_kwargs["forced_actor_type"] == "adversarial-user"
        assert second_kwargs.get("preferred_actor_type") is None


def _make_seed_with_threat(threat_id: str) -> ScenarioSeed:
    """Create a ScenarioSeed with a specific threat_id."""
    return ScenarioSeed(
        seed_id=f"AP-{threat_id}-01",
        threat_id=threat_id,
        threat_name=f"Test Threat {threat_id}",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="Test description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description for risk-1",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        atlas_technique_ids=[],
    )


class TestAdversarialOnlyThreats:
    """Tests for negligent-insider exclusion based on threat_id."""

    _PATCHES = [
        "scenario_forge.pipeline.generate._assemble_envelope",
        "scenario_forge.pipeline.generate._call_attack_tree",
        "scenario_forge.pipeline.generate._call_behavior_spec",
        "scenario_forge.pipeline.generate._call_narrative",
        "scenario_forge.pipeline.generate._call_actor_profile",
    ]

    def test_constant_contains_expected_threats(self):
        """Verify the adversarial-only set includes the correct threat IDs."""
        assert _ADVERSARIAL_ONLY_THREATS == frozenset(
            {"T3", "T6", "T7", "T8", "T9", "T10", "T15"}
        )

    @pytest.mark.parametrize("threat_id", ["T3", "T6", "T7", "T8", "T9", "T10", "T15"])
    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_negligent_insider_excluded_for_adversarial_threats(
        self,
        mock_actor,
        mock_narrative,
        mock_behavior,
        mock_tree,
        mock_assemble,
        threat_id,
    ):
        """For adversarial-only threats, negligent-insider is added to
        excluded_actor_types before the LLM call."""
        profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will send crafted queries."],
        )
        mock_actor.return_value = (profile, _make_llm_result(profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed_with_threat(threat_id),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
        )

        _, first_kwargs = mock_actor.call_args_list[0]
        excluded = first_kwargs.get("excluded_actor_types") or []
        assert "negligent-insider" in excluded, (
            f"negligent-insider should be excluded for threat {threat_id}"
        )

    @pytest.mark.parametrize("threat_id", ["T2"])
    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_negligent_insider_allowed_for_non_adversarial_threats(
        self,
        mock_actor,
        mock_narrative,
        mock_behavior,
        mock_tree,
        mock_assemble,
        threat_id,
    ):
        """For non-adversarial threats (T2), negligent-insider
        is NOT automatically excluded."""
        profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will accidentally share credentials."],
        )
        mock_actor.return_value = (profile, _make_llm_result(profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed_with_threat(threat_id),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
        )

        _, first_kwargs = mock_actor.call_args_list[0]
        excluded = first_kwargs.get("excluded_actor_types") or []
        assert "negligent-insider" not in excluded, (
            f"negligent-insider should be allowed for threat {threat_id}"
        )

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_existing_exclusions_preserved(
        self,
        mock_actor,
        mock_narrative,
        mock_behavior,
        mock_tree,
        mock_assemble,
    ):
        """Pre-existing excluded_actor_types are preserved when
        negligent-insider is appended."""
        profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will send crafted queries."],
        )
        mock_actor.return_value = (profile, _make_llm_result(profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed_with_threat("T6"),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
            excluded_actor_types=["cybercriminal"],
        )

        _, first_kwargs = mock_actor.call_args_list[0]
        excluded = first_kwargs.get("excluded_actor_types") or []
        assert "cybercriminal" in excluded
        assert "negligent-insider" in excluded

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_no_duplicate_if_already_excluded(
        self,
        mock_actor,
        mock_narrative,
        mock_behavior,
        mock_tree,
        mock_assemble,
    ):
        """If negligent-insider is already in the exclusion list, it is
        not duplicated."""
        profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will send crafted queries."],
        )
        mock_actor.return_value = (profile, _make_llm_result(profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(profile))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed_with_threat("T9"),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
            excluded_actor_types=["negligent-insider"],
        )

        _, first_kwargs = mock_actor.call_args_list[0]
        excluded = first_kwargs.get("excluded_actor_types") or []
        assert excluded.count("negligent-insider") == 1

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_caller_list_not_mutated(
        self,
        mock_actor,
        mock_narrative,
        mock_behavior,
        mock_tree,
        mock_assemble,
    ):
        """The caller's excluded_actor_types list is not mutated in place."""
        profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will send crafted queries."],
        )
        mock_actor.return_value = (profile, _make_llm_result(profile))
        mock_narrative.return_value = (MagicMock(), _make_llm_result(profile))
        mock_tree.return_value = (MagicMock(), _make_llm_result(profile))
        mock_behavior.return_value = (MagicMock(), _make_llm_result(profile))
        mock_assemble.return_value = MagicMock()

        original_list = ["cybercriminal"]
        generate_scenario(
            seed=_make_seed_with_threat("T6"),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
            excluded_actor_types=original_list,
        )

        assert original_list == ["cybercriminal"], (
            "caller's list was mutated in place"
        )

    @pytest.mark.parametrize("threat_id", ["T3", "T6", "T9", "T10", "T15"])
    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    def test_defence_in_depth_both_mechanisms(
        self,
        mock_actor,
        mock_narrative,
        mock_behavior,
        mock_tree,
        mock_assemble,
        threat_id,
    ):
        """Both threat-based exclusion and BDI keyword validation work
        together as defence in depth.  Even if the LLM ignores the
        exclusion and returns negligent-insider with adversarial
        intentions, BDI validation catches it."""
        # Simulate LLM ignoring the exclusion hint
        bad_profile = _make_actor(
            actor_type="negligent-insider",
            intentions=["I will exploit the system to steal data."],
        )
        corrected_profile = _make_actor(
            actor_type="adversarial-user",
            intentions=["I will send crafted adversarial queries."],
        )

        mock_actor.side_effect = [
            (bad_profile, _make_llm_result(bad_profile)),
            (corrected_profile, _make_llm_result(corrected_profile)),
        ]
        mock_narrative.return_value = (
            MagicMock(),
            _make_llm_result(corrected_profile),
        )
        mock_tree.return_value = (
            MagicMock(),
            _make_llm_result(corrected_profile),
        )
        mock_behavior.return_value = (
            MagicMock(),
            _make_llm_result(corrected_profile),
        )
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=_make_seed_with_threat(threat_id),
            profile=_make_profile(),
            client=_make_client_mock(),
            use_case="Test AI chatbot",
        )

        # Threat-based exclusion was applied
        _, first_kwargs = mock_actor.call_args_list[0]
        excluded = first_kwargs.get("excluded_actor_types") or []
        assert "negligent-insider" in excluded

        # BDI validation triggered regeneration
        assert mock_actor.call_count == 2
        _, assemble_kwargs = mock_assemble.call_args
        assert assemble_kwargs["actor_profile"].actor_type == "adversarial-user"
