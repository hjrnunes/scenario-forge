"""Tests for _validate_actor_type BDI validation."""

import logging

import pytest

from scenario_forge.models.scenario import ActorProfile
from scenario_forge.pipeline.generate import _validate_actor_type


def _make_actor(
    actor_type: str = "negligent-insider",
    intentions: list[str] | None = None,
) -> ActorProfile:
    return ActorProfile(
        actor_type=actor_type,  # type: ignore[arg-type]
        capability_level="intermediate",
        beliefs=["The system exposes a chat interface."],
        desires=["I want to access restricted data."],
        intentions=intentions or ["I will accidentally paste secrets."],
        resources=["Company laptop"],
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
