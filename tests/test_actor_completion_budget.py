"""Regression coverage for bounded actor-profile generation."""

from unittest.mock import MagicMock

import pytest

from scenario_forge.pipeline.generate import actor


def test_actor_profile_call_has_a_stage_specific_completion_bound(monkeypatch) -> None:
    """A tiny structured actor object must not consume the whole context window."""
    monkeypatch.setattr(
        actor, "build_call0_context", lambda **_kwargs: {"tool_inventory": []}
    )
    monkeypatch.setattr(actor, "render_prompt", lambda *_args, **_kwargs: "prompt")
    client = MagicMock()
    client.max_completion_tokens = None
    client.complete.side_effect = RuntimeError("stop after invocation")

    with pytest.raises(RuntimeError, match="stop after invocation"):
        actor._call_actor_profile(
            seed=MagicMock(),
            profile=MagicMock(zones_active=[]),
            client=client,
            use_case="test",
        )

    assert client.complete.call_args.kwargs["max_completion_tokens"] == 4096


def test_actor_profile_call_preserves_tighter_operator_completion_bound() -> None:
    client = MagicMock(max_completion_tokens=2048)

    assert actor._actor_completion_limit(client) == 2048
