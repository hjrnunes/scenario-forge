"""High-level live-LLM acceptance authorization policy.

The executor depends on this module. Feature handlers may import it, but
this module must not import feature handlers or the runtime facade.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

LIVE_LLM_ACCEPTANCE_MARKER = (
    'live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"'
)
LIVE_LLM_OPT_IN_ENV = "SCENARIO_FORGE_QA_PIPELINE"
LIVE_LLM_OPT_IN_VALUE = "1"
LIVE_LLM_SKIP_REASON = 'live LLM acceptance requires SCENARIO_FORGE_QA_PIPELINE "1"'


def live_llm_acceptance_authorized(
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Return whether live-LLM acceptance is explicitly authorized.

    Only the exact value ``1`` authorizes live work. Endpoint credentials
    are intentionally ignored here.
    """
    source = environ if environ is not None else _process_environ()
    return source.get(LIVE_LLM_OPT_IN_ENV) == LIVE_LLM_OPT_IN_VALUE


def step_is_live_llm_marker(text: str) -> bool:
    """Return whether *text* is the exact live-LLM marker, ignoring case."""
    return text.strip().casefold() == LIVE_LLM_ACCEPTANCE_MARKER.casefold()


def scenario_requires_live_llm_acceptance(
    scenario: Mapping[str, Any],
    background: list[Any] | None = None,
) -> bool:
    """Return whether a scenario is marked for live-LLM execution.

    Marker matching is exact after strip/casefold so nearby wording cannot
    opt a scenario in. Background steps count because a feature-level
    marker authorizes every scenario in that feature.
    """
    steps = list(background or [])
    steps.extend(scenario.get("steps") or [])
    return any(
        isinstance(step, dict) and step_is_live_llm_marker(str(step.get("text", "")))
        for step in steps
    )


def _process_environ() -> Mapping[str, str]:
    import os

    return os.environ
