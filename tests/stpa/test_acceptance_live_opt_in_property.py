"""Property tests for live-LLM acceptance authorization and marker matching."""

from __future__ import annotations

import string
import sys
from pathlib import Path

from hypothesis import given, strategies as st

ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(ROOT / "acceptance"))

from live_llm_opt_in import (
    LIVE_LLM_ACCEPTANCE_MARKER,
    LIVE_LLM_OPT_IN_ENV,
    live_llm_acceptance_authorized,
    scenario_requires_live_llm_acceptance,
    step_is_live_llm_marker,
)


_MARKER_CHARS = string.ascii_letters + string.digits + " \"'_-:"


@given(
    value=st.one_of(
        st.none(),
        st.text(max_size=8).filter(lambda item: item != "1"),
    ),
    extra=st.dictionaries(
        keys=st.text(min_size=1, max_size=12).filter(
            lambda name: name != LIVE_LLM_OPT_IN_ENV
        ),
        values=st.text(max_size=24),
        max_size=4,
    ),
)
def test_only_exact_one_authorizes_live_work(
    value: str | None, extra: dict[str, str]
) -> None:
    environ = dict(extra)
    if value is not None:
        environ[LIVE_LLM_OPT_IN_ENV] = value
    assert live_llm_acceptance_authorized(environ) is False


@given(
    extra=st.dictionaries(
        keys=st.sampled_from(
            (
                "SCENARIO_FORGE_MODEL_BASE_URL",
                "OPENAI_BASE_URL",
                "OPENAI_API_KEY",
                "SCENARIO_FORGE_API_KEY",
            )
        ),
        values=st.text(min_size=1, max_size=24),
        min_size=1,
        max_size=4,
    )
)
def test_endpoint_credentials_never_authorize_live_work(
    extra: dict[str, str],
) -> None:
    assert live_llm_acceptance_authorized(extra) is False
    extra[LIVE_LLM_OPT_IN_ENV] = "1"
    assert live_llm_acceptance_authorized(extra) is True


@given(padding=st.text(alphabet=string.whitespace, max_size=4))
def test_marker_match_is_stable_under_case_and_padding(padding: str) -> None:
    cased = "".join(
        char.upper() if index % 2 else char.lower()
        for index, char in enumerate(LIVE_LLM_ACCEPTANCE_MARKER)
    )
    assert step_is_live_llm_marker(f"{padding}{cased}{padding}")


@given(
    prefix=st.text(alphabet=_MARKER_CHARS, max_size=12),
    suffix=st.text(alphabet=_MARKER_CHARS, min_size=1, max_size=12),
)
def test_nearby_wording_cannot_opt_a_scenario_in(prefix: str, suffix: str) -> None:
    nearby = f"{prefix}{LIVE_LLM_ACCEPTANCE_MARKER}{suffix}".strip()
    if nearby.casefold() == LIVE_LLM_ACCEPTANCE_MARKER.casefold():
        return
    scenario = {
        "name": "nearby",
        "steps": [{"keyword": "Given", "text": nearby}],
    }
    assert scenario_requires_live_llm_acceptance(scenario) is False
