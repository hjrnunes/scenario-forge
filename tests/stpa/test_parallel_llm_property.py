"""Property-based tests for parallel LLM call infrastructure invariants.

Uses Hypothesis to verify properties that must hold across broad input
ranges:

- **Order preservation**: Results are always in input order, regardless
  of max_workers, execution delays, or which calls fail.
- **Length conservation**: ``len(results) == len(calls)`` always.
- **Error isolation**: A failing call at any position does not affect
  the results of other calls.
- **Concurrency bound**: ``max_in_flight <= max_workers`` always.
- **Empty-list idempotence**: Empty input always returns empty output.

These complement the example-based tests in ``test_parallel_llm.py``
by exploring a broader input space than hand-written cases can cover.
"""

from __future__ import annotations

import threading
import time

from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel

from scenario_forge.stpa.infra.llm import LLMResult
from scenario_forge.stpa.infra.parallel_llm import (
    LLMCallResult,
    LLMCallSpec,
    parallel_safe_llm_calls,
)


# ---------------------------------------------------------------------------
# Test model
# ---------------------------------------------------------------------------


class _PropModel(BaseModel):
    """Simple model for property-test call specs."""

    value: str = "ok"


# ---------------------------------------------------------------------------
# Thread-safe concurrent mock LLM client
# ---------------------------------------------------------------------------


class _PropMockClient:
    """Minimal thread-safe mock LLM client for property tests.

    Supports:
    - Fixed response for ``_PropModel``.
    - Step-based exceptions (step substring searched in user_prompt).
    - Step-based delays (step substring searched in user_prompt).
    - Concurrent in-flight call tracking via a lock.
    """

    def __init__(self, model: str = "prop-model") -> None:
        self.base_url = "http://test:8080"
        self.model = model
        self.temperature = 0.4
        self.max_completion_tokens = None
        self._exception_steps: set[str] = set()
        self._delay_steps: dict[str, float] = {}
        self._in_flight = 0
        self._max_in_flight = 0
        self._lock = threading.Lock()

    @property
    def max_in_flight(self) -> int:
        return self._max_in_flight

    def set_exception_for_step(self, step: str) -> None:
        self._exception_steps.add(step)

    def set_delay_for_step(self, step: str, seconds: float) -> None:
        self._delay_steps[step] = seconds

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        with self._lock:
            self._in_flight += 1
            if self._in_flight > self._max_in_flight:
                self._max_in_flight = self._in_flight

        try:
            # Check for delay
            for step, delay in self._delay_steps.items():
                if step in user_prompt:
                    time.sleep(delay)
                    break

            # Check for exception
            for step in self._exception_steps:
                if step in user_prompt:
                    raise RuntimeError(f"forced failure for {step}")

            return LLMResult(
                content=_PropModel(value="ok"),
                prompt_tokens=10,
                completion_tokens=5,
                duration_ms=1,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        finally:
            with self._lock:
                self._in_flight -= 1


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_n_calls = st.integers(min_value=0, max_value=10)
st_max_workers = st.integers(min_value=1, max_value=8)
st_fail_indices = st.lists(st.integers(min_value=0, max_value=9), min_size=0, max_size=3)


def _make_specs(n: int) -> list[LLMCallSpec]:
    """Build n call specs with distinct step names."""
    return [
        LLMCallSpec(
            system_prompt="sys",
            user_prompt=f"prompt for step_{i}",
            response_format=_PropModel,
            stage="stage_3",
            step=f"step_{i}",
            temperature=0.4,
        )
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------


class TestParallelOrderPreservation:
    """Results are always in input order, regardless of execution order."""

    @given(n_calls=st_n_calls, max_workers=st_max_workers)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_results_in_input_order(self, tmp_path, n_calls, max_workers):
        """For any N calls and any max_workers, results[i].call_spec is calls[i]."""
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        assert len(results) == n_calls
        for i, r in enumerate(results):
            assert r.call_spec is calls[i]

    @given(
        n_calls=st.integers(min_value=3, max_value=8),
        max_workers=st.integers(min_value=2, max_value=6),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_order_preserved_with_delays(self, tmp_path, n_calls, max_workers):
        """Order is preserved even when later calls finish faster than earlier ones."""
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        # Delay the first call, not the rest — first finishes last
        client.set_delay_for_step("step_0", 0.05)
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        for i, r in enumerate(results):
            assert r.call_spec.step == f"step_{i}"


class TestParallelLengthConservation:
    """len(results) == len(calls) always."""

    @given(n_calls=st_n_calls, max_workers=st_max_workers)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_result_count_equals_call_count(self, tmp_path, n_calls, max_workers):
        """The number of results always equals the number of input calls."""
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        assert len(results) == len(calls)


class TestParallelErrorIsolation:
    """A failing call at any position does not affect other calls."""

    @given(
        n_calls=st.integers(min_value=3, max_value=8),
        fail_index=st.integers(min_value=0, max_value=7),
        max_workers=st_max_workers,
    )
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_single_failure_isolates_correctly(
        self, tmp_path, n_calls, fail_index, max_workers
    ):
        """A failure at fail_index produces error there and success elsewhere."""
        # Ensure fail_index is within range
        fail_index = fail_index % n_calls
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        client.set_exception_for_step(f"step_{fail_index}")
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        assert len(results) == n_calls
        for i, r in enumerate(results):
            if i == fail_index:
                assert r.error is not None, f"Expected error at index {i}"
                assert r.model is None, f"Expected model=None at index {i}"
            else:
                assert r.error is None, f"Unexpected error at index {i}: {r.error}"
                assert r.model is not None, f"Expected model at index {i}"

    @given(
        n_calls=st.integers(min_value=5, max_value=10),
        max_workers=st.integers(min_value=1, max_value=4),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_multiple_failures_isolate(self, tmp_path, n_calls, max_workers):
        """Multiple failures at different positions don't affect each other."""
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        # Fail every other call
        fail_indices = {i for i in range(0, n_calls, 2)}
        for idx in fail_indices:
            client.set_exception_for_step(f"step_{idx}")
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        for i, r in enumerate(results):
            if i in fail_indices:
                assert r.error is not None
                assert r.model is None
            else:
                assert r.error is None
                assert r.model is not None


class TestParallelConcurrencyBound:
    """max_in_flight never exceeds max_workers."""

    @given(
        n_calls=st.integers(min_value=4, max_value=10),
        max_workers=st.integers(min_value=1, max_value=6),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
    )
    def test_concurrency_never_exceeds_max_workers(
        self, tmp_path, n_calls, max_workers
    ):
        """The number of concurrent in-flight calls never exceeds max_workers."""
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        # Add a small delay to increase chance of overlap
        for i in range(n_calls):
            client.set_delay_for_step(f"step_{i}", 0.01)
        parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        assert client.max_in_flight <= max_workers, (
            f"max_in_flight={client.max_in_flight} exceeded max_workers={max_workers}"
        )


class TestParallelEmptyList:
    """Empty input always returns empty output."""

    @given(max_workers=st_max_workers)
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_empty_calls_returns_empty(self, tmp_path, max_workers):
        """An empty call list always returns an empty result list."""
        client = _PropMockClient()
        results = parallel_safe_llm_calls(
            [], llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        assert results == []
        assert not (tmp_path / "calls.jsonl").exists()


class TestParallelResultShape:
    """LLMCallResult shape invariants hold for every result."""

    @given(
        n_calls=st.integers(min_value=1, max_value=6),
        max_workers=st_max_workers,
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_every_result_is_llm_call_result(self, tmp_path, n_calls, max_workers):
        """Every element in the result list is an LLMCallResult instance."""
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=max_workers
        )
        for r in results:
            assert isinstance(r, LLMCallResult)
            # On success: model is not None, error is None, result is not None
            assert r.model is not None
            assert r.error is None
            assert r.result is not None
            # call_spec is the original spec
            assert isinstance(r.call_spec, LLMCallSpec)

    @given(
        n_calls=st.integers(min_value=2, max_value=6),
        fail_index=st.integers(min_value=0, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_failure_result_shape(self, tmp_path, n_calls, fail_index):
        """A failed result has model=None, error non-None, and call_spec set."""
        fail_index = fail_index % n_calls
        calls = _make_specs(n_calls)
        client = _PropMockClient()
        client.set_exception_for_step(f"step_{fail_index}")
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=2
        )
        r = results[fail_index]
        assert r.model is None
        assert r.error is not None
        assert isinstance(r.call_spec, LLMCallSpec)
        assert r.call_spec.step == f"step_{fail_index}"
