# Parallel LLM Call Infrastructure — End-to-End QA Suite

This document specifies the user-visible workflows that QA verifies for the
parallel LLM call infrastructure (`parallel_llm.py`) and the `max_workers`
configuration. All verification is done through pytest execution, CLI
invocation, filesystem inspection, and module import checks — no
project-internal APIs are used beyond what pytest itself exercises.

## 1. Module Structure Verification

### QA-PAR-STRUCT-01: parallel_llm module exists and is importable

**Steps:**
1. Verify `src/scenario_forge/stpa/infra/parallel_llm.py` exists.
2. Import the module and verify `parallel_safe_llm_calls`, `LLMCallSpec`, and `LLMCallResult` are defined.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.parallel_llm import (
    parallel_safe_llm_calls, LLMCallSpec, LLMCallResult,
)
print('parallel_llm module importable with required symbols')
"
```

### QA-PAR-STRUCT-02: parallel_llm has no coupling to existing pipeline

**Steps:**
1. Grep `src/scenario_forge/stpa/infra/parallel_llm.py` for imports of `scenario_forge.pipeline.io`, `scenario_forge.manifest`, `scenario_forge.prompts`.
2. Verify none of those imports exist.

**Command:**
```bash
grep -rn "scenario_forge.pipeline.io\|scenario_forge.manifest\|scenario_forge.prompts" src/scenario_forge/stpa/infra/parallel_llm.py || echo "No coupling found"
```

### QA-PAR-STRUCT-03: parallel_llm reuses safe_llm_call from llm_helpers

**Steps:**
1. Grep `src/scenario_forge/stpa/infra/parallel_llm.py` for imports of `safe_llm_call` from `scenario_forge.stpa.infra.llm_helpers`.
2. Verify the import exists (the parallel module delegates to `safe_llm_call`, not reimplementing it).

**Command:**
```bash
grep -n "safe_llm_call" src/scenario_forge/stpa/infra/parallel_llm.py
```

## 2. Parallel Execution Verification

### QA-PAR-EXEC-01: Multiple calls execute and return results

**Steps:**
1. Run the test for ParallelLLM-01 (multiple calls execute and return results).
2. Verify three `LLMCallResult` objects are returned, each containing a validated model.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-01" -v --tb=short
```

### QA-PAR-EXEC-02: Results returned in input order

**Steps:**
1. Run the test for ParallelLLM-02 (results returned in input order regardless of execution order).
2. Verify results are ordered by input specification index, not by completion time.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-02" -v --tb=short
```

### QA-PAR-EXEC-03: Failed call does not affect other calls

**Steps:**
1. Run the test for ParallelLLM-03 (failed call does not affect other calls).
2. Verify the failed call result has an error, and the other two results have no error.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-03" -v --tb=short
```

### QA-PAR-EXEC-04: Thread-safe call log writing

**Steps:**
1. Run the test for ParallelLLM-04 (all call log entries written thread-safe).
2. Verify `calls.jsonl` contains exactly five valid JSON lines with required fields.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-04" -v --tb=short
```

### QA-PAR-EXEC-05: max_workers controls concurrency

**Steps:**
1. Run the test for ParallelLLM-05 (max_workers controls concurrency level).
2. Verify the maximum observed concurrent in-flight calls does not exceed `max_workers`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-05" -v --tb=short
```

### QA-PAR-EXEC-06: Single call degenerate case

**Steps:**
1. Run the test for ParallelLLM-06 (single call works as degenerate case).
2. Verify one `LLMCallResult` is returned with a valid model.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-06" -v --tb=short
```

### QA-PAR-EXEC-07: Empty call list returns empty results

**Steps:**
1. Run the test for ParallelLLM-07 (empty call list returns empty result list).
2. Verify an empty list is returned and no `calls.jsonl` file is created.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-07" -v --tb=short
```

### QA-PAR-EXEC-08: Temperature propagated to each call

**Steps:**
1. Run the test for ParallelLLM-12 (temperature propagated to each call).
2. Verify each call receives its specified temperature value.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-12" -v --tb=short
```

## 3. LLMCallSpec and LLMCallResult Verification

### QA-PAR-SPEC-01: LLMCallSpec bundles call arguments

**Steps:**
1. Run the test for ParallelLLM-08 (LLMCallSpec bundles call arguments).
2. Verify all fields (system_prompt, user_prompt, response_format, stage, step, temperature) are accessible.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-08" -v --tb=short
```

### QA-PAR-SPEC-02: LLMCallResult bundles result with call_spec

**Steps:**
1. Run the tests for ParallelLLM-09 (successful result) and ParallelLLM-10 (failed result).
2. Verify successful results have model set, result set, error None, and call_spec set.
3. Verify failed results have model None, error set, and call_spec set.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-09 or ParallelLLM-10" -v --tb=short
```

### QA-PAR-SPEC-03: Call log entries distinguish success and failure

**Steps:**
1. Run the test for ParallelLLM-11 (call log entries include success and failure entries).
2. Verify `calls.jsonl` has a line with `success: true` and a line with `success: false` and a non-empty `error` field.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelLLM-11" -v --tb=short
```

## 4. max_workers Configuration Verification

### QA-PAR-CONFIG-01: run_sp1 accepts max_workers parameter

**Steps:**
1. Run the test for ParallelConfig-01 (run_sp1 accepts max_workers parameter).
2. Verify the run completes without error when `max_workers=4`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelConfig-01" -v --tb=short
```

### QA-PAR-CONFIG-02: max_workers default is 1

**Steps:**
1. Run the test for ParallelConfig-02 (max_workers default is 1 for backwards compatibility).
2. Verify the run manifest records `max_workers` as 1 when not specified.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelConfig-02" -v --tb=short
```

### QA-PAR-CONFIG-03: Run manifest records max_workers

**Steps:**
1. Run the test for ParallelConfig-03 (run manifest records max_workers value).
2. Verify the manifest's `max_workers` field matches the value passed to `run_sp1`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelConfig-03" -v --tb=short
```

### QA-PAR-CONFIG-04: --max-workers CLI flag

**Steps:**
1. Run the test for ParallelConfig-04 (--max-workers CLI flag passes value to run_sp1).
2. Verify `run_sp1` receives the correct `max_workers` value from the CLI flag.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelConfig-04" -v --tb=short
```

### QA-PAR-CONFIG-05: --max-workers CLI flag defaults to 1

**Steps:**
1. Run the test for ParallelConfig-05 (--max-workers CLI flag defaults to 1).
2. Verify `run_sp1` receives `max_workers=1` when the flag is omitted.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelConfig-05" -v --tb=short
```

### QA-PAR-CONFIG-06: --max-workers accepts valid values

**Steps:**
1. Run the test for ParallelConfig-06 (--max-workers accepts valid values).
2. Verify the CLI flag correctly passes each value from the Examples table (1, 2, 4, 8, 16).

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelConfig-06" -v --tb=short
```

### QA-PAR-CONFIG-07: --max-workers flag visible in help output

**Steps:**
1. Invoke the SP1 runner script with `--help`.
2. Verify `--max-workers` appears in the help text with a description mentioning concurrency control.

**Command:**
```bash
uv run python scripts/run_sp1.py --help 2>&1 | grep -q "\-\-max-workers" && echo "Flag present" || echo "Flag missing"
```

## 5. SP1 Backwards Compatibility Verification

### QA-PAR-SP1-01: max_workers=1 produces identical output artifacts

**Steps:**
1. Run the test for ParallelSP1-01 (max_workers=1 produces identical output artifacts).
2. Verify `loss-analysis.yaml`, `capability-profile.yaml`, and `control-structure.yaml` all exist.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP1-01" -v --tb=short
```

### QA-PAR-SP1-02: Stage execution order preserved with max_workers=1

**Steps:**
1. Run the test for ParallelSP1-02 (stage execution order preserved).
2. Verify Stage 1a, 1b, and 2 execute in order.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP1-02" -v --tb=short
```

### QA-PAR-SP1-03: Call log identical with max_workers=1

**Steps:**
1. Run the test for ParallelSP1-03 (call log identical with max_workers=1).
2. Verify `calls.jsonl` entries appear in stage order (stage_1a, stage_1b, stage_2).

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP1-03" -v --tb=short
```

### QA-PAR-SP1-04: Existing SP1 tests pass with parallel module present

**Steps:**
1. Run the full existing SP1 test suite.
2. Verify no new failures are introduced by the parallel module.

**Command:**
```bash
uv run pytest tests/stpa/ -k "not Parallel" -v --tb=short -q
```

## 6. SP2/SP3 Design Verification

### QA-PAR-SP2-01: SP2 Stage 3 parallel independence

**Steps:**
1. Run the test for ParallelSP2-01 (SP2 Stage 3 slot-filling calls are independent per responsibility).
2. Verify three results are returned, each corresponding to a different responsibility.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP2-01" -v --tb=short
```

### QA-PAR-SP2-02: SP2 Stage 3 parallel equals sequential

**Steps:**
1. Run the test for ParallelSP2-02 (SP2 Stage 3 parallel calls produce same results as sequential).
2. Verify results with `max_workers=1` are identical to results with `max_workers=3`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP2-02" -v --tb=short
```

### QA-PAR-SP3-01: SP3 Stage 5 BDI independence

**Steps:**
1. Run the test for ParallelSP3-01 (SP3 Stage 5 BDI calls are independent per scenario).
2. Verify five results are returned in input order, each for a different scenario.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP3-01" -v --tb=short
```

### QA-PAR-SP3-02: SP3 Stage 6 calls independent within a scenario

**Steps:**
1. Run the test for ParallelSP3-02 (SP3 Stage 6 calls are independent within a scenario).
2. Verify three results are returned in input order for narrative, attack_tree, and gherkin.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP3-02" -v --tb=short
```

### QA-PAR-SP3-03: SP3 different scenarios can run concurrently

**Steps:**
1. Run the test for ParallelSP3-03 (SP3 different scenarios can run concurrently).
2. Verify twelve results are returned in input order with scenario grouping preserved.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP3-03" -v --tb=short
```

### QA-PAR-SP3-04: SP3 Stage 5 failure isolation

**Steps:**
1. Run the test for ParallelSP3-04 (SP3 Stage 5 failure for one scenario does not block others).
2. Verify the failing scenario has an error, while other scenarios succeed.

**Command:**
```bash
uv run pytest tests/stpa/ -k "ParallelSP3-04" -v --tb=short
```

## 7. Full Suite Execution

### QA-PAR-FULL-01: All parallel feature tests pass

**Steps:**
1. Run all tests matching the `Parallel` keyword pattern.
2. Verify all pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -k "Parallel" -v --tb=short
```

### QA-PAR-FULL-02: Existing STPA tests unaffected

**Steps:**
1. Run the full STPA test suite excluding parallel-specific tests.
2. Verify no new failures are introduced.

**Command:**
```bash
uv run pytest tests/stpa/ -k "not Parallel" -v --tb=short -q
```

### QA-PAR-FULL-03: Linting passes on new module

**Steps:**
1. Run ruff on the new parallel_llm source and test files.
2. Verify no lint errors.

**Command:**
```bash
ruff check src/scenario_forge/stpa/infra/parallel_llm.py tests/stpa/test_parallel_llm.py
```
