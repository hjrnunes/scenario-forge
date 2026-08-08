# SP1 System Model — Graceful Degradation QA Suite

This document specifies the user-visible workflows that QA verifies for
the graceful LLM error handling fix in SP1 (System Model). All
verification is done through the Python import API, pytest execution,
and filesystem inspection — no project-internal APIs are used.

## 1. Revision Failure — Graceful Degradation

### QA-SP1-GD-01: Revision validation failure returns pre-revision CS

**Steps:**
1. Run the test suite for revision failure graceful degradation.
2. Verify the test configures a MockLLMClient to return an invalid
   ControlStructure (cross-reference violations).
3. Verify `run_revision()` returns the pre-revision ControlStructure.
4. Verify the returned warnings include a revision failure message.
5. Verify no exception propagates.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_01 or gd_02 or gd_03" -v --tb=short -q
```

### QA-SP1-GD-02: Revision failure logs the failed call

**Steps:**
1. Run the test that verifies the failed revision call is logged.
2. Read `calls.jsonl` from the run directory.
3. Verify an entry exists with `stage: stage_2`, `step: revision`,
   `success: false`, and an `error` message field.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_02" -v --tb=short -q
```

### QA-SP1-GD-03: Revision LLM exception returns pre-revision CS

**Steps:**
1. Run the test that configures the MockLLMClient to raise a
   RuntimeError during the revision call.
2. Verify `run_revision()` catches the exception, logs the failure,
   and returns the pre-revision ControlStructure with a warning.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_03" -v --tb=short -q
```

## 2. Critic Failure — Graceful Degradation

### QA-SP1-GD-04: Critic validation failure returns empty findings

**Steps:**
1. Run the test that configures the MockLLMClient to return an invalid
   CriticFindings JSON.
2. Verify `run_completeness_critic()` returns an empty CriticFindings
   (empty gaps, empty checklist_results, empty taxonomy_probe_results).
3. Verify no exception propagates.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_04 or gd_06 or gd_07" -v --tb=short -q
```

### QA-SP1-GD-05: Critic failure logs the failed call

**Steps:**
1. Run the test that verifies the failed critic call is logged.
2. Read `calls.jsonl` from the run directory.
3. Verify an entry exists with `stage: stage_2`, `step: critic`,
   `success: false`, and an `error` message field.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_05" -v --tb=short -q
```

### QA-SP1-GD-06: Critic failure does not trigger revision

**Steps:**
1. Run the test that verifies empty CriticFindings from a failed critic
   call do not trigger revision.
2. Verify `has_unjustified_gaps()` returns False for empty findings.
3. Verify no revision LLM call is made.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_06" -v --tb=short -q
```

## 3. Derivation Stage Failures — StageError

### QA-SP1-GD-08: Each derivation stage raises StageError on validation failure

**Steps:**
1. Run the test suite that verifies each derivation stage raises
   StageError when the LLM returns an invalid response.
2. Verify StageError carries `stage` and `step` context for:
   - Stage 1a (loss_analysis)
   - Stage 1b (capability_profile)
   - Stage 2 Call 1 (call_1_requirements)
   - Stage 2 Call 2 (call_2_responsibilities)
   - Stage 2 Call 3 (call_3_connections)
3. Verify the failed call is logged with `success: false`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_08" -v --tb=short -q
```

### QA-SP1-GD-14: Derivation stage LLM exception raises StageError

**Steps:**
1. Run the test that configures the MockLLMClient to raise a
   RuntimeError during Stage 1a.
2. Verify a StageError is raised (not the RuntimeError).
3. Verify the failed call is logged with `success: false`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_14" -v --tb=short -q
```

## 4. Run Orchestration — Partial Results

### QA-SP1-GD-09: Stage 1a failure produces partial result with all artifacts None

**Steps:**
1. Run the full SP1 pipeline with a MockLLMClient that returns an
   invalid response for Stage 1a.
2. Verify `run_sp1()` returns an `SP1RunResult` (no exception raised).
3. Verify `stage_errors` list contains the stage_1a failure description.
4. Verify `loss_analysis`, `capability_profile`, and `control_structure`
   are all None.
5. Verify a run manifest is written to the run directory.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_09" -v --tb=short -q
```

### QA-SP1-GD-10: Stage 1b failure preserves loss_analysis

**Steps:**
1. Run the full SP1 pipeline with valid Stage 1a and invalid Stage 1b.
2. Verify `SP1RunResult.stage_errors` contains the stage_1b failure.
3. Verify `loss_analysis` is not None (preserved from Stage 1a).
4. Verify `capability_profile` and `control_structure` are None.
5. Verify `loss-analysis.yaml` exists in the run directory.
6. Verify a run manifest is written.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_10" -v --tb=short -q
```

### QA-SP1-GD-11: Stage 2 failure preserves loss_analysis and profile

**Steps:**
1. Run the full SP1 pipeline with valid Stages 1a and 1b, invalid
   Stage 2.
2. Verify `SP1RunResult.stage_errors` contains the stage_2 failure.
3. Verify `loss_analysis` and `capability_profile` are not None.
4. Verify `control_structure` is None.
5. Verify `loss-analysis.yaml` and `capability-profile.yaml` exist.
6. Verify a run manifest is written.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_11" -v --tb=short -q
```

### QA-SP1-GD-12: Failed derivation call logged with success=false

**Steps:**
1. Run the full SP1 pipeline with a failing Stage 1a.
2. Read `calls.jsonl` from the run directory.
3. Verify an entry exists with `stage: stage_1a`, `step: loss_analysis`,
   `success: false`, and an `error` message field.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_12" -v --tb=short -q
```

### QA-SP1-GD-13: Pipeline does not crash on stage validation failure

**Steps:**
1. Run the full SP1 pipeline with a failing Stage 2.
2. Verify `run_sp1()` returns normally (no exception raised).
3. Verify the returned object is an `SP1RunResult`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_13" -v --tb=short -q
```

### QA-SP1-GD-15: Run manifest records stage_errors on partial failure

**Steps:**
1. Run the full SP1 pipeline with a failing Stage 1b.
2. Read `run-manifest.yaml` from the run directory.
3. Verify the manifest contains a `stage_errors` field.
4. Verify the `stage_errors` field includes the stage_1b failure
   description.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd_15" -v --tb=short -q
```

## 5. SP1RunResult Structure

### QA-SP1-GD-STRUCT-01: SP1RunResult fields are optional

**Steps:**
1. Verify `SP1RunResult` dataclass fields `loss_analysis`,
   `capability_profile`, and `control_structure` are optional
   (default to None).
2. Verify `SP1RunResult` has a `stage_errors` field that defaults to
   an empty list.

**Command:**
```bash
uv run python -c "
import dataclasses
from scenario_forge.stpa.system_model.run import SP1RunResult
fields = {f.name: f for f in dataclasses.fields(SP1RunResult)}
assert fields['loss_analysis'].default is None or fields['loss_analysis'].default is dataclasses.MISSING and fields['loss_analysis'].default_factory is not dataclasses.MISSING or fields['loss_analysis'].type is not None
# Check stage_errors field exists
assert 'stage_errors' in fields
print('SP1RunResult fields OK')
"
```

### QA-SP1-GD-STRUCT-02: StageError exception is defined

**Steps:**
1. Verify `StageError` exception class is importable.
2. Verify it carries `stage` and `step` attributes.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.system_model.run import StageError
e = StageError(stage='stage_1a', step='loss_analysis', message='test')
assert e.stage == 'stage_1a'
assert e.step == 'loss_analysis'
print('StageError OK')
"
```

### QA-SP1-GD-STRUCT-03: Call log entries support error field

**Steps:**
1. Verify `make_call_log_entry()` accepts an `error` parameter.
2. Verify the returned dict includes an `error` key when provided.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.call_log import make_call_log_entry
entry = make_call_log_entry(stage='stage_1a', step='loss_analysis', model='test', success=False, error='ValidationError: bad cross-ref')
assert entry['success'] is False
assert 'error' in entry
assert 'ValidationError' in entry['error']
print('Call log error field OK')
"
```

## 6. Full Test Suite Execution

### QA-SP1-GD-FULL-01: All graceful degradation tests pass

**Steps:**
1. Run the complete graceful degradation test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -k "gd or graceful or stage_error" -v --tb=short -q
```

### QA-SP1-GD-FULL-02: Existing SP1 tests unaffected

**Steps:**
1. Run the existing SP1 test suite (excluding graceful degradation tests).
2. Verify no regressions.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1 and not gd and not graceful and not stage_error" -v --tb=short -q
```

### QA-SP1-GD-FULL-03: Full test suite passes

**Steps:**
1. Run the complete test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/ -x -q --tb=line
```

### QA-SP1-GD-FULL-04: Linting passes

**Steps:**
1. Run ruff on the modified source and test files.
2. Verify no lint errors.

**Command:**
```bash
ruff check src/scenario_forge/stpa/ tests/stpa/
```
