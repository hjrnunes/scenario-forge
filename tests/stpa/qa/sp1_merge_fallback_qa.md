# End-to-End QA Suite: Merge Fallback Degradation for ConnectionSet Validation Failures

## Scope

When `merge_connection_set()` in `derive_control_structure()` fails because
the Call 3 `ConnectionSet` contains invalid cross-references (e.g., a
`ProcessModelPart`'s `feedback_source` uses a FeedbackChannel ID as a
ControlledProcess ID — a namespace confusion), the pipeline must fall back
to building a `ControlStructure` from the `ResponsibilitySet` alone (Call 2
output) without coordination links. The fallback structure is written to
`control-structure.yaml`, passes through heuristics and critic, and the
pipeline completes without crashing. The merge failure is logged to
`calls.jsonl` and recorded in the run manifest `stage_errors`.

When the merge succeeds (normal case), the full `ControlStructure` with
coordination links is produced — behavior unchanged.

## QA Environment

- Project root: `/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge`
- Python: `uv run pytest`
- All commands run from project root unless noted.
- Test fixtures use `MockLLMClient` from `tests/stpa/sp1_helpers.py` to
  inject canned LLM responses, including invalid `ConnectionSet` payloads
  that trigger `ValidationError` during merge.

---

## QA-1: Merge failure triggers fallback to ResponsibilitySet-only ControlStructure

**Goal**: Verify that three distinct types of invalid `ConnectionSet` all
trigger the fallback path and produce a valid `ControlStructure` without
crashing.

### Steps

1. Run the merge fallback unit tests covering all three violation types:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_01" -v
   ```
2. Confirm each violation type produces a `ControlStructure` that passes
   foundation validation:
   - Namespace confusion: `feedback_source` uses a FeedbackChannel ID as a
     ControlledProcess ID
   - Coordination link source referencing a non-existent responsibility
   - Coordination link `shared_pm` referencing a non-existent PM

### Expected output

- All test cases report `PASSED`.
- No `FAILED` or `ERROR` entries.

---

## QA-2: Fallback ControlStructure has empty coordination_links

**Goal**: Verify that the fallback `ControlStructure` has no coordination
links (they come from Call 3, which was rejected).

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_02" -v
   ```
2. Confirm the fallback `ControlStructure.coordination_links` is an empty
   list.

### Expected output

- Test case reports `PASSED`.

---

## QA-3: Fallback ControlStructure preserves responsibilities from Call 2

**Goal**: Verify that the fallback `ControlStructure` contains all
responsibilities from the Call 2 `ResponsibilitySet`.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_03" -v
   ```
2. Confirm the fallback `ControlStructure` contains `RESP-1` and `RESP-2`
   with their descriptions, process model parts, control actions, and
   feedback channels intact from Call 2.

### Expected output

- Test case reports `PASSED`.

---

## QA-4: Fallback ControlStructure preserves controlled_processes from Call 2

**Goal**: Verify that the fallback `ControlStructure` contains
`controlled_processes` from the Call 2 `ResponsibilitySet`.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_04" -v
   ```
2. Confirm the fallback `ControlStructure` contains `CP-1` from the Call 2
   `ResponsibilitySet`.

### Expected output

- Test case reports `PASSED`.

---

## QA-5: Merge failure is logged to calls.jsonl

**Goal**: Verify that when the merge fails, a call log entry is appended to
`calls.jsonl` with `success=false`, stage `stage_2`, step
`merge_connection_set`, and an error message.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_05" -v
   ```
2. Read the `calls.jsonl` file in the test's temporary run directory and
   confirm an entry exists with:
   - `"stage": "stage_2"`
   - `"step": "merge_connection_set"`
   - `"success": false`
   - `"error"` field present and non-empty

### Expected output

- Test case reports `PASSED`.

---

## QA-6: Merge failure recorded in run manifest stage_errors

**Goal**: Verify that during a full SP1 run, the merge failure is recorded
in the run manifest's `stage_errors` field.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_06" -v
   ```
2. Read `run-manifest.yaml` in the test's temporary run directory and
   confirm:
   - `stage_errors` field exists and is non-empty
   - The stage_errors list includes a description mentioning the merge
     failure

### Expected output

- Test case reports `PASSED`.

---

## QA-7: Fallback ControlStructure written to control-structure.yaml

**Goal**: Verify that even on merge failure, the fallback
`ControlStructure` is written to `control-structure.yaml` and can be read
back as a valid model.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_07" -v
   ```
2. Confirm `control-structure.yaml` exists in the run directory.
3. Read it back with `read_yaml(path, ControlStructure)` and verify it
   parses into a valid `ControlStructure` with `responsibilities` populated
   and `coordination_links` empty.

### Expected output

- Test case reports `PASSED`.

---

## QA-8: Fallback ControlStructure passes through heuristics

**Goal**: Verify that the fallback `ControlStructure` (without coordination
links) passes through the structural heuristics stage. Heuristics may
produce warnings about missing coordination links, but the pipeline should
proceed to the critic and complete.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_08" -v
   ```
2. Confirm the `SP1RunResult.control_structure` is not `None`.
3. Confirm the heuristic result is available (warnings may be present, but
   the pipeline does not crash).

### Expected output

- Test case reports `PASSED`.

---

## QA-9: Pipeline does not crash on merge failure during full SP1 run

**Goal**: Verify that the full SP1 pipeline (`run_sp1()`) completes without
raising an exception when the merge fails, and produces a partial result
with the fallback `ControlStructure` and the merge failure in
`stage_errors`.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_09" -v
   ```
2. Confirm:
   - No exception is raised
   - `SP1RunResult.control_structure` is not `None` (fallback was used)
   - `SP1RunResult.stage_errors` contains the merge failure description

### Expected output

- Test case reports `PASSED`.

---

## QA-10: Successful merge produces full ControlStructure with coordination links

**Goal**: Verify that the normal case (valid `ConnectionSet`) is unchanged —
the merge succeeds and the full `ControlStructure` with coordination links
is produced. No merge failure is logged.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_merge_fallback.py -k "MergeFallback_10" -v
   ```
2. Confirm:
   - The `ControlStructure` contains coordination link `CL-1` with source
     `RESP-1` and target `RESP-2`
   - The control structure passes foundation validation
   - No merge failure call log entry exists in `calls.jsonl`

### Expected output

- Test case reports `PASSED`.

---

## QA-11: Existing ConnectionSet merge tests — no regression

**Goal**: Verify that the existing ConnectionSet merge tests (ConnSet-01
through ConnSet-11) still pass after the fallback fix is added.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/test_sp1_connection_set_merge.py -v
   ```
2. Confirm all existing tests pass unchanged.

### Expected output

- All test cases report `PASSED`.

---

## QA-12: Full SP1 test suite — no regressions

**Goal**: Run the entire SP1 test suite to confirm no regressions from the
merge fallback fix.

### Steps

1. Run:
   ```bash
   uv run pytest tests/stpa/ -x -v
   ```
2. Confirm all tests pass.

### Expected output

- All test cases report `PASSED`.
- No `FAILED` or `ERROR` entries.

---

## QA-13: Acceptance tests — Gherkin feature passes

**Goal**: Verify that the acceptance tests derived from the new Gherkin
feature file pass.

### Steps

1. Run acceptance tests for the merge fallback feature:
   ```bash
   uv run pytest tests/stpa/acceptance/ -k "merge_fallback" -v
   ```
   (Or the project-specific acceptance command if different.)

2. Confirm all acceptance scenarios pass:
   - `MergeFallback-01`: invalid ConnectionSet triggers fallback (3 examples)
   - `MergeFallback-02`: fallback has empty coordination_links
   - `MergeFallback-03`: fallback preserves responsibilities
   - `MergeFallback-04`: fallback preserves controlled_processes
   - `MergeFallback-05`: merge failure logged to calls.jsonl
   - `MergeFallback-06`: merge failure recorded in run manifest stage_errors
   - `MergeFallback-07`: fallback written to control-structure.yaml
   - `MergeFallback-08`: fallback passes through heuristics
   - `MergeFallback-09`: pipeline does not crash on merge failure
   - `MergeFallback-10`: successful merge unchanged

### Expected output

- All acceptance scenarios report `PASSED`.
