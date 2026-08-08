# End-to-End QA Suite: minItems Constraints + ConnectionSet Merge

## Scope

Two combined fixes for the SP1 System Model:

1. **Fix 1 — minItems constraints**: `LossAnalysis.hazards`,
   `LossAnalysis.security_constraints`, and `ControlStructure.responsibilities`
   gain `min_length=1` so constrained decoders cannot satisfy the schema with
   empty arrays. `risk_card_losses` and `use_case_losses` remain unconstrained.

2. **Fix 2 — ConnectionSet merge**: Stage 2 Call 3 uses a slim
   `ConnectionSet` response schema (coordination links, controlled processes,
   connection assignments) instead of the full `ControlStructure`. A merge
   function combines the `ResponsibilitySet` from Call 2 with the
   `ConnectionSet` from Call 3 to produce the final `ControlStructure`.

## QA Environment

- Project root: `/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge`
- Python: `uv run pytest`
- Pipeline CLI: `uv run scenario-forge generate`
- All commands run from project root unless noted.

---

## QA-1: minItems — empty critical arrays fail validation

**Goal**: Verify that empty `hazards`, `security_constraints`, or
`responsibilities` cause a validation error.

### Steps

1. Run the minItems unit tests:
   ```bash
   uv run pytest tests/stpa/test_sp1_minitems_constraints.py -v
   ```
2. Confirm all tests pass (each test constructs a model with an empty
   critical array and asserts `ValidationError` is raised).
3. Confirm tests for `risk_card_losses` and `use_case_losses` being empty
   assert validation **succeeds**.

### Expected output

- All test cases report `PASSED`.
- No `FAILED` or `ERROR` entries.

---

## QA-2: minItems — non-empty arrays pass validation (regression)

**Goal**: Verify that adding `min_length=1` does not break existing valid
models.

### Steps

1. Run the existing LossAnalysis and ControlStructure validation tests:
   ```bash
   uv run pytest tests/stpa/test_loss_analysis_validation.py -v
   uv run pytest tests/stpa/test_control_structure_validation.py -v
   ```
2. Confirm all previously passing tests still pass.

### Expected output

- All test cases report `PASSED`.

---

## QA-3: ConnectionSet — Call 3 produces and merges correctly

**Goal**: Verify that Stage 2 Call 3 uses `ConnectionSet` as its response
format and that the merge function produces a valid `ControlStructure`.

### Steps

1. Run the ConnectionSet merge unit tests:
   ```bash
   uv run pytest tests/stpa/test_sp1_connection_set_merge.py -v
   ```
2. Confirm all tests pass, including:
   - ConnSet-01: Call 3 produces a `ConnectionSet` (not `ControlStructure`)
   - ConnSet-02: `ConnectionSet` contains coordination links, controlled
     processes, and connection assignments
   - ConnSet-03: merge produces a valid `ControlStructure`
   - ConnSet-04: connection assignment updates feedback source by element ID
   - ConnSet-05: connection assignment updates control action target by
     element ID
   - ConnSet-06: coordination links appear in the final `ControlStructure`
   - ConnSet-07: controlled processes appear in the final `ControlStructure`
   - ConnSet-08: Call 3 is logged with stage `stage_2` and step
     `call_3_connections`
   - ConnSet-09: `control-structure.yaml` is written and contains a valid
     `ControlStructure`
   - ConnSet-10: Call 3 user prompt contains responsibilities from Call 2
   - ConnSet-11: revision still uses `ControlStructure` as response format

### Expected output

- All test cases report `PASSED`.

---

## QA-4: Stage 2 derivation — full pipeline regression

**Goal**: Verify that the existing Stage 2 derivation tests still pass after
the Call 3 response format change.

### Steps

1. Run the existing Stage 2 control structure tests:
   ```bash
   uv run pytest tests/stpa/test_sp1_control_structure.py -v
   ```
2. Confirm all tests pass. Tests that previously mocked `ControlStructure`
   as the Call 3 response should now mock `ConnectionSet` and verify the
   merge output.

### Expected output

- All test cases report `PASSED`.

---

## QA-5: Revision behavior unchanged

**Goal**: Verify that `run_revision()` in `critic.py` still uses
`response_format=ControlStructure` and produces a valid `ControlStructure`.

### Steps

1. Run the revision tests:
   ```bash
   uv run pytest tests/stpa/test_sp1_revision.py -v
   ```
2. Confirm all tests pass.

### Expected output

- All test cases report `PASSED`.

---

## QA-6: Full SP1 pipeline — end-to-end smoke test

**Goal**: Run the full SP1 pipeline with a mock LLM and verify that
`control-structure.yaml` is produced and valid.

### Steps

1. Run the full SP1 orchestration tests:
   ```bash
   uv run pytest tests/stpa/test_sp1_run.py -v
   ```
2. Confirm all tests pass, including:
   - The pipeline produces `control-structure.yaml` in the run directory
   - The file can be read back as a valid `ControlStructure`
   - The run manifest is written

### Expected output

- All test cases report `PASSED`.

---

## QA-7: Full test suite — no regressions

**Goal**: Run the entire test suite to confirm no regressions from either
fix.

### Steps

1. Run the full test suite:
   ```bash
   uv run pytest tests/ -x
   ```
2. Confirm all tests pass.

### Expected output

- All test cases report `PASSED`.
- No `FAILED` or `ERROR` entries.

---

## QA-8: Acceptance tests — Gherkin features pass

**Goal**: Verify that the acceptance tests derived from the new Gherkin
feature files pass.

### Steps

1. Parse and run acceptance tests for both new feature files:
   ```bash
   uv run pytest tests/stpa/acceptance/ -k "minitems or connection_set" -v
   ```
   (Or the project-specific acceptance command if different.)

2. Confirm all acceptance scenarios pass:
   - `sp1_minitems_constraints.feature`: MinItems-01 through MinItems-04
   - `sp1_connection_set_merge.feature`: ConnSet-01 through ConnSet-11

### Expected output

- All acceptance scenarios report `PASSED`.
