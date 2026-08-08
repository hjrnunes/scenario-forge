# SP1 System Model — End-to-End QA Suite

This document specifies the user-visible workflows that QA verifies for
SP1 (System Model) of the STPA-Sec Pipeline. All verification is done
through the Python import API, pytest execution, and filesystem
inspection — no project-internal APIs are used. Command-line flags are
user-interface affordances exposed to QA.

## 1. Module Structure Verification

### QA-SP1-STRUCT-01: Module layout matches spec

**Steps:**
1. Verify `src/scenario_forge/stpa/system_model/__init__.py` exists and is importable.
2. Verify the following SP1 modules exist and are importable:
   - `src/scenario_forge/stpa/system_model/loss_analysis.py` (Stage 1a)
   - `src/scenario_forge/stpa/system_model/profile.py` (Stage 1b)
   - `src/scenario_forge/stpa/system_model/control_structure.py` (Stage 2)
   - `src/scenario_forge/stpa/system_model/critic.py` (Completeness critic + revision)
   - `src/scenario_forge/stpa/system_model/heuristics.py` (Structural heuristics)
   - `src/scenario_forge/stpa/system_model/run.py` (Orchestration)
3. Verify `src/scenario_forge/stpa/system_model/prompts/` directory exists.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.system_model import loss_analysis, profile, control_structure, critic, heuristics, run
print('All SP1 modules importable')
"
```

### QA-SP1-STRUCT-02: Prompt templates exist

**Steps:**
1. Verify all 14 required Jinja2 template files exist in `src/scenario_forge/stpa/system_model/prompts/`.

**Command:**
```bash
for f in stage1a_system.j2 stage1a_user.j2 stage1b_system.j2 stage1b_user.j2 \
         stage2_call1_system.j2 stage2_call1_user.j2 \
         stage2_call2_system.j2 stage2_call2_user.j2 \
         stage2_call3_system.j2 stage2_call3_user.j2 \
         critic_system.j2 critic_user.j2 \
         revision_system.j2 revision_user.j2; do
  if [ ! -f "src/scenario_forge/stpa/system_model/prompts/$f" ]; then
    echo "Missing template: $f"
    exit 1
  fi
done
echo "All 14 prompt templates present"
```

### QA-SP1-STRUCT-03: Internal models are defined

**Steps:**
1. Verify the SP1 internal models are importable:
   - `RequirementSet`, `Requirement` from `system_model.control_structure`
   - `ResponsibilitySet` from `system_model.control_structure`
   - `CriticFindings`, `CriticGap` from `system_model.critic`

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.system_model.control_structure import RequirementSet, Requirement, ResponsibilitySet
from scenario_forge.stpa.system_model.critic import CriticFindings, CriticGap
print('All SP1 internal models importable')
"
```

### QA-SP1-STRUCT-04: No coupling to existing pipeline infrastructure

**Steps:**
1. Grep `src/scenario_forge/stpa/system_model/` for imports of `scenario_forge.pipeline.io`, `scenario_forge.manifest`, `scenario_forge.prompts`.
2. Verify none of those imports exist (SP1 uses `stpa/infra/` clean copy).

**Command:**
```bash
grep -rn "scenario_forge.pipeline.io\|scenario_forge.manifest\|scenario_forge.prompts" src/scenario_forge/stpa/system_model/ || echo "No coupling found"
```

### QA-SP1-STRUCT-05: Foundation models imported, not copied

**Steps:**
1. Verify `src/scenario_forge/stpa/system_model/` imports `LossAnalysis`, `ControlStructure` from `stpa/models/`.
2. Verify it imports `CapabilityProfile`, `Stage1Profile` from `scenario_forge.models.capability_profile`.
3. Verify it imports `RiskCard` from `scenario_forge.models.risk_card`.

**Command:**
```bash
grep -rn "from scenario_forge.stpa.models" src/scenario_forge/stpa/system_model/
grep -rn "from scenario_forge.models.capability_profile import\|from scenario_forge.models.risk_card import" src/scenario_forge/stpa/system_model/
```

## 2. Stage 1a — Loss Analysis

### QA-SP1-LA-01: Stage 1a validation rules

**Steps:**
1. Run the test suite for Stage 1a loss analysis.
2. Verify tests cover: valid LLM response, dual-source provenance (risk_card + use_case), cross-reference validation, duplicate ID rejection, call logging, YAML output.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_loss or SP1_LA or stage_1a" -v --tb=short -q
```

### QA-SP1-LA-02: Loss analysis YAML output

**Steps:**
1. Run Stage 1a with a mock LLM that returns valid loss analysis JSON.
2. Verify `loss-analysis.yaml` is written to the run directory.
3. Read the file back and verify it is a valid `LossAnalysis` model.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_loss_analysis_yaml or SP1_LA_09" -v --tb=short -q
```

### QA-SP1-LA-03: Call logging for Stage 1a

**Steps:**
1. Run Stage 1a with a mock LLM.
2. Verify a call log entry is appended to `calls.jsonl` with `stage: stage_1a` and `step: loss_analysis`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_loss_analysis_call_log or SP1_LA_08" -v --tb=short -q
```

## 3. Stage 1b — Capability Profile

### QA-SP1-CP-01: Stage 1b validation rules

**Steps:**
1. Run the test suite for Stage 1b capability profile.
2. Verify tests cover: valid LLM response → Stage1Profile → CapabilityProfile promotion, --profile flag skips LLM call, invalid KC sub-codes, call logging, YAML output.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_cap or SP1_CP or stage_1b" -v --tb=short -q
```

### QA-SP1-CP-02: Profile flag skips Stage 1b

**Steps:**
1. Run Stage 1b with a pre-built `capability-profile.yaml` and the `--profile` flag.
2. Verify no LLM call is made for Stage 1b (no `stage_1b` entry in call log).
3. Verify the loaded profile is returned.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_profile_flag or SP1_CP_03" -v --tb=short -q
```

### QA-SP1-CP-03: Loss analysis context in prompt

**Steps:**
1. Run Stage 1b with a mock LLM and a known loss analysis.
2. Verify the user prompt contains loss analysis context (losses, hazards).

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_profile_context or SP1_CP_08" -v --tb=short -q
```

## 4. Stage 2 — Control Structure Derivation

### QA-SP1-S2-01: Stage 2 Call 1 — Requirements

**Steps:**
1. Run tests for Stage 2 Call 1 (requirements derivation).
2. Verify tests cover: valid RequirementSet, classification (control/constraint), source_constraint references, invalid classification, call logging.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_s2_call1 or SP1_S2_01 or SP1_S2_02 or SP1_S2_03 or SP1_S2_04 or SP1_S2_05" -v --tb=short -q
```

### QA-SP1-S2-02: Stage 2 Call 2 — Responsibilities

**Steps:**
1. Run tests for Stage 2 Call 2 (responsibilities + elements).
2. Verify tests cover: valid ResponsibilitySet, controlled processes, ElementRef validation, call logging.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_s2_call2 or SP1_S2_06 or SP1_S2_07 or SP1_S2_08 or SP1_S2_09" -v --tb=short -q
```

### QA-SP1-S2-03: Stage 2 Call 3 — Connections

**Steps:**
1. Run tests for Stage 2 Call 3 (connections + assembly).
2. Verify tests cover: valid ControlStructure, coordination links, call logging, YAML output.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_s2_call3 or SP1_S2_10 or SP1_S2_11 or SP1_S2_12 or SP1_S2_13" -v --tb=short -q
```

### QA-SP1-S2-04: Sequential call chaining

**Steps:**
1. Run tests verifying Call 2 receives Call 1 output and Call 3 receives Call 2 output.
2. Verify the prompts contain the upstream call's structured output.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_s2_chaining or SP1_S2_14 or SP1_S2_15" -v --tb=short -q
```

## 5. Structural Heuristics

### QA-SP1-HEUR-01: Heuristic checks

**Steps:**
1. Run tests for structural heuristics.
2. Verify tests cover: valid structure passes, missing PM/CA/FB fails, orphan PM warning, orphan CP fails, hazard tracing, re-run after revision, errors after revision flagged.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_heur or SP1_HEUR" -v --tb=short -q
```

## 6. Completeness Critic

### QA-SP1-CRITIC-01: Critic validation rules

**Steps:**
1. Run tests for the completeness critic.
2. Verify tests cover: valid CriticFindings, empty gaps, gap type validation, gap fields, checklist results, call logging, taxonomy probes, revision trigger logic.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_critic or SP1_CRITIC" -v --tb=short -q
```

## 7. Revision

### QA-SP1-REV-01: Revision behavior

**Steps:**
1. Run tests for revision.
2. Verify tests cover: valid revised ControlStructure, call logging, prompt content, heuristic re-run, single attempt, no revision when justified, manifest flagging, structure replacement.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_rev or SP1_REV" -v --tb=short -q
```

## 8. Solution-Neutrality

### QA-SP1-NEUT-01: Solution-neutrality check

**Steps:**
1. Run tests for the solution-neutrality post-call check.
2. Verify tests cover: component name detection in responsibility/PM/CA/FB descriptions, case-insensitive matching, solution-neutral descriptions produce no warnings, check runs after Stage 2.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_neut or SP1_NEUT" -v --tb=short -q
```

## 9. Run Orchestration

### QA-SP1-RUN-01: Full run produces all artifacts

**Steps:**
1. Run the full SP1 pipeline with mock LLM responses.
2. Verify `loss-analysis.yaml`, `capability-profile.yaml`, and `control-structure.yaml` all exist in the run directory.
3. Verify all three files load as valid Pydantic models.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_run_artifacts or SP1_RUN_01" -v --tb=short -q
```

### QA-SP1-RUN-02: Call logging for full run

**Steps:**
1. Run the full SP1 pipeline with mock LLM responses.
2. Verify `calls.jsonl` contains entries for `stage_1a`, `stage_1b`, and `stage_2`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_run_call_log or SP1_RUN_03" -v --tb=short -q
```

### QA-SP1-RUN-03: Run manifest written

**Steps:**
1. Run the full SP1 pipeline with mock LLM responses.
2. Verify a run manifest is written with `stage_summary`, `input_hashes`, `prompt_hashes`, and `critic_findings`.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_run_manifest or SP1_RUN_04" -v --tb=short -q
```

### QA-SP1-RUN-04: Profile flag in full run

**Steps:**
1. Run the full SP1 pipeline with the `--profile` flag and a pre-built profile.
2. Verify no `stage_1b` entry in the call log.
3. Verify the pre-built profile is loaded and used.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_run_profile_flag or SP1_RUN_12" -v --tb=short -q
```

## 10. Integration with Fixtures

### QA-SP1-FIX-01: Loss analysis fixture feeds Stage 2

**Steps:**
1. Load `loss_analysis_klarna.yaml` fixture.
2. Feed it to Stage 2 (with mock LLM responses).
3. Verify the resulting `ControlStructure` passes structural heuristics when checked with the loss analysis.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_fixture_integration or SP1_FIX" -v --tb=short -q
```

### QA-SP1-FIX-02: Control structure fixture runs through critic

**Steps:**
1. Load `control_structure_klarna.yaml` fixture.
2. Run the completeness critic on it (with mock LLM).
3. Verify the critic produces a valid `CriticFindings` model (either with gaps or confirming completeness).

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_fixture_critic or SP1_FIX_02" -v --tb=short -q
```

## 11. Full Test Suite Execution

### QA-SP1-FULL-01: All SP1 tests pass

**Steps:**
1. Run the complete SP1 test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1" -v --tb=short -q
```

### QA-SP1-FULL-02: Foundation tests still pass

**Steps:**
1. Run the foundation STPA tests (non-SP1).
2. Verify no regressions in the foundation.

**Command:**
```bash
uv run pytest tests/stpa/ -k "not sp1" -v --tb=short -q
```

### QA-SP1-FULL-03: Existing pipeline tests unaffected

**Steps:**
1. Run the existing test suite (non-STPA).
2. Verify no new failures are introduced by SP1.

**Command:**
```bash
uv run pytest tests/ --ignore=tests/stpa/ -q --tb=line
```

### QA-SP1-FULL-04: Linting passes

**Steps:**
1. Run ruff on the new SP1 source and test files.
2. Verify no lint errors.

**Command:**
```bash
ruff check src/scenario_forge/stpa/system_model/ tests/stpa/
```
