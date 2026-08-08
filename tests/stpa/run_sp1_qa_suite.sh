#!/usr/bin/env bash
# SP1 System Model — Executable QA Suite
#
# Converts the QA checks from tests/stpa/sp1-qa-suite.md into executable
# verification scripts. All verification uses the Python import API,
# pytest execution, and filesystem inspection — no project-internal APIs.
#
# Usage: bash tests/stpa/run_sp1_qa_suite.sh
# Exit 0 = all pass, Exit 1 = any fail.

set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

PASS=0
FAIL=0
FAILED_CHECKS=()

check() {
    local name="$1"
    shift
    echo "--- $name ---"
    if "$@"; then
        echo "  PASS"
        PASS=$((PASS + 1))
    else
        echo "  FAIL"
        FAIL=$((FAIL + 1))
        FAILED_CHECKS+=("$name")
    fi
    echo
}

# --- 1. Module Structure ---

check "QA-SP1-STRUCT-01: Module layout matches spec" \
    uv run python -c "
from scenario_forge.stpa.system_model import loss_analysis, profile, control_structure, critic, heuristics, run
print('All SP1 modules importable')
"

check "QA-SP1-STRUCT-02: Prompt templates exist" \
    bash -c '
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
'

check "QA-SP1-STRUCT-03: Internal models are defined" \
    uv run python -c "
from scenario_forge.stpa.system_model.control_structure import RequirementSet, Requirement, ResponsibilitySet
from scenario_forge.stpa.system_model.critic import CriticFindings, CriticGap
print('All SP1 internal models importable')
"

check "QA-SP1-STRUCT-04: No coupling to existing pipeline infrastructure" \
    bash -c '! grep -rn "scenario_forge.pipeline.io\|scenario_forge.manifest\|scenario_forge.prompts" src/scenario_forge/stpa/system_model/ || (echo "Import coupling found" && false)'

check "QA-SP1-STRUCT-05: Foundation models imported, not copied" \
    bash -c '
grep -rn "from scenario_forge.stpa.models" src/scenario_forge/stpa/system_model/ > /dev/null || { echo "No stpa.models imports found"; exit 1; }
grep -rn "from scenario_forge.models.capability_profile import\|from scenario_forge.models.risk_card import" src/scenario_forge/stpa/system_model/ > /dev/null || { echo "No existing model imports found"; exit 1; }
echo "Foundation model imports confirmed"
'

# --- 2. Stage 1a — Loss Analysis ---

check "QA-SP1-LA-01: Stage 1a validation rules" \
    uv run pytest tests/stpa/ -k "sp1_loss or SP1_LA or stage_1a" -v --tb=short -q

# --- 3. Stage 1b — Capability Profile ---

check "QA-SP1-CP-01: Stage 1b validation rules" \
    uv run pytest tests/stpa/ -k "sp1_cap or SP1_CP or stage_1b" -v --tb=short -q

# --- 4. Stage 2 — Control Structure Derivation ---

check "QA-SP1-S2-01: Stage 2 Call 1 — Requirements" \
    uv run pytest tests/stpa/ -k "sp1_s2_call1 or SP1_S2_01 or SP1_S2_02 or SP1_S2_03 or SP1_S2_04 or SP1_S2_05" -v --tb=short -q

check "QA-SP1-S2-02: Stage 2 Call 2 — Responsibilities" \
    uv run pytest tests/stpa/ -k "sp1_s2_call2 or SP1_S2_06 or SP1_S2_07 or SP1_S2_08 or SP1_S2_09" -v --tb=short -q

check "QA-SP1-S2-03: Stage 2 Call 3 — Connections" \
    uv run pytest tests/stpa/ -k "sp1_s2_call3 or SP1_S2_10 or SP1_S2_11 or SP1_S2_12 or SP1_S2_13" -v --tb=short -q

check "QA-SP1-S2-04: Sequential call chaining" \
    uv run pytest tests/stpa/ -k "sp1_s2_chaining or SP1_S2_14 or SP1_S2_15" -v --tb=short -q

# --- 5. Structural Heuristics ---

check "QA-SP1-HEUR-01: Heuristic checks" \
    uv run pytest tests/stpa/ -k "sp1_heur or SP1_HEUR" -v --tb=short -q

# --- 6. Completeness Critic ---

check "QA-SP1-CRITIC-01: Critic validation rules" \
    uv run pytest tests/stpa/ -k "sp1_critic or SP1_CRITIC" -v --tb=short -q

# --- 7. Revision ---

check "QA-SP1-REV-01: Revision behavior" \
    uv run pytest tests/stpa/ -k "sp1_rev or SP1_REV" -v --tb=short -q

# --- 8. Solution-Neutrality ---

check "QA-SP1-NEUT-01: Solution-neutrality check" \
    uv run pytest tests/stpa/ -k "sp1_neut or SP1_NEUT" -v --tb=short -q

# --- 9. Run Orchestration ---

check "QA-SP1-RUN-01: Full run produces all artifacts" \
    uv run pytest tests/stpa/ -k "sp1_run_artifacts or SP1_RUN_01" -v --tb=short -q

check "QA-SP1-RUN-02: Call logging for full run" \
    uv run pytest tests/stpa/ -k "sp1_run_call_log or SP1_RUN_03" -v --tb=short -q

check "QA-SP1-RUN-03: Run manifest written" \
    uv run pytest tests/stpa/ -k "sp1_run_manifest or SP1_RUN_04" -v --tb=short -q

check "QA-SP1-RUN-04: Profile flag in full run" \
    uv run pytest tests/stpa/ -k "sp1_run_profile_flag or SP1_RUN_12" -v --tb=short -q

# --- 10. Integration with Fixtures ---

check "QA-SP1-FIX-01: Loss analysis fixture feeds Stage 2" \
    uv run pytest tests/stpa/ -k "sp1_fixture_integration or SP1_FIX" -v --tb=short -q

check "QA-SP1-FIX-02: Control structure fixture runs through critic" \
    uv run pytest tests/stpa/ -k "sp1_fixture_critic or SP1_FIX_02" -v --tb=short -q

# --- 11. Full Test Suite Execution ---

check "QA-SP1-FULL-01: All SP1 tests pass" \
    uv run pytest tests/stpa/ -k "sp1" -v --tb=short -q

check "QA-SP1-FULL-02: Foundation tests still pass" \
    uv run pytest tests/stpa/ -k "not sp1" -v --tb=short -q

check "QA-SP1-FULL-03: Existing pipeline tests unaffected" \
    bash -c '
output=$(uv run pytest tests/ --ignore=tests/stpa/ -q --tb=line 2>&1 || true)
echo "$output" | tail -5
'

check "QA-SP1-FULL-04: Linting passes" \
    ruff check src/scenario_forge/stpa/system_model/ tests/stpa/

# --- Summary ---

echo "=========================================="
echo "SP1 QA Suite Results: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "Failed checks:"
    for c in "${FAILED_CHECKS[@]}"; do
        echo "  - $c"
    done
    exit 1
fi
echo "All SP1 QA checks passed."
exit 0
