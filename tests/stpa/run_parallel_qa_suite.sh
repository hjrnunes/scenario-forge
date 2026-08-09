#!/usr/bin/env bash
# Parallel LLM Call Infrastructure — Executable QA Suite
#
# Converts the QA checks from tests/stpa/parallel-qa-suite.md into
# executable verification scripts. All verification uses pytest
# execution, CLI invocation, filesystem inspection, and module import
# checks — no project-internal APIs are used.
#
# Usage: bash tests/stpa/run_parallel_qa_suite.sh
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

check "QA-PAR-STRUCT-01: parallel_llm module exists and is importable" \
    uv run python -c "
from scenario_forge.stpa.infra.parallel_llm import (
    parallel_safe_llm_calls, LLMCallSpec, LLMCallResult,
)
print('parallel_llm module importable with required symbols')
"

check "QA-PAR-STRUCT-02: parallel_llm has no coupling to existing pipeline" \
    bash -c '! grep -rn "scenario_forge.pipeline.io\|scenario_forge.manifest\|scenario_forge.prompts" src/scenario_forge/stpa/infra/parallel_llm.py || (echo "Import coupling found" && false)'

check "QA-PAR-STRUCT-03: parallel_llm reuses safe_llm_call from llm_helpers" \
    bash -c 'grep -n "safe_llm_call" src/scenario_forge/stpa/infra/parallel_llm.py'

# --- 2. Parallel Execution ---

check "QA-PAR-EXEC-01: Multiple calls execute and return results" \
    uv run pytest tests/stpa/ -k "parallel_llm_01" -v --tb=short -q

check "QA-PAR-EXEC-02: Results returned in input order" \
    uv run pytest tests/stpa/ -k "parallel_llm_02" -v --tb=short -q

check "QA-PAR-EXEC-03: Failed call does not affect other calls" \
    uv run pytest tests/stpa/ -k "parallel_llm_03" -v --tb=short -q

check "QA-PAR-EXEC-04: Thread-safe call log writing" \
    uv run pytest tests/stpa/ -k "parallel_llm_04" -v --tb=short -q

check "QA-PAR-EXEC-05: max_workers controls concurrency" \
    uv run pytest tests/stpa/ -k "parallel_llm_05" -v --tb=short -q

check "QA-PAR-EXEC-06: Single call degenerate case" \
    uv run pytest tests/stpa/ -k "parallel_llm_06" -v --tb=short -q

check "QA-PAR-EXEC-07: Empty call list returns empty results" \
    uv run pytest tests/stpa/ -k "parallel_llm_07" -v --tb=short -q

check "QA-PAR-EXEC-08: Temperature propagated to each call" \
    uv run pytest tests/stpa/ -k "parallel_llm_12" -v --tb=short -q

# --- 3. LLMCallSpec and LLMCallResult ---

check "QA-PAR-SPEC-01: LLMCallSpec bundles call arguments" \
    uv run pytest tests/stpa/ -k "parallel_llm_08" -v --tb=short -q

check "QA-PAR-SPEC-02: LLMCallResult bundles result with call_spec" \
    uv run pytest tests/stpa/ -k "parallel_llm_09 or parallel_llm_10" -v --tb=short -q

check "QA-PAR-SPEC-03: Call log entries distinguish success and failure" \
    uv run pytest tests/stpa/ -k "parallel_llm_11" -v --tb=short -q

# --- 4. max_workers Configuration ---

check "QA-PAR-CONFIG-01: run_sp1 accepts max_workers parameter" \
    uv run pytest tests/stpa/ -k "parallel_config_01" -v --tb=short -q

check "QA-PAR-CONFIG-02: max_workers default is 1" \
    uv run pytest tests/stpa/ -k "parallel_config_02" -v --tb=short -q

check "QA-PAR-CONFIG-03: Run manifest records max_workers" \
    uv run pytest tests/stpa/ -k "parallel_config_03" -v --tb=short -q

check "QA-PAR-CONFIG-04: --max-workers CLI flag passes value" \
    uv run pytest tests/stpa/ -k "parallel_config_04" -v --tb=short -q

check "QA-PAR-CONFIG-05: --max-workers CLI flag defaults to 1" \
    uv run pytest tests/stpa/ -k "parallel_config_05" -v --tb=short -q

check "QA-PAR-CONFIG-06: --max-workers accepts valid values" \
    uv run pytest tests/stpa/ -k "parallel_config_06" -v --tb=short -q

check "QA-PAR-CONFIG-07: --max-workers flag visible in help output" \
    bash -c 'uv run python scripts/run_sp1.py --help 2>&1 | grep -q "\-\-max-workers" && echo "Flag present" || (echo "Flag missing" && false)'

# --- 5. SP1 Backwards Compatibility ---

check "QA-PAR-SP1-01: max_workers=1 produces identical output artifacts" \
    uv run pytest tests/stpa/ -k "parallel_sp1_01" -v --tb=short -q

check "QA-PAR-SP1-02: Stage execution order preserved with max_workers=1" \
    uv run pytest tests/stpa/ -k "parallel_sp1_02" -v --tb=short -q

check "QA-PAR-SP1-03: Call log identical with max_workers=1" \
    uv run pytest tests/stpa/ -k "parallel_sp1_03" -v --tb=short -q

check "QA-PAR-SP1-04: Existing SP1 tests pass with parallel module present" \
    uv run pytest tests/stpa/ -k "not Parallel" -v --tb=short -q

# --- 6. SP2/SP3 Design ---

check "QA-PAR-SP2-01: SP2 Stage 3 parallel independence" \
    uv run pytest tests/stpa/ -k "parallel_sp2_01" -v --tb=short -q

check "QA-PAR-SP2-02: SP2 Stage 3 parallel equals sequential" \
    uv run pytest tests/stpa/ -k "parallel_sp2_02" -v --tb=short -q

check "QA-PAR-SP3-01: SP3 Stage 5 BDI independence" \
    uv run pytest tests/stpa/ -k "parallel_sp3_01" -v --tb=short -q

check "QA-PAR-SP3-02: SP3 Stage 6 calls independent within a scenario" \
    uv run pytest tests/stpa/ -k "parallel_sp3_02" -v --tb=short -q

check "QA-PAR-SP3-03: SP3 different scenarios can run concurrently" \
    uv run pytest tests/stpa/ -k "parallel_sp3_03" -v --tb=short -q

check "QA-PAR-SP3-04: SP3 Stage 5 failure isolation" \
    uv run pytest tests/stpa/ -k "parallel_sp3_04" -v --tb=short -q

# --- 7. Full Suite ---

check "QA-PAR-FULL-01: All parallel feature tests pass" \
    uv run pytest tests/stpa/ -k "Parallel" -v --tb=short -q

check "QA-PAR-FULL-02: Existing STPA tests unaffected" \
    uv run pytest tests/stpa/ -k "not Parallel" -v --tb=short -q

check "QA-PAR-FULL-03: Linting passes on new module" \
    ruff check src/scenario_forge/stpa/infra/parallel_llm.py tests/stpa/test_parallel_llm.py

# --- Summary ---

echo "=========================================="
echo "Parallel QA Suite Results: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "Failed checks:"
    for c in "${FAILED_CHECKS[@]}"; do
        echo "  - $c"
    done
    exit 1
fi
echo "All parallel QA checks passed."
exit 0
