#!/usr/bin/env bash
# =============================================================================
# E2E QA Suite — SP1 Bug Fixes Batch 3 (f29s + ulc0)
#
# Bugs under test:
#   f29s — Sanitize critic-suggested IDs before injection into revision prompt
#   ulc0 — Enforce PM↔FB 1:1 correspondence in Call 2 prompt and add repair pass
#
# This QA suite operates at the user interface level:
#   1. Prompt template content checks (user-visible Jinja2 templates)
#   2. Unit/acceptance test execution via uv run pytest (user-facing test command)
#   3. Pipeline integration via scenario-forge CLI (user-facing CLI tool)
#
# Usage:
#   bash tmp/qa_sp1_batch3.sh
#
# Prerequisites:
#   - uv installed and project dependencies synced (uv sync)
#   - For pipeline integration tests: LLM endpoint configured via env vars or profile
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

PROMPTS_DIR="src/scenario_forge/stpa/system_model/prompts"
PASS=0
FAIL=0
FAIL_MESSAGES=()

check() {
    local description="$1"
    local condition="$2"
    if [ "$condition" = "true" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description"
        FAIL=$((FAIL + 1))
        FAIL_MESSAGES+=("$description")
    fi
}

echo "============================================================"
echo "E2E QA Suite — SP1 Bug Fixes Batch 3 (f29s + ulc0)"
echo "============================================================"

# -----------------------------------------------------------------------------
# Part 1: Prompt template content checks
# These are user-visible configuration files that users can inspect and modify.
# -----------------------------------------------------------------------------

echo ""
echo "--- Part 1: Prompt template content checks ---"

# Bug f29s — critic_system.j2 must instruct not to suggest specific IDs
echo "  [f29s] Checking critic_system.j2..."
CRITIC_SYS="$PROMPTS_DIR/critic_system.j2"

if [ -f "$CRITIC_SYS" ]; then
    check "critic_system.j2 contains 'Do NOT suggest specific IDs in remedies'" \
        "$(grep -q 'Do NOT suggest specific IDs in remedies' "$CRITIC_SYS" && echo true || echo false)"

    check "critic_system.j2 contains 'Describe WHAT should be added'" \
        "$(grep -q 'Describe WHAT should be added' "$CRITIC_SYS" && echo true || echo false)"

    check "critic_system.j2 contains 'not what ID it should have'" \
        "$(grep -q 'not what ID it should have' "$CRITIC_SYS" && echo true || echo false)"

    check "critic_system.j2 contains 'Let the revision model assign IDs'" \
        "$(grep -q 'Let the revision model assign IDs' "$CRITIC_SYS" && echo true || echo false)"

    check "critic_system.j2 contains example 'a responsibility for input validation'" \
        "$(grep -q 'a responsibility for input validation' "$CRITIC_SYS" && echo true || echo false)"

    check "critic_system.j2 contains example 'not add RESP-5'" \
        "$(grep -q 'add RESP-5' "$CRITIC_SYS" && echo true || echo false)"

    check "critic_system.j2 contains example 'not add PM-0-1'" \
        "$(grep -q 'add PM-0-1' "$CRITIC_SYS" && echo true || echo false)"
else
    check "critic_system.j2 exists" "false"
fi

# Bug ulc0 — stage2_call2_system.j2 must enforce PM-FB correspondence
echo "  [ulc0] Checking stage2_call2_system.j2..."
CALL2_SYS="$PROMPTS_DIR/stage2_call2_system.j2"

if [ -f "$CALL2_SYS" ]; then
    check "stage2_call2_system.j2 contains 'Every process model part (PM-X-Y) MUST have at least one feedback channel'" \
        "$(grep -q 'Every process model part.*MUST have at least one feedback channel' "$CALL2_SYS" && echo true || echo false)"

    check "stage2_call2_system.j2 contains 'whose updates field references that PM'" \
        "$(grep -q 'whose updates field references that PM' "$CALL2_SYS" && echo true || echo false)"

    check "stage2_call2_system.j2 contains 'No orphan PMs'" \
        "$(grep -q 'No orphan PMs' "$CALL2_SYS" && echo true || echo false)"

    check "stage2_call2_system.j2 contains 'N process model parts, it must have at least N feedback channels'" \
        "$(grep -q 'N process model parts.*at least N feedback channels' "$CALL2_SYS" && echo true || echo false)"
else
    check "stage2_call2_system.j2 exists" "false"
fi

# Bug ulc0 — stage2_call2_user.j2 must strengthen step 5
echo "  [ulc0] Checking stage2_call2_user.j2..."
CALL2_USER="$PROMPTS_DIR/stage2_call2_user.j2"

if [ -f "$CALL2_USER" ]; then
    check "stage2_call2_user.j2 contains 'One FB per PM part at minimum'" \
        "$(grep -q 'One FB per PM part at minimum' "$CALL2_USER" && echo true || echo false)"

    check "stage2_call2_user.j2 contains 'Each PM-X-Y must appear in at least one FB'" \
        "$(grep -q 'Each PM-X-Y must appear in at least one FB' "$CALL2_USER" && echo true || echo false)"
else
    check "stage2_call2_user.j2 exists" "false"
fi

# -----------------------------------------------------------------------------
# Part 2: Unit and acceptance test execution
# uv run pytest is the user-facing test command documented in CLAUDE.md.
# -----------------------------------------------------------------------------

echo ""
echo "--- Part 2: Unit and acceptance test execution ---"

# Bug f29s — sanitize_critic_ids unit tests
echo "  [f29s] Running sanitize_critic_ids unit tests..."
if uv run pytest tests/stpa/test_critic_id_sanitization.py tests/stpa/test_sp1_critic.py -x -q --tb=short 2>&1 | tail -5; then
    check "critic unit tests pass" "true"
else
    check "critic unit tests pass" "false"
fi

# Bug ulc0 — repair_orphan_pms unit tests
echo "  [ulc0] Running repair_orphan_pms unit tests..."
if uv run pytest tests/stpa/test_orphan_pm_repair.py tests/stpa/test_sp1_control_structure.py -x -q --tb=short 2>&1 | tail -5; then
    check "control structure unit tests pass" "true"
else
    check "control structure unit tests pass" "false"
fi

# Acceptance tests for both features
echo "  [f29s+ulc0] Running acceptance tests..."
ACCEPTANCE_F29S="tmp/acceptance/generated/sp1_critic_id_sanitization_acceptance_test.py"
ACCEPTANCE_ULC0="tmp/acceptance/generated/sp1_orphan_pm_repair_acceptance_test.py"

if [ -f "$ACCEPTANCE_F29S" ]; then
    if uv run pytest "$ACCEPTANCE_F29S" -x -q --tb=short 2>&1 | tail -5; then
        check "f29s acceptance tests pass" "true"
    else
        check "f29s acceptance tests pass" "false"
    fi
else
    check "f29s acceptance test file exists" "false"
fi

if [ -f "$ACCEPTANCE_ULC0" ]; then
    if uv run pytest "$ACCEPTANCE_ULC0" -x -q --tb=short 2>&1 | tail -5; then
        check "ulc0 acceptance tests pass" "true"
    else
        check "ulc0 acceptance tests pass" "false"
    fi
else
    check "ulc0 acceptance test file exists" "false"
fi

# -----------------------------------------------------------------------------
# Part 3: Pipeline integration via CLI
# Runs scenario-forge (or scripts/run_sp1.py) and inspects output artifacts.
# Only runs if LLM credentials are available; otherwise skipped.
# -----------------------------------------------------------------------------

echo ""
echo "--- Part 3: Pipeline integration (optional, requires LLM endpoint) ---"

LLM_AVAILABLE=false
if [ -n "${SCENARIO_FORGE_MODEL_BASE_URL:-}" ] || [ -n "${FG_BASE_URL:-}" ]; then
    LLM_AVAILABLE=true
fi

if [ "$LLM_AVAILABLE" = "true" ]; then
    echo "  LLM endpoint detected. Running pipeline integration test..."

    OUTPUT_DIR="output/qa-batch3-$(date +%s)"
    mkdir -p "$OUTPUT_DIR"

    # Use a small test use case if available
    USE_CASE_FILE=""
    for candidate in output/*/use-case.txt data/test-use-case.txt; do
        if [ -f "$candidate" ]; then
            USE_CASE_FILE="$candidate"
            break
        fi
    done

    RISK_EXTRACTION_FILE=""
    for candidate in output/*/risk-extraction.json data/risk-extraction.json; do
        if [ -f "$candidate" ]; then
            RISK_EXTRACTION_FILE="$candidate"
            break
        fi
    done

    if [ -n "$USE_CASE_FILE" ] && [ -n "$RISK_EXTRACTION_FILE" ]; then
        echo "  Running SP1 pipeline with use-case: $USE_CASE_FILE"
        if uv run python scripts/run_sp1.py \
            --use-case "@$USE_CASE_FILE" \
            --risk-extraction "$RISK_EXTRACTION_FILE" \
            --output-dir "$OUTPUT_DIR" 2>&1 | tail -20; then

            CS_FILE="$OUTPUT_DIR/control-structure.yaml"
            if [ -f "$CS_FILE" ]; then
                check "control-structure.yaml produced" "true"

                # Bug f29s: Verify no non-conforming IDs in revision calls
                CALLS_FILE="$OUTPUT_DIR/calls.jsonl"
                if [ -f "$CALLS_FILE" ]; then
                    # Check that no revision user prompt contains non-conforming IDs like PM-0
                    if grep -q '"PM-0[^-]' "$CALLS_FILE" 2>/dev/null; then
                        check "revision calls contain no non-conforming PM-0 IDs" "false"
                    else
                        check "revision calls contain no non-conforming PM-0 IDs" "true"
                    fi
                fi

                # Bug ulc0: Verify no orphan PMs in the output control structure
                # Every PM-X-Y should be referenced by at least one FB's updates field
                if uv run python -c "
import yaml
import sys

with open('$CS_FILE') as f:
    cs = yaml.safe_load(f)

orphans = []
for resp in cs.get('responsibilities', []):
    pm_ids = {pm['pm_id'] for pm in resp.get('process_model_parts', [])}
    updated = {fb['updates'] for fb in resp.get('feedback_channels', [])}
    for pm_id in pm_ids:
        if pm_id not in updated:
            orphans.append(f'{pm_id} in {resp[\"resp_id\"]}')

if orphans:
    print('ORPHAN_PMS: ' + ', '.join(orphans))
    sys.exit(1)
else:
    print('NO_ORPHANS')
    sys.exit(0)
" 2>&1; then
                    check "control structure has no orphan PMs" "true"
                else
                    check "control structure has no orphan PMs" "false"
                fi
            else
                check "control-structure.yaml produced" "false"
            fi
        else
            check "SP1 pipeline completes successfully" "false"
        fi
    else
        echo "  SKIP: No test use-case or risk extraction file found."
        check "pipeline integration test inputs available" "false"
    fi
else
    echo "  SKIP: No LLM endpoint configured (set SCENARIO_FORGE_MODEL_BASE_URL or FG_BASE_URL)."
    echo "  Pipeline integration tests skipped. Parts 1 and 2 are sufficient for QA."
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

echo ""
echo "============================================================"
echo "QA SUMMARY"
echo "============================================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  Failed checks:"
    for msg in "${FAIL_MESSAGES[@]}"; do
        echo "    - $msg"
    done
fi
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
