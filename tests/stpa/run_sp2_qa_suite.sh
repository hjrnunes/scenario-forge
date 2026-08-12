#!/usr/bin/env bash
# SP2 Threat Enumeration — Executable QA Suite
#
# Executable form of the QA checks in tests/stpa/qa-suite-sp2.md. All
# verification goes through the user interface: the run_sp2.py command
# line, Python import checks, pytest execution, and filesystem
# inspection — no project-internal APIs.
#
# The end-to-end run checks (QA-SP2-RUN-*) drive the real CLI against a
# local stub LLM endpoint (tests/stpa/sp2_qa_stub_llm.py) so the suite is
# deterministic, offline, and free of API cost while still exercising the
# real orchestration, artifact writing, and manifest code paths.
#
# Usage: bash tests/stpa/run_sp2_qa_suite.sh
# Exit 0 = all pass, Exit 1 = any fail.

set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

FIXTURES="src/scenario_forge/stpa/fixtures"
WORK_DIR="tmp/sp2-qa"
STUB_PID=""

# Pre-existing failures outside tests/stpa/ (LLM endpoint not configured,
# plus one prompt-projection assertion). QA-SP2-FULL-02 fails only if the
# count grows beyond this.
PREEXISTING_NON_STPA_FAILURES=11

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

stop_stub() {
    if [ -n "$STUB_PID" ] && kill -0 "$STUB_PID" 2>/dev/null; then
        kill "$STUB_PID" 2>/dev/null || true
        wait "$STUB_PID" 2>/dev/null || true
    fi
    STUB_PID=""
}
trap stop_stub EXIT

start_stub() {
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    local ready_file="$WORK_DIR/stub-port"
    uv run python tests/stpa/sp2_qa_stub_llm.py --port 0 --ready-file "$ready_file" \
        > "$WORK_DIR/stub.log" 2>&1 &
    STUB_PID=$!

    local waited=0
    while [ ! -s "$ready_file" ]; do
        if ! kill -0 "$STUB_PID" 2>/dev/null; then
            echo "Stub LLM endpoint exited early:"
            cat "$WORK_DIR/stub.log"
            return 1
        fi
        sleep 0.2
        waited=$((waited + 1))
        if [ "$waited" -gt 150 ]; then
            echo "Stub LLM endpoint did not become ready"
            return 1
        fi
    done

    local port
    port="$(cat "$ready_file")"
    cat > "$WORK_DIR/profiles.yaml" <<EOF
sp2-qa-stub:
  base_url: http://127.0.0.1:${port}/v1
  model: sp2-qa-stub
  api_key: unused
  temperature: 0.4
EOF
}

run_sp2_cli() {
    local out_dir="$1"
    shift
    uv run python scripts/run_sp2.py \
        --control-structure "$FIXTURES/control_structure_klarna.yaml" \
        --capability-profile "$FIXTURES/capability_profile_klarna.yaml" \
        --loss-analysis "$FIXTURES/loss_analysis_klarna.yaml" \
        --output-dir "$out_dir" \
        --profiles-file "$WORK_DIR/profiles.yaml" \
        --profile sp2-qa-stub \
        "$@"
}

# --- 1. Module Structure ---

check "QA-SP2-STRUCT-01: Module layout matches spec" \
    bash -c '
uv run python -c "
from scenario_forge.stpa.threat_enum import (
    slot_creation, technology_context, slot_filling, na_quality,
    catalog_enrichment, catalog_data, coverage, run,
)
print(\"All SP2 modules importable\")
" || exit 1
ls src/scenario_forge/stpa/threat_enum/prompts/stage3_system.j2 \
   src/scenario_forge/stpa/threat_enum/prompts/stage3_user.j2
'

check "QA-SP2-STRUCT-02: CLI script exists and accepts arguments" \
    bash -c '
[ -f scripts/run_sp2.py ] || { echo "scripts/run_sp2.py missing"; exit 1; }
help_text=$(uv run python scripts/run_sp2.py --help)
for flag in --control-structure --capability-profile --loss-analysis \
            --output-dir --max-workers --profile; do
  echo "$help_text" | grep -q -- "$flag" || { echo "Missing flag: $flag"; exit 1; }
done
echo "CLI accepts all documented flags"
'

# --- 2. Slot Creation (deterministic) ---

check "QA-SP2-SLOT-01: Slot count formula via unit tests" \
    uv run pytest tests/stpa/ -k "sp2_slot" -q --tb=short

check "QA-SP2-SLOT-02: Slot creation on Klarna fixture" \
    uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.threat_enum.slot_creation import create_slots
cs = read_yaml('src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
slots = create_slots(cs)
assert len(slots) == 40, f'Expected 40, got {len(slots)}'
resp_slots = [s for s in slots if s.responsibility]
link_slots = [s for s in slots if s.coordination_link]
assert len(resp_slots) == 32, f'Expected 32 resp slots, got {len(resp_slots)}'
assert len(link_slots) == 8, f'Expected 8 link slots, got {len(link_slots)}'
print('Slot count formula verified: 40 = 32 responsibility + 8 coordination link')
"

# --- 3. Technology Context (deterministic) ---

check "QA-SP2-TECH-01: Technology context on Klarna fixture" \
    uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.threat_enum.technology_context import build_technology_context
profile = read_yaml('src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml', CapabilityProfile)
ctx = build_technology_context(profile)
assert 'prompt injection' in ctx.lower(), 'Missing input zone failure mode'
assert 'parameter injection' in ctx.lower(), 'Missing tool_execution zone failure mode'
assert 'retrieval poisoning' in ctx.lower(), 'Missing KC6.3.3 failure mode'
assert 'refund' in ctx.lower() or 'payment' in ctx.lower(), 'Missing tool inventory entry'
print('Technology context verified')
"

check "QA-SP2-TECH-02: Technology context determinism" \
    uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.threat_enum.technology_context import build_technology_context
profile = read_yaml('src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml', CapabilityProfile)
assert build_technology_context(profile) == build_technology_context(profile)
print('Determinism verified')
"

# --- 4. N/A Quality Gates (deterministic) ---

check "QA-SP2-NA-01: N/A quality gate unit tests" \
    uv run pytest tests/stpa/ -k "sp2_na" -q --tb=short

# --- 5. Catalog Enrichment (deterministic) ---

check "QA-SP2-CAT-01: Catalog enrichment unit tests" \
    uv run pytest tests/stpa/ -k "sp2_catalog or sp2_coverage" -q --tb=short

check "QA-SP2-CAT-02: Catalog enrichment on Klarna ICA fixture" \
    uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.threat_enum.catalog_enrichment import enrich_threats
ica = read_yaml('src/scenario_forge/stpa/fixtures/ica_enumeration_klarna.yaml', ICAEnumeration)
cs = read_yaml('src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
enriched = enrich_threats(ica, cs)
EnrichedThreatSet.model_validate(enriched.model_dump())
mapped = [t for t in enriched.structural_threats if t.catalog_mappings]
unmapped = [t for t in enriched.structural_threats if not t.catalog_mappings]
assert len(mapped) >= 1, 'Expected at least one mapped threat'
assert len(unmapped) >= 1, 'Expected at least one unmapped threat'
assert enriched.coverage_analysis.structural_coverage['total_slots'] > 0
assert len(enriched.coverage_analysis.by_ica_type) > 0
assert len(enriched.coverage_analysis.by_controller) > 0
print(f'Mapped: {len(mapped)}, Unmapped: {len(unmapped)}')
"

# --- 6. Run Orchestration (end-to-end CLI run) ---

check "QA-SP2-RUN-00: Stub LLM endpoint is available" start_stub

check "QA-SP2-RUN-01: Full SP2 run produces output artifacts" \
    bash -c '
set -e
run_dir="tmp/sp2-qa/run"
uv run python scripts/run_sp2.py \
    --control-structure src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml \
    --capability-profile src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml \
    --loss-analysis src/scenario_forge/stpa/fixtures/loss_analysis_klarna.yaml \
    --output-dir "$run_dir" \
    --profiles-file tmp/sp2-qa/profiles.yaml \
    --profile sp2-qa-stub > tmp/sp2-qa/run.log 2>&1
ls "$run_dir/ica-enumeration.yaml" "$run_dir/enriched-threats.yaml" \
   "$run_dir/calls.jsonl" "$run_dir/run-manifest.yaml"
SP2_QA_RUN_DIR="$run_dir" uv run python - <<"PY"
import os
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet

run_dir = os.environ["SP2_QA_RUN_DIR"]
ica = read_yaml(f"{run_dir}/ica-enumeration.yaml", ICAEnumeration)
enriched = read_yaml(f"{run_dir}/enriched-threats.yaml", EnrichedThreatSet)
assert len(ica.slots) == 40, f"Expected 40 slots, got {len(ica.slots)}"
assert enriched.structural_threats, "No structural threats produced"
coverage_rate = enriched.coverage_analysis.structural_coverage["coverage_rate"]
print(f"ICA slots: {len(ica.slots)}")
print(f"Structural threats: {len(enriched.structural_threats)}")
print(f"Coverage rate: {coverage_rate}")
PY
grep -q "stage_3" "$run_dir/calls.jsonl" || { echo "No stage_3 entries in calls.jsonl"; exit 1; }
echo "stage_3 calls: $(grep -c stage_3 "$run_dir/calls.jsonl")"
'

check "QA-SP2-RUN-02: Run manifest records stage summary and metadata" \
    uv run python -c "
import yaml
manifest = yaml.safe_load(open('tmp/sp2-qa/run/run-manifest.yaml'))
assert 'stage_summary' in manifest, 'Missing stage_summary'
assert 'stage_3' in manifest['stage_summary'], 'Missing stage_3 in stage_summary'
for key in ('control_structure', 'capability_profile', 'loss_analysis'):
    assert key in manifest['input_hashes'], f'Missing input hash: {key}'
for key in ('stage3_system.j2', 'stage3_user.j2'):
    assert key in manifest['prompt_hashes'], f'Missing prompt hash: {key}'
assert 'na_quality_flags' in manifest, 'Missing na_quality_flags'
assert 'coverage_analysis' in manifest, 'Missing coverage_analysis'
print('Run manifest verified:', manifest['stage_summary'])
"

check "QA-SP2-RUN-03: Stage 4 makes no LLM calls" \
    bash -c '
if grep -q "stage_4" tmp/sp2-qa/run/calls.jsonl; then
  echo "Found stage_4 entries — catalog enrichment is not deterministic"
  exit 1
fi
echo "Stage 4 made no LLM calls — verified"
'

check "QA-SP2-RUN-04: --max-workers flag controls parallelism" \
    bash -c '
set -e
run_dir="tmp/sp2-qa/run-parallel"
uv run python scripts/run_sp2.py \
    --control-structure src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml \
    --capability-profile src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml \
    --loss-analysis src/scenario_forge/stpa/fixtures/loss_analysis_klarna.yaml \
    --output-dir "$run_dir" \
    --profiles-file tmp/sp2-qa/profiles.yaml \
    --profile sp2-qa-stub \
    --max-workers 2 > tmp/sp2-qa/run-parallel.log 2>&1
ls "$run_dir/ica-enumeration.yaml" "$run_dir/enriched-threats.yaml"
SP2_QA_RUN_DIR="$run_dir" uv run python - <<"PY"
import os
import yaml

run_dir = os.environ["SP2_QA_RUN_DIR"]
manifest = yaml.safe_load(open(f"{run_dir}/run-manifest.yaml"))
recorded_workers = manifest["max_workers"]
assert recorded_workers == 2, f"Expected max_workers 2, got {recorded_workers}"
parallel = yaml.safe_load(open(f"{run_dir}/ica-enumeration.yaml"))
sequential = yaml.safe_load(open("tmp/sp2-qa/run/ica-enumeration.yaml"))
parallel_slots = len(parallel["slots"])
assert parallel_slots == len(sequential["slots"]), (
    "Parallel run produced a different slot count than the sequential run"
)
print(f"max_workers=2 run produced {parallel_slots} slots, same as sequential")
PY
'

stop_stub

# --- 7. Fixture Validation ---

check "QA-SP2-FIX-01: SP2 fixtures load and validate" \
    uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
ica = read_yaml('src/scenario_forge/stpa/fixtures/ica_enumeration_klarna.yaml', ICAEnumeration)
enriched = read_yaml('src/scenario_forge/stpa/fixtures/enriched_threats_klarna.yaml', EnrichedThreatSet)
for slot in ica.slots:
    if slot.is_na:
        assert not slot.icas, f'{slot.slot_id}: N/A slot has ICAs'
        assert slot.na_justification, f'{slot.slot_id}: N/A slot missing justification'
    else:
        assert slot.icas, f'{slot.slot_id}: non-N/A slot has no ICAs'
        assert slot.na_justification is None, f'{slot.slot_id}: non-N/A slot has justification'
assert enriched.coverage_analysis.structural_consideration, 'Missing structural_consideration'
assert enriched.coverage_analysis.na_quality, 'Missing na_quality'
print(f'ICA slots: {len(ica.slots)}, structural threats: {len(enriched.structural_threats)}')
"

check "QA-SP2-FIX-02: SP2 fixtures have provenance headers" \
    bash -c '
for f in src/scenario_forge/stpa/fixtures/ica_enumeration_klarna.yaml \
         src/scenario_forge/stpa/fixtures/enriched_threats_klarna.yaml; do
  head -1 "$f" | grep -q "^#" || { echo "$f: missing provenance header"; exit 1; }
  echo "$f: $(head -1 "$f")"
done
'

# --- 8. Acceptance Tests ---

check "QA-SP2-ACCEPT-01: SP2 Gherkin acceptance tests pass" \
    uv run pytest acceptance/generated/sp2_catalog_enrichment_acceptance_test.py \
                  acceptance/generated/sp2_na_quality_acceptance_test.py \
                  acceptance/generated/sp2_run_orchestration_acceptance_test.py \
                  acceptance/generated/sp2_slot_creation_acceptance_test.py \
                  acceptance/generated/sp2_slot_filling_acceptance_test.py \
                  acceptance/generated/sp2_technology_context_acceptance_test.py \
                  -q --tb=short

# --- 9. Full Test Suite Execution ---

check "QA-SP2-FULL-01: All SP2 tests pass" \
    uv run pytest tests/stpa/ -k "sp2 or threat_enum" -q --tb=short

check "QA-SP2-FULL-02: Existing tests unaffected" \
    bash -c "
output=\$(uv run pytest tests/ --ignore=tests/stpa/ -q --tb=line 2>&1 || true)
echo \"\$output\" | tail -3
failed=\$(echo \"\$output\" | grep -o '[0-9]* failed' | grep -o '[0-9]*' || echo 0)
if [ \"\$failed\" -gt $PREEXISTING_NON_STPA_FAILURES ]; then
  echo \"New failures detected: \$failed failed (expected $PREEXISTING_NON_STPA_FAILURES pre-existing)\"
  exit 1
fi
echo \"No new failures (pre-existing: $PREEXISTING_NON_STPA_FAILURES)\"
"

check "QA-SP2-FULL-03: Linting passes" \
    ruff check src/scenario_forge/stpa/threat_enum/ tests/stpa/

# --- Summary ---

echo "=========================================="
echo "SP2 QA Suite Results: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "Failed checks:"
    for c in "${FAILED_CHECKS[@]}"; do
        echo "  - $c"
    done
    exit 1
fi
echo "All SP2 QA checks passed."
exit 0
