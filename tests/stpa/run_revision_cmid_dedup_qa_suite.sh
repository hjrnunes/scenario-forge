#!/usr/bin/env bash
# Revision Delta cm_id Dedup and Degradation Guard — Executable QA Suite
#
# Executable form of the 18 QA checks in
# tests/stpa/features/qa_revision_cmid_dedup.md. All verification goes
# through user-visible workflows: driving run_revision with mock LLM
# clients, running the full SP1 pipeline, inspecting the emitted
# control-structure.yaml, and inspecting returned warnings — no
# project-internal APIs.
#
# Usage: bash tests/stpa/run_revision_cmid_dedup_qa_suite.sh
# Exit 0 = all pass, Exit 1 = any fail.

set -uo pipefail
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

# ===========================================================================
# QA-CMID-DEDUP: Duplicate cm_id Renumbering (8 cases)
# ===========================================================================

# QA-CMID-DEDUP-01: New link with duplicate cm_id is renumbered
check "QA-CMID-DEDUP-01: New link with duplicate cm_id is renumbered" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
cs, _ = run_rev(delta)
cl_ids = {cl.link_id for cl in cs.coordination_links}
assert 'CL-1' in cl_ids and 'CL-2' in cl_ids and 'CL-3' in cl_ids
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
assert cl3.coordination_mechanism.cm_id != 'CM-1', 'CL-3 cm_id should not be CM-1'
# ControlStructure was constructed -> passed validation
assert cs is not None
print('CL-3 renumbered away from CM-1, structure valid')
"

# QA-CMID-DEDUP-02: Renumbered cm_id is the next free number
check "QA-CMID-DEDUP-02: Renumbered cm_id is the next free number (CM-3)" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
cs, _ = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
assert cl3.coordination_mechanism.cm_id == 'CM-3', f'Expected CM-3, got {cl3.coordination_mechanism.cm_id}'
print('CL-3 renumbered to CM-3 (next free)')
"

# QA-CMID-DEDUP-03: Renumbered cm_id conforms to CM-N format
check "QA-CMID-DEDUP-03: Renumbered cm_id conforms to ^CM-\\d+$ format" \
    uv run python -c "
import re
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
cs, _ = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
cm_id = cl3.coordination_mechanism.cm_id
assert re.match(r'^CM-\d+$', cm_id), f'cm_id {cm_id} does not match CM-N format'
# No suffixed or mangled IDs
assert '_' not in cm_id and '-dup' not in cm_id
print(f'cm_id {cm_id} conforms to CM-N format')
"

# QA-CMID-DEDUP-04: Link content is preserved after renumbering
check "QA-CMID-DEDUP-04: Link content preserved after renumbering" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[
    cl_dict('CL-3', 'CM-1', source='RESP-1', target='RESP-2',
            shared_pm='PM-1-1', description='shared validation gate',
            payload='sync-message', mech_desc='sync-message')
])
cs, _ = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
assert cl3.source == 'RESP-1', f'source: {cl3.source}'
assert cl3.target == 'RESP-2', f'target: {cl3.target}'
assert cl3.shared_pm == 'PM-1-1', f'shared_pm: {cl3.shared_pm}'
assert cl3.description == 'shared validation gate', f'description: {cl3.description}'
assert cl3.coordination_mechanism.payload == 'sync-message', f'payload: {cl3.coordination_mechanism.payload}'
print('All link content preserved, only cm_id changed')
"

# QA-CMID-DEDUP-05: Renumber warning is emitted
check "QA-CMID-DEDUP-05: Renumber warning mentions colliding cm_id and link_id" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
_, warnings = run_rev(delta)
wtext = ' '.join(warnings)
assert 'CM-1' in wtext, f'Warning does not mention CM-1: {warnings}'
assert 'CL-3' in wtext, f'Warning does not mention CL-3: {warnings}'
print('Renumber warning mentions CM-1 and CL-3')
"

# QA-CMID-DEDUP-06: Multiple new links with duplicate cm_ids are each renumbered
check "QA-CMID-DEDUP-06: Multiple new links with duplicate cm_ids each renumbered" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[
    cl_dict('CL-3', 'CM-1'),
    cl_dict('CL-4', 'CM-2', source='RESP-2', target='RESP-1', shared_pm='PM-2-1'),
])
cs, _ = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
cl4 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-4')
assert cl3.coordination_mechanism.cm_id != 'CM-1'
assert cl4.coordination_mechanism.cm_id != 'CM-2'
assert cl3.coordination_mechanism.cm_id != cl4.coordination_mechanism.cm_id
cm_ids = [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]
assert len(cm_ids) == len(set(cm_ids)), f'Duplicate cm_ids: {cm_ids}'
print('Both CL-3 and CL-4 renumbered, all cm_ids unique')
"

# QA-CMID-DEDUP-07: New link with unique cm_id is not renumbered
check "QA-CMID-DEDUP-07: New link with unique cm_id is not renumbered" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-3')])
cs, warnings = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
assert cl3.coordination_mechanism.cm_id == 'CM-3', f'Expected CM-3, got {cl3.coordination_mechanism.cm_id}'
renumber_warnings = [w for w in warnings if 'Renumber' in w]
assert not any('CM-3' in w for w in renumber_warnings), f'Unexpected renumber warning: {renumber_warnings}'
print('CL-3 keeps CM-3, no renumber warning')
"

# QA-CMID-DEDUP-08: No duplicate cm_id values in final structure
check "QA-CMID-DEDUP-08: No duplicate cm_id values in final structure" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
cs, _ = run_rev(delta)
cm_ids = [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]
assert len(cm_ids) == len(set(cm_ids)), f'Duplicate cm_ids found: {cm_ids}'
print(f'All {len(cm_ids)} cm_ids unique: {cm_ids}')
"

# ===========================================================================
# QA-CMID-DEGRADE: Degradation Guard (5 cases)
# ===========================================================================

# QA-CMID-DEGRADE-01: Merge failure falls back to pre-revision ControlStructure
check "QA-CMID-DEGRADE-01: Merge failure falls back to pre-revision CS" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_degradation_delta, run_rev
delta = make_degradation_delta()
cs, warnings = run_rev(delta)
# No exception was raised (we got here)
resp_ids = {r.resp_id for r in cs.responsibilities}
assert 'RESP-1' in resp_ids and 'RESP-2' in resp_ids
assert 'RESP-3' not in resp_ids, 'RESP-3 should not be in pre-revision CS'
print('Degradation returned pre-revision CS, no exception')
"

# QA-CMID-DEGRADE-02: Degradation warning is emitted
check "QA-CMID-DEGRADE-02: Degradation warning mentions merge failure" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_degradation_delta, run_rev
delta = make_degradation_delta()
_, warnings = run_rev(delta)
wtext = ' '.join(warnings)
assert 'degrad' in wtext.lower(), f'No degradation warning: {warnings}'
assert 'ValidationError' in wtext or 'ValueError' in wtext, f'No error type in warning: {warnings}'
print('Degradation warning emitted with error type')
"

# QA-CMID-DEGRADE-03: Degradation preserves existing responsibilities and links
check "QA-CMID-DEGRADE-03: Degradation preserves existing resp and links" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_degradation_delta, run_rev
delta = make_degradation_delta()
cs, _ = run_rev(delta)
resp_ids = {r.resp_id for r in cs.responsibilities}
assert 'RESP-1' in resp_ids and 'RESP-2' in resp_ids
cl_ids = {cl.link_id for cl in cs.coordination_links}
assert 'CL-1' in cl_ids and 'CL-2' in cl_ids
cl1 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-1')
cl2 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-2')
assert cl1.coordination_mechanism.cm_id == 'CM-1'
assert cl2.coordination_mechanism.cm_id == 'CM-2'
print('All pre-revision elements intact')
"

# QA-CMID-DEGRADE-04: Full SP1 run does not crash on revision merge failure
check "QA-CMID-DEGRADE-04: Full SP1 run does not crash on revision merge failure" \
    uv run python -c "
import yaml
from pathlib import Path
from tests.stpa.qa_cmid_dedup_helpers import setup_degradation_sp1_mock_client, run_full_sp1
client = setup_degradation_sp1_mock_client()
run_dir, result = run_full_sp1(client)
cs_path = run_dir / 'control-structure.yaml'
assert cs_path.exists(), 'control-structure.yaml not written'
cs_data = yaml.safe_load(cs_path.read_text(encoding='utf-8'))
assert cs_data is not None, 'control-structure.yaml is empty'
resp_ids = {r['resp_id'] for r in cs_data.get('responsibilities', [])}
assert 'RESP-1' in resp_ids and 'RESP-2' in resp_ids
assert 'RESP-3' not in resp_ids, 'RESP-3 should not be present (degradation)'
# Pipeline completed (no crash) and wrote artifacts
assert (run_dir / 'run-manifest.yaml').exists()
print('SP1 pipeline completed, control-structure.yaml written with pre-revision CS')
"

# QA-CMID-DEGRADE-05: Degradation guard catches nested pm_id collision
check "QA-CMID-DEGRADE-05: Degradation guard catches nested pm_id collision" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_degradation_delta, run_rev
delta = make_degradation_delta()
cs, warnings = run_rev(delta)
# No exception
assert cs is not None
resp_ids = {r.resp_id for r in cs.responsibilities}
assert 'RESP-3' not in resp_ids, 'RESP-3 should not be present'
assert any('degrad' in w.lower() for w in warnings), 'No degradation warning'
print('Nested pm_id collision caught, degradation warning emitted')
"

# ===========================================================================
# QA-CMID-AIRBNB: Airbnb Regression Shape (3 cases)
# ===========================================================================

# QA-CMID-AIRBNB-01: Airbnb failure shape does not crash
check "QA-CMID-AIRBNB-01: Airbnb failure shape does not crash" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
cs, _ = run_rev(delta)
assert cs is not None
cl1 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-1')
cl2 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-2')
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
assert cl1.coordination_mechanism.cm_id == 'CM-1'
assert cl2.coordination_mechanism.cm_id == 'CM-2'
assert cl3.coordination_mechanism.cm_id == 'CM-3'
cm_ids = [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]
assert len(cm_ids) == len(set(cm_ids))
print('Airbnb shape: CL-1/CM-1, CL-2/CM-2, CL-3/CM-3, all unique')
"

# QA-CMID-AIRBNB-02: Airbnb shape — warning emitted for the collision
check "QA-CMID-AIRBNB-02: Airbnb shape warning mentions CM-1 and CL-3" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-1')])
_, warnings = run_rev(delta)
wtext = ' '.join(warnings)
assert 'CM-1' in wtext and 'CL-3' in wtext, f'Warning missing CM-1/CL-3: {warnings}'
print('Airbnb collision warning mentions CM-1 and CL-3')
"

# QA-CMID-AIRBNB-03: Full SP1 run with Airbnb shape completes
check "QA-CMID-AIRBNB-03: Full SP1 run with Airbnb shape completes" \
    uv run python -c "
import yaml
from pathlib import Path
from tests.stpa.qa_cmid_dedup_helpers import setup_airbnb_sp1_mock_client, run_full_sp1
client = setup_airbnb_sp1_mock_client()
run_dir, result = run_full_sp1(client)
# Pipeline completed without crashing
cs_path = run_dir / 'control-structure.yaml'
assert cs_path.exists(), 'control-structure.yaml not written'
cs_data = yaml.safe_load(cs_path.read_text(encoding='utf-8'))
assert cs_data is not None, 'control-structure.yaml is empty'
cls = cs_data.get('coordination_links', [])
assert len(cls) >= 3, f'Expected >=3 coordination links, got {len(cls)}'
cm_ids = [cl['coordination_mechanism']['cm_id'] for cl in cls]
assert len(cm_ids) == len(set(cm_ids)), f'Duplicate cm_ids: {cm_ids}'
# Verify CL-3 is present and renumbered
cl3 = next(cl for cl in cls if cl['link_id'] == 'CL-3')
assert cl3['coordination_mechanism']['cm_id'] != 'CM-1', 'CL-3 should not have CM-1'
# Verify revision happened
assert result.revised, 'Pipeline should have triggered revision'
# Verify renumber warning is in user-visible output
wtext = ' '.join(result.post_revision_warnings)
assert 'CM-1' in wtext and 'CL-3' in wtext, f'Renumber warning not in post_revision_warnings: {result.post_revision_warnings}'
print(f'SP1 completed: {len(cls)} coordination links, all cm_ids unique: {cm_ids}')
"

# ===========================================================================
# QA-CMID-NORMAL: Normal Path Unchanged (2 cases)
# ===========================================================================

# QA-CMID-NORMAL-01: Successful merge with no collisions produces no extra warnings
check "QA-CMID-NORMAL-01: No collisions -> no renumber or degradation warnings" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[cl_dict('CL-3', 'CM-3')])
cs, warnings = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
assert cl3.coordination_mechanism.cm_id == 'CM-3'
assert not any('Renumber' in w for w in warnings), f'Unexpected renumber warning: {warnings}'
assert not any('degrad' in w.lower() for w in warnings), f'Unexpected degradation warning: {warnings}'
print('No renumber or degradation warnings on clean merge')
"

# QA-CMID-NORMAL-02: Empty revision delta produces no warnings
check "QA-CMID-NORMAL-02: Empty delta produces no renumber or degradation warnings" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, run_rev, make_pre_revision_cs
delta = make_delta_dict()
cs, warnings = run_rev(delta)
# Structure is unchanged from pre-revision
pre_cs = make_pre_revision_cs()
assert len(cs.responsibilities) == len(pre_cs.responsibilities)
assert len(cs.coordination_links) == len(pre_cs.coordination_links)
assert not any('Renumber' in w for w in warnings), f'Unexpected renumber warning: {warnings}'
assert not any('degrad' in w.lower() for w in warnings), f'Unexpected degradation warning: {warnings}'
print('Empty delta: structure unchanged, no warnings')
"

# ===========================================================================
# Independent probes (beyond the 18 spec cases)
# ===========================================================================

# PROBE-01: Renumbering collision-freedom — renumbered ID must not collide
# with a later new link's already-unique cm_id.
# Existing: CM-1, CM-2.  New links: CL-3 (cm_id=CM-1, collides),
# CL-4 (cm_id=CM-3, unique).  CL-3 is renumbered to CM-3, so CL-4's
# CM-3 must also be renumbered to CM-4.
check "PROBE-01: Renumbered ID does not collide with later unique cm_id" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_delta_dict, cl_dict, run_rev
delta = make_delta_dict(new_coordination_links=[
    cl_dict('CL-3', 'CM-1'),
    cl_dict('CL-4', 'CM-3', source='RESP-2', target='RESP-1', shared_pm='PM-2-1'),
])
cs, warnings = run_rev(delta)
cl3 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-3')
cl4 = next(cl for cl in cs.coordination_links if cl.link_id == 'CL-4')
cm_ids = [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]
assert len(cm_ids) == len(set(cm_ids)), f'Duplicate cm_ids: {cm_ids}'
# CL-3 was renumbered from CM-1, CL-4 was renumbered from CM-3
assert cl3.coordination_mechanism.cm_id != 'CM-1'
assert cl4.coordination_mechanism.cm_id != 'CM-3'
assert cl3.coordination_mechanism.cm_id != cl4.coordination_mechanism.cm_id
# Two renumber warnings
renumber_warnings = [w for w in warnings if 'Renumber' in w]
assert len(renumber_warnings) >= 2, f'Expected >=2 renumber warnings, got {len(renumber_warnings)}: {warnings}'
print(f'Both renumbered: CL-3->{cl3.coordination_mechanism.cm_id}, CL-4->{cl4.coordination_mechanism.cm_id}, all unique: {cm_ids}')
"

# PROBE-02: Degradation really degrades, not corrupts — after a degraded
# merge, the returned structure is the untouched pre-revision one.
check "PROBE-02: Degradation returns untouched pre-revision structure" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import make_degradation_delta, run_rev, make_pre_revision_cs
pre_cs = make_pre_revision_cs()
delta = make_degradation_delta()
cs, _ = run_rev(delta)
# Compare by value — the returned CS must be identical to pre-revision
assert len(cs.responsibilities) == len(pre_cs.responsibilities)
for r1, r2 in zip(cs.responsibilities, pre_cs.responsibilities):
    assert r1.resp_id == r2.resp_id
    assert r1.description == r2.description
assert len(cs.coordination_links) == len(pre_cs.coordination_links)
for cl1, cl2 in zip(cs.coordination_links, pre_cs.coordination_links):
    assert cl1.link_id == cl2.link_id
    assert cl1.coordination_mechanism.cm_id == cl2.coordination_mechanism.cm_id
print('Degraded structure is identical to pre-revision structure')
"

# PROBE-03: Warnings reach the operator in full SP1 run — renumber
# warnings appear in SP1RunResult.post_revision_warnings.
check "PROBE-03: Renumber warnings in SP1RunResult.post_revision_warnings" \
    uv run python -c "
from tests.stpa.qa_cmid_dedup_helpers import setup_airbnb_sp1_mock_client, run_full_sp1
client = setup_airbnb_sp1_mock_client()
run_dir, result = run_full_sp1(client)
assert result.revised, 'Pipeline should have triggered revision'
wtext = ' '.join(result.post_revision_warnings)
assert 'Renumber' in wtext or 'CM-1' in wtext, f'No renumber warning in post_revision_warnings: {result.post_revision_warnings}'
print(f'Warnings visible to operator: {result.post_revision_warnings}')
"

# ===========================================================================
# Unit and acceptance test gates
# ===========================================================================

check "QA-UNIT: STPA test suite passes" \
    uv run pytest tests/stpa/ -q --tb=short

check "QA-ACCEPTANCE: Acceptance tests pass (2 pre-existing failures OK)" \
    uv run python -c "
import subprocess, sys
result = subprocess.run(
    [sys.executable, '-m', 'pytest', 'build/acceptance/generated/', '-q', '--tb=line'],
    capture_output=True, text=True
)
output = result.stdout + result.stderr
# Pre-existing failures: sp3_attack_tree, stage6_jpkw_gherkin
assert '2 failed' in output, f'Expected 2 failures, got: {output[-300:]}'
assert '61 passed' in output, f'Expected 61 passed: {output[-300:]}'
# Confirm the 2 failures are the known pre-existing ones
assert 'sp3_attack_tree' in output or 'attack_tree' in output
assert 'stage6_jpkw_gherkin' in output or 'jpkw' in output
print('Acceptance: 2 pre-existing failures (sp3_attack_tree, stage6_jpkw_gherkin), 61 passed')
"

check "QA-LINT: ruff check passes on src and tests/stpa" \
    ruff check src/ tests/stpa/

# ===========================================================================
# Summary
# ===========================================================================

echo
echo "==============================================="
echo "Revision cm_id Dedup QA Suite Results"
echo "==============================================="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Total:  $((PASS + FAIL))"
echo

if [ "$FAIL" -gt 0 ]; then
    echo "Failed checks:"
    for name in "${FAILED_CHECKS[@]}"; do
        echo "  - $name"
    done
    echo
    exit 1
fi

echo "All checks passed."
exit 0
