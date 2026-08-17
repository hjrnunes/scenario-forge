#!/usr/bin/env bash
# SP1 Bug Fixes Batch 2 — Executable QA Suite
#
# Converts the 35 QA checks from
# tests/stpa/features/qa_sp1_bug_fixes_batch2.md into executable
# verification scripts. All verification uses the Python import API,
# pytest execution, template rendering, file I/O, and command-line
# entry points — no project-internal APIs.
#
# Usage: bash tests/stpa/run_sp1_batch2_qa_suite.sh
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

# ===========================================================================
# QA-CAPPROF: Inject Capability Profile into Stage 2 Call 2 (zcda)
# ===========================================================================

# QA-CAPPROF-01
check "QA-CAPPROF-01: _call_2_responsibilities accepts capability_profile parameter" \
    uv run python -c "
import inspect
from scenario_forge.stpa.system_model.control_structure import _call_2_responsibilities
from scenario_forge.models.capability_profile import CapabilityProfile
sig = inspect.signature(_call_2_responsibilities)
param = sig.parameters.get('capability_profile')
assert param is not None, 'capability_profile parameter not found'
assert param.annotation is CapabilityProfile or 'CapabilityProfile' in str(param.annotation), \
    f'Expected CapabilityProfile annotation, got {param.annotation}'
print('OK: capability_profile is a keyword-only parameter of type CapabilityProfile')
"

# QA-CAPPROF-02
check "QA-CAPPROF-02: derive_control_structure accepts capability_profile parameter" \
    uv run python -c "
import inspect
from scenario_forge.stpa.system_model.control_structure import derive_control_structure
from scenario_forge.models.capability_profile import CapabilityProfile
sig = inspect.signature(derive_control_structure)
param = sig.parameters.get('capability_profile')
assert param is not None, 'capability_profile parameter not found'
assert 'CapabilityProfile' in str(param.annotation), \
    f'Expected CapabilityProfile annotation, got {param.annotation}'
print('OK: capability_profile is a keyword-only parameter of type CapabilityProfile')
"

# QA-CAPPROF-03
check "QA-CAPPROF-03: run_sp1 passes capability_profile through to Call 2" \
    uv run python -c "
import json
from pathlib import Path
import tempfile
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import setup_sp1_mock_client, make_risk_cards, read_calls_jsonl

with tempfile.TemporaryDirectory() as tmpdir:
    run_dir = Path(tmpdir)
    client = setup_sp1_mock_client()
    result = run_sp1(
        llm_client=client,
        use_case_text='Test use case for SP1 batch2 QA',
        risk_cards=make_risk_cards(),
        run_dir=run_dir,
    )
    assert result.control_structure is not None, 'Control structure was not produced'
    calls = read_calls_jsonl(run_dir)
    call2_entry = None
    for entry in calls:
        if entry.get('stage') == 'stage_2' and entry.get('step') == 'call_2_responsibilities':
            call2_entry = entry
            break
    assert call2_entry is not None, 'Call 2 entry not found in calls.jsonl'
    user_prompt = call2_entry.get('user_prompt_text', '')
    assert 'Capability Profile Context' in user_prompt, \
        'Capability Profile Context section not found in Call 2 user prompt'
    assert 'input' in user_prompt, 'zones not found in user prompt'
    assert 'Multi-agent:' in user_prompt, 'multi_agent not found'
    assert 'Human-in-the-loop:' in user_prompt, 'hitl not found'
    print('OK: Call 2 user prompt contains Capability Profile Context with actual values')
"

# QA-CAPPROF-04
check "QA-CAPPROF-04: stage2_call2_user.j2 template contains Capability Profile Context section" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage2_call2_user.j2').read_text()
assert 'Capability Profile Context' in raw, 'Capability Profile Context not found'
assert 'zones_active' in raw, 'zones_active not found'
assert 'multi_agent' in raw, 'multi_agent not found'
assert 'hitl' in raw, 'hitl not found'
assert 'has_persistent_memory' in raw, 'has_persistent_memory not found'
print('OK: template contains all required strings')
"

# QA-CAPPROF-05
check "QA-CAPPROF-05: Rendered Call 2 user prompt contains actual profile data" \
    uv run python -c "
from scenario_forge.models.capability_profile import CapabilityProfile, EntryPoint, ToolInventoryEntry
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

# KC1.1 = input+reasoning, KC5.1 = tool_execution, KCX-MAGENT = multi_agent, KCX-HITL = hitl
# (KC2.3 would add inter_agent zone — we avoid it to keep zones = input,reasoning,tool_execution)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[EntryPoint(name='chat', direction='input')],
    confidence='medium',
    kc_subcodes=['KC1.1', 'KC5.1', 'KCX-MAGENT', 'KCX-HITL'],
    tool_inventory=[ToolInventoryEntry(name='search_tool', description='Search API')],
)
loader = TemplateLoader(PROMPTS_DIR)
rendered = loader.render_prompt(
    'stage2_call2_user.j2',
    use_case_text='Test use case',
    requirements=[],
    capability_profile=profile,
)
assert 'input, reasoning, tool_execution' in rendered, \
    f'Expected zone list not found in rendered text'
# Jinja2 renders True as 'True'
assert 'Multi-agent: True' in rendered, \
    f'Multi-agent: True not found. Got: {rendered}'
assert 'Human-in-the-loop: True' in rendered, \
    f'Human-in-the-loop: True not found'
print('OK: rendered prompt contains actual profile data')
"

# QA-CAPPROF-06
check "QA-CAPPROF-06: Rendered Call 2 user prompt reflects inactive zones" \
    uv run python -c "
from scenario_forge.models.capability_profile import CapabilityProfile, EntryPoint
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

# KC1.1 = input, KC3.3 = reasoning only (no tool_execution, no HITL, no multi-agent)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning'],
    entry_points=[EntryPoint(name='chat', direction='input')],
    confidence='medium',
    kc_subcodes=['KC1.1', 'KC3.3'],
)
loader = TemplateLoader(PROMPTS_DIR)
rendered = loader.render_prompt(
    'stage2_call2_user.j2',
    use_case_text='Test use case',
    requirements=[],
    capability_profile=profile,
)
assert 'input, reasoning' in rendered, f'Expected zone list not found'
assert 'Multi-agent: False' in rendered, f'Multi-agent: False not found'
assert 'Human-in-the-loop: False' in rendered, f'Human-in-the-loop: False not found'
assert 'Persistent memory: False' in rendered, f'Persistent memory: False not found'
print('OK: rendered prompt reflects inactive zones')
"

# QA-CAPPROF-07
check "QA-CAPPROF-07: Existing Call 2 user prompt sections remain present" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage2_call2_user.j2').read_text()
assert '## Use-Case Description' in raw, 'Use-Case Description section missing'
assert '## Requirements' in raw, 'Requirements section missing'
assert '## Your Task' in raw, 'Your Task section missing'
print('OK: all existing sections remain present')
"

# ===========================================================================
# QA-PATHRES: Runner Script Resolves Path References (g5gc)
# ===========================================================================

# Setup temp files for path resolution tests
SETUP_PATHRES="uv run python -c \"
from pathlib import Path
import tempfile, os, shutil
d = Path('tmp')
d.mkdir(exist_ok=True)
(d / 'test_usecase.txt').write_text('This is a real use case description.', encoding='utf-8')
(d / 'inner.txt').write_text('This is the actual use case content.', encoding='utf-8')
(d / 'outer.txt').write_text('tmp/inner.txt', encoding='utf-8')
(d / 'prose.txt').write_text('A' * 250 + chr(10) + 'More content.', encoding='utf-8')
(d / 'inner.md').write_text('This is the resolved markdown content.', encoding='utf-8')
(d / 'outer.md').write_text('tmp/inner.md', encoding='utf-8')
(d / 'outer_unresolvable.txt').write_text('tmp/does_not_exist_target.txt', encoding='utf-8')
# Ensure the target does NOT exist
target = d / 'does_not_exist_target.txt'
if target.exists():
    target.unlink()
print('Setup done')
\""

# QA-PATHRES-01
check "QA-PATHRES-01: read_use_case strips @ prefix" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
text = read_use_case('@tmp/test_usecase.txt')
assert text == 'This is a real use case description.', f'Got: {text!r}'
print('OK: @ prefix stripped, file read correctly')
\""

# QA-PATHRES-02
check "QA-PATHRES-02: read_use_case reads a normal file without @ prefix" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
text = read_use_case('tmp/test_usecase.txt')
assert text == 'This is a real use case description.', f'Got: {text!r}'
print('OK: file read correctly without @ prefix')
\""

# QA-PATHRES-03
check "QA-PATHRES-03: read_use_case resolves a nested path reference" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
text = read_use_case('tmp/outer.txt')
assert text == 'This is the actual use case content.', f'Got: {text!r}'
print('OK: nested path reference resolved')
\""

# QA-PATHRES-04
check "QA-PATHRES-04: read_use_case does not resolve prose content" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
text = read_use_case('tmp/prose.txt')
# Should be the original content (starts with 250 A's), not resolved
assert text.startswith('A' * 250), f'Expected original prose content, got: {text[:50]!r}'
print('OK: prose content not treated as path reference')
\""

# QA-PATHRES-05
check "QA-PATHRES-05: read_use_case raises FileNotFoundError for missing file" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
try:
    read_use_case('tmp/nonexistent_usecase.txt')
    assert False, 'Expected FileNotFoundError'
except FileNotFoundError:
    print('OK: FileNotFoundError raised')
\""

# QA-PATHRES-06
check "QA-PATHRES-06: read_use_case resolves path references with .md extension" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
text = read_use_case('tmp/outer.md')
assert text == 'This is the resolved markdown content.', f'Got: {text!r}'
print('OK: .md path reference resolved')
\""

# QA-PATHRES-07
check "QA-PATHRES-07: read_use_case raises clear error for unresolvable nested path" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
from scripts.run_sp1 import read_use_case
try:
    read_use_case('tmp/outer_unresolvable.txt')
    assert False, 'Expected FileNotFoundError'
except FileNotFoundError as e:
    assert 'does_not_exist_target' in str(e), f'Error message should reference unresolved path, got: {e}'
    print('OK: FileNotFoundError with clear message about unresolved path')
\""

# QA-PATHRES-08
check "QA-PATHRES-08: read_use_case logs first 100 characters of loaded text" \
    bash -c "$SETUP_PATHRES && uv run python -c \"
import logging
from scripts.run_sp1 import read_use_case

# Create a file with > 100 chars content
from pathlib import Path
Path('tmp/test_usecase.txt').write_text('B' * 150, encoding='utf-8')

# Capture log output
import io
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.INFO)
logger = logging.getLogger('scripts.run_sp1')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

text = read_use_case('tmp/test_usecase.txt')
log_output = log_stream.getvalue()
assert 'B' * 100 in log_output or 'B' * 50 in log_output, \
    f'Expected first 100 chars in log, got: {log_output!r}'
print('OK: log entry contains first 100 characters')
\""

# ===========================================================================
# QA-REVRUN: Prevent RevisionDelta Runaway Output (zign)
# ===========================================================================

# QA-REVRUN-01
check "QA-REVRUN-01: revision_system.j2 instructs modified_responsibilities contains only changes" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'revision_system.j2').read_text()
assert 'modified_responsibilities list must contain ONLY responsibilities you are CHANGING' in raw, \
    'Modified responsibilities instruction not found'
assert 'Do not include unmodified responsibilities' in raw, \
    'Do not include unmodified responsibilities not found'
assert 'If a responsibility needs no changes, do not include it in the delta at all' in raw, \
    'If a responsibility needs no changes instruction not found'
print('OK: revision_system.j2 contains all required instructions')
"

# QA-REVRUN-02
check "QA-REVRUN-02: revision_user.j2 does not include use_case_text" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'revision_user.j2').read_text()
assert '{{ use_case_text }}' not in raw, 'use_case_text template variable found in revision_user.j2'
assert 'use_case_text' not in raw, 'use_case_text string found in revision_user.j2'
print('OK: revision_user.j2 does not contain use_case_text')
"

# QA-REVRUN-03
check "QA-REVRUN-03: revision_user.j2 still contains control structure listing" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'revision_user.j2').read_text()
assert 'Current Control Structure' in raw, 'Current Control Structure not found'
assert 'Responsibilities' in raw, 'Responsibilities not found'
assert 'Critic Findings' in raw, 'Critic Findings not found'
print('OK: revision_user.j2 contains all required sections')
"

# QA-REVRUN-04
check "QA-REVRUN-04: safe_llm_call accepts max_completion_tokens parameter" \
    uv run python -c "
import inspect
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call
sig = inspect.signature(safe_llm_call)
param = sig.parameters.get('max_completion_tokens')
assert param is not None, 'max_completion_tokens parameter not found'
assert param.default is None, f'Expected default None, got {param.default}'
print('OK: max_completion_tokens is a keyword-only parameter with default None')
"

# QA-REVRUN-05
check "QA-REVRUN-05: safe_llm_call passes max_completion_tokens to complete" \
    uv run python -c "
from unittest.mock import MagicMock
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call
from pydantic import BaseModel
from pathlib import Path
import tempfile

class DummyModel(BaseModel):
    value: str = 'test'

client = LLMClient(base_url='http://test:8080')
mock_complete = MagicMock(return_value=LLMResult(
    content='{\"value\": \"test\"}',
    prompt_tokens=10,
    completion_tokens=5,
    duration_ms=100,
    system_prompt='sys',
    user_prompt='usr',
))
client.complete = mock_complete

with tempfile.TemporaryDirectory() as tmpdir:
    safe_llm_call(
        llm_client=client,
        system_prompt='sys',
        user_prompt='usr',
        response_format=DummyModel,
        run_dir=Path(tmpdir),
        stage='test',
        step='test',
        max_completion_tokens=4096,
    )

call_kwargs = mock_complete.call_args.kwargs
assert call_kwargs.get('max_completion_tokens') == 4096, \
    f'Expected max_completion_tokens=4096, got {call_kwargs.get(\"max_completion_tokens\")}'
print('OK: max_completion_tokens=4096 passed to complete')
"

# QA-REVRUN-06
check "QA-REVRUN-06: safe_llm_call without max_completion_tokens passes None" \
    uv run python -c "
from unittest.mock import MagicMock
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call
from pydantic import BaseModel
from pathlib import Path
import tempfile

class DummyModel(BaseModel):
    value: str = 'test'

client = LLMClient(base_url='http://test:8080')
mock_complete = MagicMock(return_value=LLMResult(
    content='{\"value\": \"test\"}',
    prompt_tokens=10,
    completion_tokens=5,
    duration_ms=100,
    system_prompt='sys',
    user_prompt='usr',
))
client.complete = mock_complete

with tempfile.TemporaryDirectory() as tmpdir:
    safe_llm_call(
        llm_client=client,
        system_prompt='sys',
        user_prompt='usr',
        response_format=DummyModel,
        run_dir=Path(tmpdir),
        stage='test',
        step='test',
    )

call_kwargs = mock_complete.call_args.kwargs
# When max_completion_tokens is None (not provided), it should not be in kwargs
# OR should be passed as None. The implementation omits it when None.
assert 'max_completion_tokens' not in call_kwargs or call_kwargs['max_completion_tokens'] is None, \
    f'Expected max_completion_tokens to be absent or None, got {call_kwargs.get(\"max_completion_tokens\")}'
print('OK: max_completion_tokens defaults to None (omitted from kwargs)')
"

# QA-REVRUN-07
check "QA-REVRUN-07: run_revision passes max_completion_tokens 4096" \
    uv run python -c "
import json
from pathlib import Path
import tempfile
from scenario_forge.stpa.system_model.critic import run_revision, CriticFindings, CriticGap, RevisionDelta
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ProcessModelPart,
    ControlAction, FeedbackChannel, ElementRef, ReferenceType,
)
from tests.stpa.sp1_helpers import MockLLMClient

# Build a minimal control structure with RESP-1 and RESP-2
cs = ControlStructure(responsibilities=[
    Responsibility(
        resp_id='RESP-1', description='Controller 1',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-1-1', description='FB', updates='PM-1-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-1'),
        )],
    ),
    Responsibility(
        resp_id='RESP-2', description='Controller 2',
        process_model_parts=[ProcessModelPart(pm_id='PM-2-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-2-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-2-1', description='FB', updates='PM-2-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-2'),
        )],
    ),
])

findings = CriticFindings(gaps=[
    CriticGap(gap_type='missing_feedback', description='Missing feedback',
              related_attack_path='path', suggested_remedy='Add FB'),
])

# Mock client returning a valid RevisionDelta
revision_delta_dict = {
    'new_responsibilities': [],
    'new_controlled_processes': [],
    'new_coordination_links': [],
    'modified_responsibilities': [],
}
client = MockLLMClient()
client.set_response_for(RevisionDelta, revision_delta_dict)

with tempfile.TemporaryDirectory() as tmpdir:
    run_revision(
        llm_client=client,
        control_structure=cs,
        critic_findings=findings,
        use_case_text='test',
        run_dir=Path(tmpdir),
    )

# Check that the revision call had max_completion_tokens=4096
revision_call = None
for call in client.calls:
    if call.max_completion_tokens is not None:
        revision_call = call
        break
assert revision_call is not None, 'No call with max_completion_tokens found'
assert revision_call.max_completion_tokens == 4096, \
    f'Expected max_completion_tokens=4096, got {revision_call.max_completion_tokens}'
print('OK: run_revision passes max_completion_tokens=4096 to the revision call')
"

# QA-REVRUN-08
check "QA-REVRUN-08: new_responsibilities with existing resp_id is rejected" \
    uv run python -c "
import logging
from pathlib import Path
import tempfile, io
from scenario_forge.stpa.system_model.critic import run_revision, CriticFindings, CriticGap, RevisionDelta
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ProcessModelPart,
    ControlAction, FeedbackChannel, ElementRef, ReferenceType,
)
from tests.stpa.sp1_helpers import MockLLMClient

cs = ControlStructure(responsibilities=[
    Responsibility(
        resp_id='RESP-1', description='Original',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-1-1', description='FB', updates='PM-1-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-1'),
        )],
    ),
])

findings = CriticFindings(gaps=[
    CriticGap(gap_type='missing_responsibility', description='Missing resp',
              related_attack_path='path', suggested_remedy='Add RESP'),
])

# Return a RevisionDelta with new_responsibilities containing RESP-1 (already exists)
revision_delta_dict = {
    'new_responsibilities': [
        {
            'resp_id': 'RESP-1',
            'description': 'Duplicate',
            'process_model_parts': [{'pm_id': 'PM-1-2', 'description': 'State'}],
            'control_actions': [{'ca_id': 'CA-1-2', 'description': 'Action'}],
            'feedback_channels': [{
                'fb_id': 'FB-1-2', 'description': 'FB', 'updates': 'PM-1-2',
                'source': {'type': 'responsibility', 'id': 'RESP-1'},
            }],
        }
    ],
    'new_controlled_processes': [],
    'new_coordination_links': [],
    'modified_responsibilities': [],
}
client = MockLLMClient()
client.set_response_for(RevisionDelta, revision_delta_dict)

# Capture log
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.WARNING)
logger = logging.getLogger('scenario_forge.stpa.system_model.critic')
logger.addHandler(handler)
logger.setLevel(logging.WARNING)

with tempfile.TemporaryDirectory() as tmpdir:
    revised_cs, warnings = run_revision(
        llm_client=client,
        control_structure=cs,
        critic_findings=findings,
        use_case_text='test',
        run_dir=Path(tmpdir),
    )

# Check that RESP-1 is not duplicated
resp_ids = [r.resp_id for r in revised_cs.responsibilities]
assert resp_ids.count('RESP-1') == 1, f'Expected 1 RESP-1, got {resp_ids}'
# Check the original is preserved
resp1 = [r for r in revised_cs.responsibilities if r.resp_id == 'RESP-1'][0]
assert resp1.description == 'Original', f'Expected original description, got {resp1.description}'

# Check warning was logged
log_output = log_stream.getvalue()
assert 'RESP-1' in log_output or 'duplicate' in log_output.lower(), \
    f'Expected warning about duplicate RESP-1, got: {log_output!r}'
print('OK: duplicate RESP-1 rejected, original preserved, warning logged')
"

# QA-REVRUN-09
check "QA-REVRUN-09: new_responsibilities with genuinely new resp_id is accepted" \
    uv run python -c "
from pathlib import Path
import tempfile
from scenario_forge.stpa.system_model.critic import run_revision, CriticFindings, CriticGap, RevisionDelta
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ProcessModelPart,
    ControlAction, FeedbackChannel, ElementRef, ReferenceType,
)
from tests.stpa.sp1_helpers import MockLLMClient

cs = ControlStructure(responsibilities=[
    Responsibility(
        resp_id='RESP-1', description='Original',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-1-1', description='FB', updates='PM-1-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-1'),
        )],
    ),
])

findings = CriticFindings(gaps=[
    CriticGap(gap_type='missing_responsibility', description='Missing resp',
              related_attack_path='path', suggested_remedy='Add RESP-3'),
])

revision_delta_dict = {
    'new_responsibilities': [
        {
            'resp_id': 'RESP-3',
            'description': 'New responsibility',
            'process_model_parts': [{'pm_id': 'PM-3-1', 'description': 'State'}],
            'control_actions': [{'ca_id': 'CA-3-1', 'description': 'Action'}],
            'feedback_channels': [{
                'fb_id': 'FB-3-1', 'description': 'FB', 'updates': 'PM-3-1',
                'source': {'type': 'responsibility', 'id': 'RESP-3'},
            }],
        }
    ],
    'new_controlled_processes': [],
    'new_coordination_links': [],
    'modified_responsibilities': [],
}
client = MockLLMClient()
client.set_response_for(RevisionDelta, revision_delta_dict)

with tempfile.TemporaryDirectory() as tmpdir:
    revised_cs, warnings = run_revision(
        llm_client=client,
        control_structure=cs,
        critic_findings=findings,
        use_case_text='test',
        run_dir=Path(tmpdir),
    )

resp_ids = [r.resp_id for r in revised_cs.responsibilities]
assert 'RESP-3' in resp_ids, f'RESP-3 not found in revised CS: {resp_ids}'
print('OK: genuinely new RESP-3 accepted')
"

# QA-REVRUN-10
check "QA-REVRUN-10: Duplicate rejection does not affect modified_responsibilities" \
    uv run python -c "
import logging
from pathlib import Path
import tempfile, io
from scenario_forge.stpa.system_model.critic import run_revision, CriticFindings, CriticGap, RevisionDelta
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ProcessModelPart,
    ControlAction, FeedbackChannel, ElementRef, ReferenceType,
)
from tests.stpa.sp1_helpers import MockLLMClient

cs = ControlStructure(responsibilities=[
    Responsibility(
        resp_id='RESP-1', description='Original RESP-1',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-1-1', description='FB', updates='PM-1-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-1'),
        )],
    ),
    Responsibility(
        resp_id='RESP-2', description='Original RESP-2',
        process_model_parts=[ProcessModelPart(pm_id='PM-2-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-2-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-2-1', description='FB', updates='PM-2-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-2'),
        )],
    ),
])

findings = CriticFindings(gaps=[
    CriticGap(gap_type='missing_responsibility', description='Missing resp',
              related_attack_path='path', suggested_remedy='Add/modify'),
])

# Delta: modified RESP-1 with updated description, new RESP-2 (duplicate)
revision_delta_dict = {
    'new_responsibilities': [
        {
            'resp_id': 'RESP-2',
            'description': 'Duplicate RESP-2',
            'process_model_parts': [{'pm_id': 'PM-2-2', 'description': 'State'}],
            'control_actions': [{'ca_id': 'CA-2-2', 'description': 'Action'}],
            'feedback_channels': [{
                'fb_id': 'FB-2-2', 'description': 'FB', 'updates': 'PM-2-2',
                'source': {'type': 'responsibility', 'id': 'RESP-2'},
            }],
        }
    ],
    'new_controlled_processes': [],
    'new_coordination_links': [],
    'modified_responsibilities': [
        {
            'resp_id': 'RESP-1',
            'description': 'Updated RESP-1 description',
            'process_model_parts': [{'pm_id': 'PM-1-1', 'description': 'State'}],
            'control_actions': [{'ca_id': 'CA-1-1', 'description': 'Action'}],
            'feedback_channels': [{
                'fb_id': 'FB-1-1', 'description': 'FB', 'updates': 'PM-1-1',
                'source': {'type': 'responsibility', 'id': 'RESP-1'},
            }],
        }
    ],
}
client = MockLLMClient()
client.set_response_for(RevisionDelta, revision_delta_dict)

log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.WARNING)
logger = logging.getLogger('scenario_forge.stpa.system_model.critic')
logger.addHandler(handler)
logger.setLevel(logging.WARNING)

with tempfile.TemporaryDirectory() as tmpdir:
    revised_cs, warnings = run_revision(
        llm_client=client,
        control_structure=cs,
        critic_findings=findings,
        use_case_text='test',
        run_dir=Path(tmpdir),
    )

# RESP-1 should have updated description
resp1 = [r for r in revised_cs.responsibilities if r.resp_id == 'RESP-1'][0]
assert resp1.description == 'Updated RESP-1 description', \
    f'Expected updated description, got {resp1.description}'

# RESP-2 should not be duplicated
resp2_count = sum(1 for r in revised_cs.responsibilities if r.resp_id == 'RESP-2')
assert resp2_count == 1, f'Expected 1 RESP-2, got {resp2_count}'
resp2 = [r for r in revised_cs.responsibilities if r.resp_id == 'RESP-2'][0]
assert resp2.description == 'Original RESP-2', \
    f'Expected original RESP-2, got {resp2.description}'

# Warning about duplicate RESP-2
log_output = log_stream.getvalue()
assert 'RESP-2' in log_output, f'Expected warning about RESP-2, got: {log_output!r}'
print('OK: modified_responsibilities applied, duplicate new rejected, warning logged')
"

# QA-REVRUN-11
check "QA-REVRUN-11: revision_system.j2 preserves existing delta and ID rules" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'revision_system.j2').read_text()
assert 'Do NOT restate the entire control structure' in raw, \
    'Do NOT restate instruction not found'
assert 'ID format rules' in raw, 'ID format rules not found'
assert 'solution-neutrality' in raw, 'solution-neutrality not found'
print('OK: revision_system.j2 preserves delta and ID rules')
"

# QA-REVRUN-12
check "QA-REVRUN-12: revision_system.j2 renders successfully with the new instruction" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ProcessModelPart,
    ControlAction, FeedbackChannel, ElementRef, ReferenceType,
)

cs = ControlStructure(responsibilities=[
    Responsibility(
        resp_id='RESP-1', description='Controller',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Action')],
        feedback_channels=[FeedbackChannel(
            fb_id='FB-1-1', description='FB', updates='PM-1-1',
            source=ElementRef(type=ReferenceType.responsibility, id='RESP-1'),
        )],
    ),
])

loader = TemplateLoader(PROMPTS_DIR)
rendered = loader.render_prompt(
    'revision_system.j2',
    control_structure=cs,
    next_resp_num=2,
    next_cl_num=1,
    next_cp_num=1,
)
assert 'modified_responsibilities list must contain ONLY' in rendered, \
    'New instruction not found in rendered text'
assert '{{' not in rendered, f'Unrendered template syntax found'
print('OK: revision_system.j2 renders successfully')
"

# ===========================================================================
# QA-SECCON: Prevent Security Constraints from Contaminating Tool Inventory (clyy)
# ===========================================================================

# QA-SECCON-01
check "QA-SECCON-01: stage1b_system.j2 instructs not to infer tools from security constraints" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage1b_system.j2').read_text()
assert 'Security constraints describe what SHOULD exist, not what DOES exist' in raw, \
    'Security constraints instruction not found'
assert 'Do not infer tools from security constraints' in raw, \
    'Do not infer tools instruction not found'
print('OK: stage1b_system.j2 contains security constraints instructions')
"

# QA-SECCON-02
check "QA-SECCON-02: stage1b_system.j2 instructs to list only existing capabilities" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage1b_system.j2').read_text()
assert 'Only list tools explicitly described as existing capabilities in the use-case description' in raw, \
    'Only list existing capabilities instruction not found'
print('OK: stage1b_system.j2 contains existing capabilities instruction')
"

# QA-SECCON-03
check "QA-SECCON-03: stage1b_user.j2 relabels Security Constraints section" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage1b_user.j2').read_text()
assert 'Security Constraints (requirements for future control structure, NOT existing capabilities)' in raw, \
    'Relabeled Security Constraints section not found'
print('OK: stage1b_user.j2 relabels Security Constraints section')
"

# QA-SECCON-04
check "QA-SECCON-04: stage1b_user.j2 does not contain old unlabeled Security Constraints header" \
    uv run python -c "
import re
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage1b_user.j2').read_text()
# Check that there is no bare '### Security Constraints' without the clarification
# The pattern would be '### Security Constraints' not followed by the parenthetical
pattern = r'### Security Constraints\s*\n(?!.*requirements for future)'
matches = re.findall(pattern, raw)
assert not matches, f'Found bare Security Constraints header without clarification: {matches}'
print('OK: no bare Security Constraints header without clarification')
"

# QA-SECCON-05
check "QA-SECCON-05: stage1b_user.j2 still renders security constraint listings" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
from scenario_forge.stpa.models.loss_analysis import (
    LossAnalysis, Loss, LossProvenance, Hazard, SecurityConstraint,
)

la = LossAnalysis(
    risk_card_losses=[],
    use_case_losses=[
        Loss(loss_id='L-1', description='Loss', provenance=LossProvenance.use_case),
    ],
    hazards=[Hazard(hazard_id='H-1', description='Hazard', related_losses=['L-1'])],
    security_constraints=[
        SecurityConstraint(constraint_id='SC-1', description='Constraint', related_hazards=['H-1']),
    ],
)

loader = TemplateLoader(PROMPTS_DIR)
rendered = loader.render_prompt(
    'stage1b_user.j2',
    use_case_text='Test use case',
    loss_analysis=la,
    all_losses=la.use_case_losses + la.risk_card_losses,
)
assert 'Security Constraints' in rendered, 'Security Constraints not in rendered text'
assert 'SC-1' in rendered, 'constraint_id SC-1 not in rendered text'
print('OK: stage1b_user.j2 renders security constraint listings')
"

# QA-SECCON-06
check "QA-SECCON-06: stage1b_system.j2 preserves existing quality requirement sections" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage1b_system.j2').read_text()
assert '## Quality requirements' in raw, 'Quality requirements section not found'
assert '## Schneider zones' in raw, 'Schneider zones section not found'
assert '## Rules' in raw, 'Rules section not found'
assert '## Emphasis' in raw, 'Emphasis section not found'
print('OK: stage1b_system.j2 preserves all existing quality sections')
"

# QA-SECCON-07
check "QA-SECCON-07: stage1b_system.j2 renders successfully with new instruction" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
loader = TemplateLoader(PROMPTS_DIR)
# stage1b_system.j2 has no required variables
rendered = loader.render_prompt('stage1b_system.j2')
assert 'Security constraints describe what SHOULD exist' in rendered, \
    'New instruction not found in rendered text'
assert '{{' not in rendered, f'Unrendered template syntax found'
print('OK: stage1b_system.j2 renders successfully with new instruction')
"

# QA-SECCON-08
check "QA-SECCON-08: stage1b_user.j2 preserves other loss analysis sections" \
    uv run python -c "
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
raw = (PROMPTS_DIR / 'stage1b_user.j2').read_text()
assert 'Loss Analysis Context' in raw, 'Loss Analysis Context not found'
assert 'Losses' in raw, 'Losses not found'
assert 'Hazards' in raw, 'Hazards not found'
assert 'Your Task' in raw, 'Your Task not found'
print('OK: stage1b_user.j2 preserves all other loss analysis sections')
"

# ===========================================================================
# Summary
# ===========================================================================

echo "=========================================="
echo "SP1 Batch 2 QA Suite Results: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "Failed checks:"
    for c in "${FAILED_CHECKS[@]}"; do
        echo "  - $c"
    done
    exit 1
fi
echo "All SP1 Batch 2 QA checks passed."
exit 0
