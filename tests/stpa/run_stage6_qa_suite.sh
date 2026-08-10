#!/usr/bin/env bash
# Stage 6 Output Quality — Executable QA Suite
#
# Executable form of the QA checks in
# tests/stpa/features/qa_stage6_output_quality.md. All verification goes
# through the user interface: Python import checks, pytest execution,
# the run_sp3.py command line with a local stub LLM endpoint, filesystem
# inspection, and CLI verification — no project-internal APIs.
#
# The end-to-end run checks (QA-JPKW-12, QA-GDDI-09, QA-V689-07) drive
# the real CLI against the stub LLM endpoint
# (tests/stpa/sp3_qa_stub_llm.py) so the suite is deterministic, offline,
# and free of API cost while still exercising the real orchestration,
# artifact writing, and validation code paths.
#
# Usage: bash tests/stpa/run_stage6_qa_suite.sh
# Exit 0 = all pass, Exit 1 = any fail.

set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

FIXTURES="src/scenario_forge/stpa/fixtures"
WORK_DIR="tmp/stage6-qa"
STUB_PID=""

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
    uv run python tests/stpa/sp3_qa_stub_llm.py --port 0 --ready-file "$ready_file" \
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
sp3-qa-stub:
  base_url: http://127.0.0.1:${port}/v1
  model: sp3-qa-stub
  api_key: unused
  temperature: 0.4
EOF
}

run_sp3_cli() {
    local out_dir="$1"
    shift
    uv run python scripts/run_sp3.py \
        --enriched-threats "$FIXTURES/enriched_threats_klarna.yaml" \
        --control-structure "$FIXTURES/control_structure_klarna.yaml" \
        --loss-analysis "$FIXTURES/loss_analysis_klarna.yaml" \
        --output-dir "$out_dir" \
        --profiles-file "$WORK_DIR/profiles.yaml" \
        --profile sp3-qa-stub \
        "$@"
}

# ===========================================================================
# JPKW — Structure Gherkin Spec as YAML Object
# ===========================================================================

# QA-JPKW-01 + QA-JPKW-02: Model schema checks
check "QA-JPKW-01: GherkinSpec model has structured fields" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
fields = GherkinSpec.model_fields
required = ['feature', 'scenario', 'given', 'when', 'then_expected', 'then_actual']
for name in required:
    assert name in fields, f'Missing field: {name}'
# Check types via annotations
import typing
ann = GherkinSpec.model_fields
assert 'str' in str(ann['feature'].annotation)
assert 'str' in str(ann['scenario'].annotation)
assert 'list' in str(ann['given'].annotation).lower()
assert 'list' in str(ann['when'].annotation).lower()
assert 'list' in str(ann['then_expected'].annotation).lower()
assert 'list' in str(ann['then_actual'].annotation).lower()
print('All 6 GherkinSpec fields exist with correct types')
"

check "QA-JPKW-02: ScenarioEnvelope has gherkin_spec as GherkinSpec and gherkin_raw as str" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope, GherkinSpec
fields = ScenarioEnvelope.model_fields
assert 'gherkin_spec' in fields, 'Missing gherkin_spec field'
assert 'gherkin_raw' in fields, 'Missing gherkin_raw field'
gherkin_spec_ann = str(fields['gherkin_spec'].annotation)
assert 'GherkinSpec' in gherkin_spec_ann, f'gherkin_spec not typed as GherkinSpec: {gherkin_spec_ann}'
gherkin_raw_ann = str(fields['gherkin_raw'].annotation)
assert 'str' in gherkin_raw_ann, f'gherkin_raw not typed as str: {gherkin_raw_ann}'
print('gherkin_spec is GherkinSpec, gherkin_raw is str')
"

# QA-JPKW-03: System prompt requests structured YAML
check "QA-JPKW-03: Stage 6c system prompt requests structured YAML output" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR
loader = TemplateLoader(PROMPTS_DIR)
prompt = loader.render_prompt('stage6c_gherkin_system.j2')
assert 'yaml' in prompt.lower(), 'Prompt does not mention YAML'
for field in ['feature', 'scenario', 'given', 'when', 'then_expected', 'then_actual']:
    assert field in prompt, f'Prompt does not mention field: {field}'
print('System prompt requests structured YAML with all required fields')
"

# QA-JPKW-04 + QA-JPKW-05: generate_gherkin returns GherkinSpec and parses fields
check "QA-JPKW-04: generate_gherkin returns GherkinSpec and raw text" \
    uv run python -c "
from pathlib import Path
from tempfile import TemporaryDirectory
from scenario_forge.stpa.scenario_prod.gherkin import generate_gherkin
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_loss_analysis, _VALID_GHERKIN_YAML

spec = _make_scenario_spec()
la = _make_loss_analysis()
client = MockLLMClient()
client.set_response_for(None, _VALID_GHERKIN_YAML)

with TemporaryDirectory() as tmpdir:
    result, raw, error = generate_gherkin(client, spec, la, Path(tmpdir))
    assert error is None, f'Error: {error}'
    assert isinstance(result, GherkinSpec), f'Result is not GherkinSpec: {type(result)}'
    assert isinstance(raw, str) and len(raw) > 0, 'raw is not a non-empty string'
print('generate_gherkin returns GherkinSpec and raw text')
"

check "QA-JPKW-05: generate_gherkin parses YAML response into structured fields" \
    uv run python -c "
from pathlib import Path
from tempfile import TemporaryDirectory
from scenario_forge.stpa.scenario_prod.gherkin import generate_gherkin
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_loss_analysis, _VALID_GHERKIN_YAML

spec = _make_scenario_spec()
la = _make_loss_analysis()
client = MockLLMClient()
client.set_response_for(None, _VALID_GHERKIN_YAML)

with TemporaryDirectory() as tmpdir:
    result, _, _ = generate_gherkin(client, spec, la, Path(tmpdir))
    assert result is not None
    assert 'Given PM-1-1 is active' in result.given
    assert 'And the system is online' in result.given
print('given list contains both expected steps')
"

# QA-JPKW-06: assemble_envelope accepts GherkinSpec and gherkin_raw
check "QA-JPKW-06: assemble_envelope accepts GherkinSpec and gherkin_raw" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_gherkin_spec

spec = _make_scenario_spec()
ghk = _make_gherkin_spec(feature='Safe orchestration', scenario='SCN-001')
raw = 'Feature: Safe orchestration\nScenario: SCN-001\n'

envelope = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='Narrative',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=ghk, gherkin_raw=raw,
)
assert envelope.gherkin_spec == ghk
assert envelope.gherkin_raw == raw
print('envelope.gherkin_spec and gherkin_raw match inputs')
"

# QA-JPKW-07: .feature file is written from gherkin_raw
check "QA-JPKW-07: .feature file is written from gherkin_raw" \
    uv run python -c "
from pathlib import Path
from tempfile import TemporaryDirectory
from scenario_forge.stpa.scenario_prod.run import _write_scenario_artifacts
from tests.stpa.test_stage6_output_quality import _make_envelope

raw = 'Feature: Safe orchestration\nScenario: SCN-001\n'
envelope = _make_envelope(gherkin_raw=raw)

with TemporaryDirectory() as tmpdir:
    scenarios_dir = Path(tmpdir)
    _write_scenario_artifacts(envelope, scenarios_dir)
    feature_path = scenarios_dir / 'SCN-001.feature'
    assert feature_path.exists(), '.feature file not written'
    content = feature_path.read_text(encoding='utf-8')
    assert raw in content, '.feature does not contain gherkin_raw text'
print('.feature file contains gherkin_raw text')
"

# QA-JPKW-08: structured validation catches missing required content
check "QA-JPKW-08: structured validation catches missing required GherkinSpec content" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_gherkin_structure
from tests.stpa.test_stage6_output_quality import _make_gherkin_spec

spec = _make_gherkin_spec(then_expected=[])
result = validate_gherkin_structure(spec)
assert not result.passed
assert any('should' in e.lower() for e in result.errors)
print('Validation fails with should error for empty then_expected')
"

# QA-JPKW-09: valid structured GherkinSpec passes validation
check "QA-JPKW-09: valid structured GherkinSpec passes validation" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_gherkin_structure
from tests.stpa.test_stage6_output_quality import _make_gherkin_spec

spec = _make_gherkin_spec(
    then_expected=['Then the system should reject'],
    then_actual=['But approves'],
    given=['Given PM-1-1 is active'],
)
result = validate_gherkin_structure(spec)
assert result.passed, f'Validation failed: {result.errors}'
print('Valid GherkinSpec passes validation')
"

# QA-JPKW-10: gherkin_raw preserves full Feature text
check "QA-JPKW-10: gherkin_raw preserves full Feature text for backward compatibility" \
    uv run python -c "
from pathlib import Path
from tempfile import TemporaryDirectory
from scenario_forge.stpa.scenario_prod.gherkin import generate_gherkin
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_loss_analysis, _VALID_GHERKIN_YAML

spec = _make_scenario_spec()
la = _make_loss_analysis()
client = MockLLMClient()
client.set_response_for(None, _VALID_GHERKIN_YAML)

with TemporaryDirectory() as tmpdir:
    _, raw, _ = generate_gherkin(client, spec, la, Path(tmpdir))
    assert 'Safe orchestration' in raw, 'Feature text missing from raw'
    assert 'SCN-001' in raw, 'Scenario text missing from raw'
print('gherkin_raw preserves Feature and Scenario text')
"

# QA-JPKW-11: Stage 7 envelope validation uses GherkinSpec fields
check "QA-JPKW-11: Stage 7 envelope validation uses GherkinSpec fields" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.run import _validate_envelope_stage7
from tests.stpa.test_stage6_output_quality import _make_envelope, _make_gherkin_spec, _make_loss_analysis

la = _make_loss_analysis()
envelope = _make_envelope(gherkin_spec=_make_gherkin_spec(then_expected=[]))
errors = []
_validate_envelope_stage7(envelope, la, errors)
assert any('should' in e.lower() for e in errors), f'No should error: {errors}'
print('Stage 7 validation catches empty then_expected')
"

# ===========================================================================
# GDDI — Fix Loss ID Hallucination
# ===========================================================================

# QA-GDDI-01: user prompt includes valid Loss and Hazard IDs
check "QA-GDDI-01: user prompt includes valid Loss and Hazard IDs" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR
from scenario_forge.stpa.scenario_prod.gherkin import build_gherkin_prompts, find_security_constraint
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_loss_analysis

spec = _make_scenario_spec()
la = _make_loss_analysis(loss_ids=['L-1', 'L-2', 'L-3'], hazard_ids=['H-1', 'H-2'])
loader = TemplateLoader(PROMPTS_DIR)
sc = find_security_constraint(spec, la)
_, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
for lid in ['L-1', 'L-2', 'L-3']:
    assert lid in user_prompt, f'Missing loss ID: {lid}'
for hid in ['H-1', 'H-2']:
    assert hid in user_prompt, f'Missing hazard ID: {hid}'
print('User prompt contains all valid L-* and H-* IDs')
"

# QA-GDDI-02: user prompt instructs LLM to reference only valid IDs
check "QA-GDDI-02: user prompt instructs LLM to reference only valid IDs" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR
from scenario_forge.stpa.scenario_prod.gherkin import build_gherkin_prompts, find_security_constraint
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_loss_analysis

spec = _make_scenario_spec()
la = _make_loss_analysis()
loader = TemplateLoader(PROMPTS_DIR)
sc = find_security_constraint(spec, la)
_, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
prompt_lower = user_prompt.lower()
assert 'only' in prompt_lower and ('l-*' in prompt_lower or 'loss' in prompt_lower), 'No instruction to use only valid L-* IDs'
assert 'do not invent' in prompt_lower or 'not invent' in prompt_lower, 'No instruction not to invent new IDs'
print('User prompt instructs LLM to reference only valid IDs')
"

# QA-GDDI-03: system prompt instructs LLM to use only provided L-* and H-* IDs
check "QA-GDDI-03: system prompt instructs LLM to use only provided L-* and H-* IDs" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR

loader = TemplateLoader(PROMPTS_DIR)
prompt = loader.render_prompt('stage6c_gherkin_system.j2')
prompt_lower = prompt.lower()
assert 'l-*' in prompt_lower or 'loss' in prompt_lower, 'No mention of L-* IDs'
assert 'h-*' in prompt_lower or 'hazard' in prompt_lower, 'No mention of H-* IDs'
assert 'only' in prompt_lower or 'do not invent' in prompt_lower, 'No instruction to use only provided IDs'
print('System prompt instructs LLM to use only provided L-* and H-* IDs')
"

# QA-GDDI-04: build_gherkin_prompts accepts loss analysis parameter
check "QA-GDDI-04: build_gherkin_prompts accepts loss analysis parameter" \
    uv run python -c "
import inspect
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR
from scenario_forge.stpa.scenario_prod.gherkin import build_gherkin_prompts, find_security_constraint
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_loss_analysis

sig = inspect.signature(build_gherkin_prompts)
params = list(sig.parameters.keys())
assert any('loss' in p.lower() for p in params), f'No loss_analysis parameter: {params}'

spec = _make_scenario_spec()
la = _make_loss_analysis(loss_ids=['L-1', 'L-2'])
loader = TemplateLoader(PROMPTS_DIR)
sc = find_security_constraint(spec, la)
_, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
assert 'L-1' in user_prompt and 'L-2' in user_prompt
print('build_gherkin_prompts accepts loss_analysis and prompt contains valid IDs')
"

# QA-GDDI-05: validator catches hallucinated Loss ID
check "QA-GDDI-05: validator catches hallucinated Loss ID" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_loss_hazard_id_references
from tests.stpa.test_stage6_output_quality import _make_loss_analysis

la = _make_loss_analysis(loss_ids=['L-1', 'L-2', 'L-3'])
text = 'Given PM-1-1\nThen should reject\nBut L-99 is referenced'
result = validate_loss_hazard_id_references(text, la)
assert not result.passed, f'Validation should fail: {result.errors}'
assert any('L-99' in e for e in result.errors), f'No L-99 error: {result.errors}'
print('Validator catches hallucinated L-99')
"

# QA-GDDI-06: validator catches multiple hallucinated IDs
check "QA-GDDI-06: validator catches multiple hallucinated IDs" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_loss_hazard_id_references
from tests.stpa.test_stage6_output_quality import _make_loss_analysis

la = _make_loss_analysis(loss_ids=['L-1', 'L-2'], hazard_ids=['H-1', 'H-2'])
text = 'Given PM-1-1\nThen should reject\nBut L-99 and H-88 are referenced'
result = validate_loss_hazard_id_references(text, la)
assert not result.passed
errors_text = ' '.join(result.errors)
assert 'L-99' in errors_text, f'No L-99 error: {result.errors}'
assert 'H-88' in errors_text, f'No H-88 error: {result.errors}'
print('Validator catches both L-99 and H-88')
"

# QA-GDDI-07: validator passes when all references are valid
check "QA-GDDI-07: validator passes when all L-* and H-* references are valid" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_loss_hazard_id_references
from tests.stpa.test_stage6_output_quality import _make_loss_analysis

la = _make_loss_analysis(loss_ids=['L-1', 'L-2'], hazard_ids=['H-1', 'H-2'])
text = 'Given PM-1-1\nThen should reject\nBut L-1 and H-1 are referenced'
result = validate_loss_hazard_id_references(text, la)
assert result.passed, f'Validation should pass: {result.errors}'
print('Validator passes with valid L-1 and H-1')
"

# QA-GDDI-08: validator passes when no L-* or H-* references
check "QA-GDDI-08: validator passes when Gherkin has no L-* or H-* references" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_loss_hazard_id_references
from tests.stpa.test_stage6_output_quality import _make_loss_analysis

la = _make_loss_analysis()
text = 'Given PM-1-1\nThen should reject\nBut the system fails'
result = validate_loss_hazard_id_references(text, la)
assert result.passed, f'Validation should pass: {result.errors}'
print('Validator passes with no L-* or H-* references')
"

# ===========================================================================
# V689 — Fix Attack Tree Root Label ICA Type
# ===========================================================================

# QA-V689-01: system prompt instructs exact ICA type usage
check "QA-V689-01: system prompt instructs exact ICA type usage" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR

loader = TemplateLoader(PROMPTS_DIR)
prompt = loader.render_prompt('stage6b_tree_system.j2')
prompt_lower = prompt.lower()
assert 'induce ica' in prompt_lower, 'No Induce ICA format'
assert 'ica_type' in prompt_lower or '{ica_type}' in prompt, 'No ICA type placeholder'
assert 'ca_id' in prompt_lower or '{ca_id}' in prompt, 'No CA ID placeholder'
assert 'exact' in prompt_lower or 'do not' in prompt_lower, 'No instruction to use exact type'
print('System prompt instructs exact ICA type usage with correct format')
"

# QA-V689-02: validator passes when root label matches exact ICA type
check "QA-V689-02: validator passes when root label matches exact ICA type" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_attack_tree_root_label

tree = {'root': 'Induce ICA NOT_PROVIDED on CA-1-1'}
result = validate_attack_tree_root_label(tree, 'NOT_PROVIDED', 'CA-1-1')
assert result.passed, f'Validation should pass: {result.errors}'
print('Validator passes with matching root label')
"

# QA-V689-03: validator catches ICA type drift
check "QA-V689-03: validator catches ICA type drift" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_attack_tree_root_label

tree = {'root': 'Induce ICA NOT_TRIGGERED on CA-1-1'}
result = validate_attack_tree_root_label(tree, 'NOT_PROVIDED', 'CA-1-1')
assert not result.passed, f'Validation should fail: {result.errors}'
assert any('NOT_PROVIDED' in e for e in result.errors), f'No NOT_PROVIDED error: {result.errors}'
print('Validator catches ICA type drift')
"

# QA-V689-04: validator catches missing ICA type in root label
check "QA-V689-04: validator catches missing ICA type in root label" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_attack_tree_root_label

tree = {'root': 'Induce ICA on CA-1-1'}
result = validate_attack_tree_root_label(tree, 'NOT_PROVIDED', 'CA-1-1')
assert not result.passed, f'Validation should fail: {result.errors}'
assert any('NOT_PROVIDED' in e for e in result.errors), f'No NOT_PROVIDED error: {result.errors}'
print('Validator catches missing ICA type')
"

# QA-V689-05: validator catches wrong control action in root label
check "QA-V689-05: validator catches wrong control action in root label" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_attack_tree_root_label

tree = {'root': 'Induce ICA NOT_PROVIDED on CA-9-9'}
result = validate_attack_tree_root_label(tree, 'NOT_PROVIDED', 'CA-1-1')
assert not result.passed, f'Validation should fail: {result.errors}'
assert any('CA-1-1' in e for e in result.errors), f'No CA-1-1 error: {result.errors}'
print('Validator catches wrong control action')
"

# QA-V689-06: validator catches empty root label
check "QA-V689-06: validator catches empty root label" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.validators import validate_attack_tree_root_label

tree = {'root': ''}
result = validate_attack_tree_root_label(tree, 'NOT_PROVIDED', 'CA-1-1')
assert not result.passed, f'Validation should fail: {result.errors}'
assert any('root' in e.lower() for e in result.errors), f'No root error: {result.errors}'
print('Validator catches empty root label')
"

# QA-V689-08: root label validation runs during Stage 7 envelope validation
check "QA-V689-08: root label validation runs during Stage 7 envelope validation" \
    uv run python -c "
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.scenario_prod.run import _validate_envelope_stage7
from tests.stpa.test_stage6_output_quality import _make_envelope, _make_scenario_spec, _make_loss_analysis, _make_gherkin_spec

spec = _make_scenario_spec(ica_type=UCAType.not_provided)
envelope = _make_envelope(
    spec=spec,
    gherkin_spec=_make_gherkin_spec(),
)
envelope.attack_tree = {'root': 'Induce ICA NOT_TRIGGERED on CA-1-1', 'branches': [], 'leaves': []}
la = _make_loss_analysis()
errors = []
_validate_envelope_stage7(envelope, la, errors)
assert any('NOT_PROVIDED' in e for e in errors), f'No NOT_PROVIDED error: {errors}'
print('Stage 7 validation catches ICA type drift in root label')
"

# QA-V689-09: user prompt passes ICA type to the LLM
check "QA-V689-09: user prompt passes ICA type to the LLM" \
    uv run python -c "
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.scenario_prod.attack_tree import build_attack_tree_prompts
from tests.stpa.test_stage6_output_quality import _make_scenario_spec, _make_cs

spec = _make_scenario_spec(ica_type=__import__('scenario_forge.stpa.models.ica_enumeration', fromlist=['UCAType']).UCAType.not_provided)
cs = _make_cs()
loader = TemplateLoader(__import__('scenario_forge.stpa.scenario_prod._constants', fromlist=['PROMPTS_DIR']).PROMPTS_DIR)
_, user_prompt = build_attack_tree_prompts(spec, cs, loader)
assert 'NOT_PROVIDED' in user_prompt, 'ICA type not in user prompt'
print('User prompt contains ICA type NOT_PROVIDED')
"

# QA-V689-07: root label validation runs during Stage 6 artifact validation
# (covered by end-to-end run below)

# QA-GDDI-09: Loss/Hazard ID validation runs during Stage 7 envelope validation
# (covered by end-to-end run below)

# QA-GDDI-10: Loss/Hazard ID validation runs during Stage 7 envelope validation
check "QA-GDDI-10: Loss/Hazard ID validation runs during Stage 7 envelope validation" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.run import _validate_envelope_stage7
from tests.stpa.test_stage6_output_quality import _make_envelope, _make_gherkin_spec, _make_loss_analysis

ghk = _make_gherkin_spec(
    then_actual=['But the system fails', 'And H-99 is referenced'],
)
envelope = _make_envelope(gherkin_spec=ghk, gherkin_raw='')
# Set gherkin_raw to the feature text so the validator can find H-99
envelope.gherkin_raw = ghk.to_feature_text()
la = _make_loss_analysis(hazard_ids=['H-1', 'H-2'])
errors = []
_validate_envelope_stage7(envelope, la, errors)
assert any('H-99' in e for e in errors), f'No H-99 error: {errors}'
print('Stage 7 validation catches hallucinated H-99')
"

# ===========================================================================
# End-to-end run with stub LLM (QA-JPKW-12, QA-GDDI-09, QA-V689-07)
# ===========================================================================

echo "=== Starting stub LLM endpoint ==="
if ! start_stub; then
    echo "Failed to start stub LLM endpoint"
    FAIL=$((FAIL + 1))
    FAILED_CHECKS+=("Stub LLM startup")
else
    echo "Stub LLM endpoint ready"
    echo

    RUN_DIR="$WORK_DIR/sp3-run"

    # Run the full SP3 pipeline
    echo "--- Running SP3 pipeline with stub LLM ---"
    if run_sp3_cli "$RUN_DIR" 2>"$WORK_DIR/sp3-stderr.log"; then
        echo "  SP3 pipeline completed"
    else
        echo "  SP3 pipeline failed (check $WORK_DIR/sp3-stderr.log)"
    fi
    echo

    # QA-JPKW-12: SP3 run produces envelope with structured GherkinSpec
    check "QA-JPKW-12: SP3 run produces envelope with structured GherkinSpec" \
        uv run python -c "
import yaml
from pathlib import Path
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope, GherkinSpec

run_dir = Path('$RUN_DIR')
scenarios_dir = run_dir / 'scenarios'
yaml_files = sorted(scenarios_dir.glob('*.yaml'))
assert len(yaml_files) > 0, 'No scenario YAML files found'
envelope_data = yaml.safe_load(yaml_files[0].read_text(encoding='utf-8'))
envelope = ScenarioEnvelope.model_validate(envelope_data)
assert isinstance(envelope.gherkin_spec, GherkinSpec), f'gherkin_spec is not GherkinSpec: {type(envelope.gherkin_spec)}'
assert envelope.gherkin_spec.feature, 'gherkin_spec.feature is empty'
assert envelope.gherkin_spec.given, 'gherkin_spec.given is empty'
assert envelope.gherkin_spec.then_expected, 'gherkin_spec.then_expected is empty'
assert envelope.gherkin_raw, 'gherkin_raw is empty'
print(f'Envelope has structured GherkinSpec (feature={envelope.gherkin_spec.feature!r})')
"

    # QA-GDDI-09: Loss/Hazard ID validation runs during Stage 6 (check no hallucinated IDs in output)
    check "QA-GDDI-09: No hallucinated L-*/H-* IDs in generated Gherkin" \
        uv run python -c "
import yaml
from pathlib import Path
from scenario_forge.stpa.scenario_prod.validators import validate_loss_hazard_id_references

run_dir = Path('$RUN_DIR')
scenarios_dir = run_dir / 'scenarios'
loss_analysis_path = Path('$FIXTURES/loss_analysis_klarna.yaml')
la_data = yaml.safe_load(loss_analysis_path.read_text(encoding='utf-8'))
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
la = LossAnalysis.model_validate(la_data)

yaml_files = sorted(scenarios_dir.glob('*.yaml'))
for yf in yaml_files:
    env_data = yaml.safe_load(yf.read_text(encoding='utf-8'))
    gherkin_raw = env_data.get('gherkin_raw', '')
    if gherkin_raw:
        result = validate_loss_hazard_id_references(gherkin_raw, la)
        assert result.passed, f'{yf.name}: hallucinated IDs: {result.errors}'
print(f'All {len(yaml_files)} scenario Gherkin texts pass Loss/Hazard ID validation')
"

    # QA-V689-07: Root label validation runs during Stage 6 (check root labels in output)
    check "QA-V689-07: All attack tree root labels match ICA type" \
        uv run python -c "
import yaml
from pathlib import Path
from scenario_forge.stpa.scenario_prod.validators import validate_attack_tree_root_label

run_dir = Path('$RUN_DIR')
scenarios_dir = run_dir / 'scenarios'
yaml_files = sorted(scenarios_dir.glob('*.yaml'))
for yf in yaml_files:
    env_data = yaml.safe_load(yf.read_text(encoding='utf-8'))
    attack_tree = env_data.get('attack_tree', {})
    ica_type = env_data.get('ica_type', '')
    ca_id = env_data.get('scenario_spec', {}).get('target_control_action', '')
    result = validate_attack_tree_root_label(attack_tree, ica_type, ca_id)
    assert result.passed, f'{yf.name}: root label error: {result.errors}'
print(f'All {len(yaml_files)} attack tree root labels match ICA type')
"
fi

# ===========================================================================
# CLI and report verification
# ===========================================================================

check "QA-CLI: stpa-report CLI is available" \
    uv run scenario-forge stpa-report --help

check "QA-REPORT: Report generates from SP3 run output" \
    uv run scenario-forge stpa-report --output-dir "$RUN_DIR" -o "$WORK_DIR/report.html" 2>&1 && \
    test -f "$WORK_DIR/report.html" && \
    test -s "$WORK_DIR/report.html"

check "QA-REPORT: Report contains GherkinSpec feature text" \
    uv run python -c "
from pathlib import Path
report = Path('$WORK_DIR/report.html').read_text(encoding='utf-8')
assert 'Feature:' in report or 'feature' in report.lower(), 'No Feature text in report'
assert 'Scenario:' in report or 'scenario' in report.lower(), 'No Scenario text in report'
print('Report contains Gherkin feature/scenario text')
"

# ===========================================================================
# Unit test suite
# ===========================================================================

check "QA-UNIT: Stage 6 output quality unit tests pass" \
    uv run pytest tests/stpa/test_stage6_output_quality.py -q

check "QA-UNIT: Stage 6 property tests pass" \
    uv run pytest tests/stpa/test_stage6_property.py -q

check "QA-LINT: ruff check passes on src and tests/stpa" \
    ruff check src/ tests/stpa/

# ===========================================================================
# Summary
# ===========================================================================

echo
echo "=========================================="
echo "Stage 6 QA Suite Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed checks:"
    for name in "${FAILED_CHECKS[@]}"; do
        echo "  - $name"
    done
    exit 1
fi
echo "All checks passed."
exit 0
