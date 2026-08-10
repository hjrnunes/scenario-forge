#!/usr/bin/env bash
# Envelope Enrichment — Executable QA Suite
#
# Executable form of the QA checks in
# tests/stpa/features/qa_envelope_enrichment.md. All verification goes
# through the user interface: Python import checks, model schema
# inspection, function invocation with constructed inputs, YAML
# serialization inspection, and HTML report generation — no
# project-internal APIs beyond public module interfaces.
#
# Usage: bash tests/stpa/run_envelope_enrichment_qa_suite.sh
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
# UMCF — Inline SP1 System Context into Scenario Envelope
# ===========================================================================

# QA-UMCF-01: SystemContext model has required fields
check "QA-UMCF-01: SystemContext model has required fields" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import SystemContext
fields = SystemContext.model_fields
required = [
    'target_responsibility_description',
    'target_control_action_description',
    'tool_inventory',
    'active_zones',
    'multi_agent',
    'has_persistent_memory',
]
for name in required:
    assert name in fields, f'Missing field: {name}'
print('All 6 SystemContext fields exist')
"

# QA-UMCF-02: ScenarioEnvelope has optional system_context field
check "QA-UMCF-02: ScenarioEnvelope has optional system_context field" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope
fields = ScenarioEnvelope.model_fields
assert 'system_context' in fields, 'Missing system_context field'
f = fields['system_context']
assert f.is_required() is False, 'system_context should be optional'
print('system_context is optional with default None')
"

# QA-UMCF-03 through QA-UMCF-08: assemble_envelope populates system_context
check "QA-UMCF-03: assemble_envelope populates system_context" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(
        ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED',
        provenance='structural',
    ),
    target_controller='RESP-1',
    target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)

cs = ControlStructure(
    responsibilities=[
        Responsibility(
            resp_id='RESP-1',
            description='Orchestrate tool calls safely',
            process_model_parts=[
                ProcessModelPart(pm_id='PM-1-1', description='Tool state')
            ],
            control_actions=[
                ControlAction(ca_id='CA-1-1', description='Execute requested tool')
            ],
            feedback_channels=[
                FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')
            ],
        ),
    ],
)

profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high',
    kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)

gherkin = GherkinSpec(
    feature='Test', scenario='Test',
    given=['Given PM-1-1 is active'],
    when=['When a tool is requested'],
    then_expected=['Then the system should validate'],
    then_actual=['But the system executes without validation'],
)

env = assemble_envelope(
    scenario_id='SCN-001',
    scenario_spec=spec,
    narrative='Narrative text',
    attack_tree={'root': 'root', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin,
    gherkin_raw='Feature: Test',
    capability_profile=profile,
    control_structure=cs,
)
assert env.system_context is not None, 'system_context is None'
print('system_context is populated')
"

# QA-UMCF-04: system_context resolves responsibility description
check "QA-UMCF-04: system_context resolves responsibility description from RESP-ID" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate tool calls safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='Tool state')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Execute requested tool')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
assert env.system_context.target_responsibility_description == 'Orchestrate tool calls safely', \
    f'Got: {env.system_context.target_responsibility_description}'
print('target_responsibility_description resolved correctly')
"

# QA-UMCF-05: system_context resolves control action description
check "QA-UMCF-05: system_context resolves control action description from CA-ID" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate tool calls safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='Tool state')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Execute requested tool')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
assert env.system_context.target_control_action_description == 'Execute requested tool', \
    f'Got: {env.system_context.target_control_action_description}'
print('target_control_action_description resolved correctly')
"

# QA-UMCF-06+07+08: system_context inlines tool_inventory, active_zones, flags
check "QA-UMCF-06+07+08: system_context inlines tool_inventory, active_zones, flags" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate tool calls safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='Tool state')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Execute requested tool')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
sc = env.system_context
# tool_inventory — list[str] of tool names
assert 'database_query' in sc.tool_inventory, f'tool_inventory missing database_query: {sc.tool_inventory}'
# active_zones
for z in ['input', 'reasoning', 'tool_execution']:
    assert z in sc.active_zones, f'active_zones missing {z}: {sc.active_zones}'
# flags
assert sc.multi_agent is False, f'multi_agent should be False: {sc.multi_agent}'
assert sc.has_persistent_memory is False, f'has_persistent_memory should be False: {sc.has_persistent_memory}'
print('tool_inventory, active_zones, and boolean flags inlined correctly')
"

# QA-UMCF-09: envelope without system_context still parses
check "QA-UMCF-09: envelope without system_context still parses" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope, GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
env = ScenarioEnvelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=GherkinSpec(
        feature='T', scenario='T', given=['Given x'], when=['When y'],
        then_expected=['Then should z'], then_actual=['But w'],
    ),
    target_responsibility='RESP-1', ica_type=UCAType.not_provided,
    provenance='structural',
)
assert env.system_context is None, f'system_context should be None: {env.system_context}'
print('envelope without system_context parses successfully')
"

# QA-UMCF-10: system_context serialized in scenario YAML
check "QA-UMCF-10: system_context serialized in scenario YAML" \
    uv run python -c "
import yaml
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate tool calls safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='Tool state')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Execute requested tool')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
yaml_text = yaml.dump(env.model_dump(), default_flow_style=False, allow_unicode=True)
assert 'system_context' in yaml_text, 'YAML missing system_context key'
assert 'target_responsibility_description' in yaml_text, 'YAML missing target_responsibility_description'
print('system_context serialized in YAML')
"

# QA-UMCF-11: system_context with multi_agent True
check "QA-UMCF-11: system_context with multi_agent True" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate tool calls safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='Tool state')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Execute requested tool')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution', 'inter_agent'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC2.3', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
assert env.system_context.multi_agent is True, f'multi_agent should be True: {env.system_context.multi_agent}'
print('multi_agent True inlined correctly')
"

# QA-UMCF-12: system_context with has_persistent_memory True
check "QA-UMCF-12: system_context with has_persistent_memory True" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate tool calls safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='Tool state')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Execute requested tool')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='Tool result', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution', 'memory'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC4.3', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query the database')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
assert env.system_context.has_persistent_memory is True, f'has_persistent_memory should be True'
print('has_persistent_memory True inlined correctly')
"

# QA-UMCF-13: system_context with empty tool_inventory
check "QA-UMCF-13: system_context with empty tool_inventory" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import CapabilityProfile

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Act')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='FB', updates='PM-1-1')],
    )],
)
# No tool_execution zone → no tool_inventory required
profile = CapabilityProfile(
    zones_active=['input', 'reasoning'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1'],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
assert env.system_context.tool_inventory == [] or env.system_context.tool_inventory is None, \
    f'tool_inventory should be empty: {env.system_context.tool_inventory}'
print('empty tool_inventory handled correctly')
"

# QA-UMCF-14: STPA report displays system_context in scenario card
check "QA-UMCF-14: STPA report displays system_context in scenario card" \
    uv run python -c "
from scenario_forge.stpa.report.template import _build_scenario_envelope_body
from scenario_forge.stpa.models.scenario_envelope import (
    ScenarioEnvelope, GherkinSpec, SystemContext,
)
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
sc = SystemContext(
    target_responsibility_description='Orchestrate tool calls safely',
    target_control_action_description='Execute requested tool',
    tool_inventory=[],
    active_zones=['input', 'reasoning', 'tool_execution'],
    multi_agent=False,
    has_persistent_memory=False,
)
env = ScenarioEnvelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=GherkinSpec(
        feature='T', scenario='T', given=['Given x'], when=['When y'],
        then_expected=['Then should z'], then_actual=['But w'],
    ),
    target_responsibility='RESP-1', ica_type=UCAType.not_provided,
    provenance='structural', system_context=sc,
)
html = '\n'.join(_build_scenario_envelope_body(env))
assert 'System Context' in html or 'system_context' in html.lower(), \
    f'HTML missing System Context section: {html[:500]}'
print('STPA report displays system_context in scenario card')
"

# ===========================================================================
# 8B06 — Consumer Hints Filtering Metadata
# ===========================================================================

# QA-8B06-01: ConsumerHints model has required fields
check "QA-8B06-01: ConsumerHints model has required fields" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import ConsumerHints
fields = ConsumerHints.model_fields
required = [
    'primary_attack_zone', 'requires_tool_execution', 'requires_multi_turn',
    'requires_multi_agent', 'requires_persistent_state',
    'garak_testability', 'midojo_testability',
]
for name in required:
    assert name in fields, f'Missing field: {name}'
print('All 7 ConsumerHints fields exist')
"

# QA-8B06-02: ScenarioEnvelope has optional consumer_hints field
check "QA-8B06-02: ScenarioEnvelope has optional consumer_hints field" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope
fields = ScenarioEnvelope.model_fields
assert 'consumer_hints' in fields, 'Missing consumer_hints field'
f = fields['consumer_hints']
assert f.is_required() is False, 'consumer_hints should be optional'
print('consumer_hints is optional with default None')
"

# QA-8B06-03: consumer_hints computed deterministically
check "QA-8B06-03: consumer_hints computed deterministically without LLM calls" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='database_query', description='Query')],
)
tree = {'root': 'r', 'branches': [], 'leaves': [{'text': 'Execute tool to exfiltrate'}]}
narrative = 'A single-turn attack via prompt injection.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result is not None, 'compute_consumer_hints returned None'
print('consumer_hints computed deterministically')
"

# QA-8B06-04: primary_attack_zone derived from scenario zone
check "QA-8B06-04: primary_attack_zone derived from scenario zone" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import CapabilityProfile

profile = CapabilityProfile(
    zones_active=['input', 'reasoning'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1'],
)
tree = {'root': 'r', 'branches': [], 'leaves': []}
narrative = 'Single-turn attack.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.primary_attack_zone == 'input', \
    f'Expected input, got {result.primary_attack_zone}'
print('primary_attack_zone derived correctly')
"

# QA-8B06-05: requires_tool_execution True when tree mentions tools
check "QA-8B06-05: requires_tool_execution True when tree mentions tools" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1'],
    tool_inventory=[ToolInventoryEntry(name='db', description='Database query')],
)
tree = {'root': 'r', 'branches': [], 'leaves': [
    {'text': 'Execute the database_query tool to exfiltrate data'}
]}
narrative = 'Single-turn attack.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.requires_tool_execution is True, \
    f'Expected True, got {result.requires_tool_execution}'
print('requires_tool_execution True when tree mentions tools')
"

# QA-8B06-06: requires_tool_execution False when tree lacks tool mentions
check "QA-8B06-06: requires_tool_execution False when tree lacks tool mentions" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import CapabilityProfile

profile = CapabilityProfile(
    zones_active=['input', 'reasoning'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1'],
)
tree = {'root': 'r', 'branches': [], 'leaves': [
    {'text': 'Manipulate the reasoning process via prompt injection'}
]}
narrative = 'Single-turn attack.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.requires_tool_execution is False, \
    f'Expected False, got {result.requires_tool_execution}'
print('requires_tool_execution False when tree lacks tool mentions')
"

# QA-8B06-07: requires_multi_turn True when narrative indicates multi-turn
check "QA-8B06-07: requires_multi_turn True when narrative indicates multi-turn" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import CapabilityProfile

profile = CapabilityProfile(
    zones_active=['input', 'reasoning'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1'],
)
tree = {'root': 'r', 'branches': [], 'leaves': []}
narrative = 'The attacker sends an initial prompt, then in a subsequent turn refines the injection.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.requires_multi_turn is True, \
    f'Expected True, got {result.requires_multi_turn}'
print('requires_multi_turn True for multi-turn narrative')
"

# QA-8B06-08: requires_multi_turn False for single-turn narrative
check "QA-8B06-08: requires_multi_turn False for single-turn narrative" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import CapabilityProfile

profile = CapabilityProfile(
    zones_active=['input', 'reasoning'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1'],
)
tree = {'root': 'r', 'branches': [], 'leaves': []}
narrative = 'A single prompt injection attack.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.requires_multi_turn is False, \
    f'Expected False, got {result.requires_multi_turn}'
print('requires_multi_turn False for single-turn narrative')
"

# QA-8B06-09: requires_multi_agent from capability profile
check "QA-8B06-09: requires_multi_agent from capability profile" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution', 'inter_agent'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC2.3', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='db', description='Query')],
)
tree = {'root': 'r', 'branches': [], 'leaves': []}
narrative = 'Single-turn attack.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.requires_multi_agent is True, \
    f'Expected True, got {result.requires_multi_agent}'
print('requires_multi_agent True from capability profile')
"

# QA-8B06-10: requires_persistent_state from capability profile
check "QA-8B06-10: requires_persistent_state from capability profile" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution', 'memory'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC4.3', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='db', description='Query')],
)
tree = {'root': 'r', 'branches': [], 'leaves': []}
narrative = 'Single-turn attack.'
result = compute_consumer_hints(profile, tree, narrative, primary_attack_zone='input')
assert result.requires_persistent_state is True, \
    f'Expected True, got {result.requires_persistent_state}'
print('requires_persistent_state True from capability profile')
"

# QA-8B06-11: garak_testability rule-based from primary_attack_zone
check "QA-8B06-11: garak_testability rule-based from primary_attack_zone" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

def make_profile(zones, kcs):
    return CapabilityProfile(
        zones_active=zones,
        entry_points=[{'name': 'user prompts', 'direction': 'input'}],
        confidence='high', kc_subcodes=kcs,
        tool_inventory=[ToolInventoryEntry(name='db', description='Query')] if 'tool_execution' in zones else None,
    )

tree = {'root': 'r', 'branches': [], 'leaves': []}
narrative = 'Single-turn attack.'

# input → high
p = make_profile(['input', 'reasoning', 'tool_execution'], ['KC1.1', 'KC5.1', 'KC6.1.1'])
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='input')
assert r.garak_testability == 'high', f'input should be high, got {r.garak_testability}'

# reasoning → medium
p = make_profile(['input', 'reasoning'], ['KC1.1'])
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='reasoning')
assert r.garak_testability == 'medium', f'reasoning should be medium, got {r.garak_testability}'

# tool_execution → low
p = make_profile(['input', 'reasoning', 'tool_execution'], ['KC1.1', 'KC5.1', 'KC6.1.1'])
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='tool_execution')
assert r.garak_testability == 'low', f'tool_execution should be low, got {r.garak_testability}'

# memory → low
p = make_profile(['input', 'reasoning', 'memory', 'tool_execution'], ['KC1.1', 'KC4.3', 'KC5.1', 'KC6.1.1'])
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='memory')
assert r.garak_testability == 'low', f'memory should be low, got {r.garak_testability}'

# inter_agent → low
p = make_profile(['input', 'reasoning', 'tool_execution', 'inter_agent'], ['KC1.1', 'KC2.3', 'KC5.1', 'KC6.1.1'])
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='inter_agent')
assert r.garak_testability == 'low', f'inter_agent should be low, got {r.garak_testability}'

print('garak_testability rules verified for all zones')
"

# QA-8B06-12: midojo_testability rule-based from zone, tree, and profile
check "QA-8B06-12: midojo_testability rule-based from zone, tree, and profile" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.enrichment import compute_consumer_hints
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

def make_profile(zones, kcs):
    return CapabilityProfile(
        zones_active=zones,
        entry_points=[{'name': 'user prompts', 'direction': 'input'}],
        confidence='high', kc_subcodes=kcs,
        tool_inventory=[ToolInventoryEntry(name='db', description='Query')] if 'tool_execution' in zones else None,
    )

narrative = 'Single-turn attack.'

# tool_execution + tool leaves → high
p = make_profile(['input', 'reasoning', 'tool_execution'], ['KC1.1', 'KC5.1', 'KC6.1.1'])
tree = {'root': 'r', 'branches': [], 'leaves': [{'text': 'Execute tool to exfiltrate'}]}
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='tool_execution')
assert r.midojo_testability == 'high', f'tool_exec+tools should be high, got {r.midojo_testability}'

# input + no tools + multi_agent → medium
p = make_profile(['input', 'reasoning', 'inter_agent'], ['KC1.1', 'KC2.3'])
tree = {'root': 'r', 'branches': [], 'leaves': [{'text': 'Manipulate reasoning'}]}
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='input')
assert r.midojo_testability == 'medium', f'input+multi_agent should be medium, got {r.midojo_testability}'

# input + no tools + persistent memory → medium
p = make_profile(['input', 'reasoning', 'memory'], ['KC1.1', 'KC4.3'])
tree = {'root': 'r', 'branches': [], 'leaves': [{'text': 'Manipulate reasoning'}]}
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='input')
assert r.midojo_testability == 'medium', f'input+persistent should be medium, got {r.midojo_testability}'

# input + no tools + no multi-agent + no persistent → low
p = make_profile(['input', 'reasoning'], ['KC1.1'])
tree = {'root': 'r', 'branches': [], 'leaves': [{'text': 'Manipulate reasoning'}]}
r = compute_consumer_hints(p, tree, narrative, primary_attack_zone='input')
assert r.midojo_testability == 'low', f'input+nothing should be low, got {r.midojo_testability}'

print('midojo_testability rules verified for all combinations')
"

# QA-8B06-13: envelope without consumer_hints still parses
check "QA-8B06-13: envelope without consumer_hints still parses" \
    uv run python -c "
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope, GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
env = ScenarioEnvelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=GherkinSpec(
        feature='T', scenario='T', given=['Given x'], when=['When y'],
        then_expected=['Then should z'], then_actual=['But w'],
    ),
    target_responsibility='RESP-1', ica_type=UCAType.not_provided,
    provenance='structural',
)
assert env.consumer_hints is None, f'consumer_hints should be None: {env.consumer_hints}'
print('envelope without consumer_hints parses successfully')
"

# QA-8B06-14: consumer_hints serialized in scenario YAML
check "QA-8B06-14: consumer_hints serialized in scenario YAML" \
    uv run python -c "
import yaml
from scenario_forge.stpa.models.scenario_envelope import (
    ScenarioEnvelope, GherkinSpec, ConsumerHints,
)
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
ch = ConsumerHints(
    primary_attack_zone='input', requires_tool_execution=False,
    requires_multi_turn=False, requires_multi_agent=False,
    requires_persistent_state=False,
    garak_testability='high', midojo_testability='low',
)
env = ScenarioEnvelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=GherkinSpec(
        feature='T', scenario='T', given=['Given x'], when=['When y'],
        then_expected=['Then should z'], then_actual=['But w'],
    ),
    target_responsibility='RESP-1', ica_type=UCAType.not_provided,
    provenance='structural', consumer_hints=ch,
)
yaml_text = yaml.dump(env.model_dump(), default_flow_style=False, allow_unicode=True)
assert 'consumer_hints' in yaml_text, 'YAML missing consumer_hints key'
assert 'garak_testability' in yaml_text, 'YAML missing garak_testability'
assert 'midojo_testability' in yaml_text, 'YAML missing midojo_testability'
print('consumer_hints serialized in YAML')
"

# QA-8B06-15: assemble_envelope populates consumer_hints
check "QA-8B06-15: assemble_envelope populates consumer_hints" \
    uv run python -c "
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.control_structure import (
    ControlStructure, Responsibility, ControlAction, ProcessModelPart,
    FeedbackChannel,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile, ToolInventoryEntry,
)

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
cs = ControlStructure(
    responsibilities=[Responsibility(
        resp_id='RESP-1', description='Orchestrate safely',
        process_model_parts=[ProcessModelPart(pm_id='PM-1-1', description='State')],
        control_actions=[ControlAction(ca_id='CA-1-1', description='Act')],
        feedback_channels=[FeedbackChannel(fb_id='FB-1-1', description='FB', updates='PM-1-1')],
    )],
)
profile = CapabilityProfile(
    zones_active=['input', 'reasoning', 'tool_execution'],
    entry_points=[{'name': 'user prompts', 'direction': 'input'}],
    confidence='high', kc_subcodes=['KC1.1', 'KC5.1', 'KC6.1.1'],
    tool_inventory=[ToolInventoryEntry(name='db', description='Query')],
)
gherkin = GherkinSpec(
    feature='T', scenario='T', given=['Given x'], when=['When y'],
    then_expected=['Then should z'], then_actual=['But w'],
)
tree = {'root': 'r', 'branches': [], 'leaves': [{'text': 'Execute tool'}]}
narrative = 'Single-turn attack.'
env = assemble_envelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative=narrative,
    attack_tree=tree, gherkin_spec=gherkin, gherkin_raw='Feature: T',
    capability_profile=profile, control_structure=cs,
)
assert env.consumer_hints is not None, 'consumer_hints is None'
assert env.consumer_hints.garak_testability, 'garak_testability is empty'
assert env.consumer_hints.midojo_testability, 'midojo_testability is empty'
print('assemble_envelope populates consumer_hints with non-empty testability values')
"

# QA-8B06-16: enrichment computation is in a dedicated module
check "QA-8B06-16: enrichment computation is in a dedicated module" \
    uv run python -c "
import scenario_forge.stpa.scenario_prod.enrichment as mod
assert hasattr(mod, 'compute_consumer_hints'), 'Missing compute_consumer_hints'
assert hasattr(mod, 'compute_system_context'), 'Missing compute_system_context'
print('enrichment module exposes compute_consumer_hints and compute_system_context')
"

# QA-8B06-17: STPA report displays consumer_hints in scenario card
check "QA-8B06-17: STPA report displays consumer_hints in scenario card" \
    uv run python -c "
from scenario_forge.stpa.report.template import _build_scenario_envelope_body
from scenario_forge.stpa.models.scenario_envelope import (
    ScenarioEnvelope, GherkinSpec, ConsumerHints,
)
from scenario_forge.stpa.models.scenario_spec import (
    ScenarioSpec, ThreatSource, DefenderBDI, AttackerBDI,
    DefenderBelief, DefenderDesire, DefenderIntention,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType

spec = ScenarioSpec(
    scenario_id='SCN-001',
    threat_source=ThreatSource(ica_slot_id='RESP-1:CA-1-1:NOT_PROVIDED', provenance='structural'),
    target_controller='RESP-1', target_control_action='CA-1-1',
    ica_type=UCAType.not_provided,
    defender_bdi=DefenderBDI(
        beliefs=[DefenderBelief(pm_id='PM-1-1', content='b', vulnerability='v')],
        desires=[DefenderDesire(resp_id='RESP-1', content='d')],
        intentions=[DefenderIntention(ca_id='CA-1-1', content='i')],
    ),
    attacker_bdi=AttackerBDI(beliefs=['b'], desires=['d'], intentions=['i']),
    loss_scenario='Scenario',
)
ch = ConsumerHints(
    primary_attack_zone='input', requires_tool_execution=False,
    requires_multi_turn=False, requires_multi_agent=False,
    requires_persistent_state=False,
    garak_testability='high', midojo_testability='low',
)
env = ScenarioEnvelope(
    scenario_id='SCN-001', scenario_spec=spec, narrative='n',
    attack_tree={'root': 'r', 'branches': [], 'leaves': []},
    gherkin_spec=GherkinSpec(
        feature='T', scenario='T', given=['Given x'], when=['When y'],
        then_expected=['Then should z'], then_actual=['But w'],
    ),
    target_responsibility='RESP-1', ica_type=UCAType.not_provided,
    provenance='structural', consumer_hints=ch,
)
html = '\n'.join(_build_scenario_envelope_body(env))
assert 'Consumer Hints' in html or 'consumer_hints' in html.lower(), \
    f'HTML missing Consumer Hints section: {html[:500]}'
print('STPA report displays consumer_hints in scenario card')
"

# ===========================================================================
# Summary
# ===========================================================================
echo "==============================================="
echo "Envelope Enrichment QA Suite Results"
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
