# End-to-End QA Suite: Envelope Enrichment (umcf, 8b06)

This QA suite verifies two envelope enrichment features through
user-visible workflows: Python module import checks, model schema
inspection, function invocation with constructed inputs, YAML
serialization inspection, and HTML report generation. No
project-internal APIs are used beyond the public module interfaces,
file I/O, and command-line entry points that a user or test harness
would perform.

---

## QA-UMCF: Inline SP1 System Context into Scenario Envelope (umcf)

### QA-UMCF-01: SystemContext model has required fields

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `SystemContext` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Inspect the model fields using `SystemContext.model_fields`.
3. Check that `target_responsibility_description` is a `str` field.
4. Check that `target_control_action_description` is a `str` field.
5. Check that `tool_inventory` is a `list` field.
6. Check that `active_zones` is a `list` field.
7. Check that `multi_agent` is a `bool` field.
8. Check that `has_persistent_memory` is a `bool` field.

**Expected**: All six fields exist with the correct types.

### QA-UMCF-02: ScenarioEnvelope has optional system_context field

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `ScenarioEnvelope` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Inspect `ScenarioEnvelope.model_fields`.
3. Check that `system_context` field exists.
4. Check that the field is optional (has a default of `None`).

**Expected**: `system_context` is an optional field with a default
of `None`.

### QA-UMCF-03: assemble_envelope populates system_context

**Preconditions**: The `scenario_forge.stpa.scenario_prod.assembly`
module is importable. A constructed `ScenarioSpec`, a
`CapabilityProfile`, and a `ControlStructure` are available.

**Steps**:
1. Import `assemble_envelope` from
   `scenario_forge.stpa.scenario_prod.assembly`.
2. Construct a `ScenarioSpec` with `target_controller="RESP-1"` and
   `target_control_action="CA-1-1"`.
3. Construct a `ControlStructure` with a responsibility `RESP-1`
   having description `"Orchestrate tool calls safely"` and a control
   action `CA-1-1` having description `"Execute requested tool"`.
4. Construct a `CapabilityProfile` with `tool_inventory` containing
   a tool named `"database_query"`, `active_zones=["input",
   "reasoning", "tool_execution"]`, `multi_agent=False`, and
   `has_persistent_memory=False`.
5. Call `assemble_envelope` with the spec, narrative, attack tree,
   gherkin spec, gherkin raw, capability profile, and control
   structure.
6. Inspect `envelope.system_context`.

**Expected**: `envelope.system_context` is not `None`.

### QA-UMCF-04: system_context resolves responsibility description from RESP-ID

**Preconditions**: Same as QA-UMCF-03.

**Steps**:
1. Follow steps 1-5 from QA-UMCF-03.
2. Check
   `envelope.system_context.target_responsibility_description`.

**Expected**: The value is `"Orchestrate tool calls safely"` — the
description from the control structure responsibility `RESP-1`.

### QA-UMCF-05: system_context resolves control action description from CA-ID

**Preconditions**: Same as QA-UMCF-03.

**Steps**:
1. Follow steps 1-5 from QA-UMCF-03.
2. Check
   `envelope.system_context.target_control_action_description`.

**Expected**: The value is `"Execute requested tool"` — the
description from the control structure control action `CA-1-1`.

### QA-UMCF-06: system_context inlines tool_inventory from capability profile

**Preconditions**: Same as QA-UMCF-03.

**Steps**:
1. Follow steps 1-5 from QA-UMCF-03.
2. Check `envelope.system_context.tool_inventory`.

**Expected**: The list contains a tool named `"database_query"`.

### QA-UMCF-07: system_context inlines active_zones from capability profile

**Preconditions**: Same as QA-UMCF-03.

**Steps**:
1. Follow steps 1-5 from QA-UMCF-03.
2. Check `envelope.system_context.active_zones`.

**Expected**: The list contains `"input"`, `"reasoning"`, and
`"tool_execution"`.

### QA-UMCF-08: system_context inlines boolean flags from capability profile

**Preconditions**: Same as QA-UMCF-03.

**Steps**:
1. Follow steps 1-5 from QA-UMCF-03.
2. Check `envelope.system_context.multi_agent`.
3. Check `envelope.system_context.has_persistent_memory`.

**Expected**: `multi_agent` is `False` and
`has_persistent_memory` is `False`.

### QA-UMCF-09: envelope without system_context still parses

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `ScenarioEnvelope` and `GherkinSpec` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Construct a `ScenarioEnvelope` without providing `system_context`.
3. Validate the envelope (Pydantic model construction succeeds).

**Expected**: The envelope is valid and `system_context` is `None`.

### QA-UMCF-10: system_context serialized in scenario YAML

**Preconditions**: Same as QA-UMCF-03. The `yaml` module is available.

**Steps**:
1. Follow steps 1-5 from QA-UMCF-03 to get an envelope.
2. Serialize the envelope to YAML using `yaml.dump` or
   `model_dump_yaml`.
3. Read the YAML text.

**Expected**: The YAML text contains a `system_context` key and a
`target_responsibility_description` sub-key.

### QA-UMCF-11: system_context with multi_agent True

**Preconditions**: Same as QA-UMCF-03 but with a capability profile
that has `multi_agent=True` (use KC sub-codes that include `KC2.3` or
`KCX-MAGENT`).

**Steps**:
1. Construct a `CapabilityProfile` with KC sub-codes including
   `KC2.3` (multi-agent collaboration).
2. Call `assemble_envelope` with the profile and control structure.
3. Check `envelope.system_context.multi_agent`.

**Expected**: `multi_agent` is `True`.

### QA-UMCF-12: system_context with has_persistent_memory True

**Preconditions**: Same as QA-UMCF-03 but with a capability profile
that has `has_persistent_memory=True` (use KC sub-codes that include
`KC4.3` or `KCX-PMEM`).

**Steps**:
1. Construct a `CapabilityProfile` with KC sub-codes including
   `KC4.3` (in-agent, cross-session memory).
2. Call `assemble_envelope` with the profile and control structure.
3. Check `envelope.system_context.has_persistent_memory`.

**Expected**: `has_persistent_memory` is `True`.

### QA-UMCF-13: system_context with empty tool_inventory

**Preconditions**: A `CapabilityProfile` with no tool_inventory
(system without tool execution capability, e.g. KC sub-codes without
KC5.* or KC6.*).

**Steps**:
1. Construct a `CapabilityProfile` with KC sub-codes `["KC1.1"]`
   (no tool execution zone).
2. Call `assemble_envelope` with the profile and control structure.
3. Check `envelope.system_context.tool_inventory`.

**Expected**: `tool_inventory` is an empty list.

### QA-UMCF-14: STPA report displays system_context in scenario card

**Preconditions**: The `scenario_forge.stpa.report.template` module is
importable. A `ScenarioEnvelope` with a populated `system_context`.

**Steps**:
1. Import `_build_scenario_envelope_body` from
   `scenario_forge.stpa.report.template`.
2. Construct a `ScenarioEnvelope` with a populated `system_context`.
3. Call `_build_scenario_envelope_body(envelope)`.
4. Join the returned parts into an HTML string.

**Expected**: The HTML contains a "System Context" section heading
and displays the `target_responsibility_description` and
`active_zones`.

---

## QA-8B06: Consumer Hints Filtering Metadata (8b06)

### QA-8B06-01: ConsumerHints model has required fields

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `ConsumerHints` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Inspect the model fields using `ConsumerHints.model_fields`.
3. Check that `primary_attack_zone` is a `str` field.
4. Check that `requires_tool_execution` is a `bool` field.
5. Check that `requires_multi_turn` is a `bool` field.
6. Check that `requires_multi_agent` is a `bool` field.
7. Check that `requires_persistent_state` is a `bool` field.
8. Check that `garak_testability` is a `str` field.
9. Check that `midojo_testability` is a `str` field.

**Expected**: All seven fields exist with the correct types.

### QA-8B06-02: ScenarioEnvelope has optional consumer_hints field

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `ScenarioEnvelope` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Inspect `ScenarioEnvelope.model_fields`.
3. Check that `consumer_hints` field exists.
4. Check that the field is optional (has a default of `None`).

**Expected**: `consumer_hints` is an optional field with a default
of `None`.

### QA-8B06-03: consumer_hints computed deterministically

**Preconditions**: The `scenario_forge.stpa.scenario_prod.enrichment`
module is importable. A constructed `CapabilityProfile`, attack tree
dict, and narrative string are available.

**Steps**:
1. Import the consumer_hints computation function from
   `scenario_forge.stpa.scenario_prod.enrichment`.
2. Construct a `CapabilityProfile`, an attack tree dict, and a
   narrative string.
3. Call the computation function.
4. Inspect the result.

**Expected**: The function returns a `ConsumerHints` object without
making any LLM calls.

### QA-8B06-04: primary_attack_zone derived from scenario zone

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. Construct inputs where the scenario's primary attack zone is
   `"input"`.
2. Call the computation function.
3. Check `result.primary_attack_zone`.

**Expected**: `primary_attack_zone` is `"input"`.

### QA-8B06-05: requires_tool_execution True when tree mentions tools

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. Construct an attack tree with leaves that mention tool execution
   (e.g. leaf text containing "tool", "execute", "call").
2. Call the computation function.
3. Check `result.requires_tool_execution`.

**Expected**: `requires_tool_execution` is `True`.

### QA-8B06-06: requires_tool_execution False when tree lacks tool mentions

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. Construct an attack tree with leaves that do not mention tool
   execution.
2. Call the computation function.
3. Check `result.requires_tool_execution`.

**Expected**: `requires_tool_execution` is `False`.

### QA-8B06-07: requires_multi_turn True when narrative indicates multi-turn

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. Construct a narrative describing a multi-turn attack (containing
   phrases like "subsequent turn", "second message", "follow-up
   request").
2. Call the computation function.
3. Check `result.requires_multi_turn`.

**Expected**: `requires_multi_turn` is `True`.

### QA-8B06-08: requires_multi_turn False for single-turn narrative

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. Construct a narrative describing a single-turn attack.
2. Call the computation function.
3. Check `result.requires_multi_turn`.

**Expected**: `requires_multi_turn` is `False`.

### QA-8B06-09: requires_multi_agent from capability profile

**Preconditions**: A `CapabilityProfile` with `multi_agent=True`.

**Steps**:
1. Construct a `CapabilityProfile` with KC sub-codes including
   `KC2.3`.
2. Call the computation function.
3. Check `result.requires_multi_agent`.

**Expected**: `requires_multi_agent` is `True`.

### QA-8B06-10: requires_persistent_state from capability profile

**Preconditions**: A `CapabilityProfile` with
`has_persistent_memory=True`.

**Steps**:
1. Construct a `CapabilityProfile` with KC sub-codes including
   `KC4.3`.
2. Call the computation function.
3. Check `result.requires_persistent_state`.

**Expected**: `requires_persistent_state` is `True`.

### QA-8B06-11: garak_testability rule-based from primary_attack_zone

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. For each zone in `["input", "reasoning", "tool_execution",
   "memory", "inter_agent"]`:
   a. Construct inputs with that primary attack zone.
   b. Call the computation function.
   c. Check `result.garak_testability`.

**Expected**:
- `input` → `high`
- `reasoning` → `medium`
- `tool_execution` → `low`
- `memory` → `low`
- `inter_agent` → `low`

### QA-8B06-12: midojo_testability rule-based from zone, tree, and profile

**Preconditions**: Same as QA-8B06-03.

**Steps**:
1. Construct inputs with `primary_attack_zone="tool_execution"` and
   an attack tree with leaves mentioning tool execution.
2. Call the computation function.
3. Check `result.midojo_testability`.
4. Construct inputs with `primary_attack_zone="input"`, tree without
   tool mentions, and `multi_agent=True`.
5. Call the computation function.
6. Check `result.midojo_testability`.
7. Construct inputs with `primary_attack_zone="input"`, tree without
   tool mentions, and `has_persistent_memory=True`.
8. Call the computation function.
9. Check `result.midojo_testability`.
10. Construct inputs with `primary_attack_zone="input"`, tree without
    tool mentions, and `multi_agent=False`,
    `has_persistent_memory=False`.
11. Call the computation function.
12. Check `result.midojo_testability`.

**Expected**:
- tool_execution + tool leaves → `high`
- input + no tools + multi_agent → `medium`
- input + no tools + persistent memory → `medium`
- input + no tools + no multi-agent + no persistent memory → `low`

### QA-8B06-13: envelope without consumer_hints still parses

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Construct a `ScenarioEnvelope` without providing `consumer_hints`.
2. Validate the envelope.

**Expected**: The envelope is valid and `consumer_hints` is `None`.

### QA-8B06-14: consumer_hints serialized in scenario YAML

**Preconditions**: An envelope with a populated `consumer_hints`.

**Steps**:
1. Construct a `ScenarioEnvelope` with a populated `consumer_hints`.
2. Serialize to YAML.
3. Read the YAML text.

**Expected**: The YAML contains a `consumer_hints` key with
`garak_testability` and `midojo_testability` sub-keys.

### QA-8B06-15: assemble_envelope populates consumer_hints

**Preconditions**: The `scenario_forge.stpa.scenario_prod.assembly`
module is importable.

**Steps**:
1. Construct a `ScenarioSpec`, `CapabilityProfile`,
   `ControlStructure`, attack tree dict, and narrative string.
2. Call `assemble_envelope` with all inputs including the capability
   profile, control structure, attack tree, and narrative.
3. Inspect `envelope.consumer_hints`.

**Expected**: `consumer_hints` is not `None`,
`garak_testability` is a non-empty string, and
`midojo_testability` is a non-empty string.

### QA-8B06-16: enrichment computation is in a dedicated module

**Preconditions**: The project source tree is available.

**Steps**:
1. Import the `scenario_forge.stpa.scenario_prod.enrichment` module.
2. Check that it exposes a function to compute `consumer_hints` from
   profile, attack tree, and narrative.
3. Check that it exposes a function to compute `system_context` from
   profile and control structure.

**Expected**: Both functions are importable from the enrichment
module.

### QA-8B06-17: STPA report displays consumer_hints in scenario card

**Preconditions**: The `scenario_forge.stpa.report.template` module is
importable. A `ScenarioEnvelope` with a populated `consumer_hints`.

**Steps**:
1. Import `_build_scenario_envelope_body` from
   `scenario_forge.stpa.report.template`.
2. Construct a `ScenarioEnvelope` with a populated `consumer_hints`.
3. Call `_build_scenario_envelope_body(envelope)`.
4. Join the returned parts into an HTML string.

**Expected**: The HTML contains a "Consumer Hints" section heading
and displays `garak_testability` and `midojo_testability`.
