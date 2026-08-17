# End-to-End QA Suite: Stage 6 Output Quality (jpkw, gddi, v689)

This QA suite verifies three Stage 6 output quality fixes through
user-visible workflows: running the SP3 pipeline with mock LLM responses,
inspecting output artifacts on disk, rendering Jinja2 templates, invoking
module functions, and verifying model schemas. No project-internal APIs
are used beyond the public module interfaces, file I/O, and command-line
entry points that a user or test harness would perform.

---

## QA-JPKW: Structure Gherkin Spec as YAML Object (jpkw)

### QA-JPKW-01: GherkinSpec model has structured fields

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `GherkinSpec` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Inspect the model fields using `GherkinSpec.model_fields`.
3. Check that `feature` is a `str` field.
4. Check that `scenario` is a `str` field.
5. Check that `given` is a `list[str]` field.
6. Check that `when` is a `list[str]` field.
7. Check that `then_expected` is a `list[str]` field.
8. Check that `then_actual` is a `list[str]` field.

**Expected**: All six fields exist with the correct types.

### QA-JPKW-02: ScenarioEnvelope has gherkin_spec as GherkinSpec and gherkin_raw as str

**Preconditions**: The `scenario_forge.stpa.models.scenario_envelope`
module is importable.

**Steps**:
1. Import `ScenarioEnvelope` and `GherkinSpec` from
   `scenario_forge.stpa.models.scenario_envelope`.
2. Inspect `ScenarioEnvelope.model_fields`.
3. Check that `gherkin_spec` field annotation is `GherkinSpec`.
4. Check that `gherkin_raw` field annotation is `str`.

**Expected**: `gherkin_spec` is typed as `GherkinSpec` and `gherkin_raw`
is typed as `str`.

### QA-JPKW-03: Stage 6c system prompt requests structured YAML output

**Preconditions**: The `stage6c_gherkin_system.j2` template exists in the
STPA SP3 prompts directory.

**Steps**:
1. Load `stage6c_gherkin_system.j2` using `TemplateLoader(PROMPTS_DIR)`.
2. Read the rendered template text.

**Expected**: The template text instructs the LLM to return a YAML
object (not raw Gherkin text) and defines the fields `feature`,
`scenario`, `given`, `when`, `then_expected`, `then_actual`.

### QA-JPKW-04: generate_gherkin returns GherkinSpec and raw text

**Preconditions**: A mock LLM client that returns a YAML string with
fields `feature`, `scenario`, `given`, `when`, `then_expected`,
`then_actual`. A `ScenarioSpec`, a `LossAnalysis`, and a run directory.

**Steps**:
1. Construct a mock LLM client that returns a structured YAML string
   with all required GherkinSpec fields.
2. Call `generate_gherkin` with the mock client, scenario spec, loss
   analysis, and run directory.
3. Inspect the return value.

**Expected**: The return value includes a `GherkinSpec` object (not a
raw string) and a `gherkin_raw` string containing the original LLM
response text.

### QA-JPKW-05: generate_gherkin parses YAML response into structured fields

**Preconditions**: A mock LLM client that returns a YAML string with
`given` containing `["Given PM-1-1 is active", "And the system is online"]`.

**Steps**:
1. Construct a mock LLM client that returns the structured YAML.
2. Call `generate_gherkin` with the mock client.
3. Inspect the `GherkinSpec.given` list.

**Expected**: The `given` list contains both "Given PM-1-1 is active"
and "And the system is online".

### QA-JPKW-06: assemble_envelope accepts GherkinSpec and gherkin_raw

**Preconditions**: A `GherkinSpec` instance and a `gherkin_raw` string.
A `ScenarioSpec`.

**Steps**:
1. Construct a `GherkinSpec` with `feature="Safe orchestration"` and
   `scenario="SCN-001"`.
2. Construct a `gherkin_raw` string containing the full Feature block.
3. Call `assemble_envelope` with the scenario ID, scenario spec,
   narrative, attack tree, GherkinSpec, and gherkin_raw.
4. Inspect the resulting `ScenarioEnvelope`.

**Expected**: `envelope.gherkin_spec` equals the GherkinSpec instance and
`envelope.gherkin_raw` equals the gherkin_raw string.

### QA-JPKW-07: .feature file is written from gherkin_raw

**Preconditions**: A `ScenarioEnvelope` with `gherkin_raw` containing
"Feature: Safe orchestration\nScenario: SCN-001\n". A scenarios output
directory.

**Steps**:
1. Construct a `ScenarioEnvelope` with the gherkin_raw text.
2. Call `_write_scenario_artifacts` with the envelope and scenarios
   directory.
3. Read the `.feature` file from the scenarios directory.

**Expected**: The `.feature` file exists and contains the gherkin_raw
text (not the structured GherkinSpec).

### QA-JPKW-08: structured validation catches missing required GherkinSpec content

**Preconditions**: A `GherkinSpec` instance with empty `then_expected`.

**Steps**:
1. Construct a `GherkinSpec` with `then_expected=[]`.
2. Call `validate_gherkin_structure` with the GherkinSpec (or its raw
   text form).
3. Inspect the validation result.

**Expected**: Validation fails with an error message containing "should".

### QA-JPKW-09: valid structured GherkinSpec passes validation

**Preconditions**: A `GherkinSpec` with `then_expected` containing a
"should" clause, `then_actual` containing a "but" clause, and `given`
referencing "PM-1-1".

**Steps**:
1. Construct a valid `GherkinSpec`.
2. Call `validate_gherkin_structure` with the GherkinSpec.
3. Inspect the validation result.

**Expected**: Validation succeeds (passed=True, no errors).

### QA-JPKW-10: gherkin_raw preserves full Feature text for backward compatibility

**Preconditions**: A mock LLM client that returns structured YAML with
`feature="Safe orchestration"` and `scenario="SCN-001"`.

**Steps**:
1. Construct a mock LLM client that returns the structured YAML.
2. Call `generate_gherkin` with the mock client.
3. Inspect the `gherkin_raw` string.

**Expected**: The `gherkin_raw` string contains the "Feature:" line and
the "Scenario:" line, preserving the full feature text for backward
compatibility.

### QA-JPKW-11: Stage 7 envelope validation uses GherkinSpec fields

**Preconditions**: A `ScenarioEnvelope` with a `GherkinSpec` that has
empty `then_expected`.

**Steps**:
1. Construct a `ScenarioEnvelope` with the deficient GherkinSpec.
2. Call `_validate_envelope_stage7` with the envelope.
3. Inspect the validation errors.

**Expected**: A validation error is reported containing "should".

### QA-JPKW-12: SP3 run produces envelope with structured GherkinSpec

**Preconditions**: A mock LLM client that returns valid structured YAML
for the Gherkin call, a valid attack tree for the tree call, and a
narrative string for the narrative call. A complete set of SP1/SP2
artifacts (enriched threat set, control structure, loss analysis).

**Steps**:
1. Construct mock LLM responses for all Stage 5 and Stage 6 calls.
2. Call `run_sp3` with the mock client and SP1/SP2 artifacts.
3. Inspect the first scenario envelope in the result.
4. Check that `envelope.gherkin_spec` is a `GherkinSpec` instance.
5. Check that `envelope.gherkin_raw` is a non-empty string.

**Expected**: The envelope contains a structured `GherkinSpec` object and
a `gherkin_raw` string.

---

## QA-GDDI: Fix Loss ID Hallucination (gddi)

### QA-GDDI-01: user prompt includes valid Loss and Hazard IDs

**Preconditions**: A `ScenarioSpec`, a `LossAnalysis` with losses L-1,
L-2, L-3 and hazards H-1, H-2, and a `SecurityConstraint`.

**Steps**:
1. Call `build_gherkin_prompts` with the scenario spec, security
   constraint, loss analysis, and a template loader.
2. Inspect the rendered user prompt text.

**Expected**: The user prompt contains the valid loss IDs L-1, L-2, L-3
and hazard IDs H-1, H-2 from the loss analysis.

### QA-GDDI-02: user prompt instructs LLM to reference only valid IDs

**Preconditions**: A `ScenarioSpec`, a `LossAnalysis`, and a
`SecurityConstraint`.

**Steps**:
1. Call `build_gherkin_prompts` with the scenario spec, security
   constraint, loss analysis, and a template loader.
2. Inspect the rendered user prompt text.

**Expected**: The user prompt contains an instruction to reference only
the provided L-* and H-* IDs and an instruction not to invent new IDs.

### QA-GDDI-03: system prompt instructs LLM to use only provided L-* and H-* IDs

**Preconditions**: The `stage6c_gherkin_system.j2` template exists in the
STPA SP3 prompts directory.

**Steps**:
1. Load `stage6c_gherkin_system.j2` using `TemplateLoader(PROMPTS_DIR)`.
2. Read the rendered template text.

**Expected**: The template text instructs the LLM to use only the
provided L-* and H-* IDs from the loss analysis.

### QA-GDDI-04: build_gherkin_prompts accepts loss analysis parameter

**Preconditions**: A `ScenarioSpec`, a `LossAnalysis`, and a
`SecurityConstraint`.

**Steps**:
1. Inspect the signature of `build_gherkin_prompts` using
   `inspect.signature()`.
2. Check that `loss_analysis` (or equivalent) is among the parameters.
3. Call `build_gherkin_prompts` with the loss analysis.
4. Inspect the rendered user prompt.

**Expected**: The function accepts a loss analysis parameter and the
user prompt contains valid Loss and Hazard IDs from the loss analysis.

### QA-GDDI-05: validator catches hallucinated Loss or Hazard ID

**Preconditions**: A Gherkin text referencing "L-99" which is not in the
loss analysis. A `LossAnalysis` with losses L-1, L-2, L-3.

**Steps**:
1. Construct a Gherkin text string containing the reference "L-99".
2. Call the Loss/Hazard ID validation function with the Gherkin text and
   the loss analysis.
3. Inspect the validation result.

**Expected**: Validation fails with an error message containing "L-99".

### QA-GDDI-06: validator catches multiple hallucinated IDs

**Preconditions**: A Gherkin text referencing "L-99" and "H-88" which are
not in the loss analysis. A `LossAnalysis` with losses L-1, L-2 and
hazards H-1, H-2.

**Steps**:
1. Construct a Gherkin text string containing references to "L-99" and
   "H-88".
2. Call the Loss/Hazard ID validation function with the Gherkin text and
   the loss analysis.
3. Inspect the validation result errors.

**Expected**: Validation fails with errors containing both "L-99" and
"H-88".

### QA-GDDI-07: validator passes when all L-* and H-* references are valid

**Preconditions**: A Gherkin text referencing "L-1" and "H-1" which are
in the loss analysis. A `LossAnalysis` with losses L-1, L-2 and hazards
H-1, H-2.

**Steps**:
1. Construct a Gherkin text string containing valid references to "L-1"
   and "H-1".
2. Call the Loss/Hazard ID validation function with the Gherkin text and
   the loss analysis.
3. Inspect the validation result.

**Expected**: Validation succeeds (passed=True, no errors).

### QA-GDDI-08: validator passes when Gherkin has no L-* or H-* references

**Preconditions**: A Gherkin text with no L-* or H-* references. A
`LossAnalysis`.

**Steps**:
1. Construct a Gherkin text string with no L-* or H-* references.
2. Call the Loss/Hazard ID validation function with the Gherkin text and
   the loss analysis.
3. Inspect the validation result.

**Expected**: Validation succeeds (passed=True, no errors).

### QA-GDDI-09: Loss/Hazard ID validation runs during Stage 6 artifact validation

**Preconditions**: A mock LLM client that returns Gherkin referencing
hallucinated Loss ID "L-99". A complete set of SP1/SP2 artifacts.

**Steps**:
1. Construct mock LLM responses for all Stage 5 and Stage 6 calls, with
   the Gherkin call returning text referencing "L-99".
2. Call `run_sp3` with the mock client and SP1/SP2 artifacts.
3. Inspect the `stage_errors` in the result.

**Expected**: A validation error is reported containing "L-99".

### QA-GDDI-10: Loss/Hazard ID validation runs during Stage 7 envelope validation

**Preconditions**: A `ScenarioEnvelope` with Gherkin referencing
hallucinated Hazard ID "H-99".

**Steps**:
1. Construct a `ScenarioEnvelope` with Gherkin text referencing "H-99".
2. Call `_validate_envelope_stage7` with the envelope and a loss
   analysis.
3. Inspect the validation errors.

**Expected**: A validation error is reported containing "H-99".

---

## QA-V689: Fix Attack Tree Root Label ICA Type (v689)

### QA-V689-01: system prompt instructs exact ICA type usage

**Preconditions**: The `stage6b_tree_system.j2` template exists in the
STPA SP3 prompts directory.

**Steps**:
1. Load `stage6b_tree_system.j2` using `TemplateLoader(PROMPTS_DIR)`.
2. Read the rendered template text.

**Expected**: The template text instructs the LLM to use the exact ICA
type enum value from the scenario seed, defines the root format as
"Induce ICA {ica_type} on {ca_id}", and instructs the LLM not to
substitute or paraphrase the ICA type.

### QA-V689-02: validator passes when root label matches exact ICA type

**Preconditions**: A `ScenarioSpec` with `ica_type=NOT_PROVIDED` and
`target_control_action=CA-1-1`. An attack tree dict with root
"Induce ICA NOT_PROVIDED on CA-1-1".

**Steps**:
1. Construct a `ScenarioSpec` with `ica_type=UCAType.not_provided`.
2. Construct an attack tree dict with root
   "Induce ICA NOT_PROVIDED on CA-1-1".
3. Call the attack tree root label validation function with the attack
   tree and scenario spec.
4. Inspect the validation result.

**Expected**: Validation succeeds (passed=True, no errors).

### QA-V689-03: validator catches ICA type drift

**Preconditions**: A `ScenarioSpec` with `ica_type=NOT_PROVIDED` and
`target_control_action=CA-1-1`. An attack tree dict with root
"Induce ICA NOT_TRIGGERED on CA-1-1".

**Steps**:
1. Construct a `ScenarioSpec` with `ica_type=UCAType.not_provided`.
2. Construct an attack tree dict with root
   "Induce ICA NOT_TRIGGERED on CA-1-1".
3. Call the attack tree root label validation function with the attack
   tree and scenario spec.
4. Inspect the validation result.

**Expected**: Validation fails with an error message containing
"NOT_PROVIDED".

### QA-V689-04: validator catches missing ICA type in root label

**Preconditions**: A `ScenarioSpec` with `ica_type=NOT_PROVIDED` and
`target_control_action=CA-1-1`. An attack tree dict with root
"Induce ICA on CA-1-1" (no ICA type).

**Steps**:
1. Construct a `ScenarioSpec` with `ica_type=UCAType.not_provided`.
2. Construct an attack tree dict with root "Induce ICA on CA-1-1".
3. Call the attack tree root label validation function with the attack
   tree and scenario spec.
4. Inspect the validation result.

**Expected**: Validation fails with an error message containing
"NOT_PROVIDED".

### QA-V689-05: validator catches wrong control action in root label

**Preconditions**: A `ScenarioSpec` with `ica_type=NOT_PROVIDED` and
`target_control_action=CA-1-1`. An attack tree dict with root
"Induce ICA NOT_PROVIDED on CA-9-9".

**Steps**:
1. Construct a `ScenarioSpec` with `ica_type=UCAType.not_provided`.
2. Construct an attack tree dict with root
   "Induce ICA NOT_PROVIDED on CA-9-9".
3. Call the attack tree root label validation function with the attack
   tree and scenario spec.
4. Inspect the validation result.

**Expected**: Validation fails with an error message containing
"CA-1-1".

### QA-V689-06: validator catches empty root label

**Preconditions**: A `ScenarioSpec` with `ica_type=NOT_PROVIDED` and
`target_control_action=CA-1-1`. An attack tree dict with root "".

**Steps**:
1. Construct a `ScenarioSpec` with `ica_type=UCAType.not_provided`.
2. Construct an attack tree dict with root "".
3. Call the attack tree root label validation function with the attack
   tree and scenario spec.
4. Inspect the validation result.

**Expected**: Validation fails with an error message containing "root".

### QA-V689-07: root label validation runs during Stage 6 artifact validation

**Preconditions**: A mock LLM client that returns an attack tree with
root "Induce ICA NOT_TRIGGERED on CA-1-1". A complete set of SP1/SP2
artifacts with a scenario seed having `ica_type=NOT_PROVIDED`.

**Steps**:
1. Construct mock LLM responses for all Stage 5 and Stage 6 calls, with
   the attack tree call returning a tree with root
   "Induce ICA NOT_TRIGGERED on CA-1-1".
2. Call `run_sp3` with the mock client and SP1/SP2 artifacts.
3. Inspect the `stage_errors` in the result.

**Expected**: A validation error is reported containing "NOT_PROVIDED".

### QA-V689-08: root label validation runs during Stage 7 envelope validation

**Preconditions**: A `ScenarioEnvelope` with `ica_type=NOT_PROVIDED` and
`attack_tree` root "Induce ICA NOT_TRIGGERED on CA-1-1".

**Steps**:
1. Construct a `ScenarioEnvelope` with `ica_type=UCAType.not_provided`
   and an attack tree with root
   "Induce ICA NOT_TRIGGERED on CA-1-1".
2. Call `_validate_envelope_stage7` with the envelope.
3. Inspect the validation errors.

**Expected**: A validation error is reported containing "NOT_PROVIDED".

### QA-V689-09: user prompt passes ICA type to the LLM

**Preconditions**: A `ScenarioSpec` with `ica_type=NOT_PROVIDED` and a
control structure.

**Steps**:
1. Call `build_attack_tree_prompts` with the scenario spec, control
   structure, and a template loader.
2. Inspect the rendered user prompt text.

**Expected**: The user prompt contains the scenario spec YAML which
includes the ICA type `NOT_PROVIDED`.
