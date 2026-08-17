# End-to-End QA Suite: KC Sub-code Display and ID Namespace Validation

## Overview

This QA suite verifies two combined model fixes for the SP1/STPA pipeline
through user-visible workflows: YAML artifact inspection, CLI-driven pipeline
runs, and template rendering. No project-internal APIs are used beyond the
public CLI commands and file I/O that a user would perform.

---

## QA-S1: KC Sub-code Display in Serialized YAML

### QA-S1-01: capability-profile.yaml contains kc_subcodes_display

**Preconditions**: A valid use-case description and risk extraction inputs
are available.

**Steps**:
1. Run the STPA pipeline Stage 1b to produce a capability profile:
   ```bash
   uv run scenario-forge generate \
       --use-case '@output/<prev>/use-case.txt' \
       --risk-extraction <path-to-risk-extraction.json> \
       --sssom <path-to-risk_to_category.sssom.tsv> \
       --output-dir output/qa-s1-01
   ```
   Alternatively, use `--profile <existing-profile.yaml>` to skip Stage 1b
   and load a pre-built profile, then re-serialize it.

2. Read `output/qa-s1-01/capability-profile.yaml`.

**Expected**: The YAML file contains a top-level key `kc_subcodes_display`
whose value is a dict (mapping).

### QA-S1-02: OWASP KC codes map to correct descriptions

**Preconditions**: The capability profile from QA-S1-01 contains at least
one OWASP KC sub-code (e.g., KC1.1).

**Steps**:
1. Read `output/qa-s1-01/capability-profile.yaml`.
2. Inspect the `kc_subcodes_display` dict.
3. For each code in `kc_subcodes` that starts with `KC` (not `KCX-`), verify
   the display value matches the corresponding entry in `KC_SUBCODE_NAMES`.

**Expected**: Every OWASP KC code in `kc_subcodes` has a human-readable
description in `kc_subcodes_display` that matches the static
`KC_SUBCODE_NAMES` dict in `capability_profile.py`.

### QA-S1-03: KCX extension codes map to correct descriptions

**Preconditions**: The capability profile contains at least one KCX-prefixed
code (e.g., KCX-PRIV).

**Steps**:
1. Read the YAML file.
2. Inspect the `kc_subcodes_display` dict.
3. For each code starting with `KCX-`, verify the display value matches the
   corresponding entry in `KCX_SUBCODES`.

**Expected**: Every KCX extension code has a description matching
`KCX_SUBCODES`.

### QA-S1-04: Unknown codes fall back to the code string itself

**Preconditions**: A capability profile YAML is manually crafted or loaded
that contains a code not present in `KC_SUBCODE_NAMES` or `KCX_SUBCODES`.

**Steps**:
1. Create a test YAML file with `kc_subcodes: [KC1.1, FAKE-CODE]`.
2. Load it as a `CapabilityProfile` via the `--profile` flag.
3. Re-serialize it by running any pipeline stage that writes
   `capability-profile.yaml`.

**Note**: The `validate_kc_subcodes` field validator on `CapabilityProfile`
rejects codes not in `VALID_KC_SUBCODES` and not starting with `KCX-`. To
test the fallback path, use a code that passes validation but is not in
either display dict — e.g., a KCX-prefixed code not in `KCX_SUBCODES` such
as `KCX-UNKNOWN`.

**Expected**: The `kc_subcodes_display` dict maps `KCX-UNKNOWN` to
`KCX-UNKNOWN` (the code string itself).

### QA-S1-05: kc_subcodes list[str] field is unchanged

**Preconditions**: The capability profile from QA-S1-01.

**Steps**:
1. Read `output/qa-s1-01/capability-profile.yaml`.
2. Inspect the `kc_subcodes` field.

**Expected**: `kc_subcodes` is a list of strings, identical to the input
profile's kc_subcodes. No codes are added, removed, or reordered.

### QA-S1-06: Reloading the YAML as CapabilityProfile succeeds

**Preconditions**: The capability-profile.yaml from QA-S1-01.

**Steps**:
1. Run the pipeline with `--profile output/qa-s1-01/capability-profile.yaml`
   to load the previously written profile.
2. Verify the pipeline starts without a validation error.

**Expected**: The profile loads successfully. The extra `kc_subcodes_display`
field is silently ignored by Pydantic (no `extra = "forbid"`). No validation
error is raised.

### QA-S1-07: Existing pipeline io.py path also injects display field

**Preconditions**: The existing (non-STPA) pipeline is runnable.

**Steps**:
1. Run the existing pipeline (not the STPA pipeline) to generate a
   capability profile:
   ```bash
   uv run scenario-forge generate \
       --use-case '@output/<prev>/use-case.txt' \
       --risk-extraction <path> \
       --sssom <path> \
       --output-dir output/qa-s1-07
   ```
2. Read `output/qa-s1-07/capability-profile.yaml`.

**Expected**: The YAML file contains `kc_subcodes_display` with the same
structure as the STPA path output.

### QA-S1-08: Both serialization paths use the same helper function

**Preconditions**: Both the STPA and existing pipeline paths are exercised.

**Steps**:
1. Inspect the source code to verify that both `write_yaml` (in
   `stpa/infra/yaml_io.py`) and `write_capability_profile` (in
   `pipeline/io.py`) call the same shared helper function to build
   `kc_subcodes_display`.

**Expected**: A single function (e.g., `build_kc_subcodes_display` in
`capability_profile.py` or a shared module) is called by both paths. No
duplicate implementation of the display-building logic exists.

---

## QA-S2: RC/PM ID Namespace Validation

### QA-S2-01: rc_id with correct prefix passes validation

**Preconditions**: A control structure YAML file with valid IDs.

**Steps**:
1. Create a YAML file with a responsibility containing
   `rc_id: RC-1-1`.
2. Load it via `read_yaml(path, ControlStructure)`.

**Expected**: The model loads successfully with no validation error.

### QA-S2-02: rc_id with wrong prefix fails validation

**Preconditions**: YAML files with wrong-prefix rc_ids.

**Steps**:
1. Create a YAML file with `rc_id: PM-1-1` in a responsibility constraint.
2. Attempt to load it via `read_yaml(path, ControlStructure)`.

**Expected**: A `ValidationError` is raised. The error message contains
`rc_id`.

### QA-S2-03: rc_id with malformed format fails validation

**Preconditions**: YAML files with malformed rc_ids.

**Steps**:
1. Create YAML files with `rc_id: RC-1`, `rc_id: RC-A-B`, and
   `rc_id: RC-1-1-1` respectively.
2. Attempt to load each via `read_yaml(path, ControlStructure)`.

**Expected**: Each load raises a `ValidationError` containing `rc_id`.

### QA-S2-04: Non-rc ID fields with wrong prefix or format fail validation

**Preconditions**: YAML files with wrong-prefix IDs in various fields.

**Steps**:
1. For each field type below, create a YAML file with the specified bad
   value and attempt to load it:
   - `pm_id: RC-1-1` (wrong prefix for ProcessModelPart)
   - `pm_id: PM-1` (malformed format)
   - `ca_id: PM-1-1` (wrong prefix for ControlAction)
   - `ca_id: CA-1` (malformed format)
   - `fb_id: PM-1-1` (wrong prefix for FeedbackChannel)
   - `fb_id: FB-1` (malformed format)
   - `cp_id: CP-1-1` (wrong format for ControlledProcess)
   - `resp_id: RESP-1-1` (wrong format for Responsibility)
   - `link_id: CL-1-1` (wrong format for CoordinationLink)
   - `cm_id: CM-1-1` (wrong format for CoordinationMechanism)

2. Attempt to load each YAML via `read_yaml(path, ControlStructure)`.

**Expected**: Each load raises a `ValidationError` whose error message
contains the relevant field name (e.g., `pm_id`, `ca_id`, `fb_id`, etc.).

### QA-S2-05: Duplicate RC IDs within the same responsibility fail validation

**Preconditions**: A YAML file with a responsibility containing two
constraints with the same `rc_id`.

**Steps**:
1. Create a YAML file with:
   ```yaml
   responsibilities:
     - resp_id: RESP-1
       description: Test
       responsibility_constraints:
         - rc_id: RC-1-1
           description: First
         - rc_id: RC-1-1
           description: Second
       process_model_parts:
         - pm_id: PM-1-1
           description: State
       control_actions:
         - ca_id: CA-1-1
           description: Action
       feedback_channels:
         - fb_id: FB-1-1
           description: Feedback
           updates: PM-1-1
   ```
2. Attempt to load via `read_yaml(path, ControlStructure)`.

**Expected**: A `ValidationError` is raised containing `Duplicate` and
`rc_id`.

### QA-S2-06: Cross-namespace collision detected by model validator

**Preconditions**: A control structure where the same ID value appears in
two different prefix families, bypassing field validators (e.g., via
`model_construct` or direct `__dict__` manipulation).

**Steps**:
1. Construct a `ControlStructure` with `rc_id: RC-1-1` and
   `pm_id: RC-1-1` by bypassing field validators (using
   `ControlStructure.model_construct()` or equivalent).
2. Trigger the model validator manually.

**Expected**: A `ValueError` is raised containing `namespace` or
`collision`.

### QA-S2-07: Valid control structure with all correct prefixes passes

**Preconditions**: A well-formed control structure YAML.

**Steps**:
1. Create a YAML file with all IDs using correct prefixes and formats:
   - `resp_id: RESP-1`
   - `rc_id: RC-1-1`
   - `pm_id: PM-1-1`
   - `ca_id: CA-1-1`
   - `fb_id: FB-1-1`
   - `cp_id: CP-1`
2. Load via `read_yaml(path, ControlStructure)`.

**Expected**: The model loads successfully with no validation error.

### QA-S2-08: Stage 2 Call 2 system prompt contains negative RC vs PM constraint

**Preconditions**: The Jinja2 template
`src/scenario_forge/stpa/system_model/prompts/stage2_call2_system.j2`
is available.

**Steps**:
1. Read the template file content.
2. Search for the negative constraint text.

**Expected**: The template contains text stating that:
- Responsibility constraints (RC-X-Y) are normative rules.
- Process model parts (PM-X-Y) are information state.
- The LLM must NOT copy PM entries as RCs.
- Every `rc_id` MUST start with `RC-`, never `PM-`.

### QA-S2-09: Existing tests updated to use correct RC-X-Y format

**Preconditions**: The test files that previously used `rc_id: "SC-1"`.

**Steps**:
1. Run the existing SP1 test suite:
   ```bash
   uv run pytest tests/stpa/test_sp1_fixtures.py tests/stpa/test_sp1_run.py tests/stpa/test_sp1_mutation.py tests/stpa/test_sp1_graceful_degradation.py -x
   ```

**Expected**: All tests pass. No test uses `rc_id: "SC-1"` or any
non-`RC-X-Y` format for `rc_id` fields.

### QA-S2-10: Full SP1 run produces a valid control structure

**Preconditions**: Valid use-case description, risk extraction, and SSSOM
inputs.

**Steps**:
1. Run the full SP1 pipeline:
   ```bash
   uv run scenario-forge generate \
       --use-case '@output/<prev>/use-case.txt' \
       --risk-extraction <path> \
       --sssom <path> \
       --output-dir output/qa-s2-10
   ```
2. Read the control structure YAML from the output directory.
3. Verify all rc_id fields match `^RC-\d+-\d+$`.
4. Verify all pm_id fields match `^PM-\d+-\d+$`.

**Expected**: All ID fields in the produced control structure conform to
their respective prefix conventions. No namespace collisions exist.
