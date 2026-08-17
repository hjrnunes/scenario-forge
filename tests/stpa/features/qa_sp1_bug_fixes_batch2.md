# End-to-End QA Suite: SP1 Bug Fixes Batch 2 (zcda, g5gc, zign, clyy)

This QA suite verifies four combined SP1 bug fixes through user-visible
workflows: running the SP1 pipeline with mock LLM responses, inspecting
output artifacts on disk, rendering Jinja2 templates, invoking the runner
script's `read_use_case` function, and verifying function signatures.
No project-internal APIs are used beyond the public module interfaces,
file I/O, and command-line entry points that a user or test harness would
perform.

---

## QA-CAPPROF: Inject Capability Profile into Stage 2 Call 2 User Prompt (zcda)

### QA-CAPPROF-01: _call_2_responsibilities accepts capability_profile parameter

**Preconditions**: The `scenario_forge.stpa.system_model.control_structure`
module is importable.

**Steps**:
1. Import `_call_2_responsibilities` from
   `scenario_for_forge.stpa.system_model.control_structure`.
2. Inspect the function signature using `inspect.signature()`.
3. Check that `capability_profile` is among the keyword-only parameters.

**Expected**: The function signature includes a keyword-only parameter
named `capability_profile`.

### QA-CAPPROF-02: derive_control_structure accepts capability_profile parameter

**Preconditions**: The `scenario_forge.stpa.system_model.control_structure`
module is importable.

**Steps**:
1. Import `derive_control_structure` from
   `scenario_forge.stpa.system_model.control_structure`.
2. Inspect the function signature using `inspect.signature()`.
3. Check that `capability_profile` is among the keyword-only parameters.

**Expected**: The function signature includes a keyword-only parameter
named `capability_profile`.

### QA-CAPPROF-03: run_sp1 passes capability_profile through to Call 2

**Preconditions**: A mock LLM client that returns valid JSON for all
Stage 1a, Stage 1b, and Stage 2 calls (Calls 1, 2, 3). A use-case text,
risk cards, and an output directory.

**Steps**:
1. Construct a mock LLM client that returns valid LossAnalysis,
   Stage1Profile, RequirementSet, ResponsibilitySet, and ConnectionSet
   JSON responses.
2. Call `run_sp1` with the mock client, use-case text, risk cards, and
   output directory.
3. Read the `calls.jsonl` file from the output directory.
4. Find the call log entry for stage `stage_2`, step `call_2_responsibilities`.
5. Inspect the `user_prompt_text` field in that entry.

**Expected**: The Call 2 user prompt text contains a "Capability Profile
Context" section with the actual zones, multi_agent, hitl, and
has_persistent_memory values from the inferred capability profile.

### QA-CAPPROF-04: stage2_call2_user.j2 template contains Capability Profile Context section

**Preconditions**: The `stage2_call2_user.j2` template exists in the STPA
prompts directory.

**Steps**:
1. Load `stage2_call2_user.j2` using `TemplateLoader(PROMPTS_DIR)`.
2. Read the raw template text.

**Expected**: The template text contains the string "Capability Profile
Context", "zones_active", "multi_agent", "hitl", and
"has_persistent_memory".

### QA-CAPPROF-05: Rendered Call 2 user prompt contains actual profile data

**Preconditions**: A `CapabilityProfile` instance with `zones_active`
including `input`, `reasoning`, `tool_execution`, `multi_agent=True`,
`hitl=True`.

**Steps**:
1. Construct a `CapabilityProfile` with the specified zones and flags
   (use kc_subcodes that produce the desired zones, e.g. KC1.1, KC5.1,
   KC2.3, KCX-HITL).
2. Render `stage2_call2_user.j2` with `use_case_text`, `requirements`,
   and `capability_profile`.
3. Inspect the rendered text.

**Expected**: The rendered text contains "input, reasoning,
tool_execution", "Multi-agent: True", and "Human-in-the-loop: True".

### QA-CAPPROF-06: Rendered Call 2 user prompt reflects inactive zones

**Preconditions**: A `CapabilityProfile` instance with `zones_active` =
`['input', 'reasoning']` only, `multi_agent=False`, `hitl=False`,
`has_persistent_memory=False`.

**Steps**:
1. Construct a `CapabilityProfile` with kc_subcodes that produce only
   `input` and `reasoning` zones (e.g. KC1.1, KC3.3).
2. Render `stage2_call2_user.j2` with the profile.
3. Inspect the rendered text.

**Expected**: The rendered text contains "input, reasoning",
"Multi-agent: False", "Human-in-the-loop: False", and "Persistent
memory: False".

### QA-CAPPROF-07: Existing Call 2 user prompt sections remain present

**Preconditions**: The `stage2_call2_user.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text still contains "## Use-Case Description",
"## Requirements", and "## Your Task".

---

## QA-PATHRES: Runner Script Resolves Path References (g5gc)

### QA-PATHRES-01: read_use_case strips @ prefix

**Preconditions**: A file `tmp/test_usecase.txt` exists with content
"This is a real use case description."

**Steps**:
1. Import `read_use_case` from `scripts.run_sp1` (or import the module
   and access the function).
2. Call `read_use_case("@tmp/test_usecase.txt")`.
3. Inspect the returned string.

**Expected**: The returned text is "This is a real use case
description." (the @ prefix was stripped and the file was read).

### QA-PATHRES-02: read_use_case reads a normal file without @ prefix

**Preconditions**: A file `tmp/test_usecase.txt` exists with content
"This is a real use case description."

**Steps**:
1. Call `read_use_case("tmp/test_usecase.txt")`.
2. Inspect the returned string.

**Expected**: The returned text is "This is a real use case
description."

### QA-PATHRES-03: read_use_case resolves a nested path reference

**Preconditions**: A file `tmp/outer.txt` contains the text
"tmp/inner.txt" (a path reference). A file `tmp/inner.txt` contains
"This is the actual use case content."

**Steps**:
1. Call `read_use_case("tmp/outer.txt")`.
2. Inspect the returned string.

**Expected**: The returned text is "This is the actual use case
content." — the function detected that `tmp/outer.txt` contained a path
reference (short, no newlines, ends with .txt) and resolved it.

### QA-PATHRES-04: read_use_case does not resolve prose content

**Preconditions**: A file `tmp/prose.txt` contains a multi-line use-case
description with newlines and more than 200 characters.

**Steps**:
1. Call `read_use_case("tmp/prose.txt")`.
2. Inspect the returned string.

**Expected**: The returned text is the original file content — the
function did not treat it as a path reference because it has newlines or
exceeds 200 characters.

### QA-PATHRES-05: read_use_case raises FileNotFoundError for missing file

**Preconditions**: No file at `tmp/nonexistent_usecase.txt`.

**Steps**:
1. Call `read_use_case("tmp/nonexistent_usecase.txt")`.

**Expected**: A `FileNotFoundError` is raised.

### QA-PATHRES-06: read_use_case resolves path references with .md extension

**Preconditions**: A file `tmp/outer.md` contains "tmp/inner.md". A
file `tmp/inner.md` contains "This is the resolved markdown content."

**Steps**:
1. Call `read_use_case("tmp/outer.md")`.
2. Inspect the returned string.

**Expected**: The returned text is "This is the resolved markdown
content."

### QA-PATHRES-07: read_use_case raises clear error for unresolvable nested path

**Preconditions**: A file `tmp/outer.txt` contains
"tmp/missing_ref.txt". No file at `tmp/missing_ref.txt`.

**Steps**:
1. Call `read_use_case("tmp/outer.txt")`.

**Expected**: A `FileNotFoundError` is raised, and the error message
references the unresolved path "tmp/missing_ref.txt".

### QA-PATHRES-08: read_use_case logs first 100 characters of loaded text

**Preconditions**: A file `tmp/test_usecase.txt` exists with content
longer than 100 characters. A logging capture mechanism is in place
(e.g. `caplog` pytest fixture).

**Steps**:
1. Call `read_use_case("tmp/test_usecase.txt")` with log capture
   enabled.
2. Inspect the captured log output.

**Expected**: A log entry (INFO level or higher) is produced that
contains the first 100 characters of the loaded text.

---

## QA-REVRUN: Prevent RevisionDelta Runaway Output (zign)

### QA-REVRUN-01: revision_system.j2 instructs modified_responsibilities contains only changes

**Preconditions**: The `revision_system.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text contains "modified_responsibilities list
must contain ONLY responsibilities you are CHANGING", "Do not include
unmodified responsibilities", and "If a responsibility needs no changes,
do not include it in the delta at all".

### QA-REVRUN-02: revision_user.j2 does not include use_case_text

**Preconditions**: The `revision_user.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text does not contain `{{ use_case_text }}`
or the string `use_case_text` as a template variable reference.

### QA-REVRUN-03: revision_user.j2 still contains control structure listing

**Preconditions**: The `revision_user.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text still contains "Current Control
Structure", "Responsibilities", and "Critic Findings".

### QA-REVRUN-04: safe_llm_call accepts max_completion_tokens parameter

**Preconditions**: The `scenario_forge.stpa.infra.llm_helpers` module is
importable.

**Steps**:
1. Import `safe_llm_call` from
   `scenario_forge.stpa.infra.llm_helpers`.
2. Inspect the function signature using `inspect.signature()`.
3. Check that `max_completion_tokens` is among the keyword-only
   parameters.

**Expected**: The function signature includes a keyword-only parameter
named `max_completion_tokens` with default `None`.

### QA-REVRUN-05: safe_llm_call passes max_completion_tokens to complete

**Preconditions**: A mock `LLMClient` with a mocked `complete` method
that records its call arguments.

**Steps**:
1. Construct a mock `LLMClient` with `base_url="http://test:8080"`.
2. Replace the `complete` method with a mock that returns a valid
   `LLMResult` and records kwargs.
3. Call `safe_llm_call` with `max_completion_tokens=4096`.
4. Inspect the kwargs passed to `complete`.

**Expected**: The `complete` method was called with
`max_completion_tokens=4096`.

### QA-REVRUN-06: safe_llm_call without max_completion_tokens passes None

**Preconditions**: A mock `LLMClient` with a mocked `complete` method.

**Steps**:
1. Construct a mock `LLMClient`.
2. Call `safe_llm_call` without the `max_completion_tokens` argument.
3. Inspect the kwargs passed to `complete`.

**Expected**: The `complete` method was called with
`max_completion_tokens=None` (the default), allowing the client's own
default to take effect.

### QA-REVRUN-07: run_revision passes max_completion_tokens 4096

**Preconditions**: A mock `LLMClient` with a mocked `complete` method.
A valid pre-revision `ControlStructure` with RESP-1 and RESP-2.
`CriticFindings` with unjustified gaps.

**Steps**:
1. Construct a mock LLM client that returns a valid `RevisionDelta`
   JSON response.
2. Call `run_revision` with the mock client, control structure, and
   critic findings.
3. Inspect the kwargs passed to `complete` (or `safe_llm_call`) for the
   revision call.

**Expected**: The revision LLM call was made with
`max_completion_tokens=4096`.

### QA-REVRUN-08: new_responsibilities with existing resp_id is rejected

**Preconditions**: A mock LLM that returns a `RevisionDelta` with
`new_responsibilities` containing a responsibility with `resp_id=RESP-1`
(which already exists in the control structure).

**Steps**:
1. Construct a mock LLM client returning the described RevisionDelta.
2. Call `run_revision`.
3. Inspect the returned control structure and warnings list.

**Expected**: The final control structure does not contain a duplicate
RESP-1 (the original RESP-1 is preserved, the new one is rejected). A
warning is logged about the rejected duplicate resp_id RESP-1.

### QA-REVRUN-09: new_responsibilities with genuinely new resp_id is accepted

**Preconditions**: A mock LLM that returns a `RevisionDelta` with
`new_responsibilities` containing RESP-3 with valid PM, CA, and FB
elements.

**Steps**:
1. Construct a mock LLM client returning the described RevisionDelta.
2. Call `run_revision`.
3. Inspect the returned control structure.

**Expected**: The final control structure contains RESP-3.

### QA-REVRUN-10: Duplicate rejection does not affect modified_responsibilities

**Preconditions**: A mock LLM that returns a `RevisionDelta` with
`modified_responsibilities` containing RESP-1 with an updated
description, AND `new_responsibilities` containing RESP-2 (which already
exists).

**Steps**:
1. Construct a mock LLM client returning the described RevisionDelta.
2. Call `run_revision`.
3. Inspect the returned control structure and warnings.

**Expected**: The final control structure contains RESP-1 with the
updated description (modified_responsibilities replacement worked). A
warning is logged about the rejected duplicate RESP-2. The final control
structure does not contain a duplicate RESP-2.

### QA-REVRUN-11: revision_system.j2 preserves existing delta and ID rules

**Preconditions**: The `revision_system.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text still contains "Do NOT restate the
entire control structure", "ID format rules", and
"solution-neutrality".

### QA-REVRUN-12: revision_system.j2 renders successfully with the new instruction

**Preconditions**: The `revision_system.j2` template is loaded. A
`ControlStructure` with responsibilities and coordination links is
available.

**Steps**:
1. Render the template with `control_structure`, `next_resp_num`,
   `next_cl_num`, and `next_cp_num`.
2. Inspect the rendered text.

**Expected**: The rendered text contains "modified_responsibilities list
must contain ONLY" and does not contain unrendered `{{` template syntax.

---

## QA-SECCON: Prevent Security Constraints from Contaminating Tool Inventory (clyy)

### QA-SECCON-01: stage1b_system.j2 instructs not to infer tools from security constraints

**Preconditions**: The `stage1b_system.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text contains "Security constraints describe
what SHOULD exist, not what DOES exist" and "Do not infer tools from
security constraints".

### QA-SECCON-02: stage1b_system.j2 instructs to list only existing capabilities

**Preconditions**: The `stage1b_system.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text contains "Only list tools explicitly
described as existing capabilities in the use-case description".

### QA-SECCON-03: stage1b_user.j2 relabels Security Constraints section

**Preconditions**: The `stage1b_user.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text contains "Security Constraints
(requirements for future control structure, NOT existing capabilities)".

### QA-SECCON-04: stage1b_user.j2 does not contain old unlabeled Security Constraints header

**Preconditions**: The `stage1b_user.j2` template is loaded.

**Steps**:
1. Read the raw template text.
2. Search for a bare "### Security Constraints" without the
  clarification parenthetical.

**Expected**: The template does not contain "### Security Constraints"
followed by a newline without the "(requirements for future control
structure, NOT existing capabilities)" clarification.

### QA-SECCON-05: stage1b_user.j2 still renders security constraint listings

**Preconditions**: A `LossAnalysis` instance with at least one security
constraint. The `stage1b_user.j2` template is loaded.

**Steps**:
1. Render the template with `use_case_text`, `loss_analysis`, and
   `all_losses`.
2. Inspect the rendered text.

**Expected**: The rendered text contains "Security Constraints" and the
constraint_id from the loss analysis.

### QA-SECCON-06: stage1b_system.j2 preserves existing quality requirement sections

**Preconditions**: The `stage1b_system.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text still contains "## Quality
requirements", "## Schneider zones", "## Rules", and "## Emphasis".

### QA-SECCON-07: stage1b_system.j2 renders successfully with new instruction

**Preconditions**: The `stage1b_system.j2` template is loaded.

**Steps**:
1. Render the template with no variables.
2. Inspect the rendered text.

**Expected**: The rendered text contains "Security constraints describe
what SHOULD exist" and does not contain unrendered `{{` template syntax.

### QA-SECCON-08: stage1b_user.j2 preserves other loss analysis sections

**Preconditions**: The `stage1b_user.j2` template is loaded.

**Steps**:
1. Read the raw template text.

**Expected**: The template text still contains "Loss Analysis Context",
"Losses", "Hazards", and "Your Task".
