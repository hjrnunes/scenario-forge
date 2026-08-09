# End-to-End QA Suite: Revision Strip Empty Responsibilities and top_k extra_body

## Overview

This QA suite verifies two combined SP1 code bug fixes through
user-visible workflows: running the revision step with mock LLM responses,
inspecting the output control-structure YAML, and verifying LLM client
request construction. No project-internal APIs are used beyond the public
module interfaces and file I/O that a user or test harness would perform.

---

## QA-STRIP: Strip Empty Responsibilities After Revision

### QA-STRIP-01: Empty responsibilities are stripped from revised control structure

**Preconditions**: A mock LLM client that returns a revised
ControlStructure containing at least one complete responsibility (with PM
parts, CAs, and FB channels) and at least one skeleton responsibility
(with a description but empty process_model_parts, control_actions, and
feedback_channels).

**Steps**:
1. Construct a mock LLM client that returns a ControlStructure JSON with:
   - RESP-1: has PM-1-1, CA-1-1, FB-1-1 (complete)
   - RESP-2: has description only, no PM/CA/FB (empty)
2. Call `run_revision` with the mock client, a valid pre-revision
   ControlStructure, and CriticFindings with unjustified gaps.
3. Inspect the returned ControlStructure.

**Expected**: The returned ControlStructure contains RESP-1 but does NOT
contain RESP-2.

### QA-STRIP-02: No empty responsibilities means no stripping

**Preconditions**: A mock LLM client that returns a revised
ControlStructure where every responsibility has at least one PM part, one
CA, and one FB channel.

**Steps**:
1. Construct a mock LLM client that returns a ControlStructure with 3
   complete responsibilities (RESP-1, RESP-2, RESP-3).
2. Call `run_revision` with the mock client.
3. Inspect the returned ControlStructure.

**Expected**: All 3 responsibilities are present in the returned
ControlStructure. No warnings about stripped responsibilities are
returned.

### QA-STRIP-03: Responsibility with some parts is not stripped

**Preconditions**: A mock LLM client that returns a revised
ControlStructure with a responsibility that has PM parts but no CAs and no
FB channels.

**Steps**:
1. Construct a mock LLM client that returns a ControlStructure with:
   - RESP-1: complete (PM, CA, FB)
   - RESP-3: has PM-3-1 but no CAs and no FBs
2. Call `run_revision` with the mock client.
3. Inspect the returned ControlStructure.

**Expected**: RESP-3 is present in the returned ControlStructure. Only
responsibilities with ALL three lists empty (PM, CA, FB) are stripped.

### QA-STRIP-04: Warning logged for each stripped responsibility

**Preconditions**: A mock LLM client that returns a revised
ControlStructure with two empty responsibilities (RESP-2 and RESP-4).

**Steps**:
1. Construct a mock LLM client that returns a ControlStructure with:
   - RESP-1: complete
   - RESP-2: empty (description only)
   - RESP-4: empty (description only)
2. Call `run_revision` with the mock client.
3. Inspect the returned post-revision warnings list.

**Expected**: The warnings list contains at least two entries — one
mentioning RESP-2 and one mentioning RESP-4. Each warning includes the
resp_id and the description of the stripped responsibility.

### QA-STRIP-05: Stripped control structure written to disk

**Preconditions**: A full SP1 run is executed with a mock or real LLM
that triggers revision and produces empty responsibilities in the revised
ControlStructure.

**Steps**:
1. Run the SP1 pipeline (or `_run_stage_2_block`) with inputs that
   trigger the revision step.
2. Read the `control-structure.yaml` file from the output directory.

**Expected**: The YAML file on disk does not contain any responsibility
with empty process_model_parts, control_actions, and feedback_channels.
The stripped result is what was written to disk.

### QA-STRIP-06: Responsibility with only constraints but no PM/CA/FB is stripped

**Preconditions**: A mock LLM client that returns a revised
ControlStructure with a responsibility that has responsibility_constraints
but no PM parts, no CAs, and no FB channels.

**Steps**:
1. Construct a mock LLM client that returns a ControlStructure with:
   - RESP-1: complete
   - RESP-5: has RC-5-1 but no PM/CA/FB
2. Call `run_revision` with the mock client.
3. Inspect the returned ControlStructure.

**Expected**: RESP-5 is NOT present in the returned ControlStructure. The
strip criterion is based solely on PM, CA, and FB emptiness — the presence
of responsibility_constraints alone does not prevent stripping.

### QA-STRIP-07: Multiple empty responsibilities stripped in one pass

**Preconditions**: A mock LLM client that returns a revised
ControlStructure with 3 empty responsibilities (RESP-2, RESP-4, RESP-7)
and 2 complete responsibilities (RESP-1, RESP-3).

**Steps**:
1. Construct a mock LLM client that returns the described ControlStructure.
2. Call `run_revision` with the mock client.
3. Inspect the returned ControlStructure and warnings.

**Expected**: The returned ControlStructure contains only RESP-1 and
RESP-3. Three warnings are returned, one for each stripped responsibility.

---

## QA-TOPK: top_k Routed Through extra_body

### QA-TOPK-01: top_k appears in extra_body, not as top-level kwarg

**Preconditions**: An LLMClient constructed with `base_url` and `top_k=40`.

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"`,
   `api_key="k"`, and `top_k=40`.
2. Replace the internal OpenAI client with a mock.
3. Call `complete(system_prompt="sys", user_prompt="usr")`.
4. Inspect the kwargs passed to `chat.completions.create`.

**Expected**: The kwargs do NOT contain a top-level `top_k` key. The
kwargs contain an `extra_body` key whose value is a dict containing
`top_k: 40`.

### QA-TOPK-02: top_p remains a top-level kwarg

**Preconditions**: An LLMClient constructed with `top_p=0.9` and
`top_k=40`.

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"`,
   `top_p=0.9`, and `top_k=40`.
2. Replace the internal OpenAI client with a mock.
3. Call `complete(system_prompt="sys", user_prompt="usr")`.
4. Inspect the kwargs passed to `chat.completions.create`.

**Expected**: The kwargs contain a top-level `top_p` key with value `0.9`.
The `top_p` key is NOT inside `extra_body`.

### QA-TOPK-03: temperature and max_completion_tokens remain top-level

**Preconditions**: An LLMClient constructed with `top_k=40`.

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"`,
   `top_k=40`, `temperature=0.7`, `max_completion_tokens=2048`.
2. Replace the internal OpenAI client with a mock.
3. Call `complete(system_prompt="sys", user_prompt="usr")`.
4. Inspect the kwargs passed to `chat.completions.create`.

**Expected**: The kwargs contain top-level `temperature` (0.7) and
`max_completion_tokens` (2048). Neither is inside `extra_body`.

### QA-TOPK-04: top_k None means no extra_body

**Preconditions**: An LLMClient constructed without `top_k` (defaults to
None).

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"` and no
   `top_k` argument.
2. Replace the internal OpenAI client with a mock.
3. Call `complete(system_prompt="sys", user_prompt="usr")`.
4. Inspect the kwargs passed to `chat.completions.create`.

**Expected**: The kwargs do NOT contain an `extra_body` key. The kwargs
do NOT contain a top-level `top_k` key.

### QA-TOPK-05: top_k forwarded in extra_body for structured parse calls

**Preconditions**: An LLMClient constructed with `top_k=40` and a
Pydantic response model.

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"`,
   `top_k=40`.
2. Replace the internal OpenAI client with a mock that returns a valid
   parsed response.
3. Define a simple Pydantic model (e.g., `class Dummy(BaseModel):
   value: str`).
4. Call `complete(system_prompt="sys", user_prompt="usr",
   response_format=Dummy)`.
5. Inspect the kwargs passed to `beta.chat.completions.parse`.

**Expected**: The parse call kwargs contain `extra_body` with `top_k: 40`.
The parse call kwargs do NOT contain a top-level `top_k` key.

### QA-TOPK-06: top_k forwarded in extra_body for unstructured create calls

**Preconditions**: An LLMClient constructed with `top_k=40` and no
response format (unstructured call).

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"`,
   `top_k=40`.
2. Replace the internal OpenAI client with a mock that returns a valid
   text response.
3. Call `complete(system_prompt="sys", user_prompt="usr")` (no
   `response_format`).
4. Inspect the kwargs passed to `chat.completions.create`.

**Expected**: The create call kwargs contain `extra_body` with `top_k: 40`.
The create call kwargs do NOT contain a top-level `top_k` key.

### QA-TOPK-07: No TypeError when top_k is set with non-OpenAI provider

**Preconditions**: An LLMClient constructed with `top_k=40` targeting a
non-OpenAI base URL (e.g., OpenRouter).

**Steps**:
1. Construct an LLMClient with
   `base_url="https://openrouter.ai/api/v1"`, `api_key="k"`,
   `top_k=40`.
2. Replace the internal OpenAI client with a mock.
3. Call `complete(system_prompt="sys", user_prompt="usr")`.
4. Verify no `TypeError` is raised about unexpected keyword argument
   `top_k`.

**Expected**: The call completes without error. `top_k` is inside
`extra_body`, not passed as a top-level kwarg to the SDK.

### QA-TOPK-08: Existing temperature and top_p behavior unchanged

**Preconditions**: An LLMClient constructed with `temperature=0.6` and
`top_p=0.8` (no `top_k`).

**Steps**:
1. Construct an LLMClient with `base_url="http://test:8080"`,
   `temperature=0.6`, `top_p=0.8`.
2. Replace the internal OpenAI client with a mock.
3. Call `complete(system_prompt="sys", user_prompt="usr")`.
4. Inspect the kwargs passed to `chat.completions.create`.

**Expected**: The kwargs contain `temperature: 0.6` and `top_p: 0.8` as
top-level keys. No `extra_body` key is present. Behavior is unchanged from
before the fix.
