# End-to-End QA Suite: SP1 Prompt Bug Fixes

## Scope

Verify the four prompt-template fixes through user-visible repository
workflows: inspect the prompt files, render them with the project CLI/runtime,
and run the generated acceptance tests. No project API or LLM service is
required.

## QA-1: Stage 1 prompts prevent hallucinated losses, hazards, tools, and entry points

**Steps:**

1. Read `src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2` and
   `stage1b_system.j2`.
2. Confirm Stage 1a says every loss is traceable to a risk card or feature in
   the use case and every hazard references a concrete described component,
   data flow, or capability.
3. Confirm Stage 1b says every tool is explicitly mentioned or directly
   implied by the use case and every entry point corresponds to an actual
   described interface.

**Command:**

```bash
uv run python - <<'PY'
from pathlib import Path
root = Path("src/scenario_forge/stpa/system_model/prompts")
a = (root / "stage1a_system.j2").read_text()
b = (root / "stage1b_system.j2").read_text()
assert "Every loss must be traceable to either a risk card or a specific feature described in the use-case text" in a
assert "Every hazard must reference a concrete component, data flow, or capability from the use-case description" in a
assert "Every tool in tool_inventory must be explicitly mentioned or directly implied by the use-case description" in b
assert "Every entry point must correspond to an actual interface described in the use case" in b
print("QA-1 OK")
PY
```

## QA-2: Stage 2 Call 3 explains and requires coordination links

**Steps:**

1. Read `stage2_call3_system.j2`.
2. Confirm it defines coordination links as dependencies between
   responsibilities sharing state, data, or control flow, representing
   inter-controller coordination.
3. Confirm it includes the three required examples and says an empty list is
   acceptable only when no responsibilities share state, data, or control
   flow.

**Command:**

```bash
uv run python - <<'PY'
from pathlib import Path
t = Path("src/scenario_forge/stpa/system_model/prompts/stage2_call3_system.j2").read_text()
for fragment in (
    "Coordination links capture dependencies between responsibilities",
    "inter-controller coordination",
    "Two responsibilities sharing a process model part not connected by a control action",
    "One responsibility's feedback channel updates a PM part that another responsibility controls",
    "Two responsibilities need to agree on a shared resource",
    "An empty coordination_links list is acceptable only when no two responsibilities share state, data, or control flow",
):
    assert fragment in t, fragment
print("QA-2 OK")
PY
```

## QA-3: Stage 2 Call 2 derives mandatory responsibilities from active zones

**Steps:**

1. Read `stage2_call2_system.j2`.
2. Confirm it checks active zones and requires tool parameter binding/action
   selection, memory lifecycle, HITL oversight, and inter-agent
   coordination responsibilities for the corresponding capabilities.
3. Confirm the requirement is hard, not optional.

**Command:**

```bash
uv run python - <<'PY'
from pathlib import Path
t = Path("src/scenario_forge/stpa/system_model/prompts/stage2_call2_system.j2").read_text()
for fragment in (
    "Check the capability profile's active zones",
    "tool_execution",
    "tool parameter validation and action selection",
    "context management and memory lifecycle",
    "escalation and human oversight",
    "inter-agent coordination and message validation",
    "hard requirement, not a suggestion",
):
    assert fragment in t, fragment
print("QA-3 OK")
PY
```

## QA-4: Stage 2 Call 2 splits composite control actions

**Steps:**

1. Read `stage2_call2_system.j2`.
2. Confirm it requires one discrete action per control action, instructs
   splitting composite actions, and gives approve/reject and execute/deny
   examples.
3. Confirm it warns about conjunctions such as `or` and `and`.

**Command:**

```bash
uv run python - <<'PY'
from pathlib import Path
t = Path("src/scenario_forge/stpa/system_model/prompts/stage2_call2_system.j2").read_text()
for fragment in (
    "Each control action must describe a single discrete action",
    "Split composite actions into separate CAs",
    "CA-X-1 Approve request",
    "CA-X-2 Reject request",
    "CA-X-1 Execute command",
    "CA-X-2 Deny command",
    "contains 'or', 'and', or similar conjunctions",
):
    assert fragment in t, fragment
print("QA-4 OK")
PY
```

## QA-5: All changed system prompts render without template errors

**Steps:**

1. Load each changed system prompt through `TemplateLoader`.
2. Render with no variables.
3. Confirm each rendered result contains its new requirement text.

**Command:**

```bash
uv run python - <<'PY'
from pathlib import Path
from scenario_forge.stpa.infra.templates import TemplateLoader
root = Path("src/scenario_forge/stpa/system_model/prompts")
loader = TemplateLoader(root)
expected = {
    "stage1a_system.j2": "Every loss must be traceable",
    "stage1b_system.j2": "Every tool in tool_inventory",
    "stage2_call2_system.j2": "Each control action must describe",
    "stage2_call3_system.j2": "Coordination links capture dependencies",
}
for name, fragment in expected.items():
    rendered = loader.render_prompt(name)
    assert fragment in rendered, name
print("QA-5 OK")
PY
```

## QA-6: Generated acceptance suite passes

```bash
cd .factory/swarmforge/aps
bb gherkin-parser ../../../tests/stpa/features/sp1_prompt_bug_fixes.feature ../../../acceptance/ir/sp1_prompt_bug_fixes.json
cd ../../..
uv run pytest acceptance/generated/sp1_prompt_bug_fixes_acceptance_test.py -v --tb=short -q
```

Expected result: every SP1 prompt bug-fix scenario passes with zero failures.

## QA-7: Regression suite passes

```bash
uv run pytest tests/stpa/ -k "sp1" -x -q --tb=line
```

Expected result: existing SP1 behavior remains passing after the prompt-only
changes.
