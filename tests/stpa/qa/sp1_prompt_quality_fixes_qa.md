# SP1 Stage 1 Prompt Quality Fixes — End-to-End QA Suite

This document specifies the user-visible workflows that QA verifies for
the Stage 1a/1b prompt template quality fixes. All verification is done
through the Python import API, pytest execution, and filesystem
inspection — no project-internal APIs are used. Command-line flags are
user-interface affordances exposed to QA.

## 1. Template File Content Verification

### QA-PQF-01: stage1a_system.j2 contains Quality requirements section

**Steps:**
1. Read `src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2`.
2. Verify the file contains `## Quality requirements`.
3. Verify `## Quality requirements` appears after `## Structural requirements`
   in the file.
4. Verify the file contains `### Hazard specificity`, `### Loss specificity`,
   and `### Acronym expansion` sub-section headings.

**Command:**
```bash
uv run python -c "
from pathlib import Path
p = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2')
text = p.read_text()
assert '## Quality requirements' in text, 'Missing Quality requirements section'
assert '## Structural requirements' in text, 'Missing Structural requirements section'
assert text.index('## Structural requirements') < text.index('## Quality requirements'), \
    'Quality requirements must appear after Structural requirements'
assert '### Hazard specificity' in text, 'Missing Hazard specificity'
assert '### Loss specificity' in text, 'Missing Loss specificity'
assert '### Acronym expansion' in text, 'Missing Acronym expansion'
print('PQF-01 OK')
"
```

### QA-PQF-02: stage1a_system.j2 contains hazard specificity anti-patterns and correct patterns

**Steps:**
1. Read `stage1a_system.j2`.
2. Verify the file contains the anti-pattern text about prompt injection
   bypassing security controls.
3. Verify the file contains the anti-pattern text about biased or
   discriminatory content.
4. Verify the file contains the correct pattern about the patient chatbot
   and EHR.
5. Verify the file contains the correct pattern about the refund processing
   API.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2').read_text()
assert 'LLM outputs are manipulated via prompt injection to bypass security controls' in text
assert 'System generates biased or discriminatory content' in text
assert 'patient chatbot generates an inaccurate surgical procedure explanation' in text
assert 'refund processing API executes an unauthorized refund amount' in text
assert 'too generic' in text
assert 'at least one specific component' in text
print('PQF-02 OK')
"
```

### QA-PQF-03: stage1a_system.j2 contains loss specificity and acronym expansion content

**Steps:**
1. Read `stage1a_system.j2`.
2. Verify the file contains `concrete consequences` and
   `not restatements of the risk card`.
3. Verify the file contains `Personally Identifiable Information (PII)`.
4. Verify the file contains `first expansion` and
   `short form alone is acceptable`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2').read_text()
assert 'concrete consequences' in text
assert 'not restatements of the risk card' in text
assert 'Personally Identifiable Information (PII)' in text
assert 'first expansion' in text
assert 'short form alone is acceptable' in text
print('PQF-03 OK')
"
```

### QA-PQF-04: stage1a_system.j2 contains gap analysis procedure and old text removed

**Steps:**
1. Read `stage1a_system.j2`.
2. Verify the file contains `gap analysis`.
3. Verify the file contains `key capabilities, integration points, and
   operational characteristics`.
4. Verify the file contains `unaddressed capability failure is a
   use-case-derived loss`.
5. Verify the file contains `empty use_case_losses list should be rare`.
6. Verify the file does NOT contain the old passive definition
   `losses identified from the use-case description that no risk card covers`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2').read_text()
assert 'gap analysis' in text
assert 'key capabilities, integration points, and operational characteristics' in text
assert 'unaddressed capability failure is a use-case-derived loss' in text
assert 'empty use_case_losses list should be rare' in text
assert 'losses identified from the use-case description that no risk card covers' not in text, \
    'Old passive definition should be replaced'
print('PQF-04 OK')
"
```

### QA-PQF-05: stage1a_user.j2 contains updated hazards and use_case_losses instructions

**Steps:**
1. Read `stage1a_user.j2`.
2. Verify the file contains `grounded in this system's specific architecture
   and mission`.
3. Verify the file contains `concrete component, data flow, or integration
   point`.
4. Verify the file does NOT contain the old hazards instruction
   `System-level hazards, each linking to at least one loss.`.
5. Verify the file contains `explicit gap analysis`.
6. Verify the file contains `architectural component, integration point, and
   operational characteristic`.
7. Verify the file contains `empty list is acceptable only if`.
8. Verify the file does NOT contain the old use_case_losses instruction
   `Losses from the use-case that no risk card covers.`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_user.j2').read_text()
assert \"grounded in this system's specific architecture and mission\" in text
assert 'concrete component, data flow, or integration point' in text
assert 'System-level hazards, each linking to at least one loss.' not in text, \
    'Old hazards instruction should be replaced'
assert 'explicit gap analysis' in text
assert 'architectural component, integration point, and operational characteristic' in text
assert 'empty list is acceptable only if' in text
assert 'Losses from the use-case that no risk card covers.' not in text, \
    'Old use_case_losses instruction should be replaced'
print('PQF-05 OK')
"
```

### QA-PQF-06: stage1b_system.j2 contains Quality requirements with acronym expansion and KC exception

**Steps:**
1. Read `stage1b_system.j2`.
2. Verify the file contains `## Quality requirements`.
3. Verify the file contains `Retrieval-Augmented Generation (RAG)`.
4. Verify the file contains `first expansion` and
   `short form alone is acceptable`.
5. Verify the file contains `KC sub-code identifiers`.
6. Verify the file contains `KCX-HITL`.
7. Verify `## Quality requirements` appears after `## Emphasis` in the file.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1b_system.j2').read_text()
assert '## Quality requirements' in text
assert '## Emphasis' in text
assert text.index('## Emphasis') < text.index('## Quality requirements'), \
    'Quality requirements must appear after Emphasis'
assert 'Retrieval-Augmented Generation (RAG)' in text
assert 'first expansion' in text
assert 'short form alone is acceptable' in text
assert 'KC sub-code identifiers' in text
assert 'KCX-HITL' in text
print('PQF-06 OK')
"
```

### QA-PQF-07: stage1a_system.j2 preserves existing sections

**Steps:**
1. Read `stage1a_system.j2`.
2. Verify the file still contains `## Structural requirements`,
   `## ID conventions`, `## Definitions`, and
   `## Output categories (four)`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_system.j2').read_text()
assert '## Structural requirements' in text
assert '## ID conventions' in text
assert '## Definitions' in text
assert '## Output categories (four)' in text
print('PQF-07 OK')
"
```

## 2. Template Rendering Verification

### QA-PQF-08: stage1a_system.j2 renders without Jinja2 errors

**Steps:**
1. Load `stage1a_system.j2` using the TemplateLoader from
   `scenario_forge.stpa.infra.templates`.
2. Render the template with no variables (system prompts have no
   template variables).
3. Verify the rendered text contains `Quality requirements`,
   `Hazard specificity`, `Loss specificity`, `Acronym expansion`, and
   `gap analysis`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
from scenario_forge.stpa.infra.templates import TemplateLoader
prompts = Path('src/scenario_forge/stpa/system_model/prompts')
loader = TemplateLoader(prompts)
rendered = loader.render_prompt('stage1a_system.j2')
assert 'Quality requirements' in rendered
assert 'Hazard specificity' in rendered
assert 'Loss specificity' in rendered
assert 'Acronym expansion' in rendered
assert 'gap analysis' in rendered
print('PQF-08 OK')
"
```

### QA-PQF-09: stage1a_user.j2 renders with use_case_text and risk_cards variables

**Steps:**
1. Load `stage1a_user.j2` using the TemplateLoader.
2. Render the template with `use_case_text` set to a test string and
   `risk_cards` set to an empty list.
3. Verify the rendered text contains the updated hazards instruction
   (`grounded in this system's specific architecture`).
4. Verify the rendered text contains the updated use_case_losses
   instruction (`explicit gap analysis`).
5. Verify the rendered text contains the test use-case string.

**Command:**
```bash
uv run python -c "
from pathlib import Path
from scenario_forge.stpa.infra.templates import TemplateLoader
prompts = Path('src/scenario_forge/stpa/system_model/prompts')
loader = TemplateLoader(prompts)
rendered = loader.render_prompt('stage1a_user.j2', use_case_text='A patient chatbot integrated with EHR systems', risk_cards=[])
assert \"grounded in this system's specific architecture\" in rendered
assert 'explicit gap analysis' in rendered
assert 'A patient chatbot integrated with EHR systems' in rendered
print('PQF-09 OK')
"
```

### QA-PQF-10: stage1b_system.j2 renders without Jinja2 errors

**Steps:**
1. Load `stage1b_system.j2` using the TemplateLoader.
2. Render the template with no variables.
3. Verify the rendered text contains `Quality requirements` and
   `Retrieval-Augmented Generation (RAG)`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
from scenario_forge.stpa.infra.templates import TemplateLoader
prompts = Path('src/scenario_forge/stpa/system_model/prompts')
loader = TemplateLoader(prompts)
rendered = loader.render_prompt('stage1b_system.j2')
assert 'Quality requirements' in rendered
assert 'Retrieval-Augmented Generation (RAG)' in rendered
print('PQF-10 OK')
"
```

### QA-PQF-11: stage1a_user.j2 preserves Jinja2 template variables

**Steps:**
1. Read the raw `stage1a_user.j2` template file.
2. Verify the file contains `{{ use_case_text }}` and `{% if risk_cards %}`.

**Command:**
```bash
uv run python -c "
from pathlib import Path
text = Path('src/scenario_forge/stpa/system_model/prompts/stage1a_user.j2').read_text()
assert '{{ use_case_text }}' in text, 'use_case_text variable missing'
assert '{% if risk_cards %}' in text, 'risk_cards variable missing'
print('PQF-11 OK')
"
```

## 3. Acceptance Test Execution

### QA-PQF-12: Acceptance tests for prompt quality fixes pass

**Steps:**
1. Run the acceptance test generated from the
   `sp1_prompt_quality_fixes.feature` Gherkin file.
2. Verify all scenarios pass with zero failures.

**Command:**
```bash
uv run pytest build/acceptance/generated/sp1_prompt_quality_fixes_acceptance_test.py -v --tb=short -q
```

## 4. Regression Verification

### QA-PQF-13: Existing SP1 Stage 1a tests still pass

**Steps:**
1. Run the existing Stage 1a loss analysis test suite.
2. Verify no regressions from the prompt template changes.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_loss or SP1_LA or stage_1a" -v --tb=short -q
```

### QA-PQF-14: Existing SP1 Stage 1b tests still pass

**Steps:**
1. Run the existing Stage 1b capability profile test suite.
2. Verify no regressions from the prompt template changes.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1_cap or SP1_CP or stage_1b" -v --tb=short -q
```

### QA-PQF-15: Full SP1 test suite passes

**Steps:**
1. Run the complete SP1 test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp1" -v --tb=short -q
```

### QA-PQF-16: Full project test suite passes

**Steps:**
1. Run the complete test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/ -x -q --tb=line
```

### QA-PQF-17: Linting passes

**Steps:**
1. Run ruff on the prompt template directory (no Python source changes
   expected, but verify no issues).
2. Verify no lint errors.

**Command:**
```bash
ruff check src/scenario_forge/stpa/ tests/stpa/
```
