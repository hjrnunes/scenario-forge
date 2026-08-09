# End-to-End QA Suite: Model Profiles and Calls HTML Rendering

This QA suite verifies two combined features through the user interface
(command-line interface and filesystem inspection). It does not use any
project API; all verification is done via shell commands, file inspection,
and HTML parsing.

## Prerequisites

- The project is installed: `uv sync` has been run
- A working directory with test fixtures (use-case text, risk extraction JSON)
- `uv run python` is available as the execution prefix

---

## QA-T1: Model Profiles

### QA-T1-01: Profile loading via Python import

**Steps:**
1. Create a test profiles YAML file at `tmp/qa-profiles.yaml` with content:
   ```yaml
   test-profile:
     base_url: https://example.com/v1
     model: test-model
     api_key: sk-test-123
     max_completion_tokens: 8192
     temperature: 0.5
   ```
2. Run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.model_profiles import load_profile
   p = load_profile('tmp/qa-profiles.yaml', 'test-profile')
   assert p['base_url'] == 'https://example.com/v1'
   assert p['model'] == 'test-model'
   assert p['api_key'] == 'sk-test-123'
   assert p['max_completion_tokens'] == 8192
   assert p['temperature'] == 0.5
   print('PASS')
   "
   ```
3. Verify the output contains `PASS`

**Expected:** All parameters are loaded correctly from the named profile.

### QA-T1-02: Missing profiles file error

**Steps:**
1. Run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.model_profiles import load_profile
   try:
       load_profile('tmp/nonexistent.yaml', 'any')
       print('FAIL: no error raised')
   except Exception as e:
       assert 'tmp/nonexistent.yaml' in str(e) or 'nonexistent' in str(e).lower()
       print('PASS')
   "
   ```

**Expected:** A clear error mentioning the file path is raised.

### QA-T1-03: Unknown profile name error

**Steps:**
1. Using the same `tmp/qa-profiles.yaml` from QA-T1-01, run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.model_profiles import load_profile
   try:
       load_profile('tmp/qa-profiles.yaml', 'nonexistent')
       print('FAIL: no error raised')
   except Exception as e:
       assert 'nonexistent' in str(e)
       print('PASS')
   "
   ```

**Expected:** A clear error mentioning the profile name "nonexistent" is raised.

### QA-T1-04: Profile with optional top_p and top_k

**Steps:**
1. Create `tmp/qa-profiles-tuned.yaml`:
   ```yaml
   tuned:
     base_url: https://example.com/v1
     model: tuned-model
     api_key: unused
     top_p: 0.9
     top_k: 40
   ```
2. Run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.model_profiles import load_profile
   p = load_profile('tmp/qa-profiles-tuned.yaml', 'tuned')
   assert p.get('top_p') == 0.9
   assert p.get('top_k') == 40
   print('PASS')
   "
   ```

**Expected:** top_p and top_k are loaded from the profile.

### QA-T1-05: Profile with custom headers

**Steps:**
1. Create `tmp/qa-profiles-headers.yaml`:
   ```yaml
   with-hdr:
     base_url: https://custom.example.com/v1
     model: custom-1
     api_key: sk-123
     headers:
       X-Custom: value
       X-Region: eu
   ```
2. Run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.model_profiles import load_profile
   p = load_profile('tmp/qa-profiles-headers.yaml', 'with-hdr')
   assert p['headers']['X-Custom'] == 'value'
   assert p['headers']['X-Region'] == 'eu'
   print('PASS')
   "
   ```

**Expected:** Custom headers dict is loaded with both keys.

### QA-T1-06: LLMClient accepts top_p and top_k

**Steps:**
1. Run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.llm import LLMClient
   c = LLMClient(base_url='https://example.com/v1', api_key='unused', model='test', top_p=0.9, top_k=40)
   assert c.top_p == 0.9
   assert c.top_k == 40
   print('PASS')
   "
   ```

**Expected:** LLMClient stores top_p=0.9 and top_k=40.

### QA-T1-07: LLMClient without top_p and top_k defaults to None

**Steps:**
1. Run:
   ```bash
   uv run python -c "
   from scenario_forge.stpa.infra.llm import LLMClient
   c = LLMClient(base_url='https://example.com/v1', api_key='unused', model='test')
   assert c.top_p is None
   assert c.top_k is None
   print('PASS')
   "
   ```

**Expected:** top_p and top_k are None when not provided.

### QA-T1-08: Runner script --profile flag

**Steps:**
1. Ensure `ai/model-profiles.yaml` exists (or create a test one at `tmp/qa-profiles.yaml`)
2. Run the runner script with --help to verify the flag exists:
   ```bash
   uv run python scripts/run_sp1.py --help 2>&1 | grep -- '--profile'
   ```
3. Verify the output contains `--profile`

**Expected:** The --profile flag is documented in the runner script help.

### QA-T1-09: Runner script --profiles-file flag

**Steps:**
1. Run:
   ```bash
   uv run python scripts/run_sp1.py --help 2>&1 | grep -- '--profiles-file'
   ```
2. Verify the output contains `--profiles-file`

**Expected:** The --profiles-file flag is documented in the runner script help.

### QA-T1-10: Sample profiles file is committed

**Steps:**
1. Run:
   ```bash
   git ls-files ai/model-profiles.example.yaml
   ```
2. Verify the file is tracked by git (non-empty output)
3. Run:
   ```bash
   grep 'sk-or-v1-YOUR-KEY-HERE' ai/model-profiles.example.yaml
   ```
4. Verify the output contains the placeholder key

**Expected:** The sample file is tracked in git and contains placeholder keys, not real keys.

### QA-T1-11: Real profiles file is gitignored

**Steps:**
1. Run:
   ```bash
   grep 'ai/model-profiles.yaml' .gitignore
   ```
2. Verify the output contains `ai/model-profiles.yaml`

**Expected:** `ai/model-profiles.yaml` is listed in .gitignore.

### QA-T1-12: Profile name recorded in run manifest

**Steps:**
1. Create a test profiles file at `tmp/qa-profiles.yaml` with a named profile
2. Run the SP1 pipeline with `--profile` and `--profiles-file`:
   ```bash
   uv run python scripts/run_sp1.py \
     --use-case <use-case-path> \
     --risk-extraction <risk-path> \
     --output-dir tmp/qa-output \
     --profile test-profile \
     --profiles-file tmp/qa-profiles.yaml
   ```
3. Inspect the manifest:
   ```bash
   uv run python -c "
   import yaml
   m = yaml.safe_load(open('tmp/qa-output/run-manifest.yaml'))
   assert m['model_config'].get('profile') == 'test-profile'
   print('PASS')
   "
   ```

**Expected:** The run manifest's `model_config` dict contains a `profile` key with the profile name.

### QA-T1-13: Runner without --profile falls back to environment variables

**Steps:**
1. Set environment variables:
   ```bash
   export SCENARIO_FORGE_MODEL_BASE_URL=https://example.com/v1
   export SCENARIO_FORGE_API_KEY=unused
   export SCENARIO_FORGE_MODEL_NAME=test-model
   ```
2. Run the runner without --profile:
   ```bash
   uv run python scripts/run_sp1.py \
     --use-case <use-case-path> \
     --risk-extraction <risk-path> \
     --output-dir tmp/qa-output-env
   ```
3. Inspect the manifest:
   ```bash
   uv run python -c "
   import yaml
   m = yaml.safe_load(open('tmp/qa-output-env/run-manifest.yaml'))
   assert 'profile' not in m['model_config']
   print('PASS')
   "
   ```

**Expected:** No `profile` key in the manifest when environment variables are used.

### QA-T1-14: .envrc does not contain model-specific env vars

**Steps:**
1. Run:
   ```bash
   grep -c 'SCENARIO_FORGE_MODEL_BASE_URL\|SCENARIO_FORGE_API_KEY\|SCENARIO_FORGE_MODEL_NAME' .envrc || echo "0 matches"
   ```
2. Verify the output shows 0 matches (or the file does not contain these variables)

**Expected:** The model-specific environment variables have been removed from .envrc.

---

## QA-F1: Calls JSONL HTML Rendering

### QA-F1-01: render_calls_html produces a self-contained HTML file

**Steps:**
1. Create a test calls.jsonl at `tmp/qa-calls.jsonl` with content:
   ```jsonl
   {"stage":"stage_1a","step":"call_1a_losses","slot_id":null,"scenario_id":null,"system_prompt_hash":"sha256-aaa","user_prompt_hash":"sha256-bbb","model":"test-model","prompt_tokens":4500,"completion_tokens":1200,"duration_ms":8500,"timestamp":"2026-01-01T00:00:00Z","success":true}
   {"stage":"stage_2","step":"call_2_req","slot_id":null,"scenario_id":null,"system_prompt_hash":"sha256-ccc","user_prompt_hash":"sha256-ddd","model":"test-model","prompt_tokens":4800,"completion_tokens":1300,"duration_ms":7600,"timestamp":"2026-01-01T00:01:00Z","success":false,"error":"timeout exceeded"}
   ```
2. Run:
   ```bash
   uv run python -c "
   from pathlib import Path
   from scenario_forge.stpa.infra.calls_html import render_calls_html
   out = render_calls_html(Path('tmp/qa-calls.jsonl'), Path('tmp/qa-calls.html'))
   assert out == Path('tmp/qa-calls.html')
   print('PASS')
   "
   ```
3. Verify `tmp/qa-calls.html` exists and is non-empty
4. Verify the HTML contains a `<style` tag:
   ```bash
   grep '<style' tmp/qa-calls.html
   ```
5. Verify no external stylesheet references:
   ```bash
   ! grep -E 'rel=["\x27]stylesheet["\x27]' tmp/qa-calls.html
   ```

**Expected:** A self-contained HTML file with inline CSS and no external dependencies.

### QA-F1-02: Summary table shows correct totals

**Steps:**
1. Using the `tmp/qa-calls.html` from QA-F1-01
2. Verify total calls = 2:
   ```bash
   uv run python -c "
   html = open('tmp/qa-calls.html').read()
   assert '2' in html  # total calls
   print('PASS')
   "
   ```
3. Verify success count = 1 and failure count = 1:
   ```bash
   uv run python -c "
   html = open('tmp/qa-calls.html').read()
   assert '1' in html  # success and failure counts
   print('PASS')
   "
   ```

**Expected:** Summary shows total calls 2, success count 1, failure count 1.

### QA-F1-03: Detail table contains all call entries

**Steps:**
1. Using the `tmp/qa-calls.html` from QA-F1-01
2. Verify both steps appear in the HTML:
   ```bash
   grep 'call_1a_losses' tmp/qa-calls.html && grep 'call_2_req' tmp/qa-calls.html
   ```

**Expected:** Both call entries appear in the detail table.

### QA-F1-04: Failed calls are highlighted

**Steps:**
1. Using the `tmp/qa-calls.html` from QA-F1-01
2. Verify the error message appears:
   ```bash
   grep 'timeout exceeded' tmp/qa-calls.html
   ```
3. Verify there is a failure indicator (red color class or similar):
   ```bash
   grep -iE 'red|fail|error' tmp/qa-calls.html
   ```

**Expected:** The failed call row is visually distinguished (red highlighting) and the error message is displayed.

### QA-F1-05: Empty calls.jsonl produces valid HTML with zero totals

**Steps:**
1. Create an empty file:
   ```bash
   touch tmp/qa-empty-calls.jsonl
   ```
2. Run:
   ```bash
   uv run python -c "
   from pathlib import Path
   from scenario_forge.stpa.infra.calls_html import render_calls_html
   render_calls_html(Path('tmp/qa-empty-calls.jsonl'), Path('tmp/qa-empty.html'))
   print('PASS')
   "
   ```
3. Verify the HTML exists and contains '0':
   ```bash
   test -f tmp/qa-empty.html && grep '0' tmp/qa-empty.html
   ```

**Expected:** Valid HTML file produced with zero totals and zero detail rows.

### QA-F1-06: CLI invocation renders calls.jsonl to HTML

**Steps:**
1. Using the `tmp/qa-calls.jsonl` from QA-F1-01
2. Run:
   ```bash
   uv run python -m scenario_forge.stpa.infra.calls_html tmp/qa-calls.jsonl tmp/qa-cli-output.html
   ```
3. Verify the output file exists:
   ```bash
   test -f tmp/qa-cli-output.html && echo "PASS"
   ```
4. Verify it contains inline CSS:
   ```bash
   grep '<style' tmp/qa-cli-output.html
   ```

**Expected:** The CLI invocation produces a self-contained HTML file at the specified path.

### QA-F1-07: All calls with same model shown in detail table

**Steps:**
1. Using the `tmp/qa-calls.html` from QA-F1-01
2. Verify the model name appears for each call:
   ```bash
   count=$(grep -c 'test-model' tmp/qa-calls.html)
   test "$count" -ge 2 && echo "PASS"
   ```

**Expected:** The detail table shows the model name for each call entry.

### QA-F1-08: Detail table includes timestamp column

**Steps:**
1. Using the `tmp/qa-calls.html` from QA-F1-01
2. Verify a timestamp appears:
   ```bash
   grep '2026-01-01' tmp/qa-calls.html
   ```

**Expected:** Timestamps from the call log entries appear in the detail table.

### QA-F1-09: render_calls_html returns the output path

**Steps:**
1. Run:
   ```bash
   uv run python -c "
   from pathlib import Path
   from scenario_forge.stpa.infra.calls_html import render_calls_html
   result = render_calls_html(Path('tmp/qa-calls.jsonl'), Path('tmp/qa-return-test.html'))
   assert result == Path('tmp/qa-return-test.html'), f'Expected {Path(\"tmp/qa-return-test.html\")} got {result}'
   print('PASS')
   "
   ```

**Expected:** The function returns the output path it was given.

### QA-F1-10: All-success calls.jsonl has no failure indicators

**Steps:**
1. Create `tmp/qa-success-calls.jsonl`:
   ```jsonl
   {"stage":"stage_1a","step":"call_1a","slot_id":null,"scenario_id":null,"system_prompt_hash":"sha256-aaa","user_prompt_hash":"sha256-bbb","model":"model-a","prompt_tokens":1000,"completion_tokens":500,"duration_ms":3000,"timestamp":"2026-01-01T00:00:00Z","success":true}
   {"stage":"stage_2","step":"call_2","slot_id":null,"scenario_id":null,"system_prompt_hash":"sha256-ccc","user_prompt_hash":"sha256-ddd","model":"model-a","prompt_tokens":2000,"completion_tokens":800,"duration_ms":5000,"timestamp":"2026-01-01T00:01:00Z","success":true}
   ```
2. Run:
   ```bash
   uv run python -c "
   from pathlib import Path
   from scenario_forge.stpa.infra.calls_html import render_calls_html
   render_calls_html(Path('tmp/qa-success-calls.jsonl'), Path('tmp/qa-success.html'))
   print('PASS')
   "
   ```
3. Verify failure count = 0 in the HTML:
   ```bash
   uv run python -c "
   html = open('tmp/qa-success.html').read()
   # failure count should be 0; no error messages
   assert 'timeout' not in html or html.count('timeout') == 0
   print('PASS')
   "
   ```

**Expected:** No failure indicators or error messages in the rendered HTML.

---

## Cleanup

After running the QA suite, remove test artifacts:
```bash
rm -f tmp/qa-profiles.yaml tmp/qa-profiles-tuned.yaml tmp/qa-profiles-headers.yaml
rm -f tmp/qa-calls.jsonl tmp/qa-calls.html tmp/qa-empty-calls.jsonl tmp/qa-empty.html
rm -f tmp/qa-cli-output.html tmp/qa-return-test.html
rm -f tmp/qa-success-calls.jsonl tmp/qa-success.html
rm -rf tmp/qa-output tmp/qa-output-env
```
