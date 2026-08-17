# End-to-End QA Suite: STPA Run CLI Command

This QA suite verifies the `scenario-forge stpa-run` CLI command through
user-visible workflows: CLI help inspection, command invocation, file
system inspection of output artifacts, console output inspection, and
module import checks. No project-internal APIs are used beyond the
public CLI entry point, file I/O, and module imports that a user or
test harness would perform.

The suite assumes a stub LLM endpoint or mock environment is available
so that the pipeline can complete without real LLM calls. When real LLM
credentials are available, the same steps apply with actual LLM
responses.

---

## QA-STPA-RUN-CLI: CLI interface

### QA-STPA-RUN-CLI-01: stpa-run subcommand is registered

**Preconditions**: The `scenario-forge` CLI is installed and on PATH.

**Steps**:
1. Run `scenario-forge --help`.
2. Check that the help output lists `stpa-run` as a subcommand.

**Expected**: `stpa-run` appears in the subcommand list.

### QA-STPA-RUN-CLI-02: stpa-run --help shows required and optional flags

**Preconditions**: The `scenario-forge` CLI is installed.

**Steps**:
1. Run `scenario-forge stpa-run --help`.
2. Check that the help output mentions `--use-case`, `--risk-extraction`,
   and `--output-dir` as required options.
3. Check that the help output mentions `--profile`, `--sp1-profile`,
   `--sp2-profile`, `--sp3-profile`, `--profiles-file`,
   `--capability-profile`, `--max-workers`, and `--resume` as optional
   options.

**Expected**: All required and optional flags appear in the help text.

### QA-STPA-RUN-CLI-03: --use-case accepts @ prefix

**Preconditions**: A use-case text file exists at `tmp/use-case.txt`
containing at least one line of text. A risk extraction JSON file
exists. A stub LLM endpoint is configured via environment variables.

**Steps**:
1. Run `scenario-forge stpa-run --use-case @tmp/use-case.txt
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-cli03`.
2. Check that the command does not report a use-case file not found
   error.

**Expected**: The use-case text is read from the file; the pipeline
starts (it may fail later if the stub LLM is insufficient, but the
use-case file is resolved).

### QA-STPA-RUN-CLI-04: --use-case accepts bare path without @ prefix

**Preconditions**: Same as QA-STPA-RUN-CLI-03.

**Steps**:
1. Run `scenario-forge stpa-run --use-case tmp/use-case.txt
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-cli04`.
2. Check that the command does not report a use-case file not found
   error.

**Expected**: The use-case text is read from the file.

### QA-STPA-RUN-CLI-05: --max-workers defaults to 1

**Preconditions**: The `scenario-forge` CLI is installed.

**Steps**:
1. Run `scenario-forge stpa-run --help`.
2. Check that the help text for `--max-workers` mentions default value
   of 1.

**Expected**: The default for `--max-workers` is 1.

### QA-STPA-RUN-CLI-06: --profiles-file defaults to ai/model-profiles.yaml

**Preconditions**: The `scenario-forge` CLI is installed.

**Steps**:
1. Run `scenario-forge stpa-run --help`.
2. Check that the help text for `--profiles-file` mentions default
   value of `ai/model-profiles.yaml`.

**Expected**: The default for `--profiles-file` is
`ai/model-profiles.yaml`.

### QA-STPA-RUN-CLI-07: runner module exists at specified path

**Preconditions**: The `scenario_forge` package is installed.

**Steps**:
1. Import `scenario_forge.stpa.pipeline.runner`.
2. Import `scenario_forge.stpa.pipeline.llm_config`.
3. Check that both imports succeed without error.

**Expected**: Both modules are importable.

### QA-STPA-RUN-CLI-08: flat artifact layout in output-dir

**Preconditions**: A full stpa-run has completed successfully in
`tmp/stpa-run-test-full`.

**Steps**:
1. List files in `tmp/stpa-run-test-full`.
2. Check that `loss-analysis.yaml`, `capability-profile.yaml`,
   `control-structure.yaml`, `ica-enumeration.yaml`,
   `enriched-threats.yaml`, `eval-scorecard.yaml`,
   `coverage-gaps.json`, `calls.jsonl`, `run-manifest.yaml`,
   `calls.html`, and `stpa-report.html` exist directly in the output
   directory.
3. Check that a `scenarios/` subdirectory exists containing `.yaml`
   and `.feature` files.

**Expected**: All artifacts use flat layout; scenarios are in a
subdirectory.

---

## QA-STPA-RUN-SP1: SP1 execution

### QA-STPA-RUN-SP1-01: SP1 writes all expected artifacts

**Preconditions**: A stub LLM endpoint returns valid responses for all
SP1 stages. A use-case file and risk extraction JSON are available.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp1`.
2. Wait for the command to complete (or fail at a later stage).
3. Check that `loss-analysis.yaml` exists in the output directory.
4. Check that `capability-profile.yaml` exists in the output directory.
5. Check that `control-structure.yaml` exists in the output directory.
6. Check that `calls.jsonl` exists in the output directory.
7. Check that `run-manifest.yaml` exists in the output directory.

**Expected**: All five SP1 artifact files exist.

### QA-STPA-RUN-SP1-02: calls.html is auto-rendered

**Preconditions**: Same as QA-STPA-RUN-SP1-01.

**Steps**:
1. Follow steps 1-2 from QA-STPA-RUN-SP1-01.
2. Check that `calls.html` exists in the output directory.
3. Read `calls.html` and verify it contains `<html>` and `<table>` tags.

**Expected**: `calls.html` exists and contains HTML markup.

### QA-STPA-RUN-SP1-03: --capability-profile skips Stage 1b

**Preconditions**: A pre-built `capability-profile.yaml` exists at a
known path. A stub LLM endpoint returns valid responses for Stage 1a
and Stage 2 but not Stage 1b.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp1cp
   --capability-profile <capability-profile.yaml>`.
2. Wait for the command to complete.
3. Read `calls.jsonl` from the output directory.
4. Check that no call log entry has `"stage": "stage_1b"`.

**Expected**: No Stage 1b LLM call appears in the call log.

### QA-STPA-RUN-SP1-04: --max-workers forwarded to SP1

**Preconditions**: Same as QA-STPA-RUN-SP1-01, with `--max-workers 4`.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp1mw
   --max-workers 4`.
2. Wait for the command to complete.
3. Read `run-manifest.yaml` from the output directory.
4. Check that the manifest records `max_workers` as 4 for SP1.

**Expected**: The manifest shows max_workers 4 for SP1.

---

## QA-STPA-RUN-SP2: SP2 execution

### QA-STPA-RUN-SP2-01: SP2 writes expected artifacts after SP1

**Preconditions**: A stub LLM endpoint returns valid responses for all
SP1 and SP2 stages.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp2`.
2. Wait for the command to complete (or fail at SP3).
3. Check that `ica-enumeration.yaml` exists in the output directory.
4. Check that `enriched-threats.yaml` exists in the output directory.

**Expected**: Both SP2 artifact files exist.

### QA-STPA-RUN-SP2-02: SP2 calls appended to calls.jsonl

**Preconditions**: Same as QA-STPA-RUN-SP2-01.

**Steps**:
1. Follow steps 1-2 from QA-STPA-RUN-SP2-01.
2. Read `calls.jsonl` from the output directory.
3. Check that some entries have `"stage": "stage_2"` (SP1 calls).
4. Check that some entries have `"stage": "stage_3"` (SP2 calls).

**Expected**: `calls.jsonl` contains entries from both SP1 and SP2.

---

## QA-STPA-RUN-SP3: SP3 execution

### QA-STPA-RUN-SP3-01: SP3 writes expected artifacts after SP2

**Preconditions**: A stub LLM endpoint returns valid responses for all
stages.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp3`.
2. Wait for the command to complete.
3. Check that a `scenarios/` directory exists in the output directory.
4. Check that at least one `.yaml` file exists in `scenarios/`.
5. Check that at least one `.feature` file exists in `scenarios/`.
6. Check that `eval-scorecard.yaml` exists in the output directory.
7. Check that `coverage-gaps.json` exists in the output directory.

**Expected**: All SP3 artifacts exist.

### QA-STPA-RUN-SP3-02: capability_profile passed to SP3 with --capability-profile

**Preconditions**: A pre-built `capability-profile.yaml` exists. A stub
LLM endpoint returns valid responses for all stages.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp3cp
   --capability-profile <capability-profile.yaml>`.
2. Wait for the command to complete.
3. Read a scenario YAML file from `scenarios/` in the output directory.
4. Check that the scenario envelope contains a `system_context` field
   that is not null.

**Expected**: Scenario envelopes include system_context when
--capability-profile is provided.

### QA-STPA-RUN-SP3-03: capability_profile not passed to SP3 without --capability-profile

**Preconditions**: A stub LLM endpoint returns valid responses for all
stages.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sp3nocp`.
2. Wait for the command to complete.
3. Read a scenario YAML file from `scenarios/` in the output directory.
4. Check that the scenario envelope does not contain a `system_context`
   field, or that it is null.

**Expected**: Scenario envelopes do not include system_context when
--capability-profile is not provided.

### QA-STPA-RUN-SP3-04: SP3 calls appended to calls.jsonl

**Preconditions**: Same as QA-STPA-RUN-SP3-01.

**Steps**:
1. Follow steps 1-2 from QA-STPA-RUN-SP3-01.
2. Read `calls.jsonl` from the output directory.
3. Check that some entries have `"stage": "stage_5"` or
   `"stage": "stage_6"` (SP3 calls).

**Expected**: `calls.jsonl` contains entries from SP1, SP2, and SP3.

---

## QA-STPA-RUN-RPT: Report generation

### QA-STPA-RUN-RPT-01: stpa-report.html generated after all stages

**Preconditions**: A full stpa-run has completed successfully in
`tmp/stpa-run-test-full`.

**Steps**:
1. Check that `stpa-report.html` exists in the output directory.
2. Read `stpa-report.html`.
3. Check that the content contains `<html>` and `</html>` tags.

**Expected**: A valid HTML report file exists.

### QA-STPA-RUN-RPT-02: report generated even with degraded SP3

**Preconditions**: A stub LLM endpoint returns valid SP1 and SP2
responses but degraded SP3 results (stage_errors populated, some
artifacts missing).

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-deg-sp3`.
2. Wait for the command to complete.
3. Check that `stpa-report.html` exists in the output directory.

**Expected**: The report is generated despite degraded SP3 results.

### QA-STPA-RUN-RPT-03: report generated even with degraded SP2

**Preconditions**: A stub LLM endpoint returns valid SP1 responses but
degraded SP2 results (stage_errors populated).

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-deg-sp2`.
2. Wait for the command to complete or exit.
3. Check that `stpa-report.html` exists in the output directory.

**Expected**: The report is generated despite degraded SP2 results.

---

## QA-STPA-RUN-SUM: Summary output

### QA-STPA-RUN-SUM-01: summary includes SP1 metrics

**Preconditions**: A full stpa-run has completed successfully.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-sum`.
2. Capture the console output.
3. Check that the output contains a section mentioning "SP1" with
   losses count, hazards count, constraints count, responsibilities
   count, and control actions count.

**Expected**: The console output includes SP1 summary metrics.

### QA-STPA-RUN-SUM-02: summary includes SP2 metrics

**Preconditions**: Same as QA-STPA-RUN-SUM-01.

**Steps**:
1. Capture the console output from the stpa-run command.
2. Check that the output contains a section mentioning "SP2" with
   total slots, N/A slots, fill rate, and structural threats count.

**Expected**: The console output includes SP2 summary metrics.

### QA-STPA-RUN-SUM-03: summary includes SP3 metrics

**Preconditions**: Same as QA-STPA-RUN-SUM-01.

**Steps**:
1. Capture the console output from the stpa-run command.
2. Check that the output contains a section mentioning "SP3" with
   scenario specs count, scenario envelopes count, and validation
   errors count.

**Expected**: The console output includes SP3 summary metrics.

### QA-STPA-RUN-SUM-04: summary includes report path

**Preconditions**: Same as QA-STPA-RUN-SUM-01.

**Steps**:
1. Capture the console output from the stpa-run command.
2. Check that the output mentions the path to `stpa-report.html`.

**Expected**: The console output includes the report file path.

---

## QA-STPA-RUN-ERR: Error handling

### QA-STPA-RUN-ERR-01: hard failure in SP1 exits with code 1

**Preconditions**: A stub LLM endpoint raises an exception when SP1
calls are made. A use-case file and risk extraction JSON are available.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-err-sp1`.
2. Check the exit code.
3. Check that the output directory does not contain
   `ica-enumeration.yaml` (SP2 did not run).
4. Check that the output directory does not contain `stpa-report.html`.

**Expected**: Exit code is 1; SP2, SP3, and report are not produced.

### QA-STPA-RUN-ERR-02: hard failure in SP2 exits with code 1

**Preconditions**: A stub LLM endpoint returns valid SP1 responses but
raises an exception during SP2.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-err-sp2`.
2. Check the exit code.
3. Check that the output directory contains `control-structure.yaml`
   (SP1 completed).
4. Check that the output directory does not contain
   `enriched-threats.yaml` (SP2 failed).
5. Check that the output directory does not contain `stpa-report.html`.

**Expected**: Exit code is 1; SP3 and report are not produced.

### QA-STPA-RUN-ERR-03: hard failure in SP3 exits with code 1

**Preconditions**: A stub LLM endpoint returns valid SP1 and SP2
responses but raises an exception during SP3.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-err-sp3`.
2. Check the exit code.
3. Check that `stpa-report.html` does not exist in the output
   directory.

**Expected**: Exit code is 1; report is not produced.

### QA-STPA-RUN-ERR-04: degraded results continue pipeline

**Preconditions**: A stub LLM endpoint returns valid responses with
`stage_errors` populated for SP1 but artifacts are produced.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-deg`.
2. Check that the exit code is 0.
3. Check that `ica-enumeration.yaml` exists (SP2 ran despite SP1
   stage_errors).
4. Check that the console output contains a warning about SP1 stage
   errors.

**Expected**: Exit code is 0; pipeline continues past degraded stage.

### QA-STPA-RUN-ERR-05: missing control_structure stops SP2

**Preconditions**: A stub LLM endpoint returns valid SP1 responses but
`control_structure` is not produced (degraded to None).

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-no-cs`.
2. Check the exit code.
3. Check that `ica-enumeration.yaml` does not exist (SP2 did not run).

**Expected**: Exit code is 1; SP2 is not executed.

### QA-STPA-RUN-ERR-06: error message printed to stderr

**Preconditions**: Same as QA-STPA-RUN-ERR-01.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-stderr`
   and capture stderr separately.
2. Check that stderr contains an error message.

**Expected**: An error message is printed to stderr.

---

## QA-STPA-RUN-RES: Resume behavior

### QA-STPA-RUN-RES-01: --resume skips SP1 when artifacts exist

**Preconditions**: An output directory contains completed SP1
artifacts (`loss-analysis.yaml`, `capability-profile.yaml`,
`control-structure.yaml`). A stub LLM endpoint is available.

**Steps**:
1. Record the modification time of `loss-analysis.yaml` in the output
   directory.
2. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir <existing-dir> --resume`.
3. Wait for the command to complete.
4. Check that `loss-analysis.yaml` was not modified (same mtime).

**Expected**: SP1 is skipped; existing artifacts are preserved.

### QA-STPA-RUN-RES-02: --resume skips SP2 when artifacts exist

**Preconditions**: An output directory contains completed SP1 and SP2
artifacts.

**Steps**:
1. Record the modification time of `ica-enumeration.yaml`.
2. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir <existing-dir> --resume`.
3. Wait for the command to complete.
4. Check that `ica-enumeration.yaml` was not modified.

**Expected**: SP2 is skipped; existing artifacts are preserved.

### QA-STPA-RUN-RES-03: --resume skips SP3 when scenarios exist

**Preconditions**: An output directory contains completed SP1, SP2,
and SP3 artifacts including `scenarios/` with `.yaml` files.

**Steps**:
1. Record the modification time of a scenario YAML file in
   `scenarios/`.
2. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir <existing-dir> --resume`.
3. Wait for the command to complete.
4. Check that the scenario YAML file was not modified.

**Expected**: SP3 is skipped; existing scenarios are preserved.

### QA-STPA-RUN-RES-04: report always generated with --resume

**Preconditions**: An output directory contains completed SP1, SP2,
and SP3 artifacts.

**Steps**:
1. Delete `stpa-report.html` from the output directory if it exists.
2. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir <existing-dir> --resume`.
3. Check that `stpa-report.html` exists in the output directory.

**Expected**: The report is generated even when all stages are skipped.

### QA-STPA-RUN-RES-05: without --resume all stages run from scratch

**Preconditions**: An output directory contains completed SP1, SP2,
and SP3 artifacts. A stub LLM endpoint is available.

**Steps**:
1. Record the modification time of `loss-analysis.yaml`.
2. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir <existing-dir>` (no
   --resume).
3. Wait for the command to complete.
4. Check that `loss-analysis.yaml` was modified (newer mtime).

**Expected**: SP1 runs from scratch; artifacts are overwritten.

### QA-STPA-RUN-RES-06: --resume runs SP1 when artifacts incomplete

**Preconditions**: An output directory contains only
`loss-analysis.yaml` but not `capability-profile.yaml` or
`control-structure.yaml`.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir <existing-dir> --resume`.
2. Wait for the command to complete.
3. Check that `capability-profile.yaml` now exists in the output
   directory.
4. Check that `control-structure.yaml` now exists in the output
   directory.

**Expected**: SP1 runs because artifacts are incomplete.

---

## QA-STPA-RUN-MP: Model profiles resolution

### QA-STPA-RUN-MP-01: --profile sets default model for all stages

**Preconditions**: A profiles YAML file exists with a profile named
`default-pro` containing model `default-model`. A stub LLM endpoint
accepts any model name.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-mp01
   --profile default-pro --profiles-file <profiles.yaml>`.
2. Wait for the command to complete.
3. Read `run-manifest.yaml` from the output directory.
4. Check that the manifest records the model as `default-model` for
   SP1, SP2, and SP3.

**Expected**: All three stages use the model from the default profile.

### QA-STPA-RUN-MP-02: --sp1-profile overrides --profile for SP1

**Preconditions**: A profiles YAML file exists with profiles
`default-pro` (model `default-model`) and `sp1-pro` (model
`sp1-model`).

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-mp02
   --profile default-pro --sp1-profile sp1-pro
   --profiles-file <profiles.yaml>`.
2. Wait for the command to complete.
3. Read `calls.jsonl` from the output directory.
4. Check that SP1 LLM calls used model `sp1-model`.
5. Check that SP2 LLM calls used model `default-model`.

**Expected**: SP1 uses the per-stage profile; SP2 uses the default
profile.

### QA-STPA-RUN-MP-03: per-stage profiles without --profile

**Preconditions**: A profiles YAML file exists with profiles
`sp1-pro`, `sp2-pro`, and `sp3-pro` with distinct model names.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-mp03
   --sp1-profile sp1-pro --sp2-profile sp2-pro --sp3-profile sp3-pro
   --profiles-file <profiles.yaml>`.
2. Wait for the command to complete.
3. Read `calls.jsonl` from the output directory.
4. Check that SP1 calls used `sp1-model`, SP2 calls used `sp2-model`,
   and SP3 calls used `sp3-model`.

**Expected**: Each stage uses its own per-stage profile.

### QA-STPA-RUN-MP-04: no profile flags fall back to environment variables

**Preconditions**: Environment variables
`SCENARIO_FORGE_MODEL_BASE_URL`, `SCENARIO_FORGE_API_KEY`, and
`SCENARIO_FORGE_MODEL_NAME` are set. No `--profile` or `--spN-profile`
flags are used.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-mp04`.
2. Wait for the command to complete.
3. Read `run-manifest.yaml`.
4. Check that the model recorded matches the value of
   `SCENARIO_FORGE_MODEL_NAME`.

**Expected**: LLM clients are created from environment variables for
all stages.

### QA-STPA-RUN-MP-05: --profiles-file uses custom path

**Preconditions**: A profiles YAML file exists at a custom path with
a profile named `custom-model`.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-mp05
   --profiles-file <custom-path> --profile custom-model`.
2. Wait for the command to complete.
3. Read `run-manifest.yaml`.
4. Check that the model matches the one defined in the custom profiles
   file.

**Expected**: The custom profiles file is used.

### QA-STPA-RUN-MP-06: llm_config module has shared resolution functions

**Preconditions**: The `scenario_forge` package is installed.

**Steps**:
1. Import `scenario_forge.stpa.pipeline.llm_config`.
2. Check that `resolve_llm_client_from_profile` is a callable function.
3. Check that `resolve_llm_client_from_env` is a callable function.

**Expected**: Both functions are defined and callable.

---

## QA-STPA-RUN-VAL: Input validation

### QA-STPA-RUN-VAL-01: missing use-case file exits with error

**Preconditions**: The path `tmp/nonexistent-use-case.txt` does not
exist. A valid risk extraction JSON exists.

**Steps**:
1. Run `scenario-forge stpa-run --use-case tmp/nonexistent-use-case.txt
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-val01`.
2. Check the exit code.
3. Check that the error output mentions the use-case file.

**Expected**: Exit code is 1; error message mentions the missing file.

### QA-STPA-RUN-VAL-02: missing risk-extraction file exits with error

**Preconditions**: A valid use-case file exists. The path
`tmp/nonexistent-risk.json` does not exist.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction tmp/nonexistent-risk.json
   --output-dir tmp/stpa-run-test-val02`.
2. Check the exit code.
3. Check that the error output mentions the risk-extraction file.

**Expected**: Exit code is 1; error message mentions the missing file.

### QA-STPA-RUN-VAL-03: missing --capability-profile file exits with error

**Preconditions**: A valid use-case file and risk extraction JSON
exist. The path `tmp/nonexistent-cap.yaml` does not exist.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-val03
   --capability-profile tmp/nonexistent-cap.yaml`.
2. Check the exit code.
3. Check that the error output mentions the capability-profile file.

**Expected**: Exit code is 1; error message mentions the missing file.

### QA-STPA-RUN-VAL-04: missing required --use-case flag

**Preconditions**: A valid risk extraction JSON and output directory
path exist.

**Steps**:
1. Run `scenario-forge stpa-run --risk-extraction <risk.json>
   --output-dir tmp/stpa-run-test-val04` (no --use-case).
2. Check the exit code.

**Expected**: Exit code is nonzero; Typer reports the missing required
option.

### QA-STPA-RUN-VAL-05: missing required --risk-extraction flag

**Preconditions**: A valid use-case file and output directory path
exist.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --output-dir tmp/stpa-run-test-val05` (no --risk-extraction).
2. Check the exit code.

**Expected**: Exit code is nonzero; Typer reports the missing required
option.

### QA-STPA-RUN-VAL-06: missing required --output-dir flag

**Preconditions**: A valid use-case file and risk extraction JSON
exist.

**Steps**:
1. Run `scenario-forge stpa-run --use-case <use-case.txt>
   --risk-extraction <risk.json>` (no --output-dir).
2. Check the exit code.

**Expected**: Exit code is nonzero; Typer reports the missing required
option.

### QA-STPA-RUN-VAL-07: input validation runs before any pipeline stage

**Preconditions**: The path `tmp/nonexistent-use-case.txt` does not
exist.

**Steps**:
1. Run `scenario-forge stpa-run --use-case tmp/nonexistent-use-case.txt
   --risk-extraction <risk.json> --output-dir tmp/stpa-run-test-val07`.
2. Check the exit code.
3. Check that the output directory does not exist or is empty.

**Expected**: Exit code is 1; no pipeline artifacts are written.
