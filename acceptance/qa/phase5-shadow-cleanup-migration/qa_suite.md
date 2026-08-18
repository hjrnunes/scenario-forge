# End-to-end QA: Phase 5 shadow-cleanup QA migration

Run from the repository root. Exercise only command-line entrypoints, process
output, filesystem artifacts, and Git observations; do not import project
modules. Set `BASE_COMMIT=5a79d55b35`, keep
`SCENARIO_FORGE_QA_PIPELINE` unset, and store new fixtures and captures only
below `tmp/qa-phase5-shadow-cleanup-migration/`. Use a local TCP contact
sentinel for endpoint assertions; no procedure may contact an LLM endpoint.

Before every procedure, record the command, stdout, stderr, exit status,
working directory, environment, and
`git status --porcelain=v1 -z --untracked-files=all`. Preserve the status and
content digest of every pre-existing modified, deleted, and untracked path.

The characterized baseline has 51 static checks (50 PASS and the existing
`sc-static-02` FAIL), 58 dynamic PASS checks, and two pipeline SKIP checks.
No arguments behave as `--all`. The generated
`shadow-cleanup/no-shadowing-invariant.feature` baseline is five PASS
scenarios.

## QA-P5QSCM-01: CLI, invalid invocations, and deterministic reporting

1. Run:

   ```bash
   env -u SCENARIO_FORGE_QA_PIPELINE \
     uv run python acceptance/qa/shadow-cleanup/qa_suite.py --help
   ```

2. Verify exit `0`; help lists `--help`, `--static`, `--dynamic`,
   `--pipeline`, `--all`, and `--run-dir RUN_DIR`. Verify the four mode flags
   are independently selectable rather than mutually exclusive.
3. Run `--not-an-option` and `--run-dir` without a value. Verify argparse
   exits `2`, respectively reports
   `unrecognized arguments: --not-an-option` and
   `argument --run-dir: expected one argument`, and starts no check or child.
4. Run each invocation below twice with live opt-in unset:

   | Arguments | PASS | FAIL | SKIP | Summary | Exit |
   |---|---:|---:|---:|---|---:|
   | `--static` | 50 | 1 | 0 | `QA suite: 50 passed, 1 failed` | 1 |
   | `--dynamic` | 58 | 0 | 0 | `QA suite: 58 passed, 0 failed` | 0 |
   | `--pipeline` | 0 | 0 | 2 | `QA suite: 0 passed, 0 failed` | 0 |
   | `--static --dynamic` | 108 | 1 | 0 | `QA suite: 108 passed, 1 failed` | 1 |
   | `--all` | 108 | 1 | 2 | `QA suite: 108 passed, 1 failed` | 1 |
   | no arguments | 108 | 1 | 2 | `QA suite: 108 passed, 1 failed` | 1 |

5. Verify each result is emitted once when recorded, in the same order on
   both runs, and the summary is terminal. Verify multiple selected modes run
   each selected section once.
6. Verify the two pipeline results remain explicit SKIP results named
   `sc-pipeline-01` and `sc-pipeline-02`; both retain the reason
   `requires SCENARIO_FORGE_QA_PIPELINE=1 and --run-dir <completed run>; no live LLM endpoint in this environment`.
7. Verify the contact sentinel records zero connections for every invocation.

## QA-P5QSCM-02: property-test subprocess and stream isolation

1. Under the QA temporary root, create a `pytest.py` stand-in and prepend its
   directory to `PYTHONPATH`. It must record argv, cwd, and selected
   environment values, print `P5-CHILD-STDOUT` to stdout,
   `P5-CHILD-STDERR` to stderr, and exit `7`. It must not open a network
   connection.
2. Invoke the suite by absolute path with the repository virtual-environment
   Python:

   ```bash
   env -u SCENARIO_FORGE_QA_PIPELINE \
     PYTHONPATH="$PWD/tmp/qa-phase5-shadow-cleanup-migration/standin" \
     "$PWD/.venv/bin/python" \
     "$PWD/acceptance/qa/shadow-cleanup/qa_suite.py" --dynamic
   ```

3. Verify exactly one child is started from the repository root with
   `-m pytest`, these two complete node identifiers, `-v`, `--tb=short`,
   `--no-header`, and `-p no:cacheprovider`:
   - `tests/stpa/test_acceptance_harness_property.py::TestNoPatternShadowing::test_no_global_pattern_conflicts_on_ir_steps`
   - `tests/stpa/test_acceptance_harness_property.py::TestNoPatternShadowing::test_no_global_pattern_conflicts_on_synthetic_steps`
4. Verify child exit `7`, stdout, and stderr are separately labeled and
   observable; the suite emits 57 PASS and one FAIL result, reports
   `QA suite: 57 passed, 1 failed`, and exits `1`.
5. Verify the parent environment and cwd are unchanged, no child artifact
   leaks into a later real `--dynamic` run, and outer captures retain separate
   `stdout.txt`, `stderr.txt`, and `exit.txt`.
6. Run real `--dynamic` twice. Verify 58 ordered PASS results,
   `QA suite: 58 passed, 0 failed`, exit `0`, identical outcomes, and zero
   endpoint contacts.

## QA-P5QSCM-03: nested working-directory invocation

1. Create `tmp/qa-phase5-shadow-cleanup-migration/nested/a/b/`.
2. From that directory, invoke absolute `.venv/bin/python`, the absolute suite
   path, and `--static` twice.
3. Verify both runs discover repository files, emit the same 50 PASS and one
   `sc-static-02` FAIL result in the same order, report
   `QA suite: 50 passed, 1 failed`, and exit `1`.
4. Verify neither run changes the caller cwd or environment and all captures
   remain beneath the QA temporary root.

## QA-P5QSCM-04: generated shadow-cleanup acceptance parity

1. Start the local contact sentinel. Point
   `SCENARIO_FORGE_MODEL_BASE_URL` and `OPENAI_BASE_URL` at it with inert API
   keys, and keep `SCENARIO_FORGE_QA_PIPELINE` unset.
2. Run twice:

   ```bash
   env -u SCENARIO_FORGE_QA_PIPELINE uv run pytest \
     build/acceptance/generated/no-shadowing-invariant_acceptance_test.py \
     -q -s
   ```

3. Deduplicate example output at `/example_`. Verify each run reports exactly
   `ShadowCleanup-01` through `ShadowCleanup-05` as PASS, with no
   shadow-cleanup FAIL or SKIP, identical ordering, and exit `0`.
4. Verify the contact sentinel records zero connections.

## QA-P5QSCM-05: exactly-one-suite and registration scope

1. Run:

   ```bash
   git diff --name-status "$BASE_COMMIT"..HEAD -- acceptance/qa
   git diff --name-status "$BASE_COMMIT"..HEAD -- \
     acceptance/runtime_features acceptance/runtime_manifest.py
   git diff --name-status "$BASE_COMMIT"..HEAD -- src
   ```

2. Verify `acceptance/qa/shadow-cleanup/qa_suite.py` is the only pre-existing
   `qa_suite.py` changed. New Phase 5 specification, QA plan, and dedicated
   acceptance test-glue modules are allowed; no other suite is migrated.
3. Compare `acceptance/runtime_features/shadow_cleanup.py` with
   `$BASE_COMMIT`. Verify it is byte-for-byte unchanged; its baseline SHA-256
   is `bdcd184067c345559ac7646d9b24723c4a85eccc1e1ac3a8d0a7bd69e50adc45`.
4. Through generated acceptance output, verify the pre-existing
   `shadow_cleanup` identity is declared and registered once and its handler
   pattern text, source priorities, global or feature scope, and selected
   outcomes are unchanged. A separate Phase 5 test-glue identity must not
   replace or alter it.
5. Verify no path beneath `src/` is added, modified, or deleted.

## QA-P5QSCM-06: configuration, generated output, and worktree preservation

1. Compare `.factory/swarmforge/config.sh`, `scripts/acceptance.sh`,
   `scripts/quality.sh`, and ignore rules with `$BASE_COMMIT`. Verify no diff.
2. Verify generated-output policy remains configured; CRAP, DRY, coverage, and
   language mutation remain scoped to `src/`; quality remains scoped to
   `src` and `acceptance`; and no generated-output scope is added or moved.
3. Run the migrated suite and generated Phase 5 acceptance test with fixtures
   and captures beneath the QA temporary root.
4. Verify `git ls-files` reports nothing beneath `build/acceptance/`,
   `build/acceptance-mutation/`, the QA temporary root, coverage outputs, or
   any other configured generated-output path.
5. Verify IR, dry reports, generated tests, and metadata stay in their
   configured directories, and generated metadata contains no absolute
   checkout path.
6. Compare final NUL-delimited Git status and content digests with the initial
   snapshot. Verify every unrelated modified, deleted, and untracked path
   retains exactly its original status and content.
