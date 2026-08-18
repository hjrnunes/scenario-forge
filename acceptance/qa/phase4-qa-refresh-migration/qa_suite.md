# End-to-end QA: Phase 4 acceptance-refresh QA migration

Run from the repository root. Exercise only command-line entrypoints, process
output, filesystem artifacts, and Git observations; do not import project
modules. Set `BASE_COMMIT=9e112ea23a`, keep `SCENARIO_FORGE_QA_PIPELINE`
unset, and store captures only below
`tmp/qa-phase4-qa-refresh-migration/captures/`. Before every procedure, record
stdout, stderr, exit status, working directory, environment, and
`git status --porcelain=v1 -z --untracked-files=all`.

The characterized pre-migration static baseline is 515 ordered PASS checks,
`QA SUMMARY: 515/515 passed, 0 failed`, and exit `0`. The Phase 4 feature adds
four deterministic corpus checks. After migration the shared report baseline
is therefore `QA suite: 519 passed, 0 failed`.

## QA-P4QRM-01: CLI and deterministic reporting

1. Run
   `env -u SCENARIO_FORGE_QA_PIPELINE uv run python acceptance/qa/acceptance-refresh/qa_suite.py --help`.
2. Verify exit `0`; the required mutually exclusive modes are `--static`,
   `--pipeline`, and `--all`; and help also lists `--use-case`,
   `--risk-extraction`, and optional `--capability-profile`.
3. Invoke the command with no mode. Verify argparse exits `2` and reports that
   one mode is required.
4. Invoke `--pipeline` and `--all` without either required input. Verify each
   exits `1`, starts no child, and prints exactly
   `ERROR: --use-case and --risk-extraction required for pipeline checks`.
5. Run `--static` twice. Verify each exits `0`, emits the static heading once,
   emits every check once in the same recording order, and ends with
   `QA suite: 519 passed, 0 failed`.
6. Verify the 515 pre-migration check names retain their relative order and
   result text. The only added static checks are the IR presence, entry-point
   resolution, IR coverage, and canonical-IR-location checks for
   `phase4_qa_refresh_migration`.

## QA-P4QRM-02: subprocess, stream, and temporary-output isolation

1. Below `tmp/qa-phase4-qa-refresh-migration/`, create input fixtures and a
   PATH-preferred executable named `uv`. The stand-in must record argv, cwd,
   and relevant environment, then either:
   - create `calls.jsonl`, `run-manifest.yaml`, and
     `control-structure.yaml` with the characterized replacement steps,
     Stage 2 order, call counts, and coordination fields; or
   - emit distinct stdout/stderr sentinels and exit `7`.
   It must never open a network connection.
2. Invoke the suite directly with the repository virtual-environment Python so
   only the child `uv` is replaced:

   ```bash
   env -u SCENARIO_FORGE_QA_PIPELINE \
     PATH="$PWD/tmp/qa-phase4-qa-refresh-migration/bin:$PATH" \
     "$PWD/.venv/bin/python" \
     "$PWD/acceptance/qa/acceptance-refresh/qa_suite.py" \
     --pipeline \
     --use-case "$PWD/tmp/qa-phase4-qa-refresh-migration/use-case.txt" \
     --risk-extraction "$PWD/tmp/qa-phase4-qa-refresh-migration/risks.json" \
     --capability-profile "$PWD/tmp/qa-phase4-qa-refresh-migration/profile.yaml"
   ```

3. With the successful stand-in, verify the child receives
   `uv run scenario-forge stpa-run`, all documented input options, and a
   temporary `--output-dir`; runs from the repository root; and the suite
   emits 18 ordered PASS checks, `QA suite: 18 passed, 0 failed`, and exit `0`.
4. Run the successful command twice. Verify identical ordered check output and
   that no first-run artifact affects the second run.
5. With the exit-7 stand-in, verify the suite does not raise for the child
   status, stdout and stderr remain distinct, it emits the two expected FAIL
   checks, reports `QA suite: 0 passed, 2 failed`, and exits `1`.
6. Verify each temporary pipeline output directory is removed, the parent
   environment/cwd are unchanged, and outer captures contain separate
   `stdout.txt`, `stderr.txt`, and `exit.txt`.

## QA-P4QRM-03: nested working-directory invocation

1. Create `tmp/qa-phase4-qa-refresh-migration/nested/a/b/`.
2. From that directory, invoke the absolute `.venv/bin/python` and absolute
   suite path with `--static`.
3. Verify repository discovery succeeds, exit/status/check ordering matches
   the root invocation, and the summary is
   `QA suite: 519 passed, 0 failed`.
4. Repeat and verify identical ordered results, unchanged caller cwd and
   environment, and isolated captures.

## QA-P4QRM-04: acceptance-refresh generated scenario parity

1. Start a local TCP contact sentinel and point
   `SCENARIO_FORGE_MODEL_BASE_URL` and `OPENAI_BASE_URL` at it with inert API
   keys. Keep `SCENARIO_FORGE_QA_PIPELINE` unset.
2. Run twice:

   ```bash
   env -u SCENARIO_FORGE_QA_PIPELINE uv run pytest \
     build/acceptance/generated/stage1b-entry-point-guidance_acceptance_test.py \
     build/acceptance/generated/stage1b-grounding_acceptance_test.py \
     build/acceptance/generated/stage2-coordination-analysis_acceptance_test.py \
     build/acceptance/generated/stage2-assembly-fallback_acceptance_test.py \
     -q -s
   ```

3. For each run, deduplicate example output at `/example_` and verify the four
   source features report respectively 8, 7, 12, and 8 distinct PASS
   scenarios, with no FAIL or SKIP.
4. Verify both runs have identical ordered scenario outcomes, exit `0`, and
   the sentinel observed zero contacts.

## QA-P4QRM-05: exactly-one-suite and registration scope

1. Run:

   ```bash
   git diff --name-status "$BASE_COMMIT"..HEAD -- acceptance/qa
   git diff --name-only "$BASE_COMMIT"..HEAD -- acceptance/runtime_manifest.py acceptance/runtime_features
   git diff --name-only "$BASE_COMMIT"..HEAD -- src
   ```

2. Verify `acceptance/qa/acceptance-refresh/qa_suite.py` is the only existing
   `qa_suite.py` changed. The new Phase 4 QA plan is allowed; no other existing
   suite is changed or migrated.
3. Verify `acceptance/qa/qa_harness.py` is byte-for-byte unchanged.
4. Verify the runtime manifest and all pre-existing runtime-feature files are
   byte-for-byte unchanged, including acceptance-refresh feature identity,
   handler patterns, priorities, and scopes.
5. Verify no path below `src/` is added, modified, or deleted.

## QA-P4QRM-06: configuration, generated output, and worktree preservation

1. Compare `.factory/swarmforge/config.sh`, `scripts/acceptance.sh`,
   `scripts/quality.sh`, and ignore rules to `$BASE_COMMIT`. Verify no diff.
2. Verify generated-output policy remains configured; CRAP, DRY, coverage, and
   language mutation remain scoped to `src/`; and quality remains scoped to
   `src` and `acceptance`.
3. Run the migrated suite and generated Phase 4 acceptance test with all
   captures under the QA temporary root.
4. Verify `git ls-files` reports nothing beneath `build/acceptance/`,
   `build/acceptance-mutation/`, the QA temporary root, coverage outputs, or
   other configured generated-output paths.
5. Verify generated artifacts remain in configured directories and generated
   metadata contains no absolute checkout path.
6. Compare the final NUL-delimited status and SHA-256 digest of every
   pre-existing modified, deleted, and untracked path with the initial
   snapshot. Verify every unrelated path retains the same status and content.
