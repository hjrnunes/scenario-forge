# End-to-end QA: acceptance QA runtime cleanup

Run from the repository root. Use only checked-in command-line entrypoints,
generated acceptance tests, process output, and filesystem or Git status
observations. Do not import project Python modules. Keep
`SCENARIO_FORGE_QA_PIPELINE` unset and put all new captures beneath
`tmp/qa-acceptance-qa-runtime-cleanup/`.

Record the cleanup's first commit as `BASE_COMMIT`. Before each procedure,
capture the command, child environment, stdout, stderr, and exit status.

## QA-AQRC-01: shared harness and migrated-suite compatibility

1. Run:
   `env -u SCENARIO_FORGE_QA_PIPELINE uv run python acceptance/qa/acceptance-framework-refactor/qa_suite.py --skip-generate`.
2. Verify the documented `--skip-generate` option is accepted.
3. Verify QA-AFR-01 is emitted once as a successful explicit skip, QA-AFR-02
   through QA-AFR-06 execute once in order, and the final summary uses
   `QA suite: <passed> passed, <failed> failed`.
4. Verify each check is emitted once in recording order, details remain
   attached to their check, and exit status is `0` exactly when the summary
   reports zero failures.
5. Verify captures are still written under
   `tmp/qa-acceptance-framework/captures/` with separate `stdout.txt`,
   `stderr.txt`, and `exit.txt` files.
6. Invoke the same command from a nested working directory by using absolute
   paths. Verify it still discovers the repository root and produces the same
   ordered check names, summary, and exit status.
7. Verify no other existing `acceptance/qa/**/qa_suite.py` or
   `tests/stpa/*qa_suite*.py` command was migrated or had its CLI behavior
   changed in this bounded pass.

## QA-AQRC-02: reporting and process isolation

1. Run the new generated AQRC test twice by node ID:
   `env -u SCENARIO_FORGE_QA_PIPELINE uv run pytest build/acceptance/generated/acceptance_qa_runtime_cleanup_acceptance_test.py::test_acceptance -q -s`.
2. Verify AQRC-01's passing case emits two PASS results and exits `0`; its
   failing case emits one PASS and one FAIL result and exits `1`.
3. Verify result lines are emitted once in recording order and the summaries
   are exactly `QA suite: 2 passed, 0 failed` and
   `QA suite: 1 passed, 1 failed`.
4. Verify AQRC-02 observes child exit status `7` without an exception, keeps
   stdout and stderr separate, removes the requested variable only from the
   child, and defaults child execution to the repository root.
5. Compare both AQRC invocations. Verify their PASS/FAIL/SKIP lines and exit
   status are identical and neither invocation changes the parent environment
   or working directory.
6. Verify independent runs write only to distinct fresh subdirectories beneath
   `tmp/qa-acceptance-qa-runtime-cleanup/`.

## QA-AQRC-03: acceptance-refresh registration stability

1. Run the generated AQRC test from QA-AQRC-02 and retain the AQRC-04 output.
2. Verify the runtime manifest exposes exactly one `acceptance_refresh`
   identity and registers it once.
3. Verify it registers exactly 38 handlers: 13 feature-scoped registrations
   with source priorities 21826 through 21838 and 25 global registrations with
   source priorities 21916 through 21940.
4. Verify the characterized pattern text, relative priority, feature scope,
   and selected handler outcome are unchanged, and the active registration
   scope is empty after registration.
5. Verify no second manifest identity was introduced solely to hold extracted
   acceptance-refresh code.

## QA-AQRC-04: acceptance-refresh behavior parity

Run these generated tests separately with live opt-in unset:

```bash
env -u SCENARIO_FORGE_QA_PIPELINE uv run pytest \
  build/acceptance/generated/stage1b-entry-point-guidance_acceptance_test.py \
  build/acceptance/generated/stage1b-grounding_acceptance_test.py \
  build/acceptance/generated/stage2-coordination-analysis_acceptance_test.py \
  build/acceptance/generated/stage2-assembly-fallback_acceptance_test.py \
  -q -s
```

Verify:

1. The command exits `0`.
2. The four source features report respectively 8, 7, 12, and 8 PASS scenario
   results, with no FAIL or SKIP result.
3. Existing Stage 1b prompt loading and rendering, Stage 2 coordination,
   fallback warnings and logging, control-structure production, and retired
   symbol assertions retain their prior visible results.
4. Running the same command a second time yields the same ordered scenario
   outcomes.

## QA-AQRC-05: default acceptance without live opt-in

1. Run
   `env -u SCENARIO_FORGE_QA_PIPELINE ./scripts/acceptance.sh --test`.
2. Verify the quality gate runs before generated tests.
3. Verify AQRC-01 through AQRC-07 and all 35 acceptance-refresh scenarios
   report PASS.
4. Verify exact live-LLM-marked scenarios report SKIP, never PASS or FAIL, and
   no live endpoint is contacted solely for those skipped scenarios.
5. Compare failures with the recorded pre-cleanup acceptance baseline. Verify
   the failure set is unchanged and contains no QA-harness,
   acceptance-refresh, registration, or isolation regression.

## QA-AQRC-06: generated-output hygiene

1. Record `git status --short --untracked-files=all`.
2. Run `./scripts/acceptance.sh` with IR, DRY, generated, and mutation
   directories redirected to fresh paths below
   `tmp/qa-acceptance-qa-runtime-cleanup/generated/`.
3. Verify the command creates all configured artifacts only in those generated
   paths and that a repeated run produces the same file set and contents.
4. Verify no IR, DRY report, generated test, metadata file, mutation workspace,
   coverage file, or QA capture becomes staged or newly tracked.
5. Verify no generated metadata contains an absolute checkout path.

## QA-AQRC-07: repository scope and unrelated-work preservation

1. Run
   `git diff --name-status "$BASE_COMMIT"..HEAD` and
   `git status --short --untracked-files=all`.
2. Verify the cleanup adds or changes no path beneath `src/`.
3. Verify `.factory/swarmforge/config.sh` still scopes CRAP and language
   mutation to `src/`, DRY to `./src`, and keeps generated-output policy.
4. Verify `scripts/quality.sh` still checks and format-checks both `src` and
   `acceptance`.
5. Verify only the intended QA harness, the single migrated suite, the
   acceptance-refresh runtime decomposition, this feature, its acceptance
   handlers, and this QA plan differ from `BASE_COMMIT`.
6. Compare the final worktree status with the pre-cleanup status. Verify every
   unrelated modified, deleted, or untracked path remains present with the same
   content and status.
