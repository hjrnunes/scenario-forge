# End-to-end QA: acceptance live LLM opt-in

Run from the repository root. Use a clean child-process environment for every
workflow; do not alter the parent shell. Capture stdout, stderr, exit status,
and any temporary output path separately for each run.

## QA-ALO-01: default execution

1. In a child process, unset `SCENARIO_FORGE_QA_PIPELINE`.
2. Set `SCENARIO_FORGE_MODEL_BASE_URL` to an unreachable loopback URL so
   endpoint discovery succeeds but any unauthorized model call fails quickly.
3. Run `./scripts/acceptance.sh`.
4. Verify exit status `0`.
5. Verify deterministic scenarios are reported as passed.
6. Verify every scenario marked by
   `live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"` is
   reported as skipped, with a reason naming the required opt-in.
7. Verify no marked scenario is also reported as passed or failed.

## QA-ALO-02: non-authorizing values

Repeat QA-ALO-01 with `SCENARIO_FORGE_QA_PIPELINE` set separately to `0`,
`true`, and `yes`. Each run must have the same pass/skip behavior and exit
status as default execution.

## QA-ALO-03: explicit opt-in

1. In a child process with a working configured LLM endpoint, set
   `SCENARIO_FORGE_QA_PIPELINE=1`.
2. Run `./scripts/acceptance.sh`.
3. Verify marked live-LLM scenarios are executed rather than skipped.
4. Verify successful marked scenarios are reported as passed.
5. If a marked scenario fails, verify the command exits nonzero and reports
   that failure; opt-in must not convert a failure into a skip.

## QA-ALO-04: opted in without an endpoint

1. In a child process, set `SCENARIO_FORGE_QA_PIPELINE=1`.
2. Unset `SCENARIO_FORGE_MODEL_BASE_URL`, `OPENAI_BASE_URL`,
   `OPENAI_API_KEY`, and `SCENARIO_FORGE_API_KEY`.
3. Run `./scripts/acceptance.sh`.
4. Verify at least one marked scenario is attempted and fails with an
   endpoint-not-configured message.
5. Verify the command exits nonzero and does not report that scenario as
   skipped.

## QA-ALO-05: isolation and generated-output policy

1. Before QA-ALO-01 through QA-ALO-04, record the parent process values of all
   environment variables above.
2. After each workflow, verify those parent values are unchanged.
3. Verify each live execution reports a fresh temporary fixture/output path
   and no later scenario reuses or observes an earlier scenario's files.
4. Run `git status --short` and verify no IR, DRY report, generated test, or
   temporary fixture is staged or appears as a new tracked artifact.
5. Verify `.factory/swarmforge/config.sh` still maps `features` to
   `build/acceptance/ir` and `build/acceptance/generated`, and that CRAP, DRY,
   and mutation commands still target only `src/`.
