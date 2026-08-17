# End-to-end QA: Stage 6 canonical Gherkin artifacts

Run from the repository root. Inspect only command output and published files;
do not import project modules.

## QA-JPKW-07: canonical structured text wins

1. Start `tests/stpa/sp3_qa_stub_llm.py` on a loopback port and point
   `SCENARIO_FORGE_MODEL_BASE_URL` and `SCENARIO_FORGE_API_KEY` at it.
2. Run `scripts/run_sp3.py` with the Klarna `enriched_threats`,
   `control_structure`, `loss_analysis`, and `capability_profile` fixtures
   from `src/scenario_forge/stpa/fixtures/`, writing to a new temporary output
   directory.
3. Select one generated `scenarios/<scenario-id>.yaml` whose `gherkin_spec`
   has a non-empty `feature`.
4. Independently render the expected feature text from the published
   `gherkin_spec` fields in this exact order:
   `Feature`, `Scenario`, `given`, `when`, `then_expected`, `then_actual`.
   Indent every step by two spaces and end the document with one newline.
5. Read `scenarios/<scenario-id>.feature`.
6. Verify the file equals the independently rendered text byte-for-byte.
7. When published `gherkin_raw` differs from that canonical text, verify the
   file still equals the canonical text and not `gherkin_raw`.

## QA-JPKW-07-FALLBACK: raw compatibility

1. Run `./scripts/acceptance.sh` without live-LLM opt-in.
2. Verify the deterministic
   `JPKW-07-FALLBACK .feature file uses gherkin_raw when structured Gherkin is unavailable`
   scenario is reported as passed.
3. Verify its temporary `.feature` artifact equals the supplied
   `gherkin_raw` text byte-for-byte.

## QA-JPKW-07-ISOLATION: no artifact cross-contamination

1. Repeat QA-JPKW-07 in a second fresh output directory.
2. Verify each run writes only beneath its selected output directory.
3. Verify scenario IDs map to same-named `.yaml` and `.feature` files within
   that run.
4. Verify neither run changes the other run's files or environment.
