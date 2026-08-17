# stage1-ordering
Feature: Stage 1 Pipeline Ordering
  The pipeline ordering changes from `1a -> 1b -> 2` to
  `1b (capability profile) ∥ 1a-1 (risk-grounded) -> merge -> 1a-2 (gap analysis)`.
  Stage 1b runs before Stage 1a. Stage 1b and 1a-1 are independent and
  can run in parallel. Stage 1a-2 (gap analysis) receives the capability
  profile as additional input for systematic coverage checking.
  Stage 2 (control structure) runs after both 1a and 1b complete.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage1-ordering-1b-before-1a
  Scenario: Capability profile call appears before loss analysis calls in call log
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And in `calls.jsonl` the `stage_1b` call appears before the first `stage_1a` call

  # stage1-ordering-risk-before-gap
  Scenario: Risk-grounded call appears before gap analysis call in call log
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And in `calls.jsonl` the `stage_1a` `risk_derivation` call appears before the `stage_1a` `gap_analysis` call

  # stage1-ordering-all-artifacts-produced
  Scenario: All Stage 1 artifacts are produced in a single run
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And the output directory contains `capability-profile.yaml`
    And the output directory contains `loss-analysis.yaml`
    And the output directory contains `control-structure.yaml`

  # stage1-ordering-profile-skip-still-runs-1a
  Scenario: Providing a pre-built capability profile still runs both loss analysis calls
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    And a pre-built `capability-profile.yaml` file is available
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir> --capability-profile <profile>`
    Then the command exits with code 0
    And `calls.jsonl` contains a call entry with `stage` `stage_1a` and `step` `risk_derivation`
    And `calls.jsonl` contains a call entry with `stage` `stage_1a` and `step` `gap_analysis`
    And `calls.jsonl` does not contain a call entry with `stage` `stage_1b`

  # stage1-ordering-gap-call-receives-profile
  Scenario: Gap analysis user prompt includes capability profile context
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And the `stage_1a` `gap_analysis` call entry in `calls.jsonl` has a `user_prompt_text` containing `kc_subcodes`

  # stage1-ordering-1b-no-loss-input
  Scenario: Capability profile call does not receive loss analysis as input
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And the `stage_1b` call entry in `calls.jsonl` has a `user_prompt_text` that does not contain `loss_analysis`
    And the `stage_1b` call entry in `calls.jsonl` has a `user_prompt_text` that does not contain `risk_card_losses`
