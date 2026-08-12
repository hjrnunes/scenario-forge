# stage1a-split
Feature: Stage 1a Loss Analysis Split
  The current single-call Stage 1a (loss analysis) is split into two
  sequential LLM calls:
    - Call 1 (risk-grounded): derives losses, hazards, and security
      constraints from organizational risks.
    - Call 2 (gap analysis): reviews the use-case description against
      Call 1's output to find missing adversary-actionable losses.
  The old templates stage1a_system.j2 / stage1a_user.j2 are replaced by
  stage1a_risk_system.j2 / stage1a_risk_user.j2 and
  stage1a_gap_system.j2 / stage1a_gap_user.j2.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage1a-split-risk-call
  Scenario: Risk-grounded call produces losses with provenance risk_card
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And the output directory contains `loss-analysis.yaml`
    And `loss-analysis.yaml` contains at least one loss with `provenance` set to `risk_card`
    And every `risk_card`-provenance loss has a non-empty `source_risk_cards` list

  # stage1a-split-risk-call-no-risk-cards
  Scenario: Risk-grounded call with no risk cards produces empty risk_card_losses
    Given the risk-extraction file contains zero risk cards
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `loss-analysis.yaml` has an empty `risk_card_losses` list

  # stage1a-split-gap-call
  Scenario: Gap analysis call produces losses with provenance use_case
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `loss-analysis.yaml` contains at least one loss with `provenance` set to `use_case`
    And every `use_case`-provenance loss has an empty `source_risk_cards` list

  # stage1a-split-gap-call-id-continuation
  Scenario: Gap analysis IDs continue from risk-grounded call
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And loss IDs in `loss-analysis.yaml` are sequential with no duplicates
    And hazard IDs in `loss-analysis.yaml` are sequential with no duplicates
    And security constraint IDs in `loss-analysis.yaml` are sequential with no duplicates

  # stage1a-split-cross-references
  Scenario: Merged cross-references are valid across both calls
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And every hazard in `loss-analysis.yaml` references at least one valid loss_id
    And every security constraint in `loss-analysis.yaml` references at least one valid hazard_id

  # stage1a-split-two-call-log-entries
  Scenario: Two LLM call-log entries are recorded for Stage 1a
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` contains a call entry with `stage` `stage_1a` and `step` `risk_derivation`
    And `calls.jsonl` contains a call entry with `stage` `stage_1a` and `step` `gap_analysis`

  # stage1a-split-manifest-call-count
  Scenario: Run manifest records two Stage 1a calls
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `run-manifest.yaml` has `stage_summary.stage_1a.call_count` equal to `2`

  # stage1a-split-old-templates-removed
  Scenario: Old stage1a templates are absent
    Then the prompts directory does not contain `stage1a_system.j2`
    And the prompts directory does not contain `stage1a_user.j2`

  # stage1a-split-new-templates-present
  Scenario: New stage1a templates are present
    Then the prompts directory contains `stage1a_risk_system.j2`
    And the prompts directory contains `stage1a_risk_user.j2`
    And the prompts directory contains `stage1a_gap_system.j2`
    And the prompts directory contains `stage1a_gap_user.j2`
