# stage2-assembly
Feature: Stage 2 Assembly and Manifest
  The assembly logic merges Call 2a (responsibilities + RCs + PM parts) and
  Call 2b (CAs + FBs + CPs) outputs into a single ControlStructure before
  passing it to Call 3 and the critic. The run manifest records the new
  call count. All Stage 2 system prompts drop references to Poh's
  Behavioral Design Process and STPA-Sec. Call 1 system prompt uses a
  solution-neutrality principle instead of an implementation blocklist.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage2-assembly-call-log-entries
  Scenario Outline: Stage 2 call log contains all four call entries
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` contains a call entry with `stage` `stage_2` and `step` `<step>`
    Examples:
      | step |
      | call_1_requirements |
      | call_2a_responsibilities |
      | call_2b_control_elements |
      | call_3_coordination |

  # stage2-assembly-old-step-names-absent
  Scenario Outline: Old Stage 2 call log step names are absent
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` does not contain a call entry with `stage` `stage_2` and `step` `<step>`
    Examples:
      | step |
      | call_2_responsibilities |
      | call_3_connections |

  # stage2-assembly-call-ordering
  Scenario: Stage 2 calls appear in the correct order in the call log
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And in `calls.jsonl` the `stage_2` `call_1_requirements` call appears before the `stage_2` `call_2a_responsibilities` call
    And in `calls.jsonl` the `stage_2` `call_2a_responsibilities` call appears before the `stage_2` `call_2b_control_elements` call
    And in `calls.jsonl` the `stage_2` `call_2b_control_elements` call appears before the `stage_2` `call_3_coordination` call

  # stage2-assembly-manifest-call-count
  Scenario: Run manifest records four Stage 2 calls
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `run-manifest.yaml` has `stage_summary.stage_2.call_count` equal to `4`

  # stage2-assembly-no-poh-stpa
  Scenario Outline: Stage 2 system prompts do not mention Poh or STPA-Sec
    Then the prompt template `<template>` does not contain `Poh`
    And the prompt template `<template>` does not contain `STPA-Sec`
    Examples:
      | template |
      | stage2_call1_system.j2 |
      | stage2_call2a_system.j2 |
      | stage2_call2b_system.j2 |
      | stage2_call3_system.j2 |

  # stage2-assembly-call1-solution-neutrality
  Scenario: Call 1 system prompt uses solution-neutrality principle
    Then the prompt template `stage2_call1_system.j2` contains `solution-neutral`
    And the prompt template `stage2_call1_system.j2` does not contain `Do NOT use implementation-specific terms`

  # stage2-assembly-control-structure-valid
  Scenario: Assembled control structure has all element types
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `control-structure.yaml` contains a non-empty `responsibilities` list
    And every responsibility in `control-structure.yaml` has at least one `process_model_part`
    And every responsibility in `control-structure.yaml` has at least one `control_action`
    And every responsibility in `control-structure.yaml` has at least one `feedback_channel`
