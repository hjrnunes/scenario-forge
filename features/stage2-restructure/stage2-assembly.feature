# mutation-stamp: sha256=1f597ed543786f44a5d18810f5c20ba437b1c2b75c2bc23d5f725a2881265fdf
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T16:21:58.376321Z","feature_name":"Stage 2 Assembly and Manifest","feature_path":"features/stage2-restructure/stage2-assembly.feature","background_hash":"3ce4ce047c4808724701c3d5045ba13b821552e7e8a42e47ce48aacf8a16b50b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Stage 2 call log contains all four call entries","scenario_hash":"3749cc36f18a2f4805cc71d3e493963d43f3fb34a663a4b24ffc31f8253a70af","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T16:21:58.376321Z"},{"index":1,"name":"Old Stage 2 call log step names are absent","scenario_hash":"e59aedccf691357ae01a78fc8dd0fd96d6eda3febdf93dfd7a5150ea7b069a74","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T16:21:58.376321Z"},{"index":4,"name":"Stage 2 system prompts do not mention Poh or STPA-Sec","scenario_hash":"00a8b9dc24d9ebfa461a2381918792020467e88ddfac8a3954bbd24611eeac58","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T16:21:58.376321Z"}]}
# acceptance-mutation-manifest-end

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
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
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
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` does not contain a call entry with `stage` `stage_2` and `step` `<step>`
    Examples:
      | step |
      | call_2_responsibilities |
      | call_3_connections |

  # stage2-assembly-call-ordering
  Scenario: Stage 2 calls appear in the correct order in the call log
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And in `calls.jsonl` the `stage_2` `call_1_requirements` call appears before the `stage_2` `call_2a_responsibilities` call
    And in `calls.jsonl` the `stage_2` `call_2a_responsibilities` call appears before the `stage_2` `call_2b_control_elements` call
    And in `calls.jsonl` the `stage_2` `call_2b_control_elements` call appears before the `stage_2` `call_3_coordination` call

  # stage2-assembly-manifest-call-count
  Scenario: Run manifest records four Stage 2 calls
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
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
    Given live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `control-structure.yaml` contains a non-empty `responsibilities` list
    And every responsibility in `control-structure.yaml` has at least one `process_model_part`
    And every responsibility in `control-structure.yaml` has at least one `control_action`
    And every responsibility in `control-structure.yaml` has at least one `feedback_channel`
