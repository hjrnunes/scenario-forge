# mutation-stamp: sha256=66c4c361fd38eb97d358f45ef563f73684240b421f2100e90ff8c9e564222aa2
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T16:22:07.345125Z","feature_name":"Stage 2 Call 2b Control Actions Feedback and Constraints","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/acceptance/features/stage2-restructure/stage2-call2b.feature","background_hash":"3ce4ce047c4808724701c3d5045ba13b821552e7e8a42e47ce48aacf8a16b50b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"New stage2_call2b templates are present","scenario_hash":"f9972de2d2b56ed910830ecf179b8ea84b8916d28d98596e1e63979b21164262","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T16:22:07.345125Z"}]}
# acceptance-mutation-manifest-end

# stage2-call2b
Feature: Stage 2 Call 2b Control Actions Feedback and Constraints
  Call 2b receives the responsibilities (with RCs and PM parts) from Call 2a
  and derives the remaining control elements: control actions (CA), feedback
  channels (FB), and controlled processes (CP). Every process model part
  (PM) must have at least one feedback channel whose updates field references
  that PM. If a responsibility has N process model parts, it must have at
  least N feedback channels.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage2-call2b-new-templates-present
  Scenario Outline: New stage2_call2b templates are present
    Then the prompts directory contains `<template>`
    Examples:
      | template |
      | stage2_call2b_system.j2 |
      | stage2_call2b_user.j2 |

  # stage2-call2b-call-log-entry
  Scenario: Call 2b produces a call-log entry with step call_2b_control_elements
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` contains a call entry with `stage` `stage_2` and `step` `call_2b_control_elements`

  # stage2-call2b-pm-fb-invariant
  Scenario: Every process model part has at least one feedback channel updating it
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And every `pm_id` in `control-structure.yaml` appears in at least one `updates` field of a feedback channel

  # stage2-call2b-fb-count-gte-pm-count
  Scenario: Each responsibility has at least as many feedback channels as process model parts
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And for every responsibility in `control-structure.yaml` the feedback channel count is greater than or equal to the process model part count

  # stage2-call2b-pm-fb-invariant-in-prompt
  Scenario: Call 2b system prompt states the PM-FB invariant
    Then the prompt template `stage2_call2b_system.j2` contains `at least one feedback channel`
    And the prompt template `stage2_call2b_system.j2` contains `at least N feedback channels`

  # stage2-call2b-responsibilities-in-user-prompt
  Scenario: Call 2b user prompt includes responsibilities from Call 2a
    Then the prompt template `stage2_call2b_user.j2` contains `responsibilities`
    And the prompt template `stage2_call2b_user.j2` contains `responsibility_constraints`
    And the prompt template `stage2_call2b_user.j2` contains `process_model_parts`
