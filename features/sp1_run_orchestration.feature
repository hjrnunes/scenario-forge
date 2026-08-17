# mutation-stamp: sha256=25000e787e58e793e0d13b990c274f0530dd96c5593e04261b8338bd87db763f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:22:22.206365Z","feature_name":"SP1 \u2014 Run orchestration","feature_path":"features/sp1_run_orchestration.feature","background_hash":"93a4ff32b850b092ffae476f5b2cf2ed3be0d0926c0e21bf8b7b001706738bd9","implementation_hash":"sha256:41587085eef4c3d4b30f0520d1fae1ca4de0de3e1e2fbe563d189e929f80188f","scenarios":[{"index":8,"name":"SP1-RUN-09 prompt templates exist for all stages","scenario_hash":"f14610730a1eb7310adfa91a71a567b9be0eee3c820ee5bd5c1d6938106b5e92","mutation_count":18,"result":{"Total":18,"Killed":18,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:22:22.206365Z"},{"index":9,"name":"SP1-RUN-09b templates retired by the Stage 1 and Stage 2 restructures are absent","scenario_hash":"4874b28276a023828cfe26f57e31252a0ff94115a9d8b6757b5e7d6eb4b81631","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:21:13.721816Z"},{"index":11,"name":"SP1-RUN-11 internal models are defined","scenario_hash":"e92a54a218f0074708a5dfb436c471b82bbe015dd6635844c5e54445e6bb4ca9","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:21:13.721816Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Run orchestration
  The SP1 run orchestrates Stages 1a, 1b, and 2 in sequence. Stage 1a produces
  LossAnalysis, Stage 1b produces CapabilityProfile (or loads a pre-built one
  with --profile), and Stage 2 produces the ControlStructure via three calls,
  heuristics, critic, and optional revision. All LLM calls are logged to
  calls.jsonl and a run manifest is written at the end.

  Background:
    Given the STPA system model run module is importable
    And a use-case description and risk extraction JSON are available as input

  # SP1-RUN-01
  Scenario: SP1-RUN-01 full run produces all three output artifacts
    Given an LLM that returns valid responses for all stages
    And a run directory for output
    When the full SP1 run is executed
    Then a file loss-analysis.yaml exists in the run directory
    And a file capability-profile.yaml exists in the run directory
    And a file control-structure.yaml exists in the run directory

  # SP1-RUN-02
  Scenario: SP1-RUN-02 stages execute in order 1b then 1a then 2
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed
    Then Stage 1b capability profile is produced first
    And Stage 1a loss analysis is produced second
    And Stage 2 control structure is produced third

  # SP1-RUN-03
  Scenario: SP1-RUN-03 all LLM calls are logged to calls.jsonl
    Given an LLM that returns valid responses for all stages
    And a run directory for output
    When the full SP1 run is executed
    Then a file calls.jsonl exists in the run directory
    And the file contains entries for stage_1a, stage_1b, and stage_2

  # SP1-RUN-04
  Scenario: SP1-RUN-04 run manifest is written at run end
    Given an LLM that returns valid responses for all stages
    And a run directory for output
    When the full SP1 run is executed
    Then a run manifest is written to the run directory
    And the manifest has stage_summary with call counts for each stage

  # SP1-RUN-05
  Scenario: SP1-RUN-05 run manifest records critic findings
    Given an LLM that returns valid responses for all stages and critic findings with two gaps
    When the full SP1 run is executed
    Then the run manifest critic_findings contains two entries

  # SP1-RUN-06
  Scenario: SP1-RUN-06 run manifest records input hashes
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed
    Then the run manifest input_hashes contains a hash for the use-case text
    And the run manifest input_hashes contains a hash for the risk extraction

  # SP1-RUN-07
  Scenario: SP1-RUN-07 run manifest records prompt hashes
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed
    Then the run manifest prompt_hashes contains SHA-256 hashes for all prompt templates

  # SP1-RUN-08
  Scenario: SP1-RUN-08 Stage 2 receives loss analysis and capability profile
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed
    Then Stage 2 Call 1 receives security constraints from the loss analysis
    And Stage 2 receives the capability profile for the critic

  # SP1-RUN-09
  Scenario Outline: SP1-RUN-09 prompt templates exist for all stages
    Given the SP1 prompt templates directory
    Then the prompts directory contains `<template>`

    Examples:
      | template                 |
      | stage1a_risk_system.j2   |
      | stage1a_risk_user.j2     |
      | stage1a_gap_system.j2    |
      | stage1a_gap_user.j2      |
      | stage1b_system.j2        |
      | stage1b_user.j2          |
      | stage2_call1_system.j2   |
      | stage2_call1_user.j2     |
      | stage2_call2a_system.j2  |
      | stage2_call2a_user.j2    |
      | stage2_call2b_system.j2  |
      | stage2_call2b_user.j2    |
      | stage2_call3_system.j2   |
      | stage2_call3_user.j2     |
      | critic_system.j2         |
      | critic_user.j2           |
      | revision_system.j2       |
      | revision_user.j2         |

  # SP1-RUN-09b
  Scenario Outline: SP1-RUN-09b templates retired by the Stage 1 and Stage 2 restructures are absent
    Given the SP1 prompt templates directory
    Then the prompts directory does not contain `<retired_template>`

    Examples:
      | retired_template       |
      | stage1a_system.j2      |
      | stage1a_user.j2        |
      | stage2_call2_system.j2 |
      | stage2_call2_user.j2   |

  # SP1-RUN-10
  Scenario Outline: SP1-RUN-10 module layout matches spec
    Given the STPA system model module
    Then the module `<module>` exists and is importable

    Examples:
      | module               |
      | loss_analysis.py     |
      | profile.py           |
      | control_structure.py |
      | critic.py            |
      | heuristics.py        |
      | run.py               |

  # SP1-RUN-11
  Scenario Outline: SP1-RUN-11 internal models are defined
    Given the STPA system model module
    Then the control_structure module exports `<model>`

    Examples:
      | model                |
      | Requirement          |
      | RequirementSet       |
      | ResponsibilitySet    |
      | ControlElementSet    |
      | CoordinationAnalysis |

  # SP1-RUN-12
  Scenario: SP1-RUN-12 run with profile flag skips Stage 1b LLM call
    Given an LLM that returns valid responses for Stage 1a and Stage 2
    And a pre-built capability-profile.yaml at a known path
    When the full SP1 run is executed with the profile flag
    Then no call log entry has stage stage_1b
    And the pre-built capability profile is used

  # SP1-RUN-13
  Scenario: SP1-RUN-13 temperature is 0.4 for all Stage 2 calls
    Given an LLM that records the temperature used
    When the full SP1 run is executed
    Then all Stage 2 LLM calls use temperature 0.4

  # SP1-RUN-14
  Scenario: SP1-RUN-14 existing pipeline tests are unaffected
    Given the SP1 system model module is implemented
    When the existing test suite is run
    Then no new failures are introduced
