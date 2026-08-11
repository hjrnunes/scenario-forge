# stage2-call2a
Feature: Stage 2 Call 2a Responsibilities and Process Model
  The current single Call 2 (responsibilities + PM + CA + FB + CP) is split
  into Call 2a (responsibilities + responsibility constraints + process
  model parts) and Call 2b (control actions + feedback channels + controlled
  processes). Call 2a receives the requirements from Call 1 and the
  capability profile, and produces responsibilities with RCs and PM parts
  only — no control actions, feedback channels, or controlled processes.
  The old templates stage2_call2_system.j2 / stage2_call2_user.j2 are
  replaced by stage2_call2a_system.j2 / stage2_call2a_user.j2 and
  stage2_call2b_system.j2 / stage2_call2b_user.j2.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage2-call2a-old-templates-removed
  Scenario Outline: Old stage2_call2 templates are absent
    Then the prompts directory does not contain `<template>`
    Examples:
      | template |
      | stage2_call2_system.j2 |
      | stage2_call2_user.j2 |

  # stage2-call2a-new-templates-present
  Scenario Outline: New stage2_call2a templates are present
    Then the prompts directory contains `<template>`
    Examples:
      | template |
      | stage2_call2a_system.j2 |
      | stage2_call2a_user.j2 |

  # stage2-call2a-call-log-entry
  Scenario: Call 2a produces a call-log entry with step call_2a_responsibilities
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` contains a call entry with `stage` `stage_2` and `step` `call_2a_responsibilities`

  # stage2-call2a-rc-id-format
  Scenario: Responsibility constraint IDs start with RC- never PM-
    When I run `scenario-forge stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And every `rc_id` in `control-structure.yaml` starts with `RC-`
    And no `rc_id` in `control-structure.yaml` starts with `PM-`

  # stage2-call2a-rc-pm-distinction-in-prompt
  Scenario: Call 2a system prompt distinguishes RCs from PMs
    Then the prompt template `stage2_call2a_system.j2` contains `RC-X-Y`
    And the prompt template `stage2_call2a_system.j2` contains `PM-X-Y`
    And the prompt template `stage2_call2a_system.j2` contains `Do NOT copy PM entries as RCs`

  # stage2-call2a-zone-driven-in-prompt
  Scenario: Call 2a system prompt includes zone-driven responsibility rules
    Then the prompt template `stage2_call2a_system.j2` contains `tool_execution`
    And the prompt template `stage2_call2a_system.j2` contains `memory`
    And the prompt template `stage2_call2a_system.j2` contains `hitl`
    And the prompt template `stage2_call2a_system.j2` contains `inter_agent`

  # stage2-call2a-capability-profile-in-user-prompt
  Scenario: Call 2a user prompt includes capability profile context
    Then the prompt template `stage2_call2a_user.j2` contains `capability_profile`
    And the prompt template `stage2_call2a_user.j2` contains `zones_active`

  # stage2-call2a-feedback-source-null-in-prompt
  Scenario: Call 2a instructs leaving feedback_source null on PM parts
    Then the prompt template `stage2_call2a_user.j2` contains `feedback_source null`

  # stage2-call2a-no-control-elements-in-prompt
  Scenario: Call 2a system prompt does not request control actions or feedback channels
    Then the prompt template `stage2_call2a_system.j2` does not contain `Control Actions`
    And the prompt template `stage2_call2a_system.j2` does not contain `Feedback Channels`
