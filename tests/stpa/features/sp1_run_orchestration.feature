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
  Scenario: SP1-RUN-02 stages execute in order 1a then 1b then 2
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed
    Then Stage 1a loss analysis is produced first
    And Stage 1b capability profile is produced second
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
  Scenario: SP1-RUN-09 prompt templates exist for all stages
    Given the SP1 prompt templates directory
    Then the following template files exist:
      | stage1a_system.j2         |
      | stage1a_user.j2           |
      | stage1b_system.j2         |
      | stage1b_user.j2           |
      | stage2_call1_system.j2    |
      | stage2_call1_user.j2      |
      | stage2_call2_system.j2    |
      | stage2_call2_user.j2      |
      | stage2_call3_system.j2    |
      | stage2_call3_user.j2      |
      | critic_system.j2          |
      | critic_user.j2            |
      | revision_system.j2        |
      | revision_user.j2          |

  # SP1-RUN-10
  Scenario: SP1-RUN-10 module layout matches spec
    Given the STPA system model module
    Then the following modules exist and are importable:
      | module              |
      | loss_analysis.py    |
      | profile.py          |
      | control_structure.py|
      | critic.py           |
      | heuristics.py       |
      | run.py              |

  # SP1-RUN-11
  Scenario: SP1-RUN-11 internal models are defined
    Given the STPA system model module
    Then the following internal models are defined:
      | model              |
      | RequirementSet     |
      | Requirement        |
      | ResponsibilitySet |
      | CriticFindings     |
      | CriticGap          |

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
