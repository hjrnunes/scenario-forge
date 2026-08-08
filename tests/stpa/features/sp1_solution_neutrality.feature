Feature: SP1 — Solution-neutrality post-call check
  The control structure is solution-neutral: responsibilities describe what
  must be true, not who or what implements it. A deterministic post-call check
  scans responsibility, process model part, control action, and feedback
  channel descriptions for implementation-specific component names (LLM,
  proxy, orchestrator, guardrail, prompt, API) and flags them as warnings.

  Background:
    Given the STPA system model heuristics module is importable
    And a control structure with responsibility RESP-1

  # SP1-NEUT-01
  Scenario Outline: SP1-NEUT-01 component name in responsibility description produces warning
    Given a responsibility RESP-1 with description containing <component_name>
    When the solution-neutrality check is run
    Then a warning is produced containing <component_name>

    Examples:
      | component_name |
      | LLM            |
      | proxy          |
      | orchestrator   |
      | guardrail      |
      | prompt         |
      | API            |

  # SP1-NEUT-02
  Scenario Outline: SP1-NEUT-02 component name in process model part description produces warning
    Given a process model part PM-1-1 with description containing <component_name>
    When the solution-neutrality check is run
    Then a warning is produced containing <component_name>

    Examples:
      | component_name |
      | LLM            |
      | proxy          |
      | orchestrator   |
      | guardrail      |
      | prompt         |
      | API            |

  # SP1-NEUT-03
  Scenario: SP1-NEUT-03 solution-neutral description produces no warning
    Given a responsibility RESP-1 with description The system must validate that user requests are within authorized scope
    When the solution-neutrality check is run
    Then no solution-neutrality warnings are produced

  # SP1-NEUT-04
  Scenario: SP1-NEUT-04 check is case-insensitive
    Given a responsibility RESP-1 with description containing llm
    When the solution-neutrality check is run
    Then a warning is produced

  # SP1-NEUT-05
  Scenario: SP1-NEUT-05 check scans all element types
    Given a control structure where RESP-1 has PM-1-1, CA-1-1, and FB-1-1
    And CA-1-1 has description containing orchestrator
    When the solution-neutrality check is run
    Then a warning is produced for CA-1-1 containing orchestrator

  # SP1-NEUT-06
  Scenario: SP1-NEUT-06 solution-neutrality check runs after Stage 2 assembly
    Given an LLM that returns valid responses for all three Stage 2 calls
    When Stage 2 control structure derivation is run
    Then the solution-neutrality check is run on the assembled ControlStructure
    And the results are available as warnings
