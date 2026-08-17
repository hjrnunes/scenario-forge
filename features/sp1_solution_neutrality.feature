# mutation-stamp: sha256=1c6fe4bb456a3f9efd9140f6171425e5b91c3ba9b8171a5ffd70db44aebf42be
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:51:52.008673Z","feature_name":"SP1 \u2014 Solution-neutrality post-call check","feature_path":"features/sp1_solution_neutrality.feature","background_hash":"5c09546ab0489d18bab6a3c913697555d78de6d1efa967627ad0e0e2d75a192d","implementation_hash":"unknown","scenarios":[{"index":0,"name":"SP1-NEUT-01 component name in responsibility description produces warning","scenario_hash":"0a75aaeef44d9e10d9ea1d9406b1bc0fc82054347ba803e5d77d39988a53aa9e","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-08T14:51:52.008673Z"},{"index":1,"name":"SP1-NEUT-02 component name in process model part description produces warning","scenario_hash":"7021576410d916b8fb68040337ba23f2332d64e0e942a43e79ed6143a0555678","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-08T14:51:52.008673Z"}]}
# acceptance-mutation-manifest-end

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
