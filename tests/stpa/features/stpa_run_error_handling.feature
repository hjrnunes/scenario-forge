Feature: STPA Run — Error handling
  The stpa-run command distinguishes hard failures (exceptions/crashes)
  from degraded results (stage_errors populated but artifacts produced).
  Hard failures stop immediately with exit code 1. Degraded results
  log warnings and continue. Missing critical artifacts between stages
  cause a hard stop.

  Background:
    Given the stpa-run pipeline runner module is importable
    And a use-case text file and risk extraction JSON are available
    And an output directory exists

  # STPA-RUN-ERR-01
  Scenario Outline: STPA-RUN-ERR-01 hard failure in <failing_stage> stops with exit code 1
    Given an LLM that raises an exception during <failing_stage>
    When the stpa-run command is invoked with all required flags
    Then the command exits with code 1
    And the report is not generated

    Examples:
      | failing_stage |
      | SP1           |
      | SP2           |
      | SP3           |

  # STPA-RUN-ERR-02
  Scenario Outline: STPA-RUN-ERR-02 degraded <stage> results continue to next stage
    Given an LLM that returns valid responses with stage_errors populated for <stage>
    When the stpa-run command is invoked with all required flags
    Then the command does not exit with code 1
    And a warning is logged for <stage> stage errors

    Examples:
      | stage |
      | SP1   |
      | SP2   |

  # STPA-RUN-ERR-03
  Scenario: STPA-RUN-ERR-03 missing control_structure after SP1 stops SP2
    Given an LLM that returns valid SP1 responses but no control_structure is produced
    When the stpa-run command is invoked with all required flags
    Then the command exits with code 1
    And SP2 is not executed

  # STPA-RUN-ERR-04
  Scenario: STPA-RUN-ERR-04 missing enriched_threat_set after SP2 stops SP3
    Given an LLM that returns valid SP1 and SP2 responses but no enriched_threat_set is produced
    When the stpa-run command is invoked with all required flags
    Then the command exits with code 1
    And SP3 is not executed

  # STPA-RUN-ERR-05
  Scenario: STPA-RUN-ERR-05 error message is printed to stderr on hard failure
    Given an LLM that raises an exception during SP1
    When the stpa-run command is invoked with all required flags
    Then an error message is printed to stderr
