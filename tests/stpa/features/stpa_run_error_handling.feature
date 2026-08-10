# mutation-stamp: sha256=2ec4a930c702772d2a4ac86ea72dbbfa9471f88c6b0cdb6e2858e11ac257e71c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T17:29:30.034037Z","feature_name":"STPA Run — Error handling","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/stpa_run_error_handling.feature","background_hash":"3ec383cb5b011d3dfa4dc96ae8b4debd8d8b7b2860ac7b26042d04ac72be8698","implementation_hash":"unknown","scenarios":[{"index":0,"name":"STPA-RUN-ERR-01 hard failure in <failing_stage> stops with exit code 1","scenario_hash":"cd72eb51fba9af6c131bd96c2edb0877af5058a8137f52c6b54029e1703b37d4","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:30.034037Z"},{"index":1,"name":"STPA-RUN-ERR-02 degraded <stage> results continue to next stage","scenario_hash":"8c2ff3eebbac1378330a3dc4deec77a4c975937709b675e49a726c8da478036c","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:30.034037Z"}]}
# acceptance-mutation-manifest-end

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
