Feature: STPA Run — CLI interface
  The `scenario-forge stpa-run` CLI command chains SP1, SP2, SP3, and the
  STPA HTML report in a single invocation. It accepts required inputs
  (--use-case, --risk-extraction, --output-dir) and optional flags for
  model profiles, parallelism, and resume.

  Background:
    Given the stpa-run CLI command is registered in the Typer app
    And a use-case text file and risk extraction JSON are available

  # STPA-RUN-CLI-01
  Scenario: STPA-RUN-CLI-01 stpa-run command exists as a Typer subcommand
    Given the scenario-forge CLI app
    Then a subcommand named "stpa-run" is registered

  # STPA-RUN-CLI-02
  Scenario: STPA-RUN-CLI-02 required flags --use-case, --risk-extraction, --output-dir
    Given the stpa-run command definition
    Then the command requires a --use-case option
    And the command requires a --risk-extraction option
    And the command requires an --output-dir option

  # STPA-RUN-CLI-03
  Scenario Outline: STPA-RUN-CLI-03 optional flags are accepted
    Given the stpa-run command definition
    Then the command accepts an optional <flag> option

    Examples:
      | flag                |
      | --profile           |
      | --sp1-profile       |
      | --sp2-profile       |
      | --sp3-profile       |
      | --profiles-file     |
      | --capability-profile|
      | --max-workers       |
      | --resume            |

  # STPA-RUN-CLI-04
  Scenario Outline: STPA-RUN-CLI-04 --use-case accepts @ prefix or bare path
    Given a use-case file at path "use-case.txt"
    When the stpa-run command is invoked with --use-case "<use_case_arg>"
    Then the use-case text is read from the file

    Examples:
      | use_case_arg   |
      | @use-case.txt  |
      | use-case.txt   |

  # STPA-RUN-CLI-05
  Scenario: STPA-RUN-CLI-05 --max-workers defaults to 1
    Given the stpa-run command definition
    Then the --max-workers option has a default value of 1

  # STPA-RUN-CLI-06
  Scenario: STPA-RUN-CLI-06 --profiles-file defaults to ai/model-profiles.yaml
    Given the stpa-run command definition
    Then the --profiles-file option has a default value of "ai/model-profiles.yaml"

  # STPA-RUN-CLI-07
  Scenario: STPA-RUN-CLI-07 all artifacts use flat layout in output-dir
    Given an LLM that returns valid responses for all stages
    And an output directory
    When the stpa-run command is invoked with all required flags
    Then SP1 artifacts are written directly in the output directory
    And SP2 artifacts are written directly in the output directory
    And SP3 artifacts are written in the output directory with scenarios in a subdirectory

  # STPA-RUN-CLI-08
  Scenario Outline: STPA-RUN-CLI-08 runner module exists at the specified path
    Given the scenario_forge.stpa package
    Then a module <module_path> exists and is importable

    Examples:
      | module_path          |
      | pipeline/runner.py   |
      | pipeline/llm_config.py|
