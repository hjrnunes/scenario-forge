# mutation-stamp: sha256=0c6f93b1cde74b8989e66109f4e83361c222c82c3a0b5e8b334345120672306b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T17:29:00.080511Z","feature_name":"STPA Run — CLI interface","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/stpa_run_cli_interface.feature","background_hash":"4288a4a6926f248f771952b58c3704b6d0904e3431751f2ff6c22ccf429bc275","implementation_hash":"unknown","scenarios":[{"index":2,"name":"STPA-RUN-CLI-03 optional flags are accepted","scenario_hash":"447e27d019be3bbae273da322ce848385f0ce980eb4ba154769753b441687861","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:00.080511Z"},{"index":3,"name":"STPA-RUN-CLI-04 --use-case accepts @ prefix or bare path","scenario_hash":"2c4c9bc36b14b7ef0da44966b18afb737aeecb53a73eabf3f61a9261803078df","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:00.080511Z"},{"index":7,"name":"STPA-RUN-CLI-08 runner module exists at the specified path","scenario_hash":"d1f954de2de6d2bef2ba34c0595cf41b63286ba62bb260cb42e780c996ba1a5e","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:00.080511Z"}]}
# acceptance-mutation-manifest-end

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
