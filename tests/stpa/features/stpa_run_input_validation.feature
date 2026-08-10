Feature: STPA Run — Input validation
  The stpa-run command validates required input files before starting any
  stage. Non-existent files produce a clear error message and exit code 1.

  Background:
    Given the stpa-run CLI command is registered in the Typer app
    And an LLM that returns valid responses for all stages

  # STPA-RUN-VAL-01
  Scenario: STPA-RUN-VAL-01 missing use-case file exits with error
    Given a use-case path "nonexistent-use-case.txt" that does not exist
    When the stpa-run command is invoked with --use-case "nonexistent-use-case.txt"
    Then the command exits with code 1
    And the error output mentions the use-case file

  # STPA-RUN-VAL-02
  Scenario: STPA-RUN-VAL-02 missing risk-extraction file exits with error
    Given a risk-extraction path "nonexistent-risk.json" that does not exist
    When the stpa-run command is invoked with --risk-extraction "nonexistent-risk.json"
    Then the command exits with code 1
    And the error output mentions the risk-extraction file

  # STPA-RUN-VAL-03
  Scenario: STPA-RUN-VAL-03 missing --capability-profile file exits with error
    Given a capability-profile path "nonexistent-cap.yaml" that does not exist
    When the stpa-run command is invoked with --capability-profile "nonexistent-cap.yaml"
    Then the command exits with code 1
    And the error output mentions the capability-profile file

  # STPA-RUN-VAL-04
  Scenario: STPA-RUN-VAL-04 missing --profiles-file exits with error
    Given a profiles-file path "nonexistent-profiles.yaml" that does not exist
    When the stpa-run command is invoked with --profiles-file "nonexistent-profiles.yaml" and --profile "some-profile"
    Then the command exits with code 1
    And the error output mentions the profiles file

  # STPA-RUN-VAL-05
  Scenario: STPA-RUN-VAL-05 missing required --use-case flag exits with error
    When the stpa-run command is invoked without --use-case
    Then the command exits with a nonzero code

  # STPA-RUN-VAL-06
  Scenario: STPA-RUN-VAL-06 missing required --risk-extraction flag exits with error
    When the stpa-run command is invoked without --risk-extraction
    Then the command exits with a nonzero code

  # STPA-RUN-VAL-07
  Scenario: STPA-RUN-VAL-07 missing required --output-dir flag exits with error
    When the stpa-run command is invoked without --output-dir
    Then the command exits with a nonzero code

  # STPA-RUN-VAL-08
  Scenario: STPA-RUN-VAL-08 input validation runs before any pipeline stage
    Given a use-case path "nonexistent-use-case.txt" that does not exist
    When the stpa-run command is invoked with --use-case "nonexistent-use-case.txt"
    Then SP1 is not executed
    And no files are written to the output directory
