# stpa-report-generation
Feature: STPA Report Generation
  The `scenario-forge stpa-report` CLI subcommand generates a self-contained
  HTML report from a combined STPA output directory containing SP1, SP2,
  and SP3 artifacts.

  Scenario: Generate report from a valid combined output directory
    Given a combined output directory containing STPA artifacts:
      | artifact                   | source_stage |
      | loss-analysis.yaml         | SP1          |
      | capability-profile.yaml    | SP1          |
      | control-structure.yaml     | SP1          |
      | ica-enumeration.yaml       | SP2          |
      | enriched-threats.yaml      | SP2          |
      | eval-scorecard.yaml        | SP3          |
      | coverage-gaps.json         | SP3          |
      | run-manifest.yaml          | SP3          |
      | calls.jsonl                | SP3          |
      | scenarios/SCN-001.yaml     | SP3          |
      | scenarios/SCN-001.feature  | SP3          |
    When I run `scenario-forge stpa-report --output-dir <dir>`
    Then the command exits with code 0
    And a file named `stpa-report.html` is written in the output directory
    And the console output mentions the report file path

  Scenario: Generate report with missing optional artifacts
    Given a combined output directory with only SP1 and SP2 artifacts
    When I run `scenario-forge stpa-report --output-dir <dir>`
    Then the command exits with code 0
    And a file named `stpa-report.html` is written in the output directory
    And the SP3 flow card section is absent from the report

  Scenario: Generate report from a nonexistent directory
    Given a directory path that does not exist
    When I run `scenario-forge stpa-report --output-dir <dir>`
    Then the command exits with a nonzero code
    And the console error output mentions "directory not found"

  Scenario: Generate report with custom output filename
    Given a combined output directory containing STPA artifacts:
      | artifact                   | source_stage |
      | loss-analysis.yaml         | SP1          |
      | control-structure.yaml     | SP1          |
      | scenarios/SCN-001.yaml     | SP3          |
    When I run `scenario-forge stpa-report --output-dir <dir> --output custom-report.html`
    Then the command exits with code 0
    And a file named `custom-report.html` is written in the output directory

  Scenario: Report is self-contained with no external dependencies
    Given a generated STPA report HTML file
    Then the report HTML contains no `<link` tags referencing external stylesheets
    And the report HTML contains no `<script src=` tags referencing external scripts
    And the report HTML contains no `<img` tags referencing external images
