# mutation-stamp: sha256=3d54e705c589404d8b8623913d4127b08693e32600594ab54a4bac3273dff79c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T09:07:35.692694Z","feature_name":"HTML rendering of calls.jsonl","feature_path":"features/calls_html_rendering.feature","background_hash":"2b4230484f333c0cd6b2478e522c7eca3db322f5752e8fba4b7bf11254da08ba","implementation_hash":"unknown","scenarios":[{"index":5,"name":"CH-06 detail table includes expected columns","scenario_hash":"b7e2b4603ad7bf4b7bfd3d5956ae83761667b7f4e3fc2a622878babda59a2bd4","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-09T09:07:35.692694Z"}]}
# acceptance-mutation-manifest-end

Feature: HTML rendering of calls.jsonl
  The STPA pipeline produces a calls.jsonl file with one JSON object per
  LLM call. A render function converts this file into a self-contained
  HTML file for easy visual inspection. The HTML includes a summary table
  (total calls, success/failure count, total tokens, total duration) and
  a detail table with all call entries. Failed calls are highlighted in
  red. All CSS is inline; no external dependencies.

  Background:
    Given the calls_html module is importable
    And the standard four-call calls.jsonl fixture

  # CH-01
  Scenario: CH-01 render_calls_html produces a self-contained HTML file
    When the calls.jsonl file is rendered to HTML
    Then an HTML file is produced at the output path
    And the HTML file contains a <style> tag with inline CSS
    And the HTML file does not reference any external stylesheet

  # CH-02
  Scenario: CH-02 summary table shows correct totals
    When the calls.jsonl file is rendered to HTML
    Then the HTML summary shows total calls 4
    And the HTML summary shows success count 3
    And the HTML summary shows failure count 1
    And the HTML summary shows total prompt tokens 17600
    And the HTML summary shows total completion tokens 4800
    And the HTML summary shows total duration 30100

  # CH-03
  Scenario: CH-03 detail table contains all call entries
    When the calls.jsonl file is rendered to HTML
    Then the HTML detail table contains 4 rows
    And the detail table includes a row with stage "stage_1a" and step "call_1a_losses"
    And the detail table includes a row with stage "stage_2" and step "call_2_requirements"

  # CH-04
  Scenario: CH-04 failed calls are highlighted in red
    When the calls.jsonl file is rendered to HTML
    Then the row for step "call_2_requirements" has a failure indicator
    And the row for step "call_1a_losses" does not have a failure indicator

  # CH-05
  Scenario: CH-05 error messages are displayed for failed calls
    When the calls.jsonl file is rendered to HTML
    Then the HTML contains the text "timeout exceeded"

  # CH-06
  Scenario Outline: CH-06 detail table includes expected columns
    When the calls.jsonl file is rendered to HTML
    Then the detail table includes a column for <column>

    Examples:
      | column            |
      | model             |
      | prompt_tokens     |
      | completion_tokens |
      | duration_ms       |
      | timestamp         |

  # CH-07
  Scenario: CH-07 rendering an empty calls.jsonl produces valid HTML with zero totals
    Given a calls.jsonl file with zero entries
    When the calls.jsonl file is rendered to HTML
    Then the HTML summary shows total calls 0
    And the HTML summary shows success count 0
    And the HTML summary shows failure count 0
    And the HTML detail table contains 0 rows

  # CH-08
  Scenario: CH-08 rendering a calls.jsonl with only successful calls
    Given a two-successful-call calls.jsonl fixture
    When the calls.jsonl file is rendered to HTML
    Then the HTML summary shows success count 2
    And the HTML summary shows failure count 0
    And no row has a failure indicator

  # CH-09
  Scenario: CH-09 CLI invocation renders calls.jsonl to HTML
    When the CLI is invoked with a calls.jsonl path and an output HTML path
    Then an HTML file is produced at the output path
    And the HTML file contains a <style> tag with inline CSS

  # CH-10
  Scenario: CH-10 render_calls_html returns the output path
    When the calls.jsonl file is rendered to HTML
    Then the returned path equals the output path

  # CH-12
  Scenario: CH-12 all calls have the same model shown in detail table
    When the calls.jsonl file is rendered to HTML
    Then the detail table includes 4 rows with model "gemma-4-26b-a4b-it"
