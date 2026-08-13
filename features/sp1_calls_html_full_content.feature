# mutation-stamp: sha256=043af6ba76130d6c946df7fd3396310d014ce80d982ccf19be223cec18973392
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T17:45:23.429882Z","feature_name":"SP1 \u2014 Calls HTML report shows full prompts and responses","feature_path":"features/sp1_calls_html_full_content.feature","background_hash":"2c36ca7df697bb9ef1d5458a05d6e268df6314ba8efcd732a3fa21309030395e","implementation_hash":"unknown","scenarios":[{"index":0,"name":"FullContent-01 make_call_log_entry includes full content fields","scenario_hash":"6e470643dbc98e65493e06eedbde248b847295a21387e7d7159ba16937f758d1","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:45:23.429882Z"},{"index":3,"name":"FullContent-06 HTML report shows prompt content in collapsible sections","scenario_hash":"994032dbad090a67a9ccbb57c3e7767b9316587c46a383779db875669fb49cf0","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:45:23.429882Z"},{"index":11,"name":"FullContent-15 existing metadata columns preserved in detail table","scenario_hash":"ba2c0b9966bce5742b4dfdb559d40dfc154b5b291da2004c6e40a90f7dd5a8b9","mutation_count":7,"result":{"Total":7,"Killed":7,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:45:23.429882Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Calls HTML report shows full prompts and responses
  The calls.html report shows only metadata (stage, step, model, tokens,
  duration, success/failure) and is useless for debugging. The fix adds
  full prompt text and response content to call log entries and renders
  them in the HTML report with collapsible sections, pretty-printed JSON,
  and a search/filter box.

  Background:
    Given the calls_html module is importable
    And the call_log module is importable
    And a run directory for call logging

  # FullContent-01
  Scenario Outline: FullContent-01 make_call_log_entry includes full content fields
    When a call log entry is created with <field_name> <field_value>
    Then the entry dict contains a "<field_name>" key
    And the <field_name> value equals <field_value>

    Examples:
      | field_name          | field_value                         |
      | system_prompt_text  | "You are a safety engineer"         |
      | user_prompt_text    | "Analyze this system"               |
      | response_content    | '{"gap_type": "missing_responsibility"}' |

  # FullContent-04
  Scenario: FullContent-04 log_llm_call stores full prompt text and response content
    Given an LLMResult with system_prompt "System instructions" and user_prompt "User task" and content '{"result": true}'
    When log_llm_call is invoked with the LLMResult
    Then the appended calls.jsonl entry contains system_prompt_text "System instructions"
    And the appended calls.jsonl entry contains user_prompt_text "User task"
    And the appended calls.jsonl entry contains response_content containing "result"

  # FullContent-05
  Scenario: FullContent-05 log_llm_call_failure stores full prompt text
    When log_llm_call_failure is invoked with system_prompt "System prompt" and user_prompt "User prompt" and error "timeout"
    Then the appended calls.jsonl entry contains system_prompt_text "System prompt"
    And the appended calls.jsonl entry contains user_prompt_text "User prompt"

  # FullContent-06
  Scenario Outline: FullContent-06 HTML report shows prompt content in collapsible sections
    Given a calls.jsonl file with an entry containing <field_name> <field_value>
    When the calls.jsonl file is rendered to HTML
    Then the HTML contains the text <search_text>
    And the HTML contains a collapsible element for <collapsible_name>

    Examples:
      | field_name          | field_value                  | search_text                | collapsible_name  |
      | system_prompt_text  | "You are a safety engineer"  | "You are a safety engineer" | system_prompt     |
      | user_prompt_text    | "Analyze this system"        | "Analyze this system"       | user_prompt       |

  # FullContent-08
  Scenario: FullContent-08 HTML report shows response_content in collapsible section
    Given a calls.jsonl file with an entry containing response_content '{"gap_type": "missing_responsibility"}'
    When the calls.jsonl file is rendered to HTML
    Then the HTML contains a collapsible element for response_content
    And the HTML contains the text "gap_type"

  # FullContent-09
  Scenario: FullContent-09 structured responses are pretty-printed as JSON
    Given a calls.jsonl file with an entry containing response_content '{"gap_type":"missing_responsibility","description":"test"}'
    When the calls.jsonl file is rendered to HTML
    Then the HTML contains pretty-printed JSON with indentation
    And the HTML contains a pre-formatted block for the JSON content

  # FullContent-10
  Scenario: FullContent-10 unstructured responses shown in pre blocks
    Given a calls.jsonl file with an entry containing response_content 'This is a plain text response without JSON structure.'
    When the calls.jsonl file is rendered to HTML
    Then the HTML contains a pre-formatted block with the response text
    And the HTML contains the text "This is a plain text response without JSON structure."

  # FullContent-11
  Scenario: FullContent-11 HTML report includes search and filter box
    Given a calls.jsonl file with entries for stages stage_1a and stage_2
    When the calls.jsonl file is rendered to HTML
    Then the HTML contains a search or filter input element
    And the HTML contains JavaScript for filtering call entries

  # FullContent-12
  Scenario: FullContent-12 summary table is preserved at top of report
    Given a two-successful-call calls.jsonl fixture
    When the calls.jsonl file is rendered to HTML
    Then the HTML summary shows total calls 2
    And the HTML summary shows success count 2

  # FullContent-13
  Scenario: FullContent-13 HTML report is self-contained with inline CSS and JavaScript
    Given a calls.jsonl file with one entry
    When the calls.jsonl file is rendered to HTML
    Then the HTML file contains a <style> tag with inline CSS
    And the HTML file contains a <script> tag with inline JavaScript
    And the HTML file does not reference any external stylesheet
    And the HTML file does not reference any external script

  # FullContent-14
  Scenario: FullContent-14 backward compatibility with entries lacking content fields
    Given a calls.jsonl file with entries that do not contain system_prompt_text, user_prompt_text, or response_content fields
    When the calls.jsonl file is rendered to HTML
    Then the HTML file is produced without errors
    And the HTML summary shows the correct total call count

  # FullContent-15
  Scenario Outline: FullContent-15 existing metadata columns preserved in detail table
    Given a calls.jsonl file with one entry
    When the calls.jsonl file is rendered to HTML
    Then the detail table includes a column for <column>

    Examples:
      | column            |
      | stage             |
      | step              |
      | model             |
      | prompt_tokens     |
      | completion_tokens |
      | duration_ms       |
      | timestamp         |
