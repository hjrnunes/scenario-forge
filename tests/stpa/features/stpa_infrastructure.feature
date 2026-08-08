Feature: STPA infrastructure clean copy
  The STPA module gets a clean copy of minimal infrastructure: LLM client,
  JSONL call logging, YAML I/O helpers, parameterized Jinja2 template loader,
  and a simplified run manifest. Zero coupling to the existing pipeline.

  Background:
    Given the STPA infra module is importable

  # InfraLLM-01
  Scenario: InfraLLM-01 LLM client resolves base_url from environment variable
    Given environment variable SCENARIO_FORGE_MODEL_BASE_URL is set to http://test:8080
    When an LLMClient is constructed without explicit base_url
    Then the client base_url is http://test:8080

  # InfraLLM-02
  Scenario: InfraLLM-02 LLM client resolves model name from environment variable
    Given environment variable SCENARIO_FORGE_MODEL_NAME is set to test-model
    When an LLMClient is constructed with base_url http://test:8080
    Then the client model is test-model

  # InfraLLM-03
  Scenario: InfraLLM-03 LLM client explicit args override environment variables
    Given environment variable SCENARIO_FORGE_MODEL_BASE_URL is set to http://env:8080
    When an LLMClient is constructed with base_url http://explicit:8080 and model explicit-model
    Then the client base_url is http://explicit:8080
    And the client model is explicit-model

  # InfraLLM-04
  Scenario: InfraLLM-04 LLM client without base_url raises ValueError
    Given no SCENARIO_FORGE_MODEL_BASE_URL environment variable is set
    When an LLMClient is constructed without explicit base_url
    Then a ValueError is raised containing No LLM endpoint configured

  # InfraLLM-05
  Scenario: InfraLLM-05 LLM client auto-injects OpenRouter headers
    Given an LLMClient constructed with base_url https://openrouter.ai/api/v1
    Then the client extra headers include HTTP-Referer and X-Title

  # InfraLLM-06
  Scenario: InfraLLM-06 LLM client default temperature is 0.4
    Given an LLMClient constructed with base_url http://test:8080
    Then the client temperature is 0.4

  # InfraLLM-07
  Scenario: InfraLLM-07 LLMResult carries content and usage telemetry
    Given an LLMResult with content text, prompt_tokens 100, completion_tokens 50, and duration_ms 5000
    Then the result content is text
    And the result prompt_tokens is 100
    And the result completion_tokens is 50
    And the result duration_ms is 5000

  # InfraCallLog-01
  Scenario: InfraCallLog-01 call log entry written as JSONL
    Given a call log entry with stage stage_2, step call_1, slot_id RESP-1:CA-1-1:NOT_PROVIDED, and scenario_id null
    When the entry is appended to calls.jsonl
    Then the file contains one valid JSON line with stage stage_2 and step call_1

  # InfraCallLog-02
  Scenario: InfraCallLog-02 call log entry with scenario_id set
    Given a call log entry with stage stage_6_narrative, step call_a, slot_id null, and scenario_id SCN-001
    When the entry is appended to calls.jsonl
    Then the file contains one valid JSON line with scenario_id SCN-001

  # InfraCallLog-03
  Scenario: InfraCallLog-03 multiple call log entries appended sequentially
    Given three call log entries with stages stage_2, stage_3, and stage_5
    When all entries are appended to calls.jsonl
    Then the file contains three valid JSON lines in order

  # InfraCallLog-04
  Scenario: InfraCallLog-04 empty entry list does not create file
    Given an empty list of call log entries
    When the entries are appended to calls.jsonl
    Then no calls.jsonl file is created

  # InfraYAML-01
  Scenario: InfraYAML-01 write_yaml serializes Pydantic model to YAML file
    Given a LossAnalysis model with one loss L-1 and one hazard H-1
    When write_yaml is called with the model and a file path
    Then a YAML file exists at the path containing loss_id L-1

  # InfraYAML-02
  Scenario: InfraYAML-02 read_yaml loads YAML file into Pydantic model
    Given a YAML file containing a valid loss analysis with loss L-1
    When read_yaml is called with the path and LossAnalysis class
    Then a LossAnalysis model is returned with loss_id L-1

  # InfraYAML-03
  Scenario: InfraYAML-03 YAML round-trip preserves model data
    Given a ControlStructure model with responsibility RESP-1 and PM-1-1
    When the model is written to YAML and read back
    Then the read-back model matches the original model

  # InfraYAML-04
  Scenario: InfraYAML-04 read_yaml on invalid data raises validation error
    Given a YAML file containing a loss analysis where hazard references non-existent loss
    When read_yaml is called with the path and LossAnalysis class
    Then a validation error is raised

  # InfraTemplates-01
  Scenario: InfraTemplates-01 template loader accepts a custom prompts directory
    Given a prompts directory at tmp/prompts containing template test.j2 with variable name
    When a template loader is created with the directory path
    And render_prompt is called with template test.j2 and name World
    Then the rendered text contains World

  # InfraTemplates-02
  Scenario: InfraTemplates-02 hash_prompt_templates returns SHA-256 hashes
    Given a prompts directory at tmp/prompts containing templates a.j2 and b.j2
    When hash_prompt_templates is called with the directory path
    Then a dict is returned with keys a.j2 and b.j2 mapping to 64-character hex digests

  # InfraTemplates-03
  Scenario: InfraTemplates-03 undefined template variable raises StrictUndefined error
    Given a prompts directory containing template test.j2 with variable name
    When render_prompt is called with template test.j2 without providing name
    Then an undefined variable error is raised

  # InfraTemplates-04
  Scenario: InfraTemplates-04 template loader is independent of existing pipeline prompts
    Given a template loader created with directory tmp/stpa_prompts
    Then the loader does not reference the existing pipeline data/prompts directory

  # InfraManifest-01
  Scenario: InfraManifest-01 valid run manifest passes validation
    Given a run manifest with run_id RUN-001, run_dir output/test, and created_at 2026-08-08T12:00:00Z
    When the manifest is validated
    Then validation succeeds

  # InfraManifest-02
  Scenario: InfraManifest-02 manifest with fill_rate and counts passes
    Given a run manifest with slot_count 10, na_count 2, fill_rate 0.8, and scenario_count 5
    When the manifest is validated
    Then validation succeeds

  # InfraManifest-03
  Scenario: InfraManifest-03 manifest with critic findings passes
    Given a run manifest with critic_findings gap in hazard coverage, missing constraint for H-2
    When the manifest is validated
    Then validation succeeds

  # InfraManifest-04
  Scenario: InfraManifest-04 manifest with eval scorecard path passes
    Given a run manifest with eval_scorecard_path output/test/eval-scorecard.yaml
    When the manifest is validated
    Then validation succeeds

  # InfraManifest-05
  Scenario: InfraManifest-05 manifest is not coupled to existing v3 sentinel system
    Given the STPA run manifest module is imported
    Then the module does not import or reference the existing pipeline manifest module
