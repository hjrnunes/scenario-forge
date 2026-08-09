Feature: Model profiles with tunable parameters
  The STPA pipeline loads LLM connection and generation parameters from
  named profiles in a YAML file. This replaces editing environment variables
  in .envrc to switch models. A sample file documents the schema without
  real keys. The runner script supports both --profile (new) and
  environment-variable fallback (backwards compatible). The profile name
  is recorded in the run manifest.

  Background:
    Given the model profiles module is importable
    And a profiles YAML file with the following profiles:
      | profile           | base_url                          | model                       | api_key       | max_completion_tokens | temperature |
      | gemma4-openrouter | https://openrouter.ai/api/v1      | google/gemma-4-26b-a4b-it   | sk-or-v1-xxx  | 16384                 | 0.4         |
      | gemma4-local      | https://local.example.com/v1      | gemma-4-26b-a4b-it          | unused        |                       | 0.4         |
      | sonnet-4          | https://openrouter.ai/api/v1      | anthropic/claude-sonnet-4   | sk-or-v1-yyy  | 16384                 | 0.3         |

  # MP-01
  Scenario: MP-01 loading a named profile returns all its parameters
    When the profile "gemma4-openrouter" is loaded
    Then the returned parameters include base_url "https://openrouter.ai/api/v1"
    And the returned parameters include model "google/gemma-4-26b-a4b-it"
    And the returned parameters include api_key "sk-or-v1-xxx"
    And the returned parameters include max_completion_tokens 16384
    And the returned parameters include temperature 0.4

  # MP-02
  Scenario: MP-02 loading a profile with optional parameters top_p and top_k
    Given a profiles YAML file with the following profiles:
      | profile  | base_url                     | model      | api_key | top_p | top_k |
      | tuned    | https://local.example.com/v1 | local-lm   | unused  | 0.9   | 40    |
    When the profile "tuned" is loaded
    Then the returned parameters include top_p 0.9
    And the returned parameters include top_k 40

  # MP-03
  Scenario: MP-03 loading a profile with custom headers
    Given a profiles YAML file with the following profiles:
      | profile    | base_url                     | model    | api_key | headers                                         |
      | with-hdr   | https://custom.example.com/v1| custom-1 | sk-123  | {"X-Custom":"value","X-Region":"eu"}            |
    When the profile "with-hdr" is loaded
    Then the returned parameters include headers with key "X-Custom" and value "value"
    And the returned parameters include headers with key "X-Region" and value "eu"

  # MP-04
  Scenario: MP-04 loading a profile without optional fields uses defaults
    When the profile "gemma4-local" is loaded
    Then the returned parameters do not include max_completion_tokens
    And the returned parameters include temperature 0.4

  # MP-05
  Scenario: MP-05 loading a profile from a custom profiles file path
    Given a profiles YAML file at a custom path with profile "custom-remote"
    When the profile "custom-remote" is loaded from the custom path
    Then the returned parameters include model "custom-model"

  # MP-06
  Scenario: MP-06 missing profiles file raises a clear error
    Given no profiles file exists at the expected path
    When loading any profile
    Then a clear error is raised mentioning the file path

  # MP-07
  Scenario: MP-07 unknown profile name raises a clear error
    When the profile "nonexistent" is loaded
    Then a clear error is raised mentioning the profile name "nonexistent"

  # MP-08
  Scenario: MP-08 profile missing a required field raises a clear error
    Given a profiles YAML file with the following profiles:
      | profile     | base_url                     | model      | api_key |
      | missing-url |                              | some-model | sk-xxx  |
    When the profile "missing-url" is loaded
    Then a clear error is raised mentioning "base_url"

  # MP-09
  Scenario: MP-09 runner script with --profile passes parameters to LLMClient
    When the runner script is invoked with --profile "gemma4-openrouter"
    Then the LLMClient is created with base_url "https://openrouter.ai/api/v1"
    And the LLMClient is created with model "google/gemma-4-26b-a4b-it"
    And the LLMClient is created with temperature 0.4

  # MP-10
  Scenario: MP-10 runner script without --profile falls back to environment variables
    Given environment variables SCENARIO_FORGE_MODEL_BASE_URL, SCENARIO_FORGE_API_KEY, and SCENARIO_FORGE_MODEL_NAME are set
    When the runner script is invoked without --profile
    Then the LLMClient is created from environment variables
    And no profile name is recorded in the run manifest

  # MP-11
  Scenario: MP-11 profile name is recorded in the run manifest
    When the runner script is invoked with --profile "sonnet-4"
    Then the run manifest model_config dict contains key "profile" with value "sonnet-4"

  # MP-12
  Scenario: MP-12 runner script with --profiles-file uses the specified file
    Given a profiles YAML file at a custom path with profile "alt-model"
    When the runner script is invoked with --profiles-file <custom-path> and --profile "alt-model"
    Then the LLMClient is created with model "alt-model"

  # MP-13
  Scenario: MP-13 LLMClient accepts top_p and top_k parameters
    When an LLMClient is created with top_p 0.9 and top_k 40
    Then the LLMClient stores top_p as 0.9
    And the LLMClient stores top_k as 40

  # MP-14
  Scenario: MP-14 LLMClient without top_p and top_k leaves them unset
    When an LLMClient is created without top_p and top_k
    Then the LLMClient top_p is None
    And the LLMClient top_k is None

  # MP-15
  Scenario: MP-15 sample profiles file is committed and contains placeholder keys
    Given the sample profiles file ai/model-profiles.example.yaml
    Then the sample file exists in the repository
    And the sample file contains at least one profile with api_key "sk-or-v1-YOUR-KEY-HERE"

  # MP-16
  Scenario: MP-16 real profiles file is gitignored
    Then ai/model-profiles.yaml is listed in .gitignore
