Feature: STPA Run — Model profiles resolution
  The stpa-run command resolves LLM clients per stage with a three-level
  fallback: per-stage --spN-profile overrides take precedence over the
  default --profile, which takes precedence over environment variables.

  Background:
    Given the stpa-run pipeline runner module is importable
    And a profiles YAML file with the following profiles:
      | profile      | base_url                      | model                  | api_key  | temperature |
      | default-pro  | https://default.example.com/v1| default-model          | sk-def   | 0.4         |
      | sp1-pro      | https://sp1.example.com/v1    | sp1-model              | sk-sp1   | 0.3         |
      | sp2-pro      | https://sp2.example.com/v1    | sp2-model              | sk-sp2   | 0.2         |
      | sp3-pro      | https://sp3.example.com/v1    | sp3-model              | sk-sp3   | 0.1         |

  # STPA-RUN-MP-01
  Scenario Outline: STPA-RUN-MP-01 --profile sets default model for all stages
    Given an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --profile "default-pro"
    Then the <stage> LLM client uses model "default-model"

    Examples:
      | stage |
      | SP1   |
      | SP2   |
      | SP3   |

  # STPA-RUN-MP-02
  Scenario Outline: STPA-RUN-MP-02 per-stage profile overrides --profile for that stage only
    Given an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --profile "default-pro" and --<flag> "<pro_name>"
    Then the <stage> LLM client uses model "<model_name>"

    Examples:
      | flag        | stage | pro_name | model_name |
      | sp1-profile | SP1   | sp1-pro  | sp1-model  |
      | sp2-profile | SP2   | sp2-pro  | sp2-model  |
      | sp3-profile | SP3   | sp3-pro  | sp3-model  |

  # STPA-RUN-MP-03
  Scenario Outline: STPA-RUN-MP-03 per-stage profiles override without --profile
    Given an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --<flag> "<pro_name>"
    Then the <stage> LLM client uses model "<model_name>"

    Examples:
      | flag        | stage | pro_name | model_name |
      | sp1-profile | SP1   | sp1-pro  | sp1-model  |
      | sp2-profile | SP2   | sp2-pro  | sp2-model  |
      | sp3-profile | SP3   | sp3-pro  | sp3-model  |

  # STPA-RUN-MP-04
  Scenario Outline: STPA-RUN-MP-04 no profile flags fall back to environment variables
    Given environment variables SCENARIO_FORGE_MODEL_BASE_URL, SCENARIO_FORGE_API_KEY, and SCENARIO_FORGE_MODEL_NAME are set
    When the stpa-run command is invoked without any profile flags
    Then the <stage> LLM client is created from environment variables

    Examples:
      | stage |
      | SP1   |
      | SP2   |
      | SP3   |

  # STPA-RUN-MP-05
  Scenario: STPA-RUN-MP-05 --profiles-file uses the specified file path
    Given a profiles YAML file at a custom path with profile "custom-model"
    When the stpa-run command is invoked with --profiles-file <custom-path> and --profile "custom-model"
    Then the SP1 LLM client uses model "custom-model"

  # STPA-RUN-MP-06
  Scenario Outline: STPA-RUN-MP-06 llm_config module provides shared resolution functions
    Given the scenario_forge.stpa.pipeline.llm_config module
    Then a function <function_name> is defined

    Examples:
      | function_name                   |
      | resolve_llm_client_from_profile |
      | resolve_llm_client_from_env     |
