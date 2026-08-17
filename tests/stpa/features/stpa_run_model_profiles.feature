# mutation-stamp: sha256=5c51915c5e70b3c42b8311f5f0002026db265d49214b54a3a099f1281c1348f7
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T17:29:32.231595Z","feature_name":"STPA Run — Model profiles resolution","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/stpa_run_model_profiles.feature","background_hash":"8964483a1fa1ca9635faa9bff857b54107e568298e0563922c18a52d7eed583e","implementation_hash":"unknown","scenarios":[{"index":0,"name":"STPA-RUN-MP-01 --profile sets default model for all stages","scenario_hash":"963e623ca477765d82693e2edbe841de95d7ec8874cc0f63712c1abafbcc1729","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:32.231595Z"},{"index":1,"name":"STPA-RUN-MP-02 per-stage profile overrides --profile for that stage only","scenario_hash":"2cdc7dd57b41d4785c4c577a63431a7b204cc75b90f1b9547b00ec47e1cedb0d","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:32.231595Z"},{"index":2,"name":"STPA-RUN-MP-03 per-stage profiles override without --profile","scenario_hash":"c963bee718ec44a84b49d8cb578acdddee1b047007533c4d25e1b48979a16668","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:32.231595Z"},{"index":3,"name":"STPA-RUN-MP-04 no profile flags fall back to environment variables","scenario_hash":"0fbd4cf5484b8f4fa8dabadfa1b63ba8886a4bffa100fd40e9394b3e39a063c5","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:32.231595Z"},{"index":5,"name":"STPA-RUN-MP-06 llm_config module provides shared resolution functions","scenario_hash":"a8ea9f7e62d7c72971712ce9d04fb94fe9a207a8b083afd8461f9d603d52752a","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-10T17:29:32.231595Z"}]}
# acceptance-mutation-manifest-end

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
