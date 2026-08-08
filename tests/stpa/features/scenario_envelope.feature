Feature: ScenarioEnvelope wrapping and faceting metadata
  The ScenarioEnvelope wraps a ScenarioSpec with Stage 6 artifacts (narrative,
  attack tree, Gherkin spec) and faceting metadata for querying and filtering.

  Background:
    Given the STPA boundary schema module is importable
    And a valid scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1

  # ScenarioEnvelope-01
  Scenario: ScenarioEnvelope-01 valid envelope with all artifacts passes validation
    Given a scenario envelope wrapping SCN-001 with narrative text, attack tree dict, and gherkin spec text
    When the scenario envelope is validated
    Then validation succeeds

  # ScenarioEnvelope-02
  Scenario: ScenarioEnvelope-02 envelope scenario_id matches spec scenario_id
    Given a scenario envelope with scenario_id SCN-001 wrapping spec SCN-001
    When the scenario envelope is validated
    Then validation succeeds

  # ScenarioEnvelope-03
  Scenario: ScenarioEnvelope-03 envelope faceting metadata derived from spec
    Given a scenario envelope wrapping SCN-001 with target_responsibility RESP-1, ica_type NOT_PROVIDED, and provenance structural
    When the scenario envelope is validated
    Then the faceting metadata target_responsibility is RESP-1
    And the faceting metadata ica_type is NOT_PROVIDED
    And the faceting metadata provenance is structural

  # ScenarioEnvelope-04
  Scenario: ScenarioEnvelope-04 envelope with catalog mappings in faceting passes
    Given a scenario envelope wrapping SCN-001 with catalog mappings OWASP_AGENTIC T2-T3 high
    When the scenario envelope is validated
    Then validation succeeds
