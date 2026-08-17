Feature: STPA fixture validation
  Every fixture YAML file in src/scenario_forge/stpa/fixtures/ must load
  and validate against its corresponding boundary schema without errors.
  Each fixture must contain a header comment documenting its provenance.

  Background:
    Given the STPA fixtures directory exists at src/scenario_forge/stpa/fixtures
    And the STPA boundary schema module is importable

  # Fixtures-01
  Scenario: Fixtures-01 loss_analysis_klarna fixture validates as LossAnalysis
    Given the fixture file loss_analysis_klarna.yaml
    When the fixture is loaded and validated as LossAnalysis
    Then validation succeeds
    And the fixture file contains a header comment documenting provenance

  # Fixtures-02
  Scenario: Fixtures-02 capability_profile_klarna fixture validates as CapabilityProfile
    Given the fixture file capability_profile_klarna.yaml
    When the fixture is loaded and validated as CapabilityProfile
    Then validation succeeds
    And the fixture file contains a header comment documenting provenance

  # Fixtures-03
  Scenario: Fixtures-03 control_structure_klarna fixture validates as ControlStructure
    Given the fixture file control_structure_klarna.yaml
    When the fixture is loaded and validated as ControlStructure
    Then validation succeeds
    And the fixture file contains a header comment documenting provenance

  # Fixtures-04
  Scenario: Fixtures-04 ica_enumeration_klarna fixture validates as ICAEnumeration
    Given the fixture file ica_enumeration_klarna.yaml
    When the fixture is loaded and validated as ICAEnumeration
    Then validation succeeds
    And the fixture file contains a header comment documenting provenance

  # Fixtures-05
  Scenario: Fixtures-05 enriched_threats_klarna fixture validates as EnrichedThreatSet
    Given the fixture file enriched_threats_klarna.yaml
    When the fixture is loaded and validated as EnrichedThreatSet
    Then validation succeeds
    And the fixture file contains a header comment documenting provenance

  # Fixtures-06
  Scenario: Fixtures-06 all five required fixture files are present
    When the fixtures directory is scanned for YAML files
    Then the fixture file loss_analysis_klarna.yaml is present
    And the fixture file capability_profile_klarna.yaml is present
    And the fixture file control_structure_klarna.yaml is present
    And the fixture file ica_enumeration_klarna.yaml is present
    And the fixture file enriched_threats_klarna.yaml is present
