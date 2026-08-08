Feature: EnrichedThreatSet boundary schema validation
  The EnrichedThreatSet model validates structural threat entries, catalog
  mappings with confidence levels, and coverage analysis metrics.

  Background:
    Given the STPA boundary schema module is importable

  # EnrichedThreatSet-01
  Scenario: EnrichedThreatSet-01 valid enriched threat set passes validation
    Given a structural threat with ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED and provenance structural
    And a coverage analysis with total_slots 10, non_na 8, na 2, and coverage_rate 0.8
    When the enriched threat set is validated
    Then validation succeeds

  # EnrichedThreatSet-02
  Scenario: EnrichedThreatSet-02 structural threat with catalog mapping passes
    Given a structural threat with ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED
    And a catalog mapping catalog OWASP_AGENTIC with id T2-T3 and confidence high
    When the enriched threat set is validated
    Then validation succeeds

  # EnrichedThreatSet-03
  Scenario Outline: EnrichedThreatSet-03 catalog mapping confidence levels
    Given a structural threat with a catalog mapping with confidence <confidence_level>
    When the enriched threat set is validated
    Then validation succeeds

    Examples:
      | confidence_level |
      | high             |
      | medium           |
      | low              |

  # EnrichedThreatSet-04
  Scenario: EnrichedThreatSet-04 structural threat with na_reconciliation_flag true passes
    Given a structural threat with ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED and na_reconciliation_flag true
    When the enriched threat set is validated
    Then validation succeeds

  # EnrichedThreatSet-05
  Scenario: EnrichedThreatSet-05 coverage analysis with by_ica_type and by_controller metrics passes
    Given a coverage analysis with by_ica_type NOT_PROVIDED 5, INCORRECT 3 and by_controller RESP-1 4, RESP-2 4
    When the enriched threat set is validated
    Then validation succeeds

  # EnrichedThreatSet-06
  Scenario: EnrichedThreatSet-06 coverage analysis with uncovered OWASP threats passes
    Given a coverage analysis with uncovered_owasp_threats T10, T15 and uncovered_reason no structural slot matched
    When the enriched threat set is validated
    Then validation succeeds

  # EnrichedThreatSet-07
  Scenario: EnrichedThreatSet-07 coverage analysis with slot-level eval metrics passes
    Given a coverage analysis with structural_consideration total_slots 10 considered 8 rate 0.8
    And na_quality na_count 2 quality_count 2 quality_rate 1.0
    When the enriched threat set is validated
    Then validation succeeds

  # EnrichedThreatSet-08
  Scenario: EnrichedThreatSet-08 catalog correspondence with catalog_only_supplements zero passes
    Given a coverage analysis with catalog_correspondence structural_with_match 8, structural_unmapped 0, catalog_only_supplements 0
    When the enriched threat set is validated
    Then validation succeeds
