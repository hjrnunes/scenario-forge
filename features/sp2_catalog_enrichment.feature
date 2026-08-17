# mutation-stamp: sha256=2cfd966dd1d37856bd8cc324ea1e94884854d20033d23283f7bd954bea0201ba
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T07:32:42.820782Z","feature_name":"SP2 Stage 4 \u2014 Catalog enrichment and coverage analysis","feature_path":"features/sp2_catalog_enrichment.feature","background_hash":"9c09a8d73ef873d3159b2eec45a4da425dd05bf46dd0391dcc9c6808edf6d559","implementation_hash":"unknown","scenarios":[{"index":2,"name":"SP2-CAT-03 confidence level depends on keyword match count","scenario_hash":"9fa29db477465e6012211b56457c3a8f2df616bcd8545586ffd7e55c9e59fac5","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-10T00:47:06.479582Z"}]}
# acceptance-mutation-manifest-end

Feature: SP2 Stage 4 — Catalog enrichment and coverage analysis
  Catalog enrichment is a deterministic reverse lookup that matches ICA text and
  loss scenarios against ATLAS and OWASP Agentic catalog entries via keyword
  matching. Three outcomes: mapped (technique found), unmapped (no match), and
  N/A reconciliation (contradiction detection when a catalog technique maps to a
  slot declared N/A). Coverage analysis produces a three-way partition, by ICA
  type, by controller, catalog correspondence, and slot-level eval metrics.
  No LLM calls.

  Background:
    Given the SP2 catalog enrichment module is importable
    And the SP2 coverage module is importable

  # SP2-CAT-01
  Scenario: SP2-CAT-01 ICA with prompt injection keywords maps to ATLAS and OWASP
    Given an ICA with ica_text containing prompt injection and loss_scenario containing attacker manipulates
    When catalog matching is performed
    Then at least one mapping has catalog ATLAS
    And at least one mapping has catalog OWASP_AGENTIC

  # SP2-CAT-02
  Scenario: SP2-CAT-02 ICA with no matching keywords is unmapped
    Given an ICA with ica_text containing routine status check and loss_scenario containing no attack vector
    When catalog matching is performed
    Then no catalog mappings are returned
    And the ICA is labeled unmapped

  # SP2-CAT-03
  Scenario Outline: SP2-CAT-03 confidence level depends on keyword match count
    Given an ICA with ica_text containing <keyword_1> and <keyword_2>
    When catalog matching is performed
    Then the mapping confidence is <confidence>

    Examples:
      | keyword_1       | keyword_2       | confidence |
      | prompt injection | instruction override | high |
      | prompt injection | routine operation    | low  |

  # SP2-CAT-04
  Scenario: SP2-CAT-04 N/A reconciliation flags contradiction when catalog matches N/A slot
    Given an N/A slot with na_justification no hazard applicable
    And the control action description contains prompt injection
    When N/A reconciliation is performed
    Then a contradiction flag is raised for the slot

  # SP2-CAT-05
  Scenario: SP2-CAT-05 N/A reconciliation passes when no catalog match for N/A slot
    Given an N/A slot with na_justification action is atomic and stateless
    And the control action description contains routine validation
    When N/A reconciliation is performed
    Then no contradiction flag is raised for the slot

  # SP2-CAT-06
  Scenario: SP2-CAT-06 coverage analysis produces three-way partition
    Given an ICA enumeration with 10 total slots, 7 non-N/A and 3 N/A
    And 4 non-N/A ICAs have catalog mappings and 3 do not
    When coverage analysis is computed
    Then the structural coverage total_slots is 10
    And the structural coverage non_na is 7
    And the structural coverage na is 3
    And the catalog correspondence structural_with_match is 4
    And the catalog correspondence structural_unmapped is 3
    And the catalog correspondence catalog_only_supplements is 0

  # SP2-CAT-07
  Scenario: SP2-CAT-07 coverage analysis partitions by ICA type
    Given an ICA enumeration with 4 NOT_PROVIDED ICAs, 3 INCORRECT ICAs, 1 WRONG_TIMING ICA, and 0 WRONG_DURATION ICAs
    When coverage analysis is computed
    Then by_ica_type has NOT_PROVIDED 4
    And by_ica_type has INCORRECT 3
    And by_ica_type has WRONG_TIMING 1
    And by_ica_type has WRONG_DURATION 0

  # SP2-CAT-08
  Scenario: SP2-CAT-08 coverage analysis partitions by controller
    Given an ICA enumeration with 5 ICAs from RESP-1, 3 ICAs from RESP-2, and 2 ICAs from CL-1
    When coverage analysis is computed
    Then by_controller has RESP-1 5
    And by_controller has RESP-2 3
    And by_controller has CL-1 2

  # SP2-CAT-09
  Scenario: SP2-CAT-09 structural consideration metric counts considered slots
    Given an ICA enumeration with 10 total slots where 7 have ICAs and 3 are N/A with justification
    When coverage analysis is computed
    Then structural_consideration total_slots is 10
    And structural_consideration considered is 10
    And structural_consideration rate is 1.0

  # SP2-CAT-10
  Scenario: SP2-CAT-10 N/A quality metric counts structural keyword citations
    Given an ICA enumeration with 4 N/A slots where 3 have structural keywords in na_justification
    When coverage analysis is computed
    Then na_quality na_count is 4
    And na_quality quality_count is 3
    And na_quality quality_rate is 0.75

  # SP2-CAT-11
  Scenario: SP2-CAT-11 uncovered OWASP threats are listed
    Given an ICA enumeration where no ICA matches OWASP threat T10 or T15
    When coverage analysis is computed
    Then uncovered_owasp_threats includes T10
    And uncovered_owasp_threats includes T15
    And uncovered_reason is not empty

  # SP2-CAT-12
  Scenario: SP2-CAT-12 catalog enrichment makes no LLM calls
    Given an ICA enumeration with 5 non-N/A ICAs and 2 N/A slots
    When catalog enrichment is performed
    Then no LLM calls are made

  # SP2-CAT-13
  Scenario: SP2-CAT-13 structural threats carry provenance structural
    Given an ICA enumeration with 3 non-N/A ICAs
    When enriched threat set is built from the ICA enumeration
    Then every structural threat has provenance structural
    And the number of structural threats equals the number of non-N/A ICAs

  # SP2-CAT-14
  Scenario: SP2-CAT-14 N/A reconciliation flags are recorded in coverage analysis
    Given an ICA enumeration with 1 N/A slot that has a catalog contradiction
    When catalog enrichment and coverage analysis are computed
    Then the coverage analysis na_reconciliation_flags has 1 entry

  # SP2-CAT-15
  Scenario: SP2-CAT-15 enriched threat set validates against the EnrichedThreatSet schema
    Given an ICA enumeration with 2 non-N/A ICAs and 1 N/A slot
    When enriched threat set is built from the ICA enumeration
    Then the enriched threat set validates successfully
