# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T09:16:14.435321Z","feature_name":"SP1 Stage 2 \u2014 Revision trigger considers all three critic probes","feature_path":"features/critic-revision-fix/critic-gap-detection.feature","background_hash":"904fafbfcb46d08fb523ef34fb80bd71c432c1128f210bc4b0be5487c71220a5","implementation_hash":"sha256:f35f8a41c84d3f620cec57156b5fa9571dc22e7ee5ad6bdb0880f969fe8a7314","scenarios":[]}
# acceptance-mutation-manifest-end

# critic-revision-fix / critic-gap-detection
Feature: SP1 Stage 2 — Revision trigger considers all three critic probes
  The completeness critic runs three probes and reports each in its own
  field of CriticFindings: probe 1 fills checklist_results, probe 2
  fills taxonomy_probe_results, and probe 3 (the adversarial probe)
  fills the gaps list.

  has_unjustified_gaps decides whether the revision call happens, and it
  reads only checklist_results. A run where the generic checklist is
  clean but the adversarial probe found three exploitable gaps, or where
  a taxonomy probe reported absent_unjustified, therefore skipped
  revision entirely — the critic's most system-specific findings were
  computed, logged, and discarded.

  has_unjustified_gaps must consider all three sources. Any
  absent_unjustified checklist result, any absent_unjustified taxonomy
  probe result, or any entry in the gaps list triggers revision. A
  findings object clean on all three does not. "none" in the tables
  below means the corresponding dict is empty.

  Background:
    Given the STPA system model critic module is importable

  # CRGap-01
  Scenario Outline: CRGap-01 any probe reporting an unaddressed gap triggers revision
    Given CriticFindings whose checklist_results are <checklist_statuses>
    And CriticFindings whose taxonomy_probe_results are <taxonomy_statuses>
    And CriticFindings with <gap_count> adversarial gaps
    Then revision is <revision_outcome>

    Examples:
      | checklist_statuses                   | taxonomy_statuses                    | gap_count | revision_outcome |
      | absent_unjustified                   | none                                 | 0         | triggered        |
      | present, absent_unjustified          | none                                 | 0         | triggered        |
      | absent_justified, absent_unjustified | none                                 | 0         | triggered        |
      | present                              | absent_unjustified                   | 0         | triggered        |
      | present                              | present, absent_unjustified          | 0         | triggered        |
      | present                              | absent_justified, absent_unjustified | 0         | triggered        |
      | present                              | present                              | 1         | triggered        |
      | present                              | present                              | 3         | triggered        |
      | none                                 | none                                 | 2         | triggered        |
      | present                              | present                              | 0         | not triggered    |
      | absent_justified                     | absent_justified                     | 0         | not triggered    |
      | present, absent_justified            | present, absent_justified            | 0         | not triggered    |
      | none                                 | none                                 | 0         | not triggered    |

  # CRGap-02
  Scenario: CRGap-02 default-constructed CriticFindings do not trigger revision
    Given empty CriticFindings
    Then revision is not triggered

  # CRGap-03
  Scenario: CRGap-03 a failed critic call does not trigger revision
    Given a control structure with responsibilities RESP-1 and RESP-2 is available
    And a capability profile and use-case text are available
    And a run directory for call logging
    And an LLM whose critic call fails
    When the completeness critic is run
    Then revision is not triggered
