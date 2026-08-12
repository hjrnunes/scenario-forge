# mutation-stamp: sha256=92bec1ea36f1177cdde9aebdd5493c8fa06c7f76f0c50c047283f132a82243ea
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T09:14:58.370154Z","feature_name":"SP1 Stage 2 \u2014 Next-available coordination-mechanism number in the revision prompt","feature_path":"features/critic-revision-fix/revision-next-cm-id.feature","background_hash":"904fafbfcb46d08fb523ef34fb80bd71c432c1128f210bc4b0be5487c71220a5","implementation_hash":"sha256:c8469d6f7ed85c2864621c29afcf6d0d4a0fe9bb5e0aae229fba28ba71501de6","scenarios":[{"index":1,"name":"CRNextCm-02 next_cm_num is one past the highest existing coordination-mechanism number","scenario_hash":"9b134523d62e9b94af2af5260cfc48bfb79bf8b96970b7b07a61ded8df3bcaad","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:14:58.370154Z"},{"index":2,"name":"CRNextCm-03 next_cm_num is computed independently of next_cl_num","scenario_hash":"c77b779a39fbad8f7be80aa5120e014549fafa9ca102ab84bfe5fb2eb548eb8a","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:46.716555Z"},{"index":3,"name":"CRNextCm-04 revision_system.j2 states the previously unstated ID rules","scenario_hash":"6a27c812b3b213211d03e673e2a4a39e513896a9ce4f8077ff004ee8484efb5b","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:46.716555Z"},{"index":4,"name":"CRNextCm-05 the rendered revision system prompt states the concrete next mechanism number","scenario_hash":"5c74712b852d6588560385af8ea7946da8b9597cdb1fa916fe71932455a792df","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:46.716555Z"}]}
# acceptance-mutation-manifest-end

# critic-revision-fix / revision-next-cm-id
Feature: SP1 Stage 2 — Next-available coordination-mechanism number in the revision prompt
  _compute_next_ids tells the revision model the next available number
  for responsibilities, coordination links, and controlled processes,
  but not for coordination mechanisms. cm_id is therefore the only
  identifier the model has to guess, which is why the Airbnb cm_id
  collision was systematic (4 of 4 runs, two backends) rather than
  stochastic.

  _compute_next_ids gains a next_cm_num key derived from the nested
  coordination_mechanism.cm_id of every existing coordination link, and
  revision_system.j2 states it alongside the existing next-number
  guidance. next_cm_num is computed independently of next_cl_num: a
  structure may number its mechanisms differently from its links, and
  the two must not be assumed to agree.

  The _renumber_colliding_cm_ids repair path and the merge degradation
  guard stay exactly as they are. This change is intended to make that
  repair path a rare safety net rather than a routinely exercised
  repair; whether it actually does so is a question for a live run, not
  for these scenarios. "none" in the table below means the control
  structure has no coordination links at all.

  Background:
    Given the STPA system model critic module is importable

  # CRNextCm-01
  Scenario: CRNextCm-01 _compute_next_ids returns a next_cm_num key
    Given a control structure with responsibilities RESP-1 and RESP-2 is available
    When the next available ID numbers are computed
    Then the computed next-ID mapping has a next_cm_num key

  # CRNextCm-02
  Scenario Outline: CRNextCm-02 next_cm_num is one past the highest existing coordination-mechanism number
    Given a control structure whose coordination links carry the coordination mechanisms <existing_cm_ids>
    When the next available ID numbers are computed
    Then next_cm_num is <expected_next_cm_num>

    Examples:
      | existing_cm_ids  | expected_next_cm_num |
      | none             | 1                    |
      | CM-1             | 2                    |
      | CM-1, CM-2       | 3                    |
      | CM-2, CM-1       | 3                    |
      | CM-7             | 8                    |
      | CM-1, CM-4, CM-2 | 5                    |

  # CRNextCm-03
  Scenario Outline: CRNextCm-03 next_cm_num is computed independently of next_cl_num
    Given a control structure whose coordination link <link_id> carries the coordination mechanism <cm_id>
    When the next available ID numbers are computed
    Then next_cl_num is <expected_next_cl_num>
    And next_cm_num is <expected_next_cm_num>

    Examples:
      | link_id | cm_id | expected_next_cl_num | expected_next_cm_num |
      | CL-1    | CM-9  | 2                    | 10                   |
      | CL-6    | CM-1  | 7                    | 2                    |
      | CL-3    | CM-3  | 4                    | 4                    |

  # CRNextCm-04
  Scenario Outline: CRNextCm-04 revision_system.j2 states the previously unstated ID rules
    Given the template revision_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                    |
      | New coordination mechanisms |
      | CM-{next_cm_num}            |
      | {{ next_cm_num }}           |
      | New controlled processes    |
      | CP-{next_cp_num}            |
      | {{ next_cp_num }}           |

  # CRNextCm-05
  Scenario Outline: CRNextCm-05 the rendered revision system prompt states the concrete next mechanism number
    Given a control structure whose coordination link <link_id> carries the coordination mechanism <cm_id>
    When the revision system prompt is rendered
    Then the rendered text contains the next available coordination mechanism number <expected_next_cm_num>

    Examples:
      | link_id | cm_id | expected_next_cm_num |
      | CL-1    | CM-1  | 2                    |
      | CL-1    | CM-4  | 5                    |

  # CRNextCm-06
  Scenario: CRNextCm-06 run_revision renders the system prompt without an undefined-variable error
    Given a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging
    And an LLM that returns a valid RevisionDelta
    When the revision is run
    Then the pipeline does not crash
    And the revision system prompt sent to the LLM contains a coordination mechanism next number

  # CRNextCm-07
  Scenario: CRNextCm-07 the cm_id collision repair path is retained
    Given a control structure with responsibilities RESP-1 and RESP-2 is available
    And the control structure has coordination links CL-1 with CM-1 and CL-2 with CM-2
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging
    And an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the final control structure has no duplicate cm_id values
    And the warnings list includes a warning that mentions CM-1
