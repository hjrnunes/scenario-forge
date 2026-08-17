# mutation-stamp: sha256=883a0b0d7feae4f74f3eb879d56939b005b53ddd0a4e15a25a58d38fdba23482
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T09:14:59.647513Z","feature_name":"SP1 Stage 2 \u2014 Revision prompt shows the structure it is asked to extend","feature_path":"features/critic-revision-fix/revision-prompt-context.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"sha256:1a5f8a6e0bfd7c0844f0d1bd86a91beef92f86c6b7a0b283bd485fa895e4ea38","scenarios":[{"index":3,"name":"CRRevCtx-04 the rendered revision system prompt shows nested element descriptions","scenario_hash":"97f232b15127635ae687d5716401083ce3c734d2c7118c580dd7f4c7fbaba376","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:14:59.647513Z"},{"index":0,"name":"CRRevCtx-01 revision_system.j2 renders each nested element with its description","scenario_hash":"5707996f90a4d35afd749c0d812bcbc574c9a861af459b328bc0763dd5fffada","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:52.320595Z"},{"index":1,"name":"CRRevCtx-02 revision_system.j2 renders the reference each new element must connect to","scenario_hash":"09f9b216ba31d97b7aeb613d6d65c844ef206558bf2ad6bce1a3c99551b74b31","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:52.320595Z"},{"index":2,"name":"CRRevCtx-03 revision_system.j2 no longer renders nested elements as bare identifier lists","scenario_hash":"086451b797900144c0466954d46a2f84b80d3e81a211f7fb058a8e4d9a3ff241","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:52.320595Z"},{"index":5,"name":"CRRevCtx-06 revision_user.j2 no longer duplicates the control-structure listing","scenario_hash":"25852b4a63645f88c635abb1398cfe17b0672fee776af0edbb6a42da41ae9061","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:52.320595Z"},{"index":6,"name":"CRRevCtx-07 revision_user.j2 keeps the critic findings listing","scenario_hash":"95649c66e70a406ca1a2cc0647795888611a7f9d69d1cd4d424869ca5149aa37","mutation_count":7,"result":{"Total":7,"Killed":7,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:52.320595Z"},{"index":8,"name":"CRRevCtx-09 revision_system.j2 keeps the existing delta and ID rules","scenario_hash":"93988cac1c8348901cd7ed551fa229a1fe6251072340f943c1f3230706b81e5f","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:52.320595Z"}]}
# acceptance-mutation-manifest-end

# critic-revision-fix / revision-prompt-context
Feature: SP1 Stage 2 — Revision prompt shows the structure it is asked to extend
  revision_system.j2 and revision_user.j2 both list the control
  structure, and both list nested elements as bare identifiers. The
  revision model is asked to add elements that "connect properly" while
  being shown neither what the existing feedback channels report nor
  where the existing control actions point.

  The control-structure listing lives in revision_system.j2 only, and it
  renders every nested element with its description plus the reference
  that makes connection possible: each process model part's feedback
  source, each control action's target, and each feedback channel's
  source and the process model part it updates. revision_user.j2 carries
  the critic findings and the task, and no longer duplicates the
  structure listing.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # CRRevCtx-01
  Scenario Outline: CRRevCtx-01 revision_system.j2 renders each nested element with its description
    Given the template revision_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                        |
      | {% for rc in resp.responsibility_constraints %} |
      | {{ rc.rc_id }}: {{ rc.description }}            |
      | {% for pm in resp.process_model_parts %}        |
      | {{ pm.pm_id }}: {{ pm.description }}            |
      | {% for ca in resp.control_actions %}            |
      | {{ ca.ca_id }}: {{ ca.description }}            |
      | {% for fb in resp.feedback_channels %}          |
      | {{ fb.fb_id }}: {{ fb.description }}            |

  # CRRevCtx-02
  Scenario Outline: CRRevCtx-02 revision_system.j2 renders the reference each new element must connect to
    Given the template revision_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                    |
      | {{ pm.feedback_source.type }}               |
      | {{ ca.target.type }}                        |
      | {{ fb.source.type }}                        |
      | {{ fb.updates }}                            |
      | {{ cl.coordination_mechanism.description }} |

  # CRRevCtx-03
  Scenario Outline: CRRevCtx-03 revision_system.j2 no longer renders nested elements as bare identifier lists
    Given the template revision_system.j2 is loaded
    Then the template text does not contain "<fragment>"

    Examples:
      | fragment               |
      | map(attribute='pm_id') |
      | map(attribute='ca_id') |
      | map(attribute='fb_id') |

  # CRRevCtx-04
  Scenario Outline: CRRevCtx-04 the rendered revision system prompt shows nested element descriptions
    Given a control structure whose <element_id> has the description "<element_description>"
    When the revision system prompt is rendered
    Then the rendered text contains "<element_id>: <element_description>"

    Examples:
      | element_id | element_description                     |
      | PM-1-1     | belief about retrieval source integrity |
      | CA-1-1     | reject unverified retrieved content     |
      | FB-1-1     | provenance verdict from the index       |

  # CRRevCtx-05
  Scenario: CRRevCtx-05 the revision system prompt renders when a nested reference is absent
    Given a control structure whose PM-1-1 has no feedback source
    When the revision system prompt is rendered
    Then the rendering succeeds
    And the rendered text does not contain an unrendered Jinja expression

  # CRRevCtx-06
  Scenario Outline: CRRevCtx-06 revision_user.j2 no longer duplicates the control-structure listing
    Given the template revision_user.j2 is loaded
    Then the template text does not contain "<fragment>"

    Examples:
      | fragment                                             |
      | ## Current Control Structure                         |
      | {% for resp in control_structure.responsibilities %} |
      | use_case_text                                        |

  # CRRevCtx-07
  Scenario Outline: CRRevCtx-07 revision_user.j2 keeps the critic findings listing
    Given the template revision_user.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                               |
      | ## Critic Findings                     |
      | {% for gap in critic_findings.gaps %}  |
      | {{ gap.gap_type }}                     |
      | {{ gap.related_attack_path }}          |
      | {{ gap.suggested_remedy }}             |
      | critic_findings.checklist_results      |
      | critic_findings.taxonomy_probe_results |

  # CRRevCtx-08
  Scenario: CRRevCtx-08 the revision system prompt drops the unexplained STPA-Sec framing
    Given the template revision_system.j2 is loaded
    Then the template text does not contain "STPA-Sec"

  # CRRevCtx-09
  Scenario Outline: CRRevCtx-09 revision_system.j2 keeps the existing delta and ID rules
    Given the template revision_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                                                           |
      | ## ID format rules                                                                 |
      | RESP-{next_resp_num}                                                               |
      | CL-{next_cl_num}                                                                   |
      | Do NOT restate the entire control structure                                        |
      | modified_responsibilities list must contain ONLY responsibilities you are CHANGING |
      | solution-neutrality                                                                |
      | ElementRef references must be valid                                                |
      | feedback channel updates must reference a PM in the same responsibility            |

  # CRRevCtx-10
  Scenario: CRRevCtx-10 the revision system prompt renders with no unrendered Jinja expression
    Given a control structure with responsibilities RESP-1 and RESP-2 is available
    When the revision system prompt is rendered
    Then the rendering succeeds
    And the rendered text does not contain an unrendered Jinja expression
