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
