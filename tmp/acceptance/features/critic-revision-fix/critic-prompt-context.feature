# critic-revision-fix / critic-prompt-context
Feature: SP1 Stage 2 — Critic prompt shows what the control structure actually does
  critic_user.j2 lists each responsibility's nested elements as bare
  identifiers: "PM parts: PM-1-1, PM-1-2". The critic is asked whether
  the process model tracks the right information and whether feedback
  arrives from the right source, but is shown only that some element
  with some identifier exists. It can judge structural presence and
  nothing else.

  The critic prompt must render the description of every nested element
  — responsibility constraints, process model parts, control actions,
  feedback channels — and the coordination mechanism behind each link.
  It must also show the loss analysis, so the critic can ask whether the
  control structure addresses the identified hazards rather than whether
  it resembles a generic control structure, and any integrity findings
  raised by the coordination analysis.

  Loss analysis and coordination warnings are optional inputs. The
  template loader uses StrictUndefined, so run_completeness_critic
  always supplies both keys and the template renders a stated fallback
  when either is absent.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # CRCtx-01
  Scenario Outline: CRCtx-01 critic_user.j2 renders each nested element with its description
    Given the template critic_user.j2 is loaded
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
      | {{ cl.coordination_mechanism.cm_id }}           |
      | {{ cl.coordination_mechanism.description }}     |

  # CRCtx-02
  Scenario Outline: CRCtx-02 critic_user.j2 no longer renders nested elements as bare identifier lists
    Given the template critic_user.j2 is loaded
    Then the template text does not contain "<fragment>"

    Examples:
      | fragment               |
      | map(attribute='pm_id') |
      | map(attribute='ca_id') |
      | map(attribute='fb_id') |

  # CRCtx-03
  Scenario Outline: CRCtx-03 the rendered critic user prompt shows nested element descriptions
    Given a control structure whose <element_id> has the description "<element_description>"
    When the critic user prompt is rendered
    Then the rendered text contains "<element_id>: <element_description>"

    Examples:
      | element_id | element_description                     |
      | RC-1-1     | retrieved content must carry provenance |
      | PM-1-1     | belief about retrieval source integrity |
      | CA-1-1     | reject unverified retrieved content     |
      | FB-1-1     | provenance verdict from the index       |

  # CRCtx-04
  Scenario Outline: CRCtx-04 critic_user.j2 renders the loss analysis using the LossAnalysis field names
    Given the template critic_user.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                  |
      | {% if loss_analysis %}                    |
      | loss_analysis.risk_card_losses            |
      | loss_analysis.use_case_losses             |
      | {% for hazard in loss_analysis.hazards %} |
      | hazard.related_losses                     |
      | loss_analysis.security_constraints        |
      | {{ sc.constraint_id }}                    |
      | sc.related_hazards                        |

  # CRCtx-05
  Scenario Outline: CRCtx-05 the rendered critic user prompt shows the loss analysis content
    Given a loss analysis containing loss L-1, hazard H-1, and security constraint SC-1
    When the critic user prompt is rendered
    Then the rendered text contains "<fragment>"

    Examples:
      | fragment                                          |
      | **L-1**                                           |
      | **H-1**                                           |
      | **SC-1**                                          |
      | Unauthorised disclosure of customer records       |
      | Retrieval returns records outside the session scope |
      | Retrieval must be scoped to the active session    |

  # CRCtx-06
  Scenario: CRCtx-06 the critic user prompt renders when no loss analysis is available
    Given no loss analysis is available
    When the critic user prompt is rendered
    Then the rendering succeeds
    And the rendered text contains "Loss analysis not available"
    And the rendered text does not contain an unrendered Jinja expression

  # CRCtx-07
  Scenario Outline: CRCtx-07 critic_user.j2 has an optional coordination-analysis warnings section
    Given the template critic_user.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                            |
      | {% if call3_warnings %}             |
      | Coordination Analysis Warnings      |
      | {% for warning in call3_warnings %} |

  # CRCtx-08
  Scenario: CRCtx-08 coordination-analysis warnings appear in the rendered critic user prompt
    Given a coordination analysis warning "CL-2 shares a process model part outside its source responsibility"
    When the critic user prompt is rendered
    Then the rendered text contains "Coordination Analysis Warnings"
    And the rendered text contains "CL-2 shares a process model part outside its source responsibility"

  # CRCtx-09
  Scenario: CRCtx-09 the warnings section is omitted when there are no coordination-analysis warnings
    Given no coordination analysis warnings are available
    When the critic user prompt is rendered
    Then the rendering succeeds
    And the rendered text does not contain "Coordination Analysis Warnings"

  # CRCtx-10
  Scenario Outline: CRCtx-10 run_completeness_critic accepts the new optional context parameters
    Given the run_completeness_critic function signature is inspected
    Then the function accepts a <parameter_name> parameter with default None

    Examples:
      | parameter_name |
      | loss_analysis  |
      | call3_warnings |

  # CRCtx-11
  Scenario Outline: CRCtx-11 run_completeness_critic passes the new context into the template
    Given a run directory for call logging
    And a capability profile and use-case text are available
    And an LLM that returns a valid CriticFindings JSON
    And a loss analysis containing loss L-1, hazard H-1, and security constraint SC-1
    And a coordination analysis warning "CL-2 shares a process model part outside its source responsibility"
    When the completeness critic is run with the loss analysis and coordination warnings
    Then the critic user prompt sent to the LLM contains "<fragment>"

    Examples:
      | fragment                                                          |
      | **L-1**                                                           |
      | **H-1**                                                           |
      | **SC-1**                                                          |
      | CL-2 shares a process model part outside its source responsibility |

  # CRCtx-12
  Scenario: CRCtx-12 the critic system prompt drops the unexplained STPA-Sec framing
    Given the template critic_system.j2 is loaded
    Then the template text does not contain "STPA-Sec"

  # CRCtx-13
  Scenario Outline: CRCtx-13 critic_system.j2 states the false-positive guidance
    Given the template critic_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                                               |
      | ## False positive guidance                                             |
      | Not every system needs every capability                                |
      | the capability IS present but the control structure fails to govern it |

  # CRCtx-14
  Scenario Outline: CRCtx-14 critic_system.j2 keeps the existing probe and output contract
    Given the template critic_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                    |
      | ## Probe 1                  |
      | ## Probe 2                  |
      | ## Probe 3                  |
      | absent_unjustified          |
      | checklist_results           |
      | taxonomy_probe_results      |
      | Do NOT suggest specific IDs |
      | {% if taxonomy_probes %}    |

  # CRCtx-15
  Scenario Outline: CRCtx-15 critic_user.j2 keeps the existing use-case and capability-profile context
    Given the template critic_user.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                        |
      | {{ use_case_text }}             |
      | capability_profile.zones_active |
      | capability_profile.kc_subcodes  |
      | capability_profile.entry_points |
      | ## Your Task                    |

  # CRCtx-16
  Scenario Outline: CRCtx-16 the SP1 orchestrator wires the new context into the critic call
    Given the SP1 orchestrator run.py is inspected
    Then the run_completeness_critic call in _run_stage_2_block passes the <parameter_name> argument

    Examples:
      | parameter_name  |
      | loss_analysis   |
      | call3_warnings  |
