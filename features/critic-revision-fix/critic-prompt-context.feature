# mutation-stamp: sha256=4c85c38971fc2f15e21c48191b72335ad310bbed03ad78ee9f5580ab62b8aa4f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T09:14:55.673673Z","feature_name":"SP1 Stage 2 \u2014 Critic prompt shows what the control structure actually does","feature_path":"features/critic-revision-fix/critic-prompt-context.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"sha256:36c4126a8b7f2cd539a049a1b4a6f47f1c468e054570d88c14cf2b1a68851635","scenarios":[{"index":2,"name":"CRCtx-03 the rendered critic user prompt shows nested element descriptions","scenario_hash":"24174f82702ff38618e86e504e255b31528adf12f7f04dbf5ba4972b96fd1593","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:14:55.673673Z"},{"index":0,"name":"CRCtx-01 critic_user.j2 renders each nested element with its description","scenario_hash":"abdaab06f2f591022522060465a8f03e01a9fc3f9beac0ff888fda5ab6aa745b","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":1,"name":"CRCtx-02 critic_user.j2 no longer renders nested elements as bare identifier lists","scenario_hash":"09dff487f4904382282510926c4074a481f5b37d3dfc5135dca5707c9b118856","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":3,"name":"CRCtx-04 critic_user.j2 renders the loss analysis using the LossAnalysis field names","scenario_hash":"85323574988273c88dac815baadadf2d960ec755b2e115ec85a6b1baea14cab1","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":4,"name":"CRCtx-05 the rendered critic user prompt shows the loss analysis content","scenario_hash":"f0ecc2767baea45c68c7531cccc9cde3c037ee0ca7880c1e5e92df65e6fa187d","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":6,"name":"CRCtx-07 critic_user.j2 has an optional coordination-analysis warnings section","scenario_hash":"2840d05c880fe7e7f2ed12092045fdf65dc2343909f058c426c31a6dc67226b1","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":9,"name":"CRCtx-10 run_completeness_critic accepts the new optional context parameters","scenario_hash":"5e7a3d2a27b044a059d93a2a4d3bb728d2022089f8e3e75fc24f4a2cd22a7bec","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":10,"name":"CRCtx-11 run_completeness_critic passes the new context into the template","scenario_hash":"1d4d64f378a94f94f31b9faa56c62e85a7e940e4657785e70bb7b38aae8b9be7","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":12,"name":"CRCtx-13 critic_system.j2 states the false-positive guidance","scenario_hash":"9be972bdda1c2d9fd474a1677c66b1efd9b3da288749df0ce5646ea1ac03a6e0","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":13,"name":"CRCtx-14 critic_system.j2 keeps the existing probe and output contract","scenario_hash":"a0c18986297322ab0e8794cf2015c87d0d8a379c2d13516cdce4d15d6365df7d","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":14,"name":"CRCtx-15 critic_user.j2 keeps the existing use-case and capability-profile context","scenario_hash":"1788d5c49ee49ca2b8764d52759fe1c34a1c5168c7223c641b7e5ee1e3dbba2b","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"},{"index":15,"name":"CRCtx-16 the SP1 orchestrator wires the new context into the critic call","scenario_hash":"13c9acad6c9d530893cc70294499f5d350296d3ff8274777487849788303f435","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:39.430271Z"}]}
# acceptance-mutation-manifest-end

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
