Feature: Runtime split migration atomicity
  The migration publishes a complete registry or no registry and supports
  rollback to the unchanged facade when structural checks fail.
  These checks use local source and subprocess probes only; live LLM checks are SKIP.

  Background:
    Given the runtime split migration is exercised in an isolated copy

  # Runtime split migration atomicity — 01 manifest is complete and ordered
  Scenario: Runtime split migration atomicity — 01 manifest is complete and ordered
    When the runtime module manifest is loaded
    Then it contains the declared modules in one deterministic order
    And every module exposes one register function and one feature identifier
    And no feature module imports acceptance_runtime during initialization

  # Runtime split migration atomicity — 02 staged registration publishes atomically
  Scenario: Runtime split migration atomicity — 02 staged registration publishes atomically
    When a manifest module raises during registration
    Then startup fails with the module name and registration error
    And STEP_PATTERNS and _REGISTERED_PATTERN_KEYS remain empty
    And no generated entrypoint observes partial registration

  # Runtime split migration atomicity — 03 rollback restores baseline
  Scenario: Runtime split migration atomicity — 03 rollback restores baseline
    When API, registry, IR-resolution, or baseline validation fails
    Then the split is rejected
    And the previous facade commit remains the rollback target
    And no application source, prompt, or generated acceptance artifact changes

  # Runtime split migration atomicity — 04 source ownership is explicit
  Scenario: Runtime split migration atomicity — 04 source ownership is explicit
    When the runtime and manifest are inspected with an AST parser
    Then acceptance_runtime.py contains only facade, registry, execution, exports, and manifest loading
    And every registered handler is defined in exactly one feature module
    And shared World state and helpers are defined in runtime_shared.py
    And no blind line-range split or duplicate handler definition exists

  # Runtime split migration atomicity — 05 the 39 jrds cleanup invariants survive
  Scenario: Runtime split migration atomicity — 05 the 39 jrds cleanup invariants survive
    When the canonical 39-entry DEAD_REGISTRATIONS inventory is checked
    Then none of its pattern, handler, and registration-function tuples is registered
    And all 12 Class B live-handler verdicts select the expected handlers
    And _h_rev_revision_run and _h_sp1_rev_run remain retained for delegation
    And both property tests pass without xfail or xpass
