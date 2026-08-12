# mutation-stamp: sha256=1c17e9c90870485be2281114d57f5d86bc7c6da2f35da7cee854b5960de1d8ef
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T15:41:36.926501Z","feature_name":"Runtime split registry semantics","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/acceptance/features/runtime-split/registry.feature","background_hash":"290e5bc497c7011341a39e050c82da8ffcce6171518c9910c5c194f672de68a2","implementation_hash":"unknown","scenarios":[{"index":2,"name":"Runtime split registry semantics — 03 feature tags scope matching","scenario_hash":"6131ba6d8c93a12689249ac2ec17de453bdab403c438e9beb0a3570c2d16cd0c","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-12T15:41:36.926501Z"}]}
# acceptance-mutation-manifest-end

Feature: Runtime split registry semantics
  The facade owns the ordered registry and feature modules register only
  through its explicit registration API.
  These checks use local handlers and subprocesses only; live LLM checks are SKIP.

  Background:
    Given the runtime split registry is isolated in a fresh process

  # Runtime split registry semantics — 01 append and priority semantics are stable
  Scenario: Runtime split registry semantics — 01 append and priority semantics are stable
    When one global entry is submitted through both priority paths
    Then _register appends its entry after existing entries
    And _register_first inserts its entry at index 0
    And first-match lookup selects the _register_first handler

  # Runtime split registry semantics — 02 repeated priority semantics are stable
  Scenario: Runtime split registry semantics — 02 repeated priority semantics are stable
    When the front-priority API is invoked twice for one raw pattern
    Then the later front-priority call is first in lookup order
    When the append API receives a duplicate raw pattern
    Then the earlier append remains first in lookup order

  # Runtime split registry semantics — 03 feature tags scope matching
  Scenario: Runtime split registry semantics — 03 feature tags scope matching
    When two feature modules register the same raw pattern with different feature tags
    And an IR file for feature tag <tag> executes the witness step
    Then only the handler tagged <tag> is eligible
    And the other feature handler cannot hijack the step

    Examples:
      | tag |
      | sp2 |
      | sp3 |
      | acceptance_refresh |
      | shadow_cleanup |

  # Runtime split registry semantics — 04 duplicate keys are rejected
  Scenario: Runtime split registry semantics — 04 duplicate keys are rejected
    When one exact raw-pattern, handler, and scope key is submitted twice
    Then the second registration raises RuntimeError
    And the registry digest is unchanged

  # Runtime split registry semantics — 05 same-scope raw conflicts are detected
  Scenario: Runtime split registry semantics — 05 same-scope raw conflicts are detected
    When two different handlers are registered for the same raw pattern in one scope
    Then find_pattern_conflicts returns the deterministic witness tuple
    When the handlers are placed in different feature scopes
    Then find_pattern_conflicts returns an empty list

  # Runtime split registry semantics — 06 omitted module is not silently accepted
  Scenario: Runtime split registry semantics — 06 omitted module is not silently accepted
    When one module is deliberately omitted from the manifest in a fresh subprocess
    Then manifest validation fails before staged registration is published
    And its representative IR is not reported as passing

  # Runtime split registry semantics — 07 duplicate registration is not silently accepted
  Scenario: Runtime split registry semantics — 07 duplicate registration is not silently accepted
    When one manifest register function is deliberately invoked twice
    Then the second invocation fails with the duplicate-registration guard
    And no partial registry is visible

  # Runtime split registry semantics — 08 helper delegation remains callable
  Scenario: Runtime split registry semantics — 08 helper delegation remains callable
    When the live revision handler delegates to the retained revision helper chain
    Then _h_rev_revision_run and _h_sp1_rev_run remain callable through the facade
    And the log-capture wrapper preserves the revision outcome
