# stpa-report-attack-tree-visual
Feature: STPA Report Attack Tree Visualization
  The attack tree in each scenario card is rendered as a visual tree using
  nested divs with connector lines. Branch nodes are color-coded by
  branch category: controller_side=blue, path_side=green,
  coordination_gap=orange.

  Background:
    Given a combined output directory containing scenario SCN-001.yaml with an attack tree:
      | node_id   | label                    | category          | gate |
      | root      | Attack goal              |                   | OR   |
      | branch-1  | Controller-side bypass   | controller_side   | AND  |
      | branch-2  | Path-side exploitation    | path_side         | AND  |
      | branch-3  | Coordination gap          | coordination_gap  | AND  |
      | leaf-1    | Inject malicious prompt  |                   | LEAF |

  Scenario: Attack tree renders as nested divs with connector lines
    When I generate the STPA report
    Then the scenario card for "SCN-001" contains an attack tree rendered as nested divs
    And the attack tree contains connector lines between parent and child nodes

  Scenario: Attack tree color-codes branches by category
    When I generate the STPA report
    Then the attack tree node "branch-1" has a blue color for category "controller_side"
    And the attack tree node "branch-2" has a green color for category "path_side"
    And the attack tree node "branch-3" has an orange color for category "coordination_gap"

  Scenario: Attack tree shows gate badges on branch nodes
    When I generate the STPA report
    Then the attack tree node "root" shows a gate badge "OR"
    And the attack tree node "branch-1" shows a gate badge "AND"
    And the attack tree node "leaf-1" shows a gate badge "LEAF"

  Scenario: Attack tree handles empty tree gracefully
    Given scenario SCN-002.yaml with an empty attack tree
    When I generate the STPA report
    Then the scenario card for "SCN-002" shows a placeholder message for the empty attack tree
