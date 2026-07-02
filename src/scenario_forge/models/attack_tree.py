"""Pydantic models for the Attack Tree artifact.

AND/OR attack tree produced by Call 2 of the scenario generation pipeline.
Each tree decomposes a single abstract attack pattern seed into a hierarchical
set of attack steps with logical gates, zone annotations, taxonomy
references, and structural exposure signals.

Design lineage:
  - AND/OR gate semantics from MITRE Attack Flow conceptual model
  - 3-5 level depth per Schneider's examples
  - Structural exposure types from Schneider Part 2 (micro simulations)
  - Zones from Schneider's five-zone model
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class GateType(str, Enum):
    """Logical gate type for attack tree nodes."""

    AND = "AND"
    OR = "OR"
    LEAF = "LEAF"


class StructuralExposure(str, Enum):
    """Structural weakness pattern at a node, per Schneider's criteria."""

    single_point_of_failure = "single_point_of_failure"
    convergence_point = "convergence_point"
    probabilistic_control = "probabilistic_control"
    defense_in_depth_claim = "defense_in_depth_claim"


class EvidenceLevel(str, Enum):
    """How well-evidenced an attack step is."""

    assumed = "assumed"
    design_reviewed = "design-reviewed"
    lab_validated = "lab-validated"
    end_to_end_validated = "end-to-end-validated"
    regression_tested = "regression-tested"


# ---------------------------------------------------------------------------
# Node model (recursive)
# ---------------------------------------------------------------------------


class AttackTreeNode(BaseModel):
    """A node in the AND/OR attack tree.

    Nodes carry zone annotation, threat/technique IDs, MAESTRO layer,
    control point, structural exposure type, and evidence level.
    """

    id: str = Field(
        description="Dotted path identifier reflecting tree position (e.g. 'n1', 'n1.1', 'n1.1.1').",
        pattern=r"^n\d+(\.\d+){0,4}$",
    )
    label: str = Field(
        description="Short human-readable label for the attack step or condition.",
        max_length=120,
    )
    description: Optional[str] = Field(
        default=None,
        description="Optional longer description of the step, its preconditions, or why it matters.",
    )
    gate: GateType = Field(
        description="Logical gate type: AND (all children must succeed), OR (any child suffices), LEAF (terminal).",
    )
    zone: str = Field(
        description="Schneider zone where this step occurs.",
    )
    threat_id: Optional[str] = Field(
        default=None,
        description="OWASP Agentic Threat ID applicable to this node (e.g. 'T2').",
        pattern=r"^T\d+$",
    )
    technique_id: Optional[str] = Field(
        default=None,
        description="MITRE ATLAS technique ID applicable to this node (e.g. 'AML.T0051').",
        pattern=r"^AML\.T\d{4}(\.\d{3})?$",
    )
    maestro_layer: Optional[int] = Field(
        default=None,
        description="MAESTRO architectural layer targeted by this step (1-7).",
        ge=1,
        le=7,
    )
    control_point: Optional[str] = Field(
        default=None,
        description="The defensive control that should block or detect this step.",
    )
    structural_exposure: Optional[StructuralExposure] = Field(
        default=None,
        description="Structural weakness pattern at this node.",
    )
    evidence_level: Optional[EvidenceLevel] = Field(
        default=EvidenceLevel.assumed,
        description="How well-evidenced this step is.",
    )
    children: Optional[list[AttackTreeNode]] = Field(
        default=None,
        description="Child nodes. Required for AND/OR gates; must be absent/empty for LEAF.",
    )

    @model_validator(mode="after")
    def validate_gate_children(self) -> AttackTreeNode:
        """LEAF nodes must have no children; AND/OR must have >= 2."""
        child_count = len(self.children) if self.children else 0

        if self.gate == GateType.LEAF:
            if child_count > 0:
                raise ValueError(
                    f"LEAF node '{self.id}' must not have children (has {child_count})"
                )
        else:
            if child_count < 2:
                raise ValueError(
                    f"{self.gate.value} node '{self.id}' must have at least 2 children (has {child_count})"
                )

        # Validate child IDs are prefixed with parent ID
        if self.children:
            for child in self.children:
                if not child.id.startswith(self.id + "."):
                    raise ValueError(
                        f"Child node '{child.id}' must have id starting with '{self.id}.' "
                        f"(parent prefix)"
                    )

        return self


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class AttackTree(BaseModel):
    """Top-level attack tree container.

    One tree per scenario seed.  Decomposes a single abstract attack pattern into a
    hierarchical AND/OR tree of attack steps.
    """

    id: str = Field(
        description="Tree identifier. Format: 'tree-{seed_id}' (e.g. 'tree-AP-T7-01').",
        pattern=r"^tree-AP-T\d+-\d+$",
    )
    seed_id: str = Field(
        description="The attack pattern seed that produced this tree (e.g. 'AP-T7-01').",
        pattern=r"^AP-T\d+-\d+$",
    )
    goal: str = Field(
        description="The attacker's top-level objective, stated as a concrete outcome.",
    )
    root: AttackTreeNode = Field(
        description="Root node of the AND/OR tree.",
    )

    @model_validator(mode="after")
    def validate_root_id(self) -> AttackTree:
        """Root node must have id 'n1'."""
        if self.root.id != "n1":
            raise ValueError(f"Root node must have id 'n1', got '{self.root.id}'")
        return self


# ---------------------------------------------------------------------------
# Pre-validation tree repair
# ---------------------------------------------------------------------------


def _repair_node(node: dict[str, Any]) -> dict[str, Any]:
    """Recursively repair a node dict, collapsing single-child AND/OR nodes.

    When an AND or OR node has exactly one child, the parent is replaced by the
    child.  The parent's ``id`` is preserved (to maintain dotted-path
    consistency), but the child's ``label``, ``gate``, ``zone``, ``children``,
    and all other fields are used.

    The function recurses depth-first so that deeply-nested single-child chains
    are collapsed from the bottom up.
    """
    children = node.get("children")

    # Recurse into children first (bottom-up repair).
    if children and isinstance(children, list):
        node["children"] = [_repair_node(c) for c in children]

    gate = node.get("gate", "").upper()

    if gate in ("AND", "OR") and children and len(children) == 1:
        parent_id = node["id"]
        child = node["children"][0]
        logger.warning(
            "Collapsing single-child %s node '%s' — replacing with child '%s' (%s)",
            gate,
            parent_id,
            child.get("id", "?"),
            child.get("label", "?"),
        )
        # Build the merged node: parent's id, everything else from child.
        merged: dict[str, Any] = {**child, "id": parent_id}
        # Recurse again in case the child itself also needs repair.
        return _repair_node(merged)

    return node


def repair_attack_tree_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Walk a raw attack-tree dict and fix single-child AND/OR nodes.

    Call this on the dict produced by ``yaml.safe_load`` **before** passing it
    to ``AttackTree.model_validate``.

    Returns the (possibly mutated) dict — safe to pass straight to Pydantic.
    """
    if "root" in data and isinstance(data["root"], dict):
        data["root"] = _repair_node(data["root"])
    return data
