"""LossAnalysis boundary schema (Section 4.1 of the STPA-Sec foundation spec).

SP1 output, consumed by SP1 Stage 2, SP2 Stage 3, and SP3 Stage 7.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class LossProvenance(str, Enum):
    """How a loss was identified."""

    risk_card = "risk_card"
    use_case = "use_case"
    critic_derived = "critic_derived"


class Loss(BaseModel):
    """A system-level loss (something stakeholders want to avoid)."""

    loss_id: str  # L-1, L-2, ...
    description: str
    provenance: LossProvenance
    source_risk_cards: list[str] = Field(
        default_factory=list,
        description="Risk ID references; empty for use_case/critic_derived provenance.",
    )


class Hazard(BaseModel):
    """A system-level hazard (a condition that can lead to a loss)."""

    hazard_id: str  # H-1, H-2, ...
    description: str
    related_losses: list[str]  # loss_id refs


class SecurityConstraint(BaseModel):
    """A security constraint (a condition that prevents a hazard)."""

    constraint_id: str  # SC-1, SC-2, ...
    description: str
    related_hazards: list[str]  # hazard_id refs


class LossAnalysis(BaseModel):
    """Loss analysis artifact: losses, hazards, and security constraints."""

    risk_card_losses: list[Loss]
    use_case_losses: list[Loss]
    hazards: list[Hazard]
    security_constraints: list[SecurityConstraint]

    @model_validator(mode="after")
    def validate_references_and_provenance(self) -> LossAnalysis:
        # Collect all loss IDs
        all_losses = self.risk_card_losses + self.use_case_losses
        loss_ids = {loss.loss_id for loss in all_losses}

        # No duplicate loss IDs across both lists
        all_loss_ids_list = [loss.loss_id for loss in all_losses]
        _check_duplicates(all_loss_ids_list, "loss_id")

        # No duplicate hazard IDs
        _check_duplicates(
            [h.hazard_id for h in self.hazards], "hazard_id"
        )

        # No duplicate constraint IDs
        _check_duplicates(
            [sc.constraint_id for sc in self.security_constraints], "constraint_id"
        )

        # Provenance consistency for risk_card_losses
        for loss in self.risk_card_losses:
            if loss.provenance != LossProvenance.risk_card:
                raise ValueError(
                    f"Loss {loss.loss_id} in risk_card_losses has provenance "
                    f"'{loss.provenance.value}' but must be 'risk_card'."
                )
            if not loss.source_risk_cards:
                raise ValueError(
                    f"Loss {loss.loss_id} has provenance 'risk_card' but "
                    f"source_risk_cards is empty."
                )

        # Provenance consistency for use_case_losses
        for loss in self.use_case_losses:
            if loss.provenance not in (
                LossProvenance.use_case,
                LossProvenance.critic_derived,
            ):
                raise ValueError(
                    f"Loss {loss.loss_id} in use_case_losses has provenance "
                    f"'{loss.provenance.value}' but must be 'use_case' or "
                    f"'critic_derived'."
                )
            if loss.source_risk_cards:
                raise ValueError(
                    f"Loss {loss.loss_id} has provenance '{loss.provenance.value}' "
                    f"but source_risk_cards is non-empty: {loss.source_risk_cards}."
                )

        # Hazard.related_losses must reference valid loss IDs
        for hazard in self.hazards:
            for ref in hazard.related_losses:
                if ref not in loss_ids:
                    raise ValueError(
                        f"Hazard {hazard.hazard_id} references non-existent "
                        f"loss '{ref}' in related_losses."
                    )

        # SecurityConstraint.related_hazards must reference valid hazard IDs
        hazard_ids = {h.hazard_id for h in self.hazards}
        for sc in self.security_constraints:
            for ref in sc.related_hazards:
                if ref not in hazard_ids:
                    raise ValueError(
                        f"SecurityConstraint {sc.constraint_id} references "
                        f"non-existent hazard '{ref}' in related_hazards."
                    )

        return self


def _check_duplicates(ids: list[str], field_name: str) -> None:
    """Raise ValueError if *ids* contains duplicates."""
    seen: set[str] = set()
    for id_val in ids:
        if id_val in seen:
            raise ValueError(f"Duplicate {field_name}: '{id_val}'.")
        seen.add(id_val)
