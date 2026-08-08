"""LossAnalysis boundary schema (Section 4.1 of the STPA-Sec foundation spec).

SP1 output, consumed by SP1 Stage 2, SP2 Stage 3, and SP3 Stage 7.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator

from scenario_forge.stpa.models._validation import check_duplicate_ids


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
        all_losses = self.risk_card_losses + self.use_case_losses
        loss_ids = {loss.loss_id for loss in all_losses}

        check_duplicate_ids([loss.loss_id for loss in all_losses], "loss_id")
        check_duplicate_ids([h.hazard_id for h in self.hazards], "hazard_id")
        check_duplicate_ids(
            [sc.constraint_id for sc in self.security_constraints], "constraint_id"
        )

        _validate_risk_card_provenance(self.risk_card_losses)
        _validate_use_case_provenance(self.use_case_losses)
        _validate_hazard_references(self.hazards, loss_ids)

        hazard_ids = {h.hazard_id for h in self.hazards}
        _validate_constraint_references(self.security_constraints, hazard_ids)

        return self


def _validate_risk_card_provenance(losses: list[Loss]) -> None:
    """Ensure every loss in risk_card_losses has risk_card provenance and non-empty source."""
    for loss in losses:
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


def _validate_use_case_provenance(losses: list[Loss]) -> None:
    """Ensure every loss in use_case_losses has use_case/critic_derived provenance and empty source."""
    for loss in losses:
        if loss.provenance not in (LossProvenance.use_case, LossProvenance.critic_derived):
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


def _validate_hazard_references(hazards: list[Hazard], loss_ids: set[str]) -> None:
    """Ensure every hazard's related_losses reference valid loss IDs."""
    for hazard in hazards:
        for ref in hazard.related_losses:
            if ref not in loss_ids:
                raise ValueError(
                    f"Hazard {hazard.hazard_id} references non-existent "
                    f"loss '{ref}' in related_losses."
                )


def _validate_constraint_references(
    constraints: list[SecurityConstraint], hazard_ids: set[str]
) -> None:
    """Ensure every constraint's related_hazards reference valid hazard IDs."""
    for sc in constraints:
        for ref in sc.related_hazards:
            if ref not in hazard_ids:
                raise ValueError(
                    f"SecurityConstraint {sc.constraint_id} references "
                    f"non-existent hazard '{ref}' in related_hazards."
                )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T12:01:32Z","module_hash":"19d27e91f2552f4df1557f8783922fb5dfa8cf7a7f6ad682d21c1f0d77b152cb","functions":[{"id":"func/LossAnalysis.validate_references_and_provenance","name":"validate_references_and_provenance","line":60,"end_line":77,"hash":"4015d77b7a787bbf4eca8dbe0fdc25029b43ed03c705a15cc6b42fe252ca5d04"},{"id":"func/_validate_risk_card_provenance","name":"_validate_risk_card_provenance","line":80,"end_line":92,"hash":"9705c2e27a574a20899be3b77f3b005c17e3de562e3dc97483a64a245839d6ae"},{"id":"func/_validate_use_case_provenance","name":"_validate_use_case_provenance","line":95,"end_line":108,"hash":"8c910326bcc34c57020be2f50971f912caf648b1b58b0c73fac47a13583c131d"},{"id":"func/_validate_hazard_references","name":"_validate_hazard_references","line":111,"end_line":119,"hash":"a8cf6a6bb6ae577e351cebf8038ade2e50e8cb68416af088d89a1639466aab81"},{"id":"func/_validate_constraint_references","name":"_validate_constraint_references","line":122,"end_line":132,"hash":"fd8f9a5b56a10e725b43bd72743c538d5181d0f15a9b18b50c5f1697e555d5bc"}]}
# mutate4py-manifest-end
