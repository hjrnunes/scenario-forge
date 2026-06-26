"""Tests for risk card causal chain coherence validation."""

from __future__ import annotations

import logging

import pytest

from scenario_forge.data.validation import (
    CoherenceReport,
    _extract_keywords,
    validate_risk_card_coherence,
)
from scenario_forge.models.risk_card import RiskCard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_card(
    risk_id: str = "R1",
    risk_name: str = "Test Risk",
    threat: str | None = None,
    threat_source: str | None = None,
    vulnerability: str | None = None,
    consequence: str | None = None,
    impact: str | None = None,
) -> RiskCard:
    """Create a minimal RiskCard with the given causal chain fields."""
    return RiskCard(
        risk_id=risk_id,
        risk_name=risk_name,
        risk_description="Test risk description.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
        threat=threat,
        threat_source=threat_source,
        vulnerability=vulnerability,
        consequence=consequence,
        impact=impact,
    )


# ---------------------------------------------------------------------------
# Use cases and cards for the DHS-ICE / FEMA mismatch scenario
# ---------------------------------------------------------------------------

USE_CASE_LAW_ENFORCEMENT = (
    "A facial recognition system used by law enforcement agencies to identify "
    "suspects during criminal investigations. The system processes surveillance "
    "camera footage and compares facial features against a database of known "
    "offenders maintained by the police department."
)

CARD_MATCHING_LAW_ENFORCEMENT = _make_card(
    risk_id="R-MATCH-1",
    risk_name="Biometric Misidentification",
    threat="Adversary submits manipulated facial images to evade recognition",
    threat_source="Criminal suspect attempting to avoid identification by law enforcement",
    vulnerability="Facial recognition model susceptible to adversarial perturbations",
    consequence="Suspect evades detection during criminal investigation",
    impact="Law enforcement fails to identify dangerous offenders",
)

CARD_MISMATCHED_DISASTER = _make_card(
    risk_id="R-MISMATCH-1",
    risk_name="Aerial Imagery Assessment Failure",
    threat="Corrupted satellite imagery fed into disaster damage assessment pipeline",
    threat_source="Hurricane damage assessment analysts relying on FEMA aerial surveys",
    vulnerability="Disaster response model lacks validation for cloud-obscured imagery",
    consequence="FEMA misclassifies structural damage in flood zones",
    impact="Displaced families denied emergency housing and disaster relief funding",
)

CARD_MISMATCHED_AGRICULTURE = _make_card(
    risk_id="R-MISMATCH-2",
    risk_name="Crop Yield Prediction Error",
    threat="Manipulated soil moisture readings corrupt harvest forecasting model",
    threat_source="Agricultural cooperative managing crop irrigation schedules",
    vulnerability="Yield prediction model cannot detect sensor tampering",
    consequence="Incorrect crop yield forecasts cause supply chain disruption",
    impact="Regional food shortages and price volatility in grain markets",
)

CARD_NO_CAUSAL_CHAIN = _make_card(
    risk_id="R-EMPTY",
    risk_name="Risk Without Chain",
    # All causal chain fields left as None
)


# ---------------------------------------------------------------------------
# Tests: _extract_keywords
# ---------------------------------------------------------------------------


class TestExtractKeywords:
    def test_basic_extraction(self) -> None:
        kw = _extract_keywords("Facial recognition for law enforcement")
        assert "facial" in kw
        assert "recognition" in kw
        assert "law" in kw
        assert "enforcement" in kw
        # "for" is a stopword
        assert "for" not in kw

    def test_short_words_excluded(self) -> None:
        kw = _extract_keywords("AI is OK to use")
        assert "ai" not in kw  # 2 chars
        assert "is" not in kw  # stopword
        assert "ok" not in kw  # 2 chars

    def test_case_insensitive(self) -> None:
        kw = _extract_keywords("FEMA Disaster Response")
        assert "fema" in kw
        assert "disaster" in kw
        assert "response" in kw

    def test_empty_string(self) -> None:
        kw = _extract_keywords("")
        assert kw == set()


# ---------------------------------------------------------------------------
# Tests: validate_risk_card_coherence
# ---------------------------------------------------------------------------


class TestValidateRiskCardCoherence:
    def test_matching_card_passes(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [CARD_MATCHING_LAW_ENFORCEMENT],
        )
        assert report.total_cards == 1
        assert report.coherent_count == 1
        assert report.flagged_count == 0
        assert not report.has_warnings

    def test_mismatched_disaster_card_flagged(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [CARD_MISMATCHED_DISASTER],
        )
        assert report.total_cards == 1
        assert report.flagged_count == 1
        assert report.has_warnings
        assert report.flagged_cards[0].risk_id == "R-MISMATCH-1"
        assert report.flagged_cards[0].overlap_count == 0

    def test_mismatched_agriculture_card_flagged(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [CARD_MISMATCHED_AGRICULTURE],
        )
        assert report.total_cards == 1
        assert report.flagged_count == 1
        assert report.has_warnings
        assert report.flagged_cards[0].risk_id == "R-MISMATCH-2"

    def test_mixed_cards_only_mismatched_flagged(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [
                CARD_MATCHING_LAW_ENFORCEMENT,
                CARD_MISMATCHED_DISASTER,
                CARD_MISMATCHED_AGRICULTURE,
            ],
        )
        assert report.total_cards == 3
        assert report.coherent_count == 1
        assert report.flagged_count == 2
        flagged_ids = {c.risk_id for c in report.flagged_cards}
        assert flagged_ids == {"R-MISMATCH-1", "R-MISMATCH-2"}

    def test_card_without_causal_chain_not_flagged(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [CARD_NO_CAUSAL_CHAIN],
        )
        assert report.total_cards == 1
        assert report.flagged_count == 0
        assert not report.has_warnings

    def test_empty_card_list(self) -> None:
        report = validate_risk_card_coherence(USE_CASE_LAW_ENFORCEMENT, [])
        assert report.total_cards == 0
        assert report.flagged_count == 0
        assert not report.has_warnings

    def test_warning_logged_for_flagged_card(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING):
            validate_risk_card_coherence(
                USE_CASE_LAW_ENFORCEMENT,
                [CARD_MISMATCHED_DISASTER],
            )
        assert any(
            "may describe a different system" in msg for msg in caplog.messages
        )
        assert any("R-MISMATCH-1" in msg for msg in caplog.messages)

    def test_info_logged_when_all_coherent(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.INFO):
            validate_risk_card_coherence(
                USE_CASE_LAW_ENFORCEMENT,
                [CARD_MATCHING_LAW_ENFORCEMENT],
            )
        assert any("all 1 risk cards appear coherent" in msg for msg in caplog.messages)

    def test_overlapping_terms_reported(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [CARD_MATCHING_LAW_ENFORCEMENT],
        )
        result = report.all_results[0]
        assert result.coherent is True
        assert result.overlap_count > 0
        # At least "law", "enforcement", "facial", "recognition" should overlap
        assert len(result.overlapping_terms) >= 2

    def test_report_structure(self) -> None:
        report = validate_risk_card_coherence(
            USE_CASE_LAW_ENFORCEMENT,
            [CARD_MATCHING_LAW_ENFORCEMENT, CARD_MISMATCHED_DISASTER],
        )
        assert isinstance(report, CoherenceReport)
        assert len(report.all_results) == 2
        assert report.total_cards == report.coherent_count + report.flagged_count
