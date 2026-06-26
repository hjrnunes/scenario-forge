"""Risk card causal chain coherence validation.

Checks that risk card causal chain text is semantically coherent with
the use case description.  Uses keyword overlap to detect cases where
a risk card describes a completely unrelated system (e.g. FEMA disaster
response when the use case is about DHS-ICE law enforcement).

This is a defensive check: it warns but does NOT reject.  The operator
decides whether to re-run with corrected upstream data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from scenario_forge.models.risk_card import RiskCard

logger = logging.getLogger(__name__)

# Words that are too generic to signal domain coherence.
_STOPWORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "to",
        "in",
        "for",
        "is",
        "it",
        "by",
        "on",
        "at",
        "be",
        "as",
        "with",
        "from",
        "that",
        "this",
        "are",
        "was",
        "were",
        "can",
        "may",
        "will",
        "not",
        "has",
        "have",
        "had",
        "its",
        "but",
        "if",
        "so",
        "do",
        "no",
        "all",
        "any",
        "each",
        "such",
        "than",
        "into",
        "also",
        "very",
        "been",
        "being",
        "other",
        "their",
        "them",
        "they",
        "what",
        "when",
        "which",
        "who",
        "whom",
        "how",
        "about",
        "would",
        "could",
        "should",
        "these",
        "those",
        "there",
        "where",
        "then",
        "more",
        "some",
        "through",
        "over",
        "under",
        "between",
        "after",
        "before",
        "during",
        "without",
        "within",
        "against",
        "use",
        "used",
        "using",
        "system",
        "systems",
        "data",
        "information",
        "process",
        "based",
        "include",
        "includes",
        "including",
        "provide",
        "provides",
        "ensure",
        "may",
        "must",
        "shall",
        "related",
    }
)

# Minimum word length to consider as a meaningful term.
_MIN_WORD_LENGTH = 3

# Minimum number of use-case keywords required to overlap for coherence.
# If fewer than this many terms from the use case appear in the causal
# chain, the card is flagged.
_MIN_OVERLAP = 1


def _extract_keywords(text: str) -> set[str]:
    """Extract meaningful lowercase keywords from text.

    Splits on non-alphanumeric boundaries, lowercases, filters stopwords
    and short tokens.
    """
    tokens = re.findall(r"[a-zA-Z0-9]+", text.lower())
    return {
        t
        for t in tokens
        if len(t) >= _MIN_WORD_LENGTH and t not in _STOPWORDS
    }


def _causal_chain_text(card: RiskCard) -> str:
    """Concatenate all causal chain fields into a single string."""
    parts: list[str] = []
    for field_name in ("threat", "threat_source", "vulnerability", "consequence", "impact"):
        value = getattr(card, field_name, None)
        if value:
            parts.append(value)
    return " ".join(parts)


@dataclass
class CardCoherenceResult:
    """Coherence check result for a single risk card."""

    risk_id: str
    risk_name: str
    coherent: bool
    overlap_count: int
    overlapping_terms: list[str] = field(default_factory=list)
    use_case_term_count: int = 0


@dataclass
class CoherenceReport:
    """Summary report from validating a set of risk cards against a use case."""

    total_cards: int
    coherent_count: int
    flagged_count: int
    flagged_cards: list[CardCoherenceResult] = field(default_factory=list)
    all_results: list[CardCoherenceResult] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        return self.flagged_count > 0


def validate_risk_card_coherence(
    use_case: str,
    risk_cards: list[RiskCard],
) -> CoherenceReport:
    """Check risk card causal chains for semantic coherence with the use case.

    For each risk card, extracts keywords from the causal chain fields
    (threat, threat_source, vulnerability, consequence, impact) and checks
    how many use-case keywords appear.  Cards with zero overlap are flagged
    as potentially describing a different system.

    This function only warns -- it does NOT filter or reject cards.

    Args:
        use_case: Free-text description of the AI system under assessment.
        risk_cards: List of RiskCard instances to validate.

    Returns:
        CoherenceReport summarising which cards passed and which were flagged.
    """
    use_case_keywords = _extract_keywords(use_case)

    results: list[CardCoherenceResult] = []
    flagged: list[CardCoherenceResult] = []

    for card in risk_cards:
        chain_text = _causal_chain_text(card)
        if not chain_text.strip():
            # No causal chain to validate -- skip silently.
            result = CardCoherenceResult(
                risk_id=card.risk_id,
                risk_name=card.risk_name,
                coherent=True,
                overlap_count=0,
                overlapping_terms=[],
                use_case_term_count=len(use_case_keywords),
            )
            results.append(result)
            continue

        chain_keywords = _extract_keywords(chain_text)
        overlap = use_case_keywords & chain_keywords
        is_coherent = len(overlap) >= _MIN_OVERLAP

        result = CardCoherenceResult(
            risk_id=card.risk_id,
            risk_name=card.risk_name,
            coherent=is_coherent,
            overlap_count=len(overlap),
            overlapping_terms=sorted(overlap),
            use_case_term_count=len(use_case_keywords),
        )
        results.append(result)

        if not is_coherent:
            flagged.append(result)
            logger.warning(
                "Risk card %s (%s) causal chain may describe a different system: "
                "zero keyword overlap with use case. "
                "Chain excerpt: %.120s...",
                card.risk_id,
                card.risk_name,
                chain_text,
            )

    report = CoherenceReport(
        total_cards=len(risk_cards),
        coherent_count=len(risk_cards) - len(flagged),
        flagged_count=len(flagged),
        flagged_cards=flagged,
        all_results=results,
    )

    if report.has_warnings:
        logger.warning(
            "Causal chain coherence check: %d/%d risk cards flagged as "
            "potentially describing a different system. Review flagged cards "
            "and re-run with corrected upstream data if necessary.",
            report.flagged_count,
            report.total_cards,
        )
    else:
        logger.info(
            "Causal chain coherence check: all %d risk cards appear "
            "coherent with the use case.",
            report.total_cards,
        )

    return report
