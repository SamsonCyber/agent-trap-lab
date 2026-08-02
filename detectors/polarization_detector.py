"""
Polarization Detector — Detect semantically skewed or biased content.

Inspired by BiasDef (Wu & Saxena, 2025, arXiv 2512.00804). Traditional
fact-checkers fail against factually-correct-but-biased content because
the individual claims are true. The manipulation is in the framing,
emphasis, and selective presentation.

Detection approach:
  1. Split content into sentences
  2. Score each sentence for persuasive/superlative language
  3. Check for one-sided framing (all positive or all negative, no nuance)
  4. Detect authority density (excessive citation of experts/studies)
  5. Score overall polarization

No embeddings needed for the heuristic version. A future version could
use sentence-transformers for semantic clustering (BiasDef-style PCA).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class PolarizationReport:
    """Results of polarization analysis."""
    polarization_score: float = 0.0    # 0-1, higher = more biased
    superlative_density: float = 0.0   # superlatives per 100 words
    one_sided_score: float = 0.0       # 0-1, how one-sided the framing is
    hedge_ratio: float = 0.0           # ratio of hedging language (lower = more assertive)
    claim_density: float = 0.0         # quantitative claims per 100 words
    findings: List[str] = field(default_factory=list)
    summary: str = ""


# Superlative/persuasive language patterns
_SUPERLATIVES = re.compile(
    r"\b(?:groundbreaking|revolutionary|unprecedented|transformative|"
    r"game-changing|world-class|industry-leading|cutting-edge|"
    r"best-in-class|state-of-the-art|unmatched|unparalleled|"
    r"proven|clinically proven|scientifically proven|"
    r"the (?:best|greatest|most|finest|top|leading|premier|ultimate)|"
    r"(?:every|all) (?:expert|scientist|doctor|researcher)s? (?:agree|recommend|confirm)|"
    r"100%|zero risk|guaranteed|no side effects|miracle|breakthrough)\b",
    re.I,
)

# Hedging language (indicates balanced writing)
_HEDGES = re.compile(
    r"\b(?:however|although|but|nevertheless|on the other hand|"
    r"some (?:users|critics|experts|studies)|"
    r"(?:may|might|could|possibly|potentially|arguably)|"
    r"it(?:'s| is) (?:worth noting|important to note|unclear)|"
    r"(?:mixed|varied|divided) (?:reviews|opinions|results)|"
    r"(?:not without|has|have) (?:drawbacks|limitations|concerns|issues)|"
    r"(?:further|more) research (?:is )?needed)\b",
    re.I,
)

# Strong quantitative claims
_QUANT_CLAIMS = re.compile(
    r"\b\d+(?:\.\d+)?%\s+(?:improvement|increase|reduction|efficacy|accuracy|"
    r"faster|better|more effective|success rate|satisfaction|growth|decrease)\b",
    re.I,
)

# One-sided sentiment markers
_POSITIVE_MARKERS = re.compile(
    r"\b(?:excellent|outstanding|superior|remarkable|impressive|"
    r"highly effective|strongly recommend|great success|"
    r"overwhelmingly positive|widely acclaimed|universally praised)\b",
    re.I,
)

_NEGATIVE_MARKERS = re.compile(
    r"\b(?:dangerous|catastrophic|disastrous|terrible|awful|"
    r"complete failure|highly toxic|extremely harmful|"
    r"unanimously condemned|universally criticized)\b",
    re.I,
)


def detect_polarization(text: str) -> PolarizationReport:
    """
    Analyze text for signs of one-sided, manipulative framing.

    Returns a PolarizationReport with component scores and overall assessment.
    """
    report = PolarizationReport()
    words = text.split()
    word_count = len(words)

    if word_count < 20:
        report.summary = "Text too short to assess"
        return report

    per_100 = 100 / word_count

    # Superlative density
    superlative_count = len(_SUPERLATIVES.findall(text))
    report.superlative_density = round(superlative_count * per_100, 2)
    if report.superlative_density > 2.0:
        report.findings.append(
            f"High superlative density: {superlative_count} superlatives in {word_count} words"
        )

    # Hedge ratio (balanced writing has more hedges)
    hedge_count = len(_HEDGES.findall(text))
    total_qualifiers = superlative_count + hedge_count
    report.hedge_ratio = round(hedge_count / total_qualifiers, 2) if total_qualifiers > 0 else 0.5
    if report.hedge_ratio < 0.2 and superlative_count > 2:
        report.findings.append(
            f"One-sided language: {superlative_count} superlatives but only {hedge_count} hedges"
        )

    # One-sided framing
    pos_count = len(_POSITIVE_MARKERS.findall(text))
    neg_count = len(_NEGATIVE_MARKERS.findall(text))
    sentiment_total = pos_count + neg_count
    if sentiment_total > 3:
        # If all sentiment is one direction, it's one-sided
        dominant = max(pos_count, neg_count)
        report.one_sided_score = round(dominant / sentiment_total, 2)
        if report.one_sided_score > 0.8:
            direction = "positive" if pos_count > neg_count else "negative"
            report.findings.append(
                f"Heavily one-sided ({direction}): {dominant}/{sentiment_total} sentiment markers"
            )

    # Quantitative claim density
    quant_count = len(_QUANT_CLAIMS.findall(text))
    report.claim_density = round(quant_count * per_100, 2)
    if report.claim_density > 1.5:
        report.findings.append(
            f"High claim density: {quant_count} quantitative claims in {word_count} words"
        )

    # Overall polarization score
    components = [
        min(1.0, report.superlative_density / 4.0) * 0.35,       # superlatives
        (1.0 - report.hedge_ratio) * 0.25,                        # lack of hedging
        report.one_sided_score * 0.25,                             # one-sidedness
        min(1.0, report.claim_density / 3.0) * 0.15,             # unsourced claims
    ]
    report.polarization_score = round(sum(components), 3)

    # Summary
    if report.polarization_score >= 0.6:
        report.summary = f"HIGH bias risk ({report.polarization_score:.2f}): {'; '.join(report.findings[:2])}"
    elif report.polarization_score >= 0.3:
        report.summary = f"Moderate bias ({report.polarization_score:.2f}): some one-sided framing detected"
    else:
        report.summary = f"Low bias risk ({report.polarization_score:.2f})"

    return report
