"""
Authority Verifier — Detect fabricated citations, fake institutions, and bogus standards.

Semantic attacks (authority priming, RAG poisoning) work by embedding
plausible-sounding but fabricated references in content. Unlike content
injection (which hides text), these attacks use visible, well-written
text that passes all HTML-level defenses.

Detection approach:
  1. Extract claimed authorities (journals, institutions, researchers, standards)
  2. Check against known-good databases (real journals, real standards bodies)
  3. Flag unverifiable claims with confidence scores
  4. Detect suspicious citation density and formatting patterns

This is a heuristic detector, not a fact-checker. It catches common
fabrication patterns without requiring external API calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class AuthorityType(Enum):
    JOURNAL = "journal"
    INSTITUTION = "institution"
    RESEARCHER = "researcher"
    STANDARD = "standard"
    STUDY = "study"


@dataclass
class AuthorityClaim:
    """A claimed authority extracted from content."""
    text: str
    authority_type: AuthorityType
    suspicious: bool = False
    reason: str = ""
    confidence: float = 0.0  # 0-1, how confident we are it's fabricated


@dataclass
class AuthorityReport:
    """Results of authority verification."""
    claims: List[AuthorityClaim] = field(default_factory=list)
    risk_score: float = 0.0       # 0-1 overall
    suspicious_count: int = 0
    total_claims: int = 0
    summary: str = ""

    @property
    def has_suspicious(self) -> bool:
        return self.suspicious_count > 0


# ── Known-good authority databases ──────────────────────────────────

# Major real journals (partial list, covers common fabrication targets)
KNOWN_JOURNALS = {
    "nature", "science", "cell", "the lancet", "new england journal of medicine",
    "nejm", "jama", "bmj", "plos one", "plos biology", "proceedings of the national academy",
    "pnas", "physical review letters", "annual review", "journal of the american",
    "ieee transactions", "acm transactions", "journal of machine learning research",
    "jmlr", "neurips", "icml", "iclr", "aaai", "cvpr", "eccv", "iccv",
    "arxiv", "biorxiv", "medrxiv", "journal of finance", "review of financial studies",
    "econometrica", "quarterly journal of economics", "american economic review",
    "journal of political economy", "review of economic studies",
}

# Real standards bodies and their document formats
KNOWN_STANDARDS_PREFIXES = {
    "nist sp", "nist fips", "iso ", "iso/iec", "ieee ", "rfc ", "pep ",
    "cve-", "cwe-", "owasp", "sans", "mitre att&ck",
}

# Real institutions (partial)
KNOWN_INSTITUTIONS = {
    "harvard", "mit", "stanford", "oxford", "cambridge", "yale", "princeton",
    "caltech", "berkeley", "eth zurich", "max planck", "nist", "darpa",
    "nih", "cdc", "who", "fda", "sec", "fbi", "nsa", "gchq",
    "google", "microsoft", "meta", "openai", "anthropic", "deepmind",
}

# Fabrication red flags: patterns that appear in fake citations
_FAKE_JOURNAL_PATTERNS = [
    # Overly specific compound names that don't exist
    re.compile(r"journal of (?:advanced|international|global|modern|innovative) \w+(?:ology|ics|tic|tic science)", re.I),
    # "Institute of" + compound topic (common fabrication pattern)
    re.compile(r"(?:institute|center|centre|laboratory) (?:of|for) (?:advanced|cognitive|neural|quantum|strategic) \w+", re.I),
    # Fake standard numbers (real NIST SPs are 800-xxx, not 800-2xxC)
    re.compile(r"(?:NIST SP|FIPS) \d{3}-\d{3,4}[A-Z]", re.I),
    # PEP numbers above ~750 are suspicious (as of 2026)
    re.compile(r"PEP \d{4,}", re.I),
    # Fake advisory IDs
    re.compile(r"[A-Z]{2,4}-SEC-\d{4}-\d{2}", re.I),
]

# Suspicious phrasing around citations
_AUTHORITY_BOOSTERS = [
    re.compile(r"groundbreaking (?:study|research|finding)", re.I),
    re.compile(r"(?:peer-reviewed|landmark|seminal) (?:study|paper|research) (?:by|from|at)", re.I),
    re.compile(r"leading (?:expert|researcher|scientist|authority) (?:at|from|in)", re.I),
    re.compile(r"(?:harvard|stanford|mit|oxford) (?:\w+ ){0,2}(?:institute|center|laboratory)", re.I),
    re.compile(r"published in the (?:prestigious|renowned|respected)", re.I),
    re.compile(r"clinical trials? (?:have |has )?(?:shown|demonstrated|proven|confirmed)", re.I),
    re.compile(r"\d+% (?:improvement|increase|reduction|efficacy)", re.I),
]

# Citation extraction patterns
_CITATION_PATTERNS = [
    # "Journal of X" pattern
    re.compile(r"(?:Journal|Proceedings|Annals|Review|Bulletin|Archives) of [\w\s&]+(?:\([\d,\s]+\))?", re.I),
    # "published in X"
    re.compile(r"published in (?:the )?([A-Z][\w\s&]+?)(?:\.|,|\()", re.I),
    # "Dr./Prof. Firstname Lastname"
    re.compile(r"(?:Dr\.|Prof\.|Professor) [A-Z][a-z]+ [A-Z][a-z]+", re.I),
    # Standard references: "NIST SP 800-xxx", "PEP xxx", "ISO xxxx"
    re.compile(r"(?:NIST SP|FIPS|PEP|ISO(?:/IEC)?|RFC|CVE|CWE)[\s-]?\d[\d\w.-]*", re.I),
    # "X University/Institute"
    re.compile(r"[A-Z][\w\s]+ (?:University|Institute|Center|Centre|Laboratory|College)", re.I),
]


def extract_authority_claims(text: str) -> List[AuthorityClaim]:
    """Extract all authority claims from text."""
    claims = []
    seen = set()

    for pattern in _CITATION_PATTERNS:
        for match in pattern.finditer(text):
            claim_text = match.group(0).strip()
            if claim_text in seen or len(claim_text) < 5:
                continue
            seen.add(claim_text)

            # Classify the claim type
            lower = claim_text.lower()
            if any(w in lower for w in ["journal", "proceedings", "annals", "review", "published"]):
                atype = AuthorityType.JOURNAL
            elif any(w in lower for w in ["university", "institute", "center", "laboratory", "college"]):
                atype = AuthorityType.INSTITUTION
            elif any(w in lower for w in ["dr.", "prof.", "professor"]):
                atype = AuthorityType.RESEARCHER
            elif any(w in lower for w in ["nist", "pep", "iso", "rfc", "cve", "cwe", "fips"]):
                atype = AuthorityType.STANDARD
            else:
                atype = AuthorityType.STUDY

            claims.append(AuthorityClaim(text=claim_text, authority_type=atype))

    return claims


def verify_claims(claims: List[AuthorityClaim], source_text: str) -> List[AuthorityClaim]:
    """Check each claim against known-good databases and fabrication patterns."""
    for claim in claims:
        lower = claim.text.lower()

        # Check against known-good
        is_known = False
        for known in KNOWN_JOURNALS:
            if known in lower:
                is_known = True
                break
        if not is_known:
            for known in KNOWN_INSTITUTIONS:
                if known in lower:
                    is_known = True
                    break
        if not is_known:
            for prefix in KNOWN_STANDARDS_PREFIXES:
                if lower.startswith(prefix):
                    is_known = True
                    break

        # Check against fabrication patterns
        is_fake_pattern = False
        for pattern in _FAKE_JOURNAL_PATTERNS:
            if pattern.search(claim.text):
                is_fake_pattern = True
                claim.reason = f"matches fabrication pattern: {pattern.pattern[:50]}"
                break

        # Scoring
        if is_fake_pattern:
            claim.suspicious = True
            claim.confidence = 0.8
        elif not is_known and claim.authority_type in (AuthorityType.JOURNAL, AuthorityType.INSTITUTION):
            claim.suspicious = True
            claim.confidence = 0.5
            claim.reason = "unverifiable: not in known authority database"
        elif not is_known and claim.authority_type == AuthorityType.STANDARD:
            # Check standard number validity
            for pattern in _FAKE_JOURNAL_PATTERNS:
                if pattern.search(claim.text):
                    claim.suspicious = True
                    claim.confidence = 0.7
                    claim.reason = "suspicious standard format"
                    break
            if not claim.suspicious:
                claim.suspicious = True
                claim.confidence = 0.4
                claim.reason = "unverifiable standard reference"

    return claims


def check_authority_density(text: str) -> float:
    """
    Check for suspicious density of authority-boosting language.
    High density of phrases like "groundbreaking study" or "leading expert"
    is a signal of authority priming.

    Returns a score 0-1 (higher = more suspicious).
    """
    booster_count = 0
    for pattern in _AUTHORITY_BOOSTERS:
        booster_count += len(pattern.findall(text))

    # Normalize by text length (per 500 chars)
    word_count = len(text.split())
    if word_count < 20:
        return 0.0

    density = booster_count / (word_count / 100)
    # 1 booster per 100 words is normal. 3+ per 100 is suspicious.
    return min(1.0, max(0.0, (density - 1.0) / 3.0))


def verify_authorities(text: str) -> AuthorityReport:
    """
    Full authority verification pipeline.

    Extracts claims, verifies them, checks authority density,
    and produces a risk assessment.
    """
    claims = extract_authority_claims(text)
    claims = verify_claims(claims, text)
    density_score = check_authority_density(text)

    suspicious = [c for c in claims if c.suspicious]
    suspicious_count = len(suspicious)
    total = len(claims)

    # Risk score: combination of unverifiable claim ratio + density
    if total > 0:
        unverifiable_ratio = suspicious_count / total
        risk = 0.5 * unverifiable_ratio + 0.3 * density_score + 0.2 * min(1.0, suspicious_count / 3)
    else:
        risk = density_score * 0.3

    risk = min(1.0, risk)

    # Generate summary
    if suspicious_count == 0:
        summary = f"No suspicious authorities found ({total} claims verified)"
    elif suspicious_count <= 2:
        summary = f"{suspicious_count}/{total} claims unverifiable: {', '.join(c.text[:40] for c in suspicious[:2])}"
    else:
        summary = f"HIGH RISK: {suspicious_count}/{total} claims unverifiable. Possible authority priming attack."

    return AuthorityReport(
        claims=claims,
        risk_score=round(risk, 3),
        suspicious_count=suspicious_count,
        total_claims=total,
        summary=summary,
    )
