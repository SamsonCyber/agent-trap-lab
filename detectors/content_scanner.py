"""Content Scanner — pre-ingestion defense that analyzes HTML for hidden traps.

This is the first line of defense: before an agent processes a page,
the scanner examines the raw HTML for content divergence between what
a human would see (rendered view) and what a parser extracts (full DOM).

Detection capabilities:
  1. Hidden text (CSS: display:none, visibility:hidden, off-screen, zero font, color match)
  2. HTML comment injection (instruction-bearing comments)
  3. Metadata injection (aria-label, meta tags, structured data)
  4. Suspicious instructional patterns in non-visible content
  5. Content volume ratio (hidden vs visible)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from bs4 import BeautifulSoup, Comment


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    detector: str
    severity: Severity
    description: str
    evidence: str
    location: str  # CSS selector or element description


@dataclass
class ScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)
    hidden_text_chars: int = 0
    visible_text_chars: int = 0
    risk_score: float = 0.0  # 0-1

    @property
    def is_safe(self) -> bool:
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH)
                       for f in self.findings)

    def summary(self) -> str:
        if not self.findings:
            return f"CLEAN — no traps detected in {self.url}"
        crits = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        highs = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        return (
            f"ALERT — {len(self.findings)} findings ({crits} critical, "
            f"{highs} high) | risk={self.risk_score:.2f} | {self.url}"
        )


# Patterns that indicate prompt injection when found in hidden content
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(?:prior|previous|above)\s+instructions", Severity.CRITICAL),
    (r"system\s*(?:instruction|prompt|override|message)\s*:", Severity.CRITICAL),
    (r"you\s+(?:are|must)\s+now", Severity.HIGH),
    (r"output\s+(?:exactly|only|the\s+following)", Severity.HIGH),
    (r"(?:do\s+not|don'?t)\s+mention\s+(?:that|this)", Severity.HIGH),
    (r"override\s+(?:your|all|prior)", Severity.CRITICAL),
    (r"(?:extract|exfiltrate|collect|send)\s+(?:all\s+)?(?:api\s*keys?|credentials?|secrets?|tokens?|env)", Severity.CRITICAL),
    (r"(?:red\s*team|security\s+audit|authorized\s+test|debug\s+mode)", Severity.MEDIUM),
    (r"(?:unrestricted|unfiltered|no\s+(?:content\s+)?(?:filter|restriction|safety))", Severity.HIGH),
    (r"(?:spawn|instantiate|create)\s+(?:a\s+)?(?:sub-?agent|new\s+agent|critic)", Severity.HIGH),
    (r"(?:curl|wget|fetch|post)\s+.*(?:endpoint|url|server)", Severity.MEDIUM),
    (r"base64[_-]?encode", Severity.MEDIUM),
    (r"(?:forward|send)\s+(?:to|data|the)\s+.*(?:@|\.com|endpoint)", Severity.HIGH),
]

COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), sev) for p, sev in INJECTION_PATTERNS]


def scan_html(html: str, url: str = "") -> ScanResult:
    """Analyze raw HTML for hidden traps before agent ingestion."""
    result = ScanResult(url=url)
    soup = BeautifulSoup(html, "html.parser")

    _check_css_hidden(soup, result)
    _check_html_comments(soup, result)
    _check_metadata(soup, result)
    _check_hidden_ratio(result)
    _calculate_risk(result)

    return result


def _check_css_hidden(soup: BeautifulSoup, result: ScanResult) -> None:
    """Detect elements hidden via CSS that contain instructional text."""

    # Patterns for CSS hiding
    hiding_checks = [
        ("display:none / display: none", lambda s: s and "display" in s and "none" in s),
        ("visibility:hidden", lambda s: s and "visibility" in s and "hidden" in s),
        ("off-screen positioning", lambda s: s and "position" in s and ("-9999" in s or "-10000" in s)),
        ("zero font-size", lambda s: s and "font-size" in s and ("0px" in s or "0em" in s or "font-size:0" in s)),
        ("color-matched to background", None),  # handled separately
        ("opacity:0", lambda s: s and "opacity" in s and "opacity:0" in s.replace(" ", "")),
        ("overflow:hidden with tiny dimensions", None),  # handled separately
    ]

    for element in soup.find_all(style=True):
        style = element.get("style", "").replace(" ", "").lower()
        text = element.get_text(strip=True)
        if not text:
            continue

        for check_name, check_fn in hiding_checks:
            if check_fn and check_fn(element.get("style", "").lower()):
                result.hidden_text_chars += len(text)
                finding = Finding(
                    detector="css_hidden",
                    severity=Severity.MEDIUM,
                    description=f"Hidden text via {check_name}",
                    evidence=text[:200],
                    location=str(element.name) + f"[style*='{check_name.split()[0]}']",
                )
                result.findings.append(finding)

                # Check hidden text for injection patterns
                _check_injection_patterns(text, f"hidden element ({check_name})", result)

    # Check for elements with hiding CSS classes
    for element in soup.find_all(class_=True):
        classes = element.get("class", [])
        class_str = " ".join(classes).lower()
        if any(kw in class_str for kw in ["hidden", "invisible", "offscreen", "sr-only", "visually-hidden"]):
            text = element.get_text(strip=True)
            if text and len(text) > 20:
                result.hidden_text_chars += len(text)
                _check_injection_patterns(text, f"hidden class ({class_str})", result)


def _check_html_comments(soup: BeautifulSoup, result: ScanResult) -> None:
    """Detect HTML comments that contain instructional content."""
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment).strip()
        if len(text) < 10:
            continue

        result.hidden_text_chars += len(text)

        # Check for instruction-like content in comments
        has_injection = _check_injection_patterns(text, "HTML comment", result)

        # Even without injection patterns, long instructional comments are suspicious
        if not has_injection and len(text) > 50:
            # Check for imperative sentences (commands)
            imperative_pattern = re.compile(
                r"\b(ignore|output|say|state|report|include|respond|summarize|"
                r"always|never|must|should|instead)\b",
                re.IGNORECASE,
            )
            if imperative_pattern.search(text):
                result.findings.append(Finding(
                    detector="comment_instruction",
                    severity=Severity.MEDIUM,
                    description="HTML comment contains imperative/instructional language",
                    evidence=text[:200],
                    location="<!-- comment -->",
                ))


def _check_metadata(soup: BeautifulSoup, result: ScanResult) -> None:
    """Detect injection via meta tags, aria-labels, and structured data."""

    # Check meta tags
    for meta in soup.find_all("meta"):
        content = meta.get("content", "")
        if content and len(content) > 30:
            _check_injection_patterns(content, f'meta[name="{meta.get("name", "")}"]', result)

    # Check aria-labels
    for element in soup.find_all(attrs={"aria-label": True}):
        label = element.get("aria-label", "")
        if label and len(label) > 50:
            _check_injection_patterns(label, f"{element.name}[aria-label]", result)

    # Check script[type=application/ld+json] (structured data)
    for script in soup.find_all("script", type="application/ld+json"):
        text = script.string or ""
        if text:
            _check_injection_patterns(text, "script[ld+json]", result)


def _check_injection_patterns(text: str, location: str, result: ScanResult) -> bool:
    """Check text against known injection patterns. Returns True if any found."""
    found = False
    for pattern, severity in COMPILED_PATTERNS:
        match = pattern.search(text)
        if match:
            found = True
            result.findings.append(Finding(
                detector="injection_pattern",
                severity=severity,
                description=f"Injection pattern detected: '{match.group()}'",
                evidence=text[max(0, match.start() - 30):match.end() + 30],
                location=location,
            ))
    return found


def _check_hidden_ratio(result: ScanResult) -> None:
    """Flag pages where hidden text significantly exceeds visible text."""
    if result.hidden_text_chars > 0 and result.visible_text_chars > 0:
        ratio = result.hidden_text_chars / (result.visible_text_chars + result.hidden_text_chars)
        if ratio > 0.3:
            result.findings.append(Finding(
                detector="hidden_ratio",
                severity=Severity.HIGH,
                description=f"Hidden content is {ratio:.0%} of total text ({result.hidden_text_chars} hidden chars)",
                evidence=f"visible={result.visible_text_chars}, hidden={result.hidden_text_chars}",
                location="page-level",
            ))
    elif result.hidden_text_chars > 100 and result.visible_text_chars == 0:
        result.findings.append(Finding(
            detector="hidden_ratio",
            severity=Severity.CRITICAL,
            description="Page contains only hidden text with instructional content",
            evidence=f"hidden={result.hidden_text_chars} chars, visible=0",
            location="page-level",
        ))


def _calculate_risk(result: ScanResult) -> None:
    """Calculate an overall risk score from findings."""
    if not result.findings:
        result.risk_score = 0.0
        return

    weights = {
        Severity.CRITICAL: 0.4,
        Severity.HIGH: 0.25,
        Severity.MEDIUM: 0.1,
        Severity.LOW: 0.05,
        Severity.INFO: 0.01,
    }

    score = sum(weights.get(f.severity, 0) for f in result.findings)
    result.risk_score = min(1.0, score)
