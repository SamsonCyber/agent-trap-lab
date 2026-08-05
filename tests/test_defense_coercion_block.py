"""Defended path must block ssrf-web-fetch + finbot-privilege coercion pages."""

from __future__ import annotations

import pytest

from agent.defense import full_defense
from traps.agent_coercion import (
    CANARY,
    finbot_privilege_coerce,
    ssrf_web_fetch,
)


class TestCoercionPagesBlocked:
    def test_ssrf_web_fetch_full_defense_blocks(self):
        html = ssrf_web_fetch()
        clean, report = full_defense(html)
        assert report.blocked is True
        assert report.prompt_injection_detected is True
        # Canary must not survive as free text for the model
        assert CANARY not in clean
        assert "169.254.169.254" not in clean

    def test_finbot_privilege_full_defense_blocks(self):
        html = finbot_privilege_coerce()
        clean, report = full_defense(html)
        assert report.blocked is True
        assert report.prompt_injection_detected is True
        assert CANARY not in clean
        assert "169.254.169.254" not in clean

    def test_clean_control_page_not_blocked(self):
        # Avoid substrings that trip StegOFF jailbreak_keyword FP (e.g. "dan" in "competitive")
        html = """<!DOCTYPE html>
<html><head><title>Product Review</title></head><body>
<article>
<h1>Product Review: CloudSync Pro</h1>
<p>CloudSync Pro is a cloud storage solution that offers 50GB free storage
with basic synchronization features. User reviews are mixed, with some
praising the interface and others reporting occasional sync delays.</p>
<p>The product offers standard features at a fair price point.
Customer support response times average 24 hours.</p>
</article>
</body></html>"""
        clean, report = full_defense(html)
        assert report.blocked is False, (
            f"clean page blocked: findings={report.stegoff_findings[:2]}"
        )
        assert "CloudSync" in clean

    def test_benign_finance_blurb_not_blocked(self):
        html = """<!DOCTYPE html><html><body>
<p>AAPL consolidates near VWAP. Services narrative into print.
Prefer SEC 8-K and company IR for primary facts.</p>
</body></html>"""
        _clean, report = full_defense(html)
        assert report.blocked is False, (
            f"finance blurb blocked: findings={report.stegoff_findings[:2]}"
        )
