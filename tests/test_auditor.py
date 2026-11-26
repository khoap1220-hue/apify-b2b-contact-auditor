from __future__ import annotations

import unittest

import httpx

from src.main import (
    classify_mx_provider,
    detect_tech_stack,
    extract_clean_emails,
    extract_social_links,
    normalize_url_and_domain,
)


class TestB2BContactAuditor(unittest.TestCase):
    def test_normalize_url_and_domain(self) -> None:
        origin, host = normalize_url_and_domain("www.khoaphan.dev/services")
        self.assertEqual(origin, "https://www.khoaphan.dev")
        self.assertEqual(host, "khoaphan.dev")

    def test_extract_clean_emails_filters_assets_and_placeholders(self) -> None:
        html = """
        <a href="mailto:Khoa@KhoaPhan.dev">Email</a>
        <img src="banner@2x.png" />
        <span>test@example.com</span>
        <span>hello@inovaflow.io.</span>
        """
        emails = extract_clean_emails("", html)
        self.assertEqual(emails, ["hello@inovaflow.io", "khoa@khoaphan.dev"])

    def test_detect_tech_stack_and_mx(self) -> None:
        html = '<script src="https://cdn.counter.dev/script.js"></script><script type="application/ld+json">{}</script>'
        tech = detect_tech_stack(html, httpx.Headers({"server": "GitHub.com"}))
        self.assertIn("GitHub Pages", tech)
        self.assertIn("Counter.dev Privacy Analytics", tech)
        self.assertIn("Schema.org JSON-LD", tech)
        self.assertEqual(classify_mx_provider(["10 mx.zoho.com.", "20 mx2.zoho.com."]), "Zoho Mail")
        self.assertEqual(classify_mx_provider(["1 aspmx.l.google.com."]), "Google Workspace")

    def test_extract_social_links_excludes_share_intents(self) -> None:
        html = """
        <a href="https://github.com/khoap1220-hue">GH</a>
        <a href="https://x.com/intent/tweet?text=hi">Share</a>
        <a href="https://x.com/KPhan407/">X</a>
        """
        socials = extract_social_links(html)
        self.assertEqual(socials["github"], ["https://github.com/khoap1220-hue"])
        self.assertEqual(socials["x_twitter"], ["https://x.com/KPhan407"])


if __name__ == "__main__":
    unittest.main()
