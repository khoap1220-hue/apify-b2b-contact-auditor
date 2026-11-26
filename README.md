# B2B Company Contact, Tech Stack & DNS Auth Auditor (`n8n` / `Make` / `Zapier` / `MCP` Ready)

Deterministic, `robots.txt`-compliant B2B company enrichment Actor designed for **Automation Agencies, RevOps Workflows, and Model Context Protocol (MCP) Agents**.

## What It Extracts Per Domain
1. **Verified First-Party Public Contacts**: Deduplicated public emails across `/`, `/contact`, `/about`, `/services`, and `/.well-known/security.txt` (with asset/placeholder noise stripped).
2. **Social & Engineering Footprint**: Official GitHub, LinkedIn, X/Twitter, and YouTube links.
3. **Web & GTM Tech Stack**: Detects Next.js, Webflow, Shopify, WordPress, HubSpot, Stripe, Cloudflare, Intercom, Zendesk, PostHog, Plausible, Counter.dev, Vercel, Netlify, GitHub Pages, and JSON-LD Schema.
4. **Email Infrastructure & Deliverability Posture (`DNS-over-HTTPS`)**: Identifies active MX provider (`Google Workspace`, `Microsoft 365`, `Zoho Mail`, `Proton Mail`, etc.) plus `SPF` (`v=spf1`) and `DMARC` (`v=DMARC1`) policies.

## Sample Output
```json
{
  "domain": "khoaphan.dev",
  "start_url": "https://khoaphan.dev",
  "http_status": 200,
  "title": "Khoa Phan — Systems & AI Architect",
  "emails": ["khoa@khoaphan.dev", "khoap1220@gmail.com"],
  "social_links": {
    "github": ["https://github.com/khoap1220-hue"],
    "linkedin": ["https://www.linkedin.com/in/khoa-phan-55bab8448"],
    "x_twitter": ["https://x.com/KPhan407"]
  },
  "tech_stack": ["Counter.dev Privacy Analytics", "GitHub Pages", "Schema.org JSON-LD"],
  "email_provider": "Zoho Mail",
  "has_spf": true,
  "has_dmarc": true,
  "pages_scanned": 4,
  "audited_at_utc": "2026-11-26T14:35:00Z"
}
```

## Custom White-Label Actors, Playwright Pipelines & MCP Servers
Built by **Khoa Phan** ([khoaphan.dev](https://khoaphan.dev) · `khoa@khoaphan.dev` · 20+ merged upstream OSS PRs · 4 official Anthropic MCP Registry servers). Available for white-label agency subcontracting and custom Apify/Playwright/MCP integrations.
