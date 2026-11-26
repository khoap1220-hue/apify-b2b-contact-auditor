from __future__ import annotations

import datetime as dt
import logging
import re
import urllib.parse
import urllib.robotparser
from typing import Any

import httpx
from bs4 import BeautifulSoup

try:
    from apify import Actor  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - local unit-test fallback outside Actor container
    Actor = None  # type: ignore[assignment]

logger = logging.getLogger("b2b_contact_auditor")

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}")
IGNORE_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "domain.com",
    "yourdomain.com",
    "email.com",
    "sentry.io",
    "wixpress.com",
}
IGNORE_EMAIL_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff", ".woff2")

TECH_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "Next.js": ("/_next/static/", "__NEXT_DATA__"),
    "Nuxt": ("/_nuxt/", "__NUXT__"),
    "Webflow": ("data-wf-site", "webflow.com"),
    "WordPress": ("/wp-content/", "/wp-includes/"),
    "Shopify": ("cdn.shopify.com", "Shopify.theme"),
    "HubSpot": ("js.hs-scripts.com", "hsforms.net", "hubspot"),
    "Stripe": ("js.stripe.com", "stripe.com/v3"),
    "Cloudflare": ("cloudflare", "cdn-cgi/"),
    "Intercom": ("widget.intercom.io", "intercomSettings"),
    "Zendesk": ("zdassets.com", "zendesk"),
    "Google Tag Manager": ("googletagmanager.com/gtm.js",),
    "Counter.dev Privacy Analytics": ("cdn.counter.dev/script.js",),
    "Plausible Analytics": ("plausible.io/js/",),
    "PostHog": ("posthog.com", "us.i.posthog.com"),
    "Schema.org JSON-LD": ("application/ld+json",),
}

SOCIAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "github": re.compile(r"https?://(?:www\.)?github\.com/[A-Za-z0-9_.\-]+", re.IGNORECASE),
    "linkedin": re.compile(
        r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|in)/[A-Za-z0-9_.\-%]+",
        re.IGNORECASE,
    ),
    "x_twitter": re.compile(r"https?://(?:www\.)?(?:x\.com|twitter\.com)/[A-Za-z0-9_]+", re.IGNORECASE),
    "youtube": re.compile(
        r"https?://(?:www\.)?youtube\.com/(?:@[A-Za-z0-9_.\-]+|channel/[A-Za-z0-9_\-]+)",
        re.IGNORECASE,
    ),
}

USER_AGENT = "ApifyB2BContactTechAuditor/1.0 (+https://khoaphan.dev; robots-compliant)"


def normalize_url_and_domain(raw: str) -> tuple[str, str]:
    cleaned = raw.strip()
    if not cleaned:
        return "", ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    parsed = urllib.parse.urlparse(cleaned)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if not host or "." not in host:
        return "", ""
    origin = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    return origin, host


def extract_clean_emails(text: str, html: str) -> list[str]:
    found: set[str] = set()
    for candidate in EMAIL_RE.findall(f"{text}\n{html}"):
        email = candidate.strip().strip(".,;:()[]<>\"'").lower()
        if any(email.endswith(ext) for ext in IGNORE_EMAIL_SUFFIXES):
            continue
        local, _, domain = email.partition("@")
        if not local or not domain or domain in IGNORE_EMAIL_DOMAINS:
            continue
        if len(local) > 64 or ".." in email:
            continue
        found.add(email)
    return sorted(found)


def detect_tech_stack(html: str, headers: httpx.Headers) -> list[str]:
    detected: set[str] = set()
    header_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    lower_html = html.lower()
    combined = f"{lower_html}\n{header_blob}"
    for name, needles in TECH_FINGERPRINTS.items():
        if any(n.lower() in combined for n in needles):
            detected.add(name)
    server_hdr = headers.get("server", "").lower()
    if "github.com" in server_hdr:
        detected.add("GitHub Pages")
    elif "vercel" in server_hdr or "x-vercel-id" in headers:
        detected.add("Vercel")
    elif "netlify" in server_hdr:
        detected.add("Netlify")
    return sorted(detected)


RESERVED_SOCIAL_SLUGS = {"share", "intent", "sharer", "home", "explore", "search", "i", "login", "privacy", "tos"}


def extract_social_links(html: str) -> dict[str, list[str]]:
    socials: dict[str, list[str]] = {}
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = sorted(
            {
                m.rstrip("/")
                for m in pattern.findall(html)
                if m.rstrip("/").rsplit("/", 1)[-1].lower() not in RESERVED_SOCIAL_SLUGS
            }
        )
        if matches:
            socials[platform] = matches[:5]
    return socials


async def query_doh_txt_or_mx(client: httpx.AsyncClient, name: str, rr_type: str) -> list[str]:
    try:
        resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": name, "type": rr_type},
            headers={"Accept": "application/dns-json"},
            timeout=6.0,
        )
        if resp.status_code != 200:
            return []
        payload = resp.json()
        return [str(ans.get("data", "")).strip().strip('"') for ans in payload.get("Answer", []) if ans.get("data")]
    except (httpx.HTTPError, ValueError):
        return []


def classify_mx_provider(mx_records: list[str]) -> str:
    joined = " ".join(mx_records).lower()
    if not joined:
        return "none"
    if "google.com" in joined or "googlemail.com" in joined:
        return "Google Workspace"
    if "outlook.com" in joined or "protection.outlook.com" in joined:
        return "Microsoft 365"
    if "zoho." in joined:
        return "Zoho Mail"
    if "protonmail." in joined or "proton.ch" in joined:
        return "Proton Mail"
    if "yahoodns." in joined:
        return "Yahoo Business"
    if "fastmail." in joined:
        return "Fastmail"
    if "improvmx." in joined or "forwardemail." in joined:
        return "Email Forwarding"
    return mx_records[0].split()[-1].rstrip(".")


async def is_allowed_by_robots(client: httpx.AsyncClient, origin: str, url: str) -> bool:
    try:
        resp = await client.get(f"{origin}/robots.txt", timeout=5.0)
        if resp.status_code != 200:
            return True
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(resp.text.splitlines())
        return rp.can_fetch(USER_AGENT, url)
    except (httpx.HTTPError, ValueError):
        return True


async def audit_single_domain(
    client: httpx.AsyncClient,
    raw_domain: str,
    crawl_contact_pages: bool,
    check_dns_email_auth: bool,
    respect_robots: bool,
    timeout_secs: int,
) -> dict[str, Any] | None:
    origin, domain = normalize_url_and_domain(raw_domain)
    if not origin or not domain:
        return None

    routes = ["/"]
    if crawl_contact_pages:
        routes.extend(["/contact", "/about", "/services", "/.well-known/security.txt"])

    all_emails: set[str] = set()
    all_tech: set[str] = set()
    merged_socials: dict[str, set[str]] = {}
    page_title = ""
    primary_status = 0
    pages_scanned = 0

    for idx, route in enumerate(routes):
        target_url = f"{origin}{route}"
        if respect_robots and not await is_allowed_by_robots(client, origin, target_url):
            continue
        try:
            resp = await client.get(target_url, timeout=float(timeout_secs), follow_redirects=True)
        except httpx.HTTPError as exc:
            if idx == 0:
                if Actor is not None:
                    Actor.log.warning(f"Failed fetching {target_url}: {exc}")
                else:
                    logger.warning("Failed fetching %s: %s", target_url, exc)
            continue

        if idx == 0:
            primary_status = resp.status_code
        if resp.status_code >= 400:
            continue

        pages_scanned += 1
        html = resp.text[:350_000]
        soup = BeautifulSoup(html, "html.parser")
        if idx == 0 and soup.title and soup.title.string:
            page_title = soup.title.string.strip()[:180]

        visible_text = soup.get_text(" ", strip=True)
        all_emails.update(extract_clean_emails(visible_text, html))
        all_tech.update(detect_tech_stack(html, resp.headers))
        for k, vals in extract_social_links(html).items():
            merged_socials.setdefault(k, set()).update(vals)

    mx_provider = "unchecked"
    has_spf = False
    has_dmarc = False
    if check_dns_email_auth:
        mx_records, txt_records, dmarc_records = await asyncio_gather_dns(client, domain)
        mx_provider = classify_mx_provider(mx_records)
        has_spf = any("v=spf1" in r.lower() for r in txt_records)
        has_dmarc = any("v=dmarc1" in r.lower() for r in dmarc_records)

    return {
        "domain": domain,
        "start_url": origin,
        "http_status": primary_status,
        "title": page_title,
        "emails": sorted(all_emails),
        "social_links": {k: sorted(v) for k, v in sorted(merged_socials.items())},
        "tech_stack": sorted(all_tech),
        "email_provider": mx_provider,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "pages_scanned": pages_scanned,
        "audited_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


async def asyncio_gather_dns(client: httpx.AsyncClient, domain: str) -> tuple[list[str], list[str], list[str]]:
    import asyncio

    mx_task = query_doh_txt_or_mx(client, domain, "MX")
    txt_task = query_doh_txt_or_mx(client, domain, "TXT")
    dmarc_task = query_doh_txt_or_mx(client, f"_dmarc.{domain}", "TXT")
    return await asyncio.gather(mx_task, txt_task, dmarc_task)


async def main() -> None:
    if Actor is None:
        raise RuntimeError("apify SDK is required at runtime inside the Actor container")
    async with Actor:
        actor_input = await Actor.get_input() or {}
        domains = actor_input.get("domains") or ["https://khoaphan.dev"]
        crawl_contact_pages = bool(actor_input.get("crawlContactPages", True))
        check_dns_email_auth = bool(actor_input.get("checkDnsEmailAuth", True))
        respect_robots = bool(actor_input.get("respectRobotsTxt", True))
        timeout_secs = int(actor_input.get("requestTimeoutSecs", 12))

        Actor.log.info(f"Auditing {len(domains)} domain(s) (robots={respect_robots}, dns={check_dns_email_auth})")
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"}
        async with httpx.AsyncClient(headers=headers) as client:
            for raw_domain in domains[:100]:
                record = await audit_single_domain(
                    client=client,
                    raw_domain=str(raw_domain),
                    crawl_contact_pages=crawl_contact_pages,
                    check_dns_email_auth=check_dns_email_auth,
                    respect_robots=respect_robots,
                    timeout_secs=timeout_secs,
                )
                if record:
                    await Actor.push_data(record)
                    Actor.log.info(
                        f"Enriched {record['domain']}: status={record['http_status']} "
                        f"emails={len(record['emails'])} mx={record['email_provider']} tech={len(record['tech_stack'])}"
                    )
