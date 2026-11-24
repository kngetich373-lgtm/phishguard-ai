"""
URL phishing / scam detection engine (2026 edition) — pentest-style report.

This uses a transparent, explainable heuristic scoring model rather than a
black-box classifier, so every verdict comes with a percentage risk score
AND a human-readable, weighted breakdown of exactly which signals drove
that number (e.g. "+40 pts (46% of total) — domain is 98 days old").
It's designed so a real ML/GBM/logistic-regression model (see app/ml/) can
be dropped in later to replace or augment the scoring without touching
callers - the public functions keep stable return shapes.

Signals checked
----------------
Structural / URL-level:
  - IP address used instead of a domain name
  - "@" symbol in the URL (classic redirect trick)
  - Excessive subdomains / URL length
  - Excessive hyphens in the domain (common in throwaway scam domains,
    e.g. "secure-account-verify-paypal-login.com")
  - Suspicious / high-abuse TLDs (updated for 2026: .zip, .top, .icu,
    .cam, .sbs, .quest, .cyou, .mom, .bond, .rest, .surf, .lat, etc.)
  - Punycode / homograph domains (xn--)
  - Missing HTTPS
  - URL shorteners (hides real destination)

Brand-impersonation:
  - Brand keyword + non-brand domain ("secure-paypal-login.com")
  - Typosquatting distance to well-known brand / bank / trading domains
  - Homoglyph / leetspeak character-substitution squatting
    (e.g. "paypa1.com", "arnazon.com" using rn->m, 0->o, 1->l, vv->w)

Domain / network infrastructure (the signals a pentester checks that a
purely lexical scanner can't):
  - Domain age via WHOIS - newly-registered domains are one of the
    single strongest phishing signals, since scam infrastructure is
    typically stood up and burned within days or weeks (Bolster AI
    tracked 11.9M+ malicious domains registered in 2025 alone).
  - Free / no-code app-builder & static-hosting platforms (Lovable,
    Vercel, Netlify, Replit, GitHub Pages, etc.) - anyone can register a
    subdomain here in minutes with zero verification, so WHOIS on the
    apex domain tells you nothing about the specific scam page. For
    these, site age is instead measured via Certificate Transparency
    logs (crt.sh) on the exact hostname.
  - WHOIS privacy/proxy protection - a weak signal alone (very common
    even for legitimate sites now) but contributes when stacked with
    other factors.
  - DNS resolution failure - a hostname that doesn't resolve at all is
    either already taken down, brand new, or entirely fabricated.
  - Redirect-chain cloaking - if the URL redirects to a completely
    different registrable domain than the one shown, that mismatch is
    itself a classic phishing/cloaking technique.

Content / social-engineering keyword families (each scored and reported
separately so the "why" is transparent):
  - Generic urgency / credential-harvesting keywords (verify, confirm,
    suspended, password-reset...)
  - Predatory loan / debt-relief / "free government money" keywords,
    which disproportionately target financially vulnerable people
    (instant-loan, no-credit-check, guaranteed-approval, debt-relief,
    stimulus-payment, grant-approved...)
  - Crypto / trading / "guaranteed returns" investment-scam keywords
    (double-your-bitcoin, wallet-recovery, seed-phrase, airdrop-claim,
    connect-wallet, trading-bot, high-yield...)
  - Tech-support / remote-access scam keywords (virus-detected,
    remote-access, call-now, refund-department...)
  - Bare financial-sector words in the hostname itself (loan, credit,
    wallet...) - weak alone, meaningful stacked with other factors.

Not implemented here (noted for future work, since they need
repeated/longitudinal queries or a live rendering engine rather than a
single-pass URL check): fast-flux DNS detection (IP churn over time),
nameserver-clustering across a threat actor's domain portfolio, and
visual/screenshot similarity matching against real login pages.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.request
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract
import Levenshtein

try:
    import whois as _whois  # python-whois package: pip install python-whois
except ImportError:  # pragma: no cover - optional dependency
    _whois = None


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# High-abuse TLDs. Cheap/bulk-registered TLDs remain the top choice for
# throwaway scam infrastructure because they are inexpensive and require
# little verification. List refreshed with 2025/2026 abused new gTLDs.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "gq", "tk", "ml", "cf", "ga", "work",
    "click", "link", "loan", "download", "review", "country", "kim",
    "icu", "cam", "sbs", "quest", "cyou", "mom", "bond", "rest", "surf",
    "lat", "monster", "beauty", "makeup", "wiki", "fit", "cfd", "biz",
    "info", "live", "vip",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc",
    "shorturl.at", "v.gd", "tr.im", "s.id", "qr.ae", "rb.gy", "gg.gg",
}

# Well-known brand / bank / trading / government domains that are
# frequently impersonated. Expanded to cover fintech, crypto exchanges,
# and trading platforms, since "clone" investment sites are one of the
# fastest-growing scam categories in 2026.
BRAND_DOMAINS = {
    # payments & big tech
    "paypal.com", "apple.com", "amazon.com", "microsoft.com", "google.com",
    "netflix.com", "facebook.com", "instagram.com", "linkedin.com",
    "venmo.com", "cashapp.com", "zellepay.com",
    # banks
    "bankofamerica.com", "wellsfargo.com", "chase.com", "citibank.com",
    "capitalone.com", "usbank.com", "hsbc.com", "revolut.com",
    # shipping / government (heavily used in smishing lures)
    "dhl.com", "usps.com", "fedex.com", "ups.com",
    "irs.gov", "ssa.gov", "medicare.gov", "usa.gov",
    # crypto & trading platforms (clone-site target list)
    "coinbase.com", "binance.com", "kraken.com", "robinhood.com",
    "fidelity.com", "schwab.com", "etrade.com", "etoro.com",
    "outlook.com", "office.com",
    # security / tech-support brand names abused in fake-alert scams
    "mcafee.com", "norton.com",
}

# Free / no-code app-builder and static-hosting platforms. Anyone can spin
# up a subdomain here in minutes with zero verification, so WHOIS on the
# apex domain is meaningless (it just reflects the platform's own age, e.g.
# "lovable.app" or "vercel.app" - both legitimate, long-established
# companies). Scammers increasingly use AI/no-code site builders to clone a
# bank/loan/crypto page in minutes, so a financial-sounding subdomain living
# on one of these platforms is itself a strong red flag. Legitimate banks,
# lenders, and brokerages do not operate on shared consumer platforms.
FREE_HOSTING_PLATFORMS = {
    "lovable.app", "vercel.app", "netlify.app", "pages.dev", "repl.co",
    "replit.app", "glitch.me", "weebly.com", "wixsite.com", "github.io",
    "framer.app", "framer.website", "webflow.io", "typedream.app",
    "carrd.co", "streamlit.app", "herokuapp.com", "firebaseapp.com",
    "web.app", "surge.sh", "onrender.com", "000webhostapp.com",
    "yolasite.com", "square.site", "godaddysites.com", "notion.site",
    "super.site", "bubbleapps.io", "myshopify.com",
}

# Character substitutions commonly used to visually squat on a brand name
# without tripping a plain edit-distance check (e.g. "paypa1", "rnicrosoft").
_HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "rn": "m", "vv": "w", "ii": "u",
}

GENERIC_SUSPICIOUS_KEYWORDS = [
    "verify", "confirm", "suspend", "update-account", "secure-login",
    "unlock-account", "login-alert", "billing-issue", "reactivate",
    "signin", "password-reset", "gift-card", "claim-prize", "urgent-action",
]

# Predatory lending / "free money" keywords. These specifically target
# people under financial stress - a group that fraud-prevention research
# (AARP, FTC) consistently flags as most vulnerable to loan and
# government-benefit scams.
LOAN_AND_BENEFIT_SCAM_KEYWORDS = [
    "instant-loan", "same-day-loan", "no-credit-check", "guaranteed-approval",
    "payday-loan", "debt-relief", "loan-approved", "cash-advance",
    "quick-cash", "bad-credit-loan", "loan-now", "borrow-now",
    "student-loan-forgiveness", "grant-approved", "stimulus-payment",
    "government-grant", "free-money", "unclaimed-funds", "debt-forgiveness",
]

# Crypto / trading / investment scam keywords. "Guaranteed return" and
# wallet-drain lures are the dominant pattern in 2026 investment fraud.
INVESTMENT_AND_CRYPTO_SCAM_KEYWORDS = [
    "double-your-bitcoin", "guaranteed-returns", "guaranteed-profit",
    "crypto-investment", "forex-signal", "trading-bot", "high-yield",
    "mining-platform", "airdrop-claim", "wallet-recovery", "wallet-verify",
    "seed-phrase", "connect-wallet", "wallet-connect", "investment-opportunity",
    "risk-free-trading", "copy-trading",
]

# Tech-support / remote-access / romance-scam callback keywords.
SOCIAL_ENGINEERING_SCAM_KEYWORDS = [
    "virus-detected", "remote-access", "call-now", "refund-department",
    "account-recovery-service", "tech-support", "security-alert-call",
    "customer-support-verify",
]

# Bare financial-sector words. On their own these are weak signals (many
# legitimate fintechs use "loan" or "credit" in a domain), so they score
# low individually - but combined with a free-hosting platform or a
# brand-new site, they matter a lot. This is what catches a subdomain
# like "zam-loans" that doesn't contain any of the longer compound scam
# phrases above.
GENERIC_FINANCIAL_TERMS = {
    "loan", "loans", "credit", "lending", "mortgage", "borrow", "borrower",
    "invest", "investing", "trading", "forex", "crypto", "wallet", "bank",
    "banking",
}

KEYWORD_FAMILIES = {
    "generic urgency/credential-harvesting": GENERIC_SUSPICIOUS_KEYWORDS,
    "predatory loan / government-benefit scam": LOAN_AND_BENEFIT_SCAM_KEYWORDS,
    "crypto / trading investment scam": INVESTMENT_AND_CRYPTO_SCAM_KEYWORDS,
    "tech-support / remote-access scam": SOCIAL_ENGINEERING_SCAM_KEYWORDS,
}

# Domain-age thresholds (in days). New domains/sites are one of the
# strongest phishing signals because scam infrastructure is usually stood
# up and burned within days to weeks of a campaign.
DOMAIN_AGE_VERY_NEW_DAYS = 7
DOMAIN_AGE_NEW_DAYS = 30
DOMAIN_AGE_YOUNG_DAYS = 180

# Substrings in a WHOIS registrant name/org that indicate privacy-proxy
# registration. Very common for legitimate sites too, so this is a light,
# stacking-only signal, never scored alone as decisive.
WHOIS_PRIVACY_MARKERS = (
    "privacy", "redacted", "whoisguard", "domains by proxy", "proxy protection",
    "perfect privacy", "identity protection service", "withheld for privacy",
)


@dataclass(frozen=True)
class RiskFactor:
    """A single contributing signal: how many points it added, and why."""
    points: float
    reason: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_homoglyphs(name: str) -> str:
    """Collapse common look-alike character substitutions back to Latin
    letters so typosquats like 'paypa1' or 'arnaz0n' still match their
    target brand."""
    normalized = name.lower()
    for fake, real in _HOMOGLYPH_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized


def _closest_brand_distance(domain: str) -> tuple[str, int] | None:
    """Return (brand, edit_distance) for the closest known brand domain,
    checking both the raw name and a homoglyph-normalized version."""
    best = None
    domain_name = domain.split(".")[0]
    domain_variants = {domain_name, _normalize_homoglyphs(domain_name)}
    for brand in BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        for variant in domain_variants:
            dist = Levenshtein.distance(variant, brand_name)
            if best is None or dist < best[1]:
                best = (brand, dist)
    return best


def get_domain_age_days(registered_domain: str, timeout: float = 5.0) -> int | None:
    """
    Look up a domain's WHOIS creation date and return its age in days.

    Returns None if the lookup fails or the `python-whois` package isn't
    installed (`pip install python-whois`) - callers should treat None as
    "unknown", not "safe". This performs a network call, so pass
    check_live_signals=False to score_url()/generate_report() in
    offline/batch contexts.
    """
    if _whois is None or not registered_domain:
        return None
    try:
        record = _whois.whois(registered_domain)
        created = record.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - created
        return max(0, age.days)
    except Exception:
        # WHOIS servers are unreliable/rate-limited; any failure just
        # means "age unknown", not "safe" or "malicious".
        return None


def whois_uses_privacy_proxy(registered_domain: str) -> bool | None:
    """Return True if WHOIS registrant details are masked by a privacy
    proxy service, False if visible, None if unknown/lookup failed."""
    if _whois is None or not registered_domain:
        return None
    try:
        record = _whois.whois(registered_domain)
        haystack = " ".join(
            str(v) for v in (record.get("org"), record.get("name"), record.get("registrant_name"))
            if v
        ).lower()
        if not haystack:
            return None
        return any(marker in haystack for marker in WHOIS_PRIVACY_MARKERS)
    except Exception:
        return None


def get_subdomain_first_seen_days(hostname: str, timeout: float = 6.0) -> int | None:
    """
    Look up the earliest publicly-logged TLS certificate for this *exact*
    hostname via Certificate Transparency logs (crt.sh) and return its age
    in days.

    Unlike WHOIS - which only knows the registration date of the apex
    domain - this reflects when the specific hostname first went live.
    That makes it the right tool for subdomains on shared platforms like
    "zam-loans.lovable.app", where WHOIS would only ever tell you how old
    "lovable.app" (the platform) is, not how old the scam page itself is.

    Returns None on any failure (no network, no cert history, rate limit,
    malformed response) - callers should treat None as "unknown".
    """
    if not hostname:
        return None
    try:
        query_url = f"https://crt.sh/?q={hostname}&output=json"
        request = urllib.request.Request(
            query_url, headers={"User-Agent": "url-scam-detector/1.0"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="ignore").strip()
        if not raw:
            return None
        # crt.sh's JSON endpoint sometimes streams back-to-back objects
        # without wrapping them in an array; normalize before parsing.
        if not raw.startswith("["):
            raw = "[" + raw.replace("}\n{", "},{").replace("}{", "},{") + "]"
        records = json.loads(raw)
        if not records:
            return None
        earliest = None
        for record in records:
            not_before = record.get("not_before")
            if not not_before:
                continue
            try:
                issued = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue
            issued = issued.replace(tzinfo=timezone.utc)
            if earliest is None or issued < earliest:
                earliest = issued
        if earliest is None:
            return None
        age = datetime.now(timezone.utc) - earliest
        return max(0, age.days)
    except Exception:
        return None


def resolves_in_dns(host: str, timeout: float = 3.0) -> bool | None:
    """Return True if the hostname resolves to an IP address, False if it
    doesn't, None if the check itself failed (e.g. no network)."""
    if not host:
        return None
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def final_redirect_domain(url: str, timeout: float = 6.0) -> str | None:
    """Follow redirects and return the registrable domain the URL actually
    lands on. Returns None on failure/no network. A mismatch between the
    domain shown to the user and the domain actually reached is a classic
    cloaking technique."""
    try:
        initial = urllib.parse.urlsplit(url)
        if initial.scheme not in {"http", "https"} or not initial.hostname:
            return None
        if initial.hostname.lower() in {"localhost"} or initial.hostname.lower().endswith(".localhost"):
            return None
        for item in socket.getaddrinfo(initial.hostname, initial.port or (443 if initial.scheme == "https" else 80)):
            ip = ipaddress.ip_address(item[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return None
    except (socket.gaierror, ValueError):
        return None

    class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            try:
                parsed = urllib.parse.urlsplit(newurl)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    return None
                for item in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)):
                    ip = ipaddress.ip_address(item[4][0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                        return None
            except (socket.gaierror, ValueError):
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    try:
        request = urllib.request.Request(url, headers={"User-Agent": "url-scam-detector/1.0"})
        opener = urllib.request.build_opener(SafeRedirectHandler)
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
        final_ext = tldextract.extract(final_url)
        if not final_ext.suffix:
            return None
        return f"{final_ext.domain}.{final_ext.suffix}"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Core scoring
# ---------------------------------------------------------------------------

def _collect_risk_factors(raw_url: str, check_live_signals: bool = True) -> list[RiskFactor]:
    """Run every heuristic and return the list of (points, reason) factors
    that fired. This is the single source of truth used by both
    score_url() (legacy tuple API) and generate_report() (percentage
    report API), so the two can never drift out of sync."""
    factors: list[RiskFactor] = []

    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url  # normalize so urlparse works

    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # 1. IP address as host
    if host and _is_ip_address(host):
        factors.append(RiskFactor(30, "Uses a raw IP address instead of a domain name"))

    # 2. "@" trick - browsers ignore everything before @
    if "@" in url:
        factors.append(RiskFactor(
            25, 'Contains an "@" symbol, often used to mask the real destination'
        ))

    # 3. Excessive subdomains
    subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0
    if subdomain_count >= 3:
        factors.append(RiskFactor(
            15, f"Unusually deep subdomain chain ({subdomain_count} levels)"
        ))

    # 4. Very long URL (often used to obscure the real domain)
    if len(url) > 90:
        factors.append(RiskFactor(10, "Unusually long URL"))

    # 5. Excessive hyphens in the domain (typical of throwaway scam domains
    #    like "secure-account-verify-paypal-login.com")
    hyphen_count = ext.domain.count("-") if ext.domain else 0
    if hyphen_count >= 3:
        factors.append(RiskFactor(
            15, f"Domain name contains an unusually high number of hyphens ({hyphen_count})"
        ))

    # 6. Suspicious TLD
    if ext.suffix and ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        factors.append(RiskFactor(
            15, f'Top-level domain ".{ext.suffix}" is frequently abused for phishing/scams'
        ))

    # 7. No HTTPS
    if parsed.scheme != "https":
        factors.append(RiskFactor(10, "Connection is not encrypted (no HTTPS)"))

    # 8. URL shortener
    if registered_domain in URL_SHORTENERS:
        factors.append(RiskFactor(
            15, "Uses a URL shortener, which hides the real destination"
        ))

    # 9. Punycode / homograph attack
    if "xn--" in host:
        factors.append(RiskFactor(
            30, "Domain uses punycode encoding, a common homograph-attack technique"
        ))

    # 10. Brand keyword / typosquat / homoglyph-squat present but domain
    #     isn't the real brand
    if ext.domain:
        closest = _closest_brand_distance(registered_domain)
        if closest:
            brand, dist = closest
            if registered_domain != brand and 0 < dist <= 2:
                factors.append(RiskFactor(
                    35,
                    f'Domain closely mimics "{brand}" (possible typosquatting or '
                    "character-substitution/homoglyph squatting)"
                ))
        normalized_domain = _normalize_homoglyphs(ext.domain)
        for brand in BRAND_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name in normalized_domain and registered_domain != brand:
                factors.append(RiskFactor(
                    25, f'Contains brand name "{brand_name}" but is not the official domain'
                ))
                break

    # 11. Suspicious keyword families - scanned across the FULL hostname
    #     (including subdomain, e.g. "zam-loans" in
    #     "zam-loans.lovable.app") plus path/query, not just path/query.
    searchable_text = f"{host} {parsed.path} {parsed.query}".lower().replace("_", "-")
    normalized_text = searchable_text.replace("-", "")
    for family_label, keywords in KEYWORD_FAMILIES.items():
        hits = [kw for kw in keywords if kw.replace("-", "") in normalized_text]
        if hits:
            factors.append(RiskFactor(
                min(25, 8 * len(hits)),
                f"Contains {family_label} keywords: {', '.join(hits[:3])}"
            ))

    # 11b. Bare financial-sector words in the hostname (catches subdomains
    #      like "zam-loans" that don't match a full compound scam phrase).
    host_tokens = set(re.split(r"[^a-z0-9]+", host.lower()))
    financial_hits = host_tokens & GENERIC_FINANCIAL_TERMS
    if financial_hits:
        factors.append(RiskFactor(
            10,
            "Hostname references a financial-sector term ("
            f"{', '.join(sorted(financial_hits))}) - worth extra scrutiny, "
            "especially combined with other signals below"
        ))

    # 12. Free / no-code app-builder hosting platforms. Legitimate banks,
    #     lenders, and brokerages don't operate on shared consumer
    #     platforms.
    is_free_hosting_platform = registered_domain.lower() in FREE_HOSTING_PLATFORMS
    if is_free_hosting_platform:
        factors.append(RiskFactor(
            20,
            f'Hosted on "{registered_domain}", a free/no-code site-builder platform - '
            "legitimate financial institutions do not operate on shared consumer hosting"
        ))

    if check_live_signals and (registered_domain or host):
        # 13. Domain / site age. Shared-hosting platforms get a
        #     Certificate Transparency lookup on the exact hostname
        #     instead of WHOIS on the apex domain.
        if is_free_hosting_platform:
            age_days = get_subdomain_first_seen_days(host)
            age_source = "certificate transparency logs for this exact hostname"
        else:
            age_days = get_domain_age_days(registered_domain)
            age_source = "WHOIS"

        if age_days is not None:
            if age_days <= DOMAIN_AGE_VERY_NEW_DAYS:
                factors.append(RiskFactor(
                    40,
                    f"This hostname is only {age_days} day(s) old per {age_source} - "
                    "extremely new sites are strongly correlated with scam infrastructure"
                ))
            elif age_days <= DOMAIN_AGE_NEW_DAYS:
                factors.append(RiskFactor(
                    25,
                    f"This hostname is only {age_days} days old per {age_source} "
                    "(within the last month)"
                ))
            elif age_days <= DOMAIN_AGE_YOUNG_DAYS:
                factors.append(RiskFactor(
                    10,
                    f"This hostname is relatively young ({age_days} days old per "
                    f"{age_source}, under 6 months)"
                ))
        else:
            factors.append(RiskFactor(
                0, f"Site age could not be verified ({age_source} lookup unavailable or failed)"
            ))

        # 14. DNS resolution. A hostname that doesn't resolve at all is
        #     either taken down, brand new, or fabricated.
        resolves = resolves_in_dns(host)
        if resolves is False:
            factors.append(RiskFactor(
                20,
                "Hostname does not resolve to any IP address - the site may be "
                "freshly created, already taken down, or entirely fabricated"
            ))

        # 15. WHOIS privacy/proxy protection - a weak, stacking-only
        #     signal (very common for legitimate sites too).
        if not is_free_hosting_platform:
            privacy = whois_uses_privacy_proxy(registered_domain)
            if privacy is True:
                factors.append(RiskFactor(
                    5,
                    "Domain registrant identity is hidden behind a WHOIS privacy proxy "
                    "(common for legitimate sites too, but adds up with other factors)"
                ))

        # 16. Redirect-chain cloaking. If the URL redirects to a
        #     completely different registrable domain, that mismatch is a
        #     classic phishing/cloaking technique.
        if resolves is not False:
            landing_domain = final_redirect_domain(url)
            if landing_domain and registered_domain and landing_domain != registered_domain:
                factors.append(RiskFactor(
                    30,
                    f'URL redirects to a different domain ("{landing_domain}") than the '
                    f'one shown ("{registered_domain}") - a classic cloaking technique'
                ))

    return factors


def score_url(raw_url: str, check_domain_age: bool = True) -> tuple[float, list[str]]:
    """
    Legacy API. Returns (risk_score 0-100, reasons[]).
    0-29 = safe, 30-64 = suspicious, 65-100 = malicious (see classify_score).

    check_domain_age: if True (default), performs live lookups (WHOIS,
    Certificate Transparency, DNS resolution, redirect-chain following) to
    score infrastructure freshness and cloaking. Set to False for offline
    use or bulk scoring where lookup latency/rate limits are a concern.

    Prefer generate_report() for a full percentage breakdown; this
    function is kept so existing callers don't need to change.
    """
    factors = _collect_risk_factors(raw_url, check_live_signals=check_domain_age)
    total = max(0.0, min(100.0, sum(f.points for f in factors)))
    reasons = [f.reason for f in factors if f.points > 0] or [f.reason for f in factors]
    if not reasons:
        reasons = ["No known phishing indicators detected"]
    return total, reasons


def classify_score(score: float) -> str:
    if score >= 65:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "safe"


def generate_report(raw_url: str, check_live_signals: bool = True) -> dict:
    """
    Full pentest-style risk report with a percentage score and a weighted,
    ranked breakdown of every contributing factor - e.g.:

        {
          "url": "https://zam-loans.lovable.app/",
          "risk_percentage": 65.0,
          "verdict": "malicious",
          "summary": "65% risk score, primarily because this hostname is
                      only 4 days old per certificate transparency logs
                      for this exact hostname.",
          "factors": [
              {"points": 40, "weight_percent": 61.5,
               "reason": "This hostname is only 4 day(s) old per..."},
              {"points": 20, "weight_percent": 30.8,
               "reason": "Hosted on \"lovable.app\", a free/no-code..."},
              {"points": 5,  "weight_percent": 7.7,
               "reason": "Hostname references a financial-sector term..."},
          ]
        }

    check_live_signals: if True (default), performs live network lookups
    (WHOIS, Certificate Transparency, DNS, redirect-following). Set False
    for offline/bulk use.
    """
    factors = _collect_risk_factors(raw_url, check_live_signals=check_live_signals)
    scored_factors = [f for f in factors if f.points > 0]
    informational = [f for f in factors if f.points == 0]

    raw_total = sum(f.points for f in scored_factors)
    risk_percentage = round(max(0.0, min(100.0, raw_total)), 1)
    verdict = classify_score(risk_percentage)

    ranked = sorted(scored_factors, key=lambda f: f.points, reverse=True)
    breakdown = [
        {
            "points": f.points,
            "weight_percent": round((f.points / raw_total * 100), 1) if raw_total else 0.0,
            "reason": f.reason,
        }
        for f in ranked
    ]
    for f in informational:
        breakdown.append({"points": 0, "weight_percent": 0.0, "reason": f.reason})

    if not ranked:
        summary = f"{risk_percentage:.0f}% risk score - no known phishing indicators detected."
    elif len(ranked) == 1:
        summary = f"{risk_percentage:.0f}% risk score, because {ranked[0].reason[0].lower()}{ranked[0].reason[1:]}."
    else:
        top = ranked[0]
        second = ranked[1]
        summary = (
            f"{risk_percentage:.0f}% risk score, primarily because "
            f"{top.reason[0].lower()}{top.reason[1:]} "
            f"(also: {second.reason[0].lower()}{second.reason[1:]})."
        )

    return {
        "url": raw_url,
        "risk_percentage": risk_percentage,
        "verdict": verdict,
        "summary": summary,
        "factors": breakdown,
    }


def generate_report_with_reputation(raw_url: str, reputation_factor: dict | None,
                                     check_live_signals: bool = True) -> dict:
    """
    Same as generate_report(), but also folds in an externally-computed
    reputation signal (see reputation_search.py) - e.g. real scam reports
    found via an AI-driven web search. Kept as a separate function rather
    than baking the API call into this module, since that call is slow,
    costly, and needs a server-side API key; the caller decides when to
    run it (e.g. only for URLs that already scored >=20-30 here) and
    passes the result in.

    reputation_factor: a dict like {"points": 55, "reason": "..."}, e.g.
    from reputation_search.reputation_to_risk_factor(). Pass None to skip.
    """
    report = generate_report(raw_url, check_live_signals=check_live_signals)
    if not reputation_factor:
        return report

    points = reputation_factor["points"]
    reason = reputation_factor["reason"]
    old_total = sum(f["points"] for f in report["factors"] if f["points"] > 0)
    new_total = max(0.0, min(100.0, old_total + points))

    factors = [f for f in report["factors"] if f["points"] > 0]
    factors.append({"points": points, "reason": reason, "weight_percent": 0.0})
    factors.sort(key=lambda f: f["points"], reverse=True)
    for f in factors:
        f["weight_percent"] = round((f["points"] / new_total * 100), 1) if new_total else 0.0

    report["risk_percentage"] = round(new_total, 1)
    report["verdict"] = classify_score(new_total)
    report["factors"] = factors
    top = factors[0]
    lead = top['reason'] if top['reason'][:2].isupper() else f"{top['reason'][0].lower()}{top['reason'][1:]}"
    report["summary"] = f"{new_total:.0f}% risk score, primarily because {lead}."
    return report
