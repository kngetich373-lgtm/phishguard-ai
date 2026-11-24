"""
AI-powered scam-reputation lookup.

Wraps the Claude API's server-side web_search tool to check a domain
against real-world reviews, complaint forums, and third-party scam trackers
(Trustpilot, Reddit, ScamAdviser, Scam Detector, BBB, etc.) - the kind of
evidence no lexical/WHOIS heuristic can ever see on its own. A "get paid
to chat" scheme advertised on TikTok, for example, won't trip an IP/TLD/
typosquat check at all if it uses a normal-looking .com domain - but a web
search immediately surfaces that scam-tracking sites already rate its
sibling domains as untrustworthy with 5-day-old registrations.

IMPORTANT - run this server-side only. It needs a real ANTHROPIC_API_KEY
and makes outbound calls; it must never run in a browser/client artifact
where the key would be exposed.

Anti-hallucination / anti-defamation design:
  - The model is instructed to report ONLY claims it can attribute to a
    specific retrieved source URL, never invented ones.
  - A "scam" verdict requires corroboration from at least 2 independent
    sources - a single anonymous complaint is not enough to brand a real
    business a scam and risks defamation if wrong.
  - "no_reports_found" is treated as neutral/unknown, never as "safe" -
    plenty of scams are simply too new to have been written about yet.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from app.config import get_settings

try:
    import anthropic
except ImportError:  # pragma: no cover - optional dependency
    anthropic = None

REPUTATION_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = """You are a fraud-research assistant for a scam-detection tool. \
Given a domain, use web search to find real-world evidence about whether it is a \
scam: third-party scam-checker reports (ScamAdviser, Scam Detector, Gridinsoft, \
Trustpilot, BBB), Reddit/forum complaints, and news coverage. Also check whether \
the same brand/scheme is running under other TLDs or near-identical domains \
(scammers routinely clone the same site across .com/.net/.org/.xyz etc. once one \
gets reported or taken down) - search for the brand name alone, not just the exact \
domain, to catch this.

Rules you must follow:
1. Only report claims you can attribute to a specific URL you actually retrieved. \
Never invent a source, a quote, or a statistic.
2. A "scam" verdict requires at least 2 independent corroborating sources. A single \
anonymous complaint alone is "insufficient_evidence", not "scam".
3. If you find nothing either way, say so plainly - do not guess.
4. Respond with ONLY a single JSON object, no other text, matching this schema:
{
  "verdict": "scam" | "likely_scam" | "mixed_reports" | "insufficient_evidence" | "no_negative_reports_found",
  "confidence": 0-100,
  "independent_source_count": <int>,
  "related_domains_found": ["..."],
  "findings": [
    {"claim": "<one-sentence factual claim>", "source_url": "<url>", "source_name": "<site name>"}
  ]
}"""


@dataclass
class ReputationResult:
    domain: str
    verdict: str
    confidence: int
    independent_source_count: int
    related_domains_found: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


# Simple process-local cache so you're not paying for a fresh web-search
# call every time the same domain gets scanned. Swap this dict for Redis/
# your DB in production - and note the TTL: reputation data doesn't change
# minute to minute, so 48-72h is a reasonable default.
_CACHE: dict[str, tuple[float, ReputationResult]] = {}
CACHE_TTL_SECONDS = 60 * 60 * 48  # 48 hours


def search_scam_reports(
    domain: str,
    api_key: str | None = None,
    max_searches: int = 5,
    use_cache: bool = True,
) -> ReputationResult:
    """
    Ask Claude to web-search for real scam reports/reviews about `domain`
    (and its likely clone-domain family) and return a structured verdict.

    Costs a real API call with several web searches behind it - this is
    token-intensive, so:
      - it's cached per-domain for CACHE_TTL_SECONDS
      - callers should gate this behind an already-elevated heuristic
        score (e.g. only run it when generate_report() from
        url_detection.py already scored >=20-30), not on every single URL
    """
    domain = domain.strip().lower()

    if use_cache and domain in _CACHE:
        cached_at, cached_result = _CACHE[domain]
        if time.time() - cached_at < CACHE_TTL_SECONDS:
            return cached_result

    if anthropic is None:
        return ReputationResult(
            domain=domain, verdict="insufficient_evidence", confidence=0,
            independent_source_count=0,
            error="`anthropic` package not installed (`pip install anthropic`)",
        )

    key = api_key or get_settings().anthropic_api_key
    if not key:
        return ReputationResult(
            domain=domain, verdict="insufficient_evidence", confidence=0,
            independent_source_count=0,
            error="No ANTHROPIC_API_KEY provided/set",
        )

    client = anthropic.Anthropic(api_key=key)

    try:
        response = client.messages.create(
            model=REPUTATION_MODEL,
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            tools=[{
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": max_searches,
            }],
            messages=[{
                "role": "user",
                "content": (
                    f'Investigate the domain "{domain}". Search for scam reports, '
                    "reviews, and complaints about it and about the same brand/scheme "
                    "under any other domain names. Return the JSON object only."
                ),
            }],
        )

        # Pull the final text block (Claude's closing summary after any
        # web_search_tool_result blocks) and parse it as JSON.
        text_parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        raw_text = "\n".join(text_parts).strip()

        # Models occasionally wrap JSON in a code fence despite instructions.
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`")
            if raw_text.lower().startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        parsed = json.loads(raw_text)
        result = ReputationResult(
            domain=domain,
            verdict=parsed.get("verdict", "insufficient_evidence"),
            confidence=int(parsed.get("confidence", 0)),
            independent_source_count=int(parsed.get("independent_source_count", 0)),
            related_domains_found=parsed.get("related_domains_found", []),
            findings=parsed.get("findings", []),
        )
    except Exception as exc:  # network error, bad JSON, rate limit, etc.
        result = ReputationResult(
            domain=domain, verdict="insufficient_evidence", confidence=0,
            independent_source_count=0, error=str(exc),
        )

    if use_cache:
        _CACHE[domain] = (time.time(), result)
    return result


# ---------------------------------------------------------------------------
# Verdict -> risk-point mapping, for feeding into url_detection.generate_report
# ---------------------------------------------------------------------------

_VERDICT_POINTS = {
    "scam": 55,
    "likely_scam": 35,
    "mixed_reports": 15,
    "insufficient_evidence": 0,
    "no_negative_reports_found": 0,
}


def reputation_to_risk_factor(result: ReputationResult) -> dict | None:
    """Convert a ReputationResult into a RiskFactor-shaped dict you can
    append to url_detection's factor list. Returns None when there's
    nothing actionable to add (no evidence either way, or a lookup
    error) - absence of complaints is never scored as a positive
    ("safe") signal, only as neutral."""
    if result.error or result.verdict in ("insufficient_evidence", "no_negative_reports_found"):
        return None

    points = _VERDICT_POINTS.get(result.verdict, 0)
    if points == 0:
        return None

    sources = ", ".join(
        f'{f.get("source_name", "source")} ({f.get("source_url", "")})'
        for f in result.findings[:3]
    )
    related = (
        f' Related clone domains found: {", ".join(result.related_domains_found)}.'
        if result.related_domains_found else ""
    )
    reason = (
        f"AI web-search reputation check found {result.independent_source_count} "
        f"independent source(s) reporting this as \"{result.verdict}\" "
        f"({result.confidence}% confidence): {sources}.{related}"
    )
    return {"points": points, "reason": reason}
