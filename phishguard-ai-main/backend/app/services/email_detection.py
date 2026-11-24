"""
Email phishing detection engine (works standalone, and is the same engine
that would be applied to messages pulled in via the Gmail API integration).

Gmail integration note:
  To connect a real Gmail inbox you need a Google Cloud OAuth client
  (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env) with the
  `gmail.readonly` scope, then use the google-auth-oauthlib +
  google-api-python-client libraries to list/fetch messages and pass their
  subject/body/sender into `score_email()` below. That wiring is
  environment-specific (requires a real OAuth consent screen) so this
  scaffold exposes the endpoints and detection logic; app/routers/email_scanner.py
  has a clearly marked stub showing exactly where to plug in the Gmail
  client calls.
"""
import re

from app.services.sms_detection import URGENCY_PHRASES, CREDENTIAL_REQUESTS, PRIZE_BAIT
from app.services.url_detection import score_url, BRAND_DOMAINS

URL_PATTERN = re.compile(r"https?://\S+", re.I)

SPOOFABLE_DISPLAY_BRANDS = [b.split(".")[0] for b in BRAND_DOMAINS]

MISMATCHED_REPLY_TO_HINT = ["reply-to", "do-not-reply", "noreply"]

ATTACHMENT_LURE_WORDS = [
    "invoice attached", "see attached", "download the attached",
    "open the attachment", "attached document", "review the file",
]


def _domain_of(email_addr: str) -> str:
    match = re.search(r"@([\w.-]+)", email_addr or "")
    return match.group(1).lower() if match else ""


def score_email(subject: str, body: str, sender: str | None = None) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    full_text = f"{subject}\n{body}".lower()

    def _hit(phrases: list[str]) -> list[str]:
        return [p for p in phrases if p in full_text]

    urgency_hits = _hit(URGENCY_PHRASES)
    if urgency_hits:
        score += min(20, 7 * len(urgency_hits))
        reasons.append(f"Subject/body uses urgency language: {', '.join(urgency_hits[:3])}")

    cred_hits = _hit(CREDENTIAL_REQUESTS)
    if cred_hits:
        score += min(30, 12 * len(cred_hits))
        reasons.append(f"Requests sensitive credentials: {', '.join(cred_hits[:3])}")

    prize_hits = _hit(PRIZE_BAIT)
    if prize_hits:
        score += min(20, 10 * len(prize_hits))
        reasons.append(f"Uses prize/lottery bait language: {', '.join(prize_hits[:3])}")

    attach_hits = _hit(ATTACHMENT_LURE_WORDS)
    if attach_hits:
        score += 10
        reasons.append("References an attachment - verify sender before opening any file")

    # Brand impersonation: display name mentions a brand but sending domain doesn't match
    if sender:
        sender_domain = _domain_of(sender)
        for brand_name in SPOOFABLE_DISPLAY_BRANDS:
            if brand_name in full_text and brand_name not in sender_domain:
                score += 25
                reasons.append(
                    f'Mentions "{brand_name}" but sender domain "{sender_domain or "unknown"}" does not match'
                )
                break

    # Links in the body, cross-checked with URL engine
    urls_found = URL_PATTERN.findall(body)
    if urls_found:
        worst_url_score = 0.0
        for u in urls_found[:5]:
            u_score, _ = score_url(u)
            worst_url_score = max(worst_url_score, u_score)
        if worst_url_score >= 30:
            score += 20
            reasons.append("Contains a link that itself shows phishing indicators")

    score = max(0.0, min(100.0, score))
    if not reasons:
        reasons.append("No known phishing indicators detected")

    return score, reasons
