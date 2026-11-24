"""
SMS phishing ("smishing") detection engine.

Heuristic + lexical scoring model. Flags urgency language, requests for
sensitive data, prize/lottery bait, spoofed shortcodes, and embedded links
(which are cross-checked against the URL detection engine for extra signal).
"""
import re

from app.services.url_detection import score_url

URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "verify now", "24 hours",
    "account suspended", "account locked", "unusual activity",
    "final notice", "expire", "limited time", "action required",
]

CREDENTIAL_REQUESTS = [
    "otp", "one-time password", "pin number", "verification code",
    "social security", "ssn", "card number", "cvv", "password",
    "login details", "confirm your identity",
]

PRIZE_BAIT = [
    "you have won", "you've won", "claim your prize", "free gift",
    "congratulations", "lottery", "sweepstake", "cash reward",
]

DELIVERY_SPOOF = [
    "package", "delivery failed", "redelivery", "customs fee",
    "shipping fee", "parcel", "tracking number",
]

URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|org|xyz|top|info|biz|click)\S*)", re.I)


def score_sms(message: str, sender: str | None = None) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    text = message.lower()

    def _hit(phrases: list[str]) -> list[str]:
        return [p for p in phrases if p in text]

    urgency_hits = _hit(URGENCY_PHRASES)
    if urgency_hits:
        score += min(25, 8 * len(urgency_hits))
        reasons.append(f"Uses urgency/pressure language: {', '.join(urgency_hits[:3])}")

    cred_hits = _hit(CREDENTIAL_REQUESTS)
    if cred_hits:
        score += min(35, 15 * len(cred_hits))
        reasons.append(f"Requests sensitive credentials: {', '.join(cred_hits[:3])}")

    prize_hits = _hit(PRIZE_BAIT)
    if prize_hits:
        score += min(25, 12 * len(prize_hits))
        reasons.append(f"Uses prize/lottery bait language: {', '.join(prize_hits[:3])}")

    delivery_hits = _hit(DELIVERY_SPOOF)
    if delivery_hits:
        score += min(15, 7 * len(delivery_hits))
        reasons.append(f"Impersonates a delivery/shipping notice: {', '.join(delivery_hits[:3])}")

    # Embedded links are cross-checked with the URL engine
    urls_found = URL_PATTERN.findall(message)
    if urls_found:
        worst_url_score = 0.0
        for u in urls_found[:3]:
            u_score, _ = score_url(u)
            worst_url_score = max(worst_url_score, u_score)
        if worst_url_score >= 30:
            score += 20
            reasons.append("Contains a link that itself shows phishing indicators")
        else:
            score += 5
            reasons.append("Contains an embedded link")

    # Sender looks like a spoofed long number / random alphanumeric shortcode
    if sender:
        if re.match(r"^\+?\d{11,}$", sender.strip()):
            score += 5
            reasons.append("Sent from an unusually long/international number")

    # All-caps shouting is a common low-effort smishing tell
    letters = [c for c in message if c.isalpha()]
    if letters and sum(1 for c in letters if c.isupper()) / len(letters) > 0.6 and len(letters) > 15:
        score += 10
        reasons.append("Message is written mostly in capital letters")

    score = max(0.0, min(100.0, score))
    if not reasons:
        reasons.append("No known smishing indicators detected")

    return score, reasons
