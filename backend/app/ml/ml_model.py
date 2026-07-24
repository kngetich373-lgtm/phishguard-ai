"""
Trained ML classifier for URL phishing detection - the drop-in model that
url_detection.py's own docstring anticipated ("a real ML/GBM/logistic-
regression model ... can be dropped in later to replace or augment the
scoring without touching callers").

Trained on GregaVrbancic/Phishing-Dataset (88,647 real labeled URLs, 111
structural/lexical/network features). Held-out test set (13,298 URLs never
used in training or model selection):
    accuracy   96.9%
    ROC-AUC    99.5%
    precision  95.4% (phishing class)
    recall     96.1% (phishing class)
See training_report.json for the full breakdown, confusion matrix, and
per-fold cross-validation numbers - please read those before trusting a
"96.9% accurate" headline number; it's a held-out estimate, not a guarantee
against URLs unlike anything in the training set (e.g. brand-new attack
patterns, or the many features that silently fall back to "unknown" when a
live lookup fails/times out).
"""
from __future__ import annotations

import joblib
from pathlib import Path

from .feature_extractor import extract_features

_MODEL_PATH = Path(__file__).parent / "phishing_url_model.joblib"
_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(_MODEL_PATH)
    return _bundle


def predict_url(raw_url: str, check_live_signals: bool = True) -> dict:
    """
    Returns:
        {
          "phishing_probability": 0.0-1.0,
          "predicted_label": "phishing" | "legitimate",
          "model_name": "random_forest",
          "features_used": {...}   # for debugging / transparency
        }
    """
    bundle = _load()
    model, feature_names = bundle["model"], bundle["feature_names"]

    feats = extract_features(raw_url, check_live_signals=check_live_signals)
    row = [[feats.get(f, -1) for f in feature_names]]

    proba = model.predict_proba(row)[0][1]
    label = "phishing" if proba >= 0.5 else "legitimate"

    # Confidence: how many of the live/network features actually resolved
    # vs fell back to "unknown" (-1). The model was trained mostly on rows
    # where these lookups succeeded; a verdict built on mostly-unknown
    # network signals is much less trustworthy than one where WHOIS/DNS/SSL
    # all resolved cleanly - callers should surface this, not just the
    # probability, especially since network restrictions, WHOIS rate
    # limits, or a slow DNS server can all produce "unknown", not just an
    # actual phishing site with burnt infrastructure.
    net_keys = ["time_domain_activation", "time_domain_expiration", "ttl_hostname",
                "asn_ip", "qty_nameservers", "qty_mx_servers", "domain_spf",
                "qty_redirects", "qty_ip_resolved"]
    known = sum(1 for k in net_keys if feats.get(k, -1) != -1)
    known_ratio = known / len(net_keys)
    if not check_live_signals:
        confidence = "low (offline mode: no live network signals used)"
    elif known_ratio >= 0.7:
        confidence = "high (most live signals resolved)"
    elif known_ratio >= 0.3:
        confidence = "medium (some live lookups failed/unavailable)"
    else:
        confidence = "low (most live lookups failed - verdict is unreliable, driven mostly by URL text alone)"

    return {
        "phishing_probability": round(float(proba), 4),
        "predicted_label": label,
        "confidence": confidence,
        "model_name": bundle["model_name"],
        "features_used": feats,
    }


def ml_to_risk_factor(ml_result: dict) -> dict | None:
    """
    Convert an ML prediction into a {"points", "reason"} dict compatible
    with generate_report_with_reputation()'s reputation_factor argument in
    url_detection.py - i.e. this can be passed straight in, alongside or
    instead of a reputation-search factor, without modifying that file.

    IMPORTANT: the point cap is gated by confidence. When most of the
    live network features couldn't be resolved (blocked lookups, WHOIS
    rate limits, restrictive network, etc.), a high phishing_probability
    is much less trustworthy - the model has learned that "many unknown
    signals" correlates with phishing, which is a real pattern but also
    misfires on legitimate sites when checks simply fail to run. Capping
    the contribution by confidence means a shaky ML read alone can never
    push a URL past ~35 points (i.e. never past "malicious" on its own);
    it still has to be corroborated by the heuristic engine's own signals.
    """
    p = ml_result["phishing_probability"]
    confidence = ml_result.get("confidence", "")

    if confidence.startswith("high"):
        max_points = 45
    elif confidence.startswith("medium"):
        max_points = 30
    else:  # low confidence, incl. offline mode
        max_points = 15

    if p < 0.2:
        return None  # model confidently says clean; add nothing
    points = round(p * max_points, 1)
    reason = (
        f"ML classifier ({ml_result['model_name']}, trained on 88k labeled "
        f"URLs) estimates a {p*100:.1f}% probability this is phishing "
        f"[confidence: {confidence}]"
    )
    return {"points": points, "reason": reason}
