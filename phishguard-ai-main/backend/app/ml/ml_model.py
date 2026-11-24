"""
Load and run the bundled URL classification model.

The artifact is a HistGradientBoostingClassifier with 111 named features.
No dataset or independently reproducible training/evaluation artifacts are
included, so this module does not claim a verified accuracy statistic.
"""
from __future__ import annotations

import joblib
import math
import pandas as pd
from pathlib import Path

from .feature_extractor import extract_features

_MODEL_PATH = Path(__file__).parent / "phishing_url_model.joblib"
_bundle = None
FEATURE_COUNT = 111


class ModelUnavailableError(RuntimeError):
    pass


def _load():
    global _bundle
    if _bundle is None:
        if not _MODEL_PATH.is_file():
            raise ModelUnavailableError(f"Model artifact not found: {_MODEL_PATH.name}")
        try:
            bundle = joblib.load(_MODEL_PATH)
        except Exception as exc:
            raise ModelUnavailableError("Model artifact could not be loaded") from exc
        if not isinstance(bundle, dict):
            raise ModelUnavailableError("Model artifact has an invalid bundle format")
        model = bundle.get("model")
        feature_names = bundle.get("feature_names")
        if model is None or not hasattr(model, "predict_proba"):
            raise ModelUnavailableError("Model artifact does not provide predict_proba")
        if not isinstance(feature_names, list) or len(feature_names) != FEATURE_COUNT:
            raise ModelUnavailableError("Model artifact has invalid feature metadata")
        if hasattr(model, "n_features_in_") and int(model.n_features_in_) != len(feature_names):
            raise ModelUnavailableError("Model feature count does not match artifact metadata")
        fitted_names = getattr(model, "feature_names_in_", None)
        if fitted_names is not None and list(fitted_names) != feature_names:
            raise ModelUnavailableError("Model feature order does not match artifact metadata")
        _bundle = bundle
    return _bundle


def predict_url(raw_url: str, check_live_signals: bool = True) -> dict:
    """
    Returns:
        {
          "phishing_probability": 0.0-1.0,
          "predicted_label": "phishing" | "legitimate",
          "model_name": "HistGradientBoostingClassifier",
          "features_used": {...}   # for debugging / transparency
        }
    """
    bundle = _load()
    model, feature_names = bundle["model"], bundle["feature_names"]

    feats = extract_features(raw_url, check_live_signals=check_live_signals)
    missing = [name for name in feature_names if name not in feats]
    if missing:
        raise ModelUnavailableError(f"Missing model features: {len(missing)}")
    values = [feats[name] for name in feature_names]
    if any(value is None or (isinstance(value, float) and not math.isfinite(value)) for value in values):
        raise ModelUnavailableError("Model received missing or non-finite feature values")
    row = pd.DataFrame([values], columns=feature_names, dtype="float64")

    probability = model.predict_proba(row)
    if probability.shape != (1, len(model.classes_)):
        raise ModelUnavailableError("Model returned an invalid probability shape")
    phishing_indices = [
        i for i, label in enumerate(model.classes_)
        if str(label).lower() in {"1", "phishing", "malicious", "true"}
    ]
    if len(phishing_indices) != 1:
        raise ModelUnavailableError("Model class mapping could not identify the phishing class")
    p = float(probability[0, phishing_indices[0]])
    if not math.isfinite(p) or not 0.0 <= p <= 1.0:
        raise ModelUnavailableError("Model returned an invalid phishing probability")
    label = "phishing" if p >= 0.5 else "legitimate"

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

    model_name = type(model).__name__
    model_version = bundle.get("model_version", "1.0.0")

    return {
        "phishing_probability": round(p, 4),
        "predicted_label": label,
        "confidence": confidence,
        "model_name": model_name,
        "model_version": str(model_version),
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
