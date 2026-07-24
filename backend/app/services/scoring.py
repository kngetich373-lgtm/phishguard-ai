"""Shared verdict classification used across all detection engines."""


def classify(score: float) -> str:
    if score >= 65:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "safe"
