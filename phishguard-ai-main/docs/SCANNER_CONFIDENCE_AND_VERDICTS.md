# URL Scanner Confidence and Verdicts

The scanner combines deterministic heuristics with the bundled
`HistGradientBoostingClassifier`. A model probability is not presented as a
calibrated probability until an independent evaluation supports calibration.

- `safe`, `suspicious`, and `malicious` remain the existing verdict values.
- `confidence` indicates evidence availability, not proof of correctness.
- Offline scans use no live network signals and are confidence-qualified.
- A missing network signal is unavailable evidence, never negative or positive evidence.
- The API exposes `degraded`, `network_status`, and `unavailable_signals`.
- Private, loopback, link-local, reserved, and unsupported URLs are rejected.

The repository does not contain a reproducible source dataset or evaluation
artifacts. Consequently, no accuracy, precision, recall, or false-positive
rate is claimed as verified, and the existing 96.9% statement is not
reproducible.
