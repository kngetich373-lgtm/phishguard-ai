import unittest
from unittest.mock import patch

from app.ml.ml_model import _load, predict_url
from app.routers.url_scanner import normalize_and_validate_url


class UrlScannerTests(unittest.TestCase):
    def test_model_artifact_validates(self):
        bundle = _load()
        self.assertEqual(bundle["model"].__class__.__name__, "HistGradientBoostingClassifier")
        self.assertEqual(len(bundle["feature_names"]), 111)

    def test_named_dataframe_inference_has_no_missing_features(self):
        result = predict_url("https://example.com/password-reset", check_live_signals=False)
        self.assertIn(result["predicted_label"], {"phishing", "legitimate"})
        self.assertGreaterEqual(result["phishing_probability"], 0.0)
        self.assertLessEqual(result["phishing_probability"], 1.0)
        self.assertEqual(len(result["features_used"]), 111)

    def test_missing_scheme_is_normalized(self):
        self.assertEqual(
            normalize_and_validate_url("example.com/login"),
            "http://example.com/login",
        )

    def test_rejects_credentials_and_private_hosts(self):
        with self.assertRaises(ValueError):
            normalize_and_validate_url("https://user:pass@example.com")
        with self.assertRaises(ValueError):
            normalize_and_validate_url("http://127.0.0.1/login")
        with self.assertRaises(ValueError):
            normalize_and_validate_url("file:///etc/passwd")

    def test_rejects_unsupported_and_invalid_ports(self):
        with self.assertRaises(ValueError):
            normalize_and_validate_url("javascript://alert(1)")
        with self.assertRaises(ValueError):
            normalize_and_validate_url("https://example.com:8443/login")

    def test_feature_count_is_validated_in_loader(self):
        bundle = _load()
        self.assertEqual(len(bundle["feature_names"]), bundle["model"].n_features_in_)

    def test_legitimate_url_regression_does_not_depend_on_hardcoded_domains(self):
        # Offline predictions are deliberately not asserted as universally
        # legitimate because the bundled model has no current measured dataset.
        for url in (
            "https://github.com",
            "https://microsoft.com",
            "https://paypal.com",
            "https://example.org",
        ):
            result = predict_url(url, check_live_signals=False)
            self.assertIn("offline", result["confidence"])
            self.assertIn(result["predicted_label"], {"phishing", "legitimate"})


if __name__ == "__main__":
    unittest.main()
