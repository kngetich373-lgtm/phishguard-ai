import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from app.config import Settings


class SettingsTests(unittest.TestCase):
    def settings(self, **overrides):
        values = {"secret_key": secrets.token_hex(32)}
        values.update(overrides)
        with patch.dict(os.environ, {}, clear=True):
            return Settings(_env_file=None, **values)

    def test_sqlite_development_defaults_and_optional_integrations(self):
        settings = self.settings()

        self.assertEqual(settings.database_url, "sqlite+aiosqlite:///./phishguard.db")
        self.assertEqual(settings.anthropic_api_key, "")
        self.assertEqual(settings.google_client_id, "")

    def test_postgresql_production_configuration_is_valid(self):
        settings = self.settings(
            environment="production",
            database_url="postgresql+asyncpg://user:pass@db.example.com:5432/phishguard",
            redis_url="redis://:test-password@cache.example.com:6379/0",
            frontend_url="https://app.example.com",
            cors_origins="https://app.example.com",
        )

        self.assertEqual(settings.environment, "production")
        self.assertEqual(settings.cors_origin_list, ["https://app.example.com"])

    def test_production_rejects_sqlite_and_local_cors(self):
        with self.assertRaisesRegex(ValidationError, "Production requires PostgreSQL"):
            self.settings(
                environment="production",
                frontend_url="https://app.example.com",
                cors_origins="https://app.example.com",
            )

        with self.assertRaisesRegex(ValidationError, "explicit non-local origins"):
            self.settings(
                environment="production",
                database_url="postgresql+asyncpg://user:pass@db.example.com:5432/phishguard",
                redis_url="redis://:test-password@cache.example.com:6379/0",
            )

    def test_missing_or_placeholder_secrets_are_rejected(self):
        with self.assertRaisesRegex(ValidationError, "SECRET_KEY is required"):
            self.settings(secret_key="")

        with self.assertRaisesRegex(ValidationError, "non-placeholder"):
            self.settings(secret_key="REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_CHARACTERS")

    def test_unsupported_database_url_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "sqlite\\+aiosqlite or postgresql\\+asyncpg"):
            self.settings(database_url="postgresql://user:pass@db.example.com/phishguard")

    def test_dotenv_values_load_and_process_values_override_them(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "SECRET_KEY=" + secrets.token_hex(32) + "\n"
                "APP_ENV=test\n"
                "PORT=8123\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                settings = Settings(_env_file=env_file, port=8124)

        self.assertEqual(settings.environment, "test")
        self.assertEqual(settings.port, 8124)


if __name__ == "__main__":
    unittest.main()
