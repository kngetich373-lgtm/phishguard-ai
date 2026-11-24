import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
class MigrationTests(unittest.TestCase):
    def run_upgrade(self, database_url):
        env = os.environ.copy()
        env.update(
            {
                "SECRET_KEY": secrets.token_hex(32),
                "APP_ENV": "test",
                "DATABASE_URL": database_url,
                "FRONTEND_URL": "http://localhost:5173",
                "CORS_ORIGINS": "http://localhost:5173",
            }
        )
        return subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=BACKEND_DIR,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_fresh_sqlite_database_migrates_to_head(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "fresh.db"
            url = f"sqlite+aiosqlite:///{path.as_posix()}"
            result = self.run_upgrade(url)
            self.assertEqual(result.returncode, 0, result.stderr)

            with closing(sqlite3.connect(path)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                revision = connection.execute(
                    "SELECT version_num FROM alembic_version"
                ).fetchone()[0]
            self.assertTrue({"users", "teams", "api_keys", "scans", "alerts"} <= tables)
            self.assertEqual(revision, "e60d19a4c73b")

    def test_legacy_sqlite_records_are_preserved_and_api_keys_hashed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "legacy.db"
            with closing(sqlite3.connect(path)) as connection:
                with connection:
                    connection.executescript(
                        """
                        CREATE TABLE teams (
                            id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL,
                            created_at DATETIME NOT NULL
                        );
                        CREATE TABLE users (
                            id VARCHAR PRIMARY KEY, email VARCHAR NOT NULL,
                            hashed_password VARCHAR NOT NULL, full_name VARCHAR NOT NULL,
                            is_admin BOOLEAN NOT NULL, created_at DATETIME NOT NULL,
                            team_id VARCHAR
                        );
                        CREATE TABLE api_keys (
                            id VARCHAR PRIMARY KEY, key VARCHAR NOT NULL,
                            label VARCHAR NOT NULL, active BOOLEAN NOT NULL,
                            created_at DATETIME NOT NULL, owner_id VARCHAR NOT NULL
                        );
                        CREATE TABLE scans (
                            id VARCHAR PRIMARY KEY, scan_type VARCHAR NOT NULL,
                            input_value TEXT NOT NULL, verdict VARCHAR NOT NULL,
                            risk_score FLOAT NOT NULL, reasons_json TEXT NOT NULL,
                            created_at DATETIME NOT NULL, owner_id VARCHAR
                        );
                        CREATE TABLE alerts (
                            id VARCHAR PRIMARY KEY, title VARCHAR NOT NULL,
                            message TEXT NOT NULL, severity VARCHAR NOT NULL,
                            scan_id VARCHAR, created_at DATETIME NOT NULL,
                            read BOOLEAN NOT NULL, owner_id VARCHAR
                        );
                        INSERT INTO users VALUES (
                            'user-1', 'legacy@example.com', 'password-hash',
                            'Legacy User', 0, '2026-01-01 00:00:00', NULL
                        );
                        INSERT INTO api_keys VALUES (
                            'key-1', 'pg_live_legacy_existing_key',
                            'Legacy key', 1, '2026-01-01 00:00:00', 'user-1'
                        );
                        INSERT INTO scans VALUES (
                            'scan-1', 'SMS', 'legacy scan', 'SAFE', 0.0, '[]',
                            '2026-01-01 00:00:00', 'user-1'
                        );
                        """
                    )

            url = f"sqlite+aiosqlite:///{path.as_posix()}"
            result = self.run_upgrade(url)
            self.assertEqual(result.returncode, 0, result.stderr)

            with closing(sqlite3.connect(path)) as connection:
                user = connection.execute(
                    "SELECT email, is_email_verified, failed_login_attempts, token_version, mfa_enabled "
                    "FROM users WHERE id='user-1'"
                ).fetchone()
                scan = connection.execute(
                    "SELECT input_value FROM scans WHERE id='scan-1'"
                ).fetchone()
                key, key_hash, prefix = connection.execute(
                    "SELECT key, key_hash, key_prefix FROM api_keys WHERE id='key-1'"
                ).fetchone()

            self.assertEqual(user[0], "legacy@example.com")
            self.assertEqual(user[1:], (0, 0, 0, 0))
            self.assertEqual(scan[0], "legacy scan")
            self.assertEqual(key, key_hash)
            self.assertNotEqual(key, "pg_live_legacy_existing_key")
            self.assertEqual(prefix, "pg_live_lega")


if __name__ == "__main__":
    unittest.main()
