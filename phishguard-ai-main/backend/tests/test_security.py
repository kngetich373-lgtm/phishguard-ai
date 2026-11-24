import asyncio
import os
import re
import secrets
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

os.environ["SECRET_KEY"] = secrets.token_hex(32)
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["FRONTEND_URL"] = "http://localhost:5173"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect
from starlette.requests import Request
import jwt

from app.auth import settings
from app.main import SimpleRateLimitMiddleware, app
from app.services.websocket_manager import ConnectionManager, manager
from app.services.mfa import totp_code


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def register(self, email=None, team_name=None):
        email = email or f"{secrets.token_hex(6)}@example.com"
        response = self.client.post(
            "/api/auth/register",
            json={
                "email": email,
                "password": "a-strong-test-password",
                "full_name": "Security Test",
                "team_name": team_name,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return email, response.json()

    def scan_sms(self, token, message):
        return self.client.post(
            "/api/scan/sms",
            json={"message": message},
            headers={"Authorization": f"Bearer {token}"} if token else {},
        )

    def test_auth_required_expired_token_rejected_and_security_headers_present(self):
        self.assertEqual(self.client.get("/api/reports/history").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/scan/sms",
                json={"message": "Test message"},
                headers={"Authorization": "Bearer invalid-token"},
            ).status_code,
            401,
        )
        response = self.client.get("/api/health")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")

        _, user = self.register()
        me = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {user['access_token']}"},
        )
        self.assertEqual(me.status_code, 200)

        expired = jwt.encode(
            {"sub": user["user"]["id"], "exp": int(time.time()) - 1},
            settings.secret_key,
            algorithm=settings.algorithm,
        )
        self.assertEqual(
            self.client.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {expired}"},
            ).status_code,
            401,
        )

    def test_login_accepts_json_and_oauth_form(self):
        email, _ = self.register()
        json_response = self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "a-strong-test-password"},
        )
        form_response = self.client.post(
            "/api/auth/login",
            data={"username": email, "password": "a-strong-test-password"},
        )
        self.assertEqual(json_response.status_code, 200, json_response.text)
        self.assertEqual(form_response.status_code, 200, form_response.text)

    def test_refresh_rotates_token_and_reuse_revokes_token_family(self):
        _, user = self.register()
        original_refresh = user["refresh_token"]
        rotated = self.client.post(
            "/api/auth/refresh",
            json={"refresh_token": original_refresh},
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        next_refresh = rotated.json()["refresh_token"]
        self.assertNotEqual(next_refresh, original_refresh)

        reuse = self.client.post(
            "/api/auth/refresh",
            json={"refresh_token": original_refresh},
        )
        self.assertEqual(reuse.status_code, 401)
        family_revoked = self.client.post(
            "/api/auth/refresh",
            json={"refresh_token": next_refresh},
        )
        self.assertEqual(family_revoked.status_code, 401)

    def test_expired_refresh_token_is_rejected(self):
        _, user = self.register()
        expired_now = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=31)
        with patch("app.services.auth_sessions._utcnow_naive", return_value=expired_now):
            expired = self.client.post(
                "/api/auth/refresh",
                json={"refresh_token": user["refresh_token"]},
            )
        self.assertEqual(expired.status_code, 401)

    def test_logout_revokes_access_and_refresh_tokens(self):
        _, user = self.register()
        response = self.client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {user['access_token']}"},
            json={"refresh_token": user["refresh_token"]},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            self.client.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {user['access_token']}"},
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/auth/refresh",
                json={"refresh_token": user["refresh_token"]},
            ).status_code,
            401,
        )

    def test_password_reset_invalidates_existing_sessions(self):
        email, user = self.register()
        sent = {}

        async def capture_email(_recipient, _subject, body):
            sent["token"] = re.search(r"token=([^\s]+)", body).group(1)

        with patch("app.routers.auth.deliver_account_email", capture_email):
            requested = self.client.post(
                "/api/auth/password-reset/request",
                json={"email": email},
            )
        self.assertEqual(requested.status_code, 200, requested.text)
        completed = self.client.post(
            "/api/auth/password-reset/confirm",
            json={
                "token": sent["token"],
                "new_password": "a-new-strong-password",
            },
        )
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(
            self.client.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {user['access_token']}"},
            ).status_code,
            401,
        )
        login = self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "a-new-strong-password"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        reused = self.client.post(
            "/api/auth/password-reset/confirm",
            json={
                "token": sent["token"],
                "new_password": "another-new-strong-password",
            },
        )
        self.assertEqual(reused.status_code, 400)

    def test_email_verification_is_single_use_when_required(self):
        sent = {}

        async def capture_email(_recipient, _subject, body):
            sent["token"] = re.search(r"token=([^\s]+)", body).group(1)

        with (
            patch("app.routers.auth.settings.email_verification_required", True),
            patch("app.routers.auth.deliver_account_email", capture_email),
        ):
            email, registration = self.register()
            blocked = self.client.post(
                "/api/auth/login",
                json={"email": email, "password": "a-strong-test-password"},
            )
            self.assertEqual(blocked.status_code, 403)
            verified = self.client.post(
                "/api/auth/email-verification/confirm",
                json={"token": sent["token"]},
            )
            self.assertEqual(verified.status_code, 200, verified.text)
            login = self.client.post(
                "/api/auth/login",
                json={"email": email, "password": "a-strong-test-password"},
            )
            self.assertEqual(login.status_code, 200, login.text)
            reused = self.client.post(
                "/api/auth/email-verification/confirm",
                json={"token": sent["token"]},
            )
            self.assertEqual(reused.status_code, 400)
        self.assertTrue(registration["refresh_token"])

    def test_repeated_bad_passwords_lock_account_temporarily(self):
        email, _ = self.register()
        for _ in range(5):
            failed = self.client.post(
                "/api/auth/login",
                json={"email": email, "password": "wrong-password"},
            )
            self.assertEqual(failed.status_code, 401)
        locked = self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "a-strong-test-password"},
        )
        self.assertEqual(locked.status_code, 423)

    def test_mfa_setup_enable_login_and_disable(self):
        email, user = self.register()
        auth = {"Authorization": f"Bearer {user['access_token']}"}
        setup = self.client.post("/api/auth/mfa/setup", headers=auth)
        self.assertEqual(setup.status_code, 200, setup.text)
        secret = setup.json()["secret"]
        self.assertTrue(setup.json()["otpauth_uri"].startswith("otpauth://totp/"))

        rejected = self.client.post(
            "/api/auth/mfa/enable",
            headers=auth,
            json={"code": totp_code(secret, int(time.time()) - 600)},
        )
        self.assertEqual(rejected.status_code, 400)
        code = totp_code(secret)
        enabled = self.client.post(
            "/api/auth/mfa/enable",
            headers=auth,
            json={"code": code},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)

        no_code = self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "a-strong-test-password"},
        )
        self.assertEqual(no_code.status_code, 401)
        login = self.client.post(
            "/api/auth/login",
            json={
                "email": email,
                "password": "a-strong-test-password",
                "mfa_code": totp_code(secret),
            },
        )
        self.assertEqual(login.status_code, 200, login.text)

        disabled = self.client.post(
            "/api/auth/mfa/disable",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            json={"code": totp_code(secret)},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertEqual(
            self.client.post(
                "/api/auth/login",
                json={"email": email, "password": "a-strong-test-password"},
            ).status_code,
            200,
        )

    def test_scan_history_and_alerts_are_isolated_by_owner(self):
        _, alice = self.register()
        _, bob = self.register()
        alice_scan = self.scan_sms(
            alice["access_token"],
            "URGENT account suspended, send your verification code and password immediately",
        )
        bob_scan = self.scan_sms(bob["access_token"], "Your appointment is tomorrow.")
        self.assertEqual(alice_scan.status_code, 200, alice_scan.text)
        self.assertEqual(bob_scan.status_code, 200, bob_scan.text)

        alice_history = self.client.get(
            "/api/reports/history",
            headers={"Authorization": f"Bearer {alice['access_token']}"},
        ).json()
        bob_history = self.client.get(
            "/api/reports/history",
            headers={"Authorization": f"Bearer {bob['access_token']}"},
        ).json()
        self.assertEqual([scan["id"] for scan in alice_history], [alice_scan.json()["id"]])
        self.assertEqual([scan["id"] for scan in bob_history], [bob_scan.json()["id"]])

        alice_alerts = self.client.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {alice['access_token']}"},
        )
        bob_alerts = self.client.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {bob['access_token']}"},
        )
        self.assertEqual(alice_alerts.status_code, 200)
        self.assertEqual(bob_alerts.json(), [])
        if alice_alerts.json():
            cross_owner = self.client.post(
                f"/api/alerts/{alice_alerts.json()[0]['id']}/read",
                headers={"Authorization": f"Bearer {bob['access_token']}"},
            )
            self.assertEqual(cross_owner.status_code, 404)

    def test_api_key_is_masked_usable_and_revocable(self):
        _, user = self.register()
        auth = {"Authorization": f"Bearer {user['access_token']}"}
        created = self.client.post("/api/reports/api-keys", headers=auth)
        self.assertEqual(created.status_code, 200, created.text)
        key = created.json()["key"]
        self.assertTrue(key.startswith("pg_live_"))

        listed = self.client.get("/api/reports/api-keys", headers=auth)
        self.assertEqual(listed.status_code, 200)
        self.assertNotIn(key, [item["key"] for item in listed.json()])
        self.assertTrue(all(item["key"].endswith("...") for item in listed.json()))

        valid_scan = self.client.post(
            "/api/scan/sms",
            json={"message": "Regular delivery update."},
            headers={"X-API-Key": key},
        )
        self.assertEqual(valid_scan.status_code, 200, valid_scan.text)

        revoked = self.client.delete(
            f"/api/reports/api-keys/{created.json()['id']}",
            headers=auth,
        )
        self.assertEqual(revoked.status_code, 204)
        rejected_scan = self.client.post(
            "/api/scan/sms",
            json={"message": "Regular delivery update."},
            headers={"X-API-Key": key},
        )
        self.assertEqual(rejected_scan.status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/scan/sms",
                json={"message": "Regular delivery update."},
                headers={"X-API-Key": "pg_live_invalid"},
            ).status_code,
            401,
        )

    def test_api_keys_cannot_be_listed_or_revoked_by_another_user(self):
        _, owner = self.register()
        _, other = self.register()
        owner_auth = {"Authorization": f"Bearer {owner['access_token']}"}
        other_auth = {"Authorization": f"Bearer {other['access_token']}"}
        created = self.client.post("/api/reports/api-keys", headers=owner_auth)
        self.assertEqual(created.status_code, 200, created.text)

        self.assertEqual(self.client.get("/api/reports/api-keys", headers=other_auth).json(), [])
        denied = self.client.delete(
            f"/api/reports/api-keys/{created.json()['id']}",
            headers=other_auth,
        )
        self.assertEqual(denied.status_code, 404)

    def test_team_invitation_requires_team_admin(self):
        _, owner = self.register(team_name="Red Team")
        owner_auth = {"Authorization": f"Bearer {owner['access_token']}"}
        invite = self.client.post(
            "/api/team/invite",
            headers=owner_auth,
            json={
                "email": f"{secrets.token_hex(6)}@example.com",
                "password": "a-strong-test-password",
                "full_name": "Member",
            },
        )
        self.assertEqual(invite.status_code, 200, invite.text)
        member_auth = {"Authorization": f"Bearer {invite.json()['access_token']}"}
        denied = self.client.post(
            "/api/team/invite",
            headers=member_auth,
            json={
                "email": f"{secrets.token_hex(6)}@example.com",
                "password": "a-strong-test-password",
            },
        )
        self.assertEqual(denied.status_code, 403)

    def test_websocket_requires_a_valid_jwt(self):
        with self.assertRaises(WebSocketDisconnect) as failure:
            with self.client.websocket_connect(
                "/api/alerts/ws",
                headers={"origin": "http://localhost:5173"},
            ):
                self.fail("unauthenticated WebSocket was accepted")
        self.assertEqual(failure.exception.code, 1008)

    def test_websocket_authenticates_user_and_validates_origin(self):
        _, user = self.register()
        token = user["access_token"]
        user_id = user["user"]["id"]
        with self.assertRaises(WebSocketDisconnect) as failure:
            with self.client.websocket_connect(
                f"/api/alerts/ws?token={token}",
                headers={"origin": "https://attacker.example"},
            ):
                self.fail("untrusted origin was accepted")
        self.assertEqual(failure.exception.code, 1008)

        with self.client.websocket_connect(
            f"/api/alerts/ws?token={token}",
            headers={"origin": "http://localhost:5173"},
        ):
            self.assertEqual(set(manager.connection_owners.values()), {user_id})
        self.assertNotIn(user_id, manager.connection_owners.values())

    def test_owner_broadcast_does_not_leak_unowned_alerts(self):
        class FakeSocket:
            def __init__(self):
                self.messages = []

            async def send_text(self, message):
                self.messages.append(message)

        connection_manager = ConnectionManager()
        first = FakeSocket()
        second = FakeSocket()
        connection_manager.active_connections.extend([first, second])
        connection_manager.connection_owners[first] = "user-a"
        connection_manager.connection_owners[second] = "user-b"

        asyncio.run(connection_manager.broadcast({"owner_id": "user-a", "type": "alert"}))
        asyncio.run(connection_manager.broadcast({"owner_id": None, "type": "alert"}))
        self.assertEqual(len(first.messages), 1)
        self.assertEqual(second.messages, [])

    def test_rate_limit_blocks_after_window_quota(self):
        limiter = SimpleRateLimitMiddleware(FastAPI())
        limiter.requests["127.0.0.1"] = [time.monotonic()] * 60
        request = Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/test",
                "raw_path": b"/test",
                "query_string": b"",
                "headers": [],
                "client": ("127.0.0.1", 1234),
                "server": ("testserver", 80),
            }
        )

        async def next_handler(_request):
            self.fail("rate-limited request reached downstream handler")

        response = asyncio.run(limiter.dispatch(request, next_handler))
        self.assertEqual(response.status_code, 429)

    def test_redis_rate_limit_failure_fails_closed_in_production(self):
        limiter = SimpleRateLimitMiddleware(FastAPI())
        limiter.redis = type(
            "BrokenRedis",
            (),
            {"incr": AsyncMock(side_effect=RuntimeError("Redis unavailable"))},
        )()
        request = Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/test",
                "raw_path": b"/test",
                "query_string": b"",
                "headers": [],
                "client": ("127.0.0.1", 1234),
                "server": ("testserver", 80),
            }
        )

        async def next_handler(_request):
            self.fail("production request reached downstream without Redis")

        with patch("app.main.settings.environment", "production"):
            response = asyncio.run(limiter.dispatch(request, next_handler))
        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
