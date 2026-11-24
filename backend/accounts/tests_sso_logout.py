"""OpenID Connect Back-Channel Logout: bdren.ai (ZITADEL) tells Questiz a sign-in session ended."""

import time
import uuid

from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from . import sso
from .models import SsoSession
from .tests_sso import CLIENT_ID, ISSUER, JWKS_URI, OTHER_KEY, SIGNING_KEY, SSO_SETTINGS, SSOTestBase

BACKCHANNEL_URL = "/api/auth/sso/backchannel-logout/"
LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class BackchannelLogoutTests(SSOTestBase):
    # --- helpers ---------------------------------------------------------------------------

    def sign_in(self, sid="sid-1", sub="zitadel-user-1"):
        """Finish an SSO sign-in in a fresh browser; returns (client, refresh token string)."""
        self.client = APIClient()
        overrides = {"sub": sub}
        if sid is not None:
            overrides["sid"] = sid
        response = self.finish(overrides)
        self.assertSignedIn(response)
        refresh = response.cookies["questiz_refresh"].value
        return self.client, refresh

    def access_for(self, client):
        response = client.post("/api/auth/token/refresh/", {}, format="json")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["access"]

    def logout_claims(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": [CLIENT_ID],
            "iat": now,
            "exp": now + 120,
            "jti": uuid.uuid4().hex,
            "events": {LOGOUT_EVENT: {}},
            "sub": "zitadel-user-1",
            "sid": "sid-1",
        }
        claims.update(overrides)
        return {key: value for key, value in claims.items() if value is not None}

    def send_logout(self, claims=None, *, key=SIGNING_KEY, raw=None):
        token = raw if raw is not None else self.sign(claims or self.logout_claims(), key=key)
        return APIClient().post(BACKCHANNEL_URL, {"logout_token": token})

    def api_status(self, access):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return client.get("/api/auth/user/").status_code

    # --- sign-in records the session -------------------------------------------------------

    def test_sign_in_records_session_and_tags_tokens(self):
        _, refresh = self.sign_in(sid="sid-abc")
        token = RefreshToken(refresh)
        session = SsoSession.objects.get()
        self.assertEqual(token[sso.SSO_SESSION_CLAIM], str(session.id))
        self.assertEqual(session.sid, "sid-abc")
        self.assertEqual(session.subject, "zitadel-user-1")
        self.assertEqual(session.issuer, ISSUER)
        self.assertIsNone(session.ended_at)

    # --- a valid logout ends exactly that session ------------------------------------------

    def test_logout_by_sid_ends_api_access_and_refresh(self):
        client, _ = self.sign_in(sid="sid-1")
        access = self.access_for(client)
        self.assertEqual(self.api_status(access), 200)

        response = self.send_logout()

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIsNotNone(SsoSession.objects.get().ended_at)
        self.assertEqual(self.api_status(access), 401)
        refresh_response = client.post("/api/auth/token/refresh/", {}, format="json")
        self.assertEqual(refresh_response.status_code, 401)
        self.assertEqual(refresh_response.cookies["questiz_refresh"].value, "")

    def test_other_browser_session_keeps_working(self):
        client_a, _ = self.sign_in(sid="sid-a")
        client_b, _ = self.sign_in(sid="sid-b")
        access_a, access_b = self.access_for(client_a), self.access_for(client_b)

        self.assertEqual(self.send_logout(self.logout_claims(sid="sid-a")).status_code, 200)

        self.assertEqual(self.api_status(access_a), 401)
        self.assertEqual(self.api_status(access_b), 200)
        self.assertEqual(client_b.post("/api/auth/token/refresh/", {}, format="json").status_code, 200)

    def test_logout_without_sid_ends_every_session_of_the_subject(self):
        client_a, _ = self.sign_in(sid="sid-a")
        client_b, _ = self.sign_in(sid="sid-b")
        access_a, access_b = self.access_for(client_a), self.access_for(client_b)

        self.assertEqual(self.send_logout(self.logout_claims(sid=None)).status_code, 200)

        self.assertEqual(self.api_status(access_a), 401)
        self.assertEqual(self.api_status(access_b), 401)

    def test_sid_logout_ends_sessions_recorded_without_sid(self):
        # If the provider left sid out of the id_token, fall back to the subject.
        client, _ = self.sign_in(sid=None)
        access = self.access_for(client)

        self.assertEqual(self.send_logout(self.logout_claims(sid="sid-unknown")).status_code, 200)

        self.assertEqual(self.api_status(access), 401)

    def test_logout_for_someone_else_changes_nothing(self):
        client, _ = self.sign_in(sid="sid-1", sub="zitadel-user-1")
        access = self.access_for(client)

        response = self.send_logout(self.logout_claims(sub="zitadel-user-2", sid="sid-9"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.api_status(access), 200)

    def test_rotated_refresh_token_keeps_the_session_tag(self):
        client, _ = self.sign_in(sid="sid-1")
        refresh_response = client.post("/api/auth/token/refresh/", {}, format="json")
        rotated = RefreshToken(refresh_response.cookies["questiz_refresh"].value)
        self.assertEqual(rotated[sso.SSO_SESSION_CLAIM], str(SsoSession.objects.get().id))

        self.send_logout()

        self.assertEqual(client.post("/api/auth/token/refresh/", {}, format="json").status_code, 401)

    def test_password_sessions_are_not_affected(self):
        from django.contrib.auth import get_user_model

        get_user_model().objects.create_user(
            username="local", email="local@example.com", password="Str0ng-pass!", email_verified=True
        )
        login = APIClient().post(
            "/api/auth/login/", {"username": "local", "password": "Str0ng-pass!"}, format="json"
        )
        access = login.json()["access_token"]

        self.send_logout(self.logout_claims(sid=None))

        self.assertEqual(self.api_status(access), 200)

    def test_ended_state_survives_a_cache_flush(self):
        client, _ = self.sign_in(sid="sid-1")
        access = self.access_for(client)
        self.send_logout()
        cache.clear()
        self.assertEqual(self.api_status(access), 401)

    # --- invalid logout tokens are refused and change nothing ------------------------------

    def assertRejected(self, response, client):
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["error"], "invalid_request")
        self.assertIsNone(SsoSession.objects.get().ended_at)
        self.assertEqual(client.post("/api/auth/token/refresh/", {}, format="json").status_code, 200)

    def test_rejects_token_signed_by_another_key(self):
        client, _ = self.sign_in()
        self.mock.replace("GET", JWKS_URI, json={"keys": [SIGNING_KEY.as_dict(private=False)]})
        forged = self.sign(self.logout_claims(), key=OTHER_KEY)
        # OTHER_KEY's kid is unknown: one forced JWKS refresh, still unknown, refused.
        self.assertRejected(self.send_logout(raw=forged), client)

    def test_rejects_bad_claims(self):
        client, _ = self.sign_in()
        now = int(time.time())
        cases = {
            "wrong issuer": {"iss": "https://evil.example"},
            "wrong audience": {"aud": ["someone-else"]},
            "nonce present": {"nonce": "n"},
            "missing event": {"events": {"something-else": {}}},
            "missing jti": {"jti": None},
            "too old": {"iat": now - 3600, "exp": None},
            "from the future": {"iat": now + 3600},
            "expired": {"exp": now - 600},
            "no sub or sid": {"sub": None, "sid": None},
        }
        for label, overrides in cases.items():
            with self.subTest(label):
                self.assertRejected(self.send_logout(self.logout_claims(**overrides)), client)

    def test_rejects_garbage_and_missing_token(self):
        client, _ = self.sign_in()
        self.assertRejected(self.send_logout(raw="not-a-jwt"), client)
        self.assertRejected(APIClient().post(BACKCHANNEL_URL, {}), client)

    def test_rejects_hs256_token(self):
        from joserfc import jwt
        from joserfc.jwk import OctKey

        client, _ = self.sign_in()
        hs_token = jwt.encode({"alg": "HS256"}, self.logout_claims(), OctKey.import_key("x" * 32))
        self.assertRejected(self.send_logout(raw=hs_token), client)

    def test_replayed_token_is_refused(self):
        self.sign_in()
        token = self.sign(self.logout_claims(jti="once"))
        self.assertEqual(self.send_logout(raw=token).status_code, 200)
        self.assertEqual(self.send_logout(raw=token).status_code, 400)

    def test_signing_key_rotation_refetches_jwks(self):
        client, _ = self.sign_in()
        access = self.access_for(client)
        self.mock.replace(
            "GET",
            JWKS_URI,
            json={"keys": [SIGNING_KEY.as_dict(private=False), OTHER_KEY.as_dict(private=False)]},
        )
        response = self.send_logout(key=OTHER_KEY)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.api_status(access), 401)


@override_settings(SSO_ENABLED=False, CACHES=SSO_SETTINGS["CACHES"])
class BackchannelLogoutDisabledTests(SSOTestBase):
    def test_404_when_sso_is_off(self):
        self.assertEqual(APIClient().post(BACKCHANNEL_URL, {"logout_token": "x"}).status_code, 404)
