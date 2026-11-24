"""Single sign-on tests against a mocked OpenID Connect provider (discovery, JWKS, token endpoint)."""

import time
from urllib.parse import parse_qs, urlsplit

import responses
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from . import sso
from .models import ExternalIdentity

User = get_user_model()

ISSUER = "https://auth.example.test"
CLIENT_ID = "questiz-client"
REDIRECT_URI = "http://testserver/api/auth/sso/callback/"
TOKEN_ENDPOINT = f"{ISSUER}/oauth/v2/token"
JWKS_URI = f"{ISSUER}/oauth/v2/keys"
END_SESSION = f"{ISSUER}/oidc/v1/end_session"

SSO_SETTINGS = dict(
    SSO_ENABLED=True,
    SSO_PROVIDER_LABEL="bdren.ai",
    SSO_ISSUER=ISSUER,
    SSO_CLIENT_ID=CLIENT_ID,
    SSO_CLIENT_SECRET="secret",
    SSO_SCOPES="openid profile email",
    SSO_REDIRECT_URI=REDIRECT_URI,
    SSO_ALLOW_SIGNUP=True,
    SSO_LINK_BY_VERIFIED_EMAIL=False,
    SSO_CLAIM_ORGANIZATION="urn:zitadel:iam:user:resourceowner:name",
    SSO_RP_LOGOUT=False,
    SSO_POST_LOGOUT_REDIRECT_URI="",
    SSO_RATE_LIMIT="1000/min",
    PUBLIC_APP_URL="http://localhost:5555",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)

SIGNING_KEY = RSAKey.generate_key(2048, parameters={"kid": "key-1", "use": "sig", "alg": "RS256"})
OTHER_KEY = RSAKey.generate_key(2048, parameters={"kid": "key-2", "use": "sig", "alg": "RS256"})


def discovery_document():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/v2/authorize",
        "token_endpoint": TOKEN_ENDPOINT,
        "jwks_uri": JWKS_URI,
        "end_session_endpoint": END_SESSION,
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@override_settings(**SSO_SETTINGS)
class SSOTestBase(TestCase):
    def setUp(self):
        cache.clear()
        sso._client_cache.clear()
        self.client = APIClient()
        self.mock = responses.RequestsMock(assert_all_requests_are_fired=False)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.addCleanup(self.mock.reset)
        self.mock.get(f"{ISSUER}/.well-known/openid-configuration", json=discovery_document())
        self.mock.get(JWKS_URI, json={"keys": [SIGNING_KEY.as_dict(private=False)]})

    # --- helpers ---------------------------------------------------------------------------

    def claims(self, nonce_value, **overrides):
        now = int(time.time())
        base = {
            "iss": ISSUER,
            "sub": "zitadel-user-1",
            "aud": [CLIENT_ID],
            "azp": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "nonce": nonce_value,
            "email": "person@du.ac.bd",
            "email_verified": True,
            "given_name": "Rahim",
            "family_name": "Uddin",
            "urn:zitadel:iam:user:resourceowner:name": "University of Dhaka",
        }
        base.update(overrides)
        return {key: value for key, value in base.items() if value is not None}

    def start(self, path="/api/auth/sso/login/?next=/surveys/abc"):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 302, response.content)
        query = parse_qs(urlsplit(response["Location"]).query)
        return response, query

    def sign(self, claims, key=SIGNING_KEY, alg="RS256"):
        header = {"alg": alg}
        if alg.startswith("RS"):
            header["kid"] = key.kid
        return jwt.encode(header, claims, key)

    def finish(self, claim_overrides=None, *, start_path=None, id_token=None, state=None):
        _, query = self.start(start_path) if start_path else self.start()
        nonce = query["nonce"][0]
        if id_token is None:
            id_token = self.sign(self.claims(nonce, **(claim_overrides or {})))
        self.mock.post(
            TOKEN_ENDPOINT,
            json={"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token},
        )
        return self.client.get(
            "/api/auth/sso/callback/",
            {"code": "auth-code", "state": state or query["state"][0]},
        )

    def assertSignedIn(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertIn("questiz_refresh", response.cookies)
        self.assertTrue(response.cookies["questiz_refresh"].value)
        token = RefreshToken(response.cookies["questiz_refresh"].value)
        self.assertEqual(token.get(sso.AUTH_METHOD_CLAIM), sso.AUTH_METHOD_SSO)
        return User.objects.get(pk=token["user_id"])

    def assertFailed(self, response, code, *, path="/login"):
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, path)
        self.assertEqual(parse_qs(location.query).get("sso_error"), [code])
        cookie = response.cookies.get("questiz_refresh")
        self.assertTrue(cookie is None or not cookie.value)


@override_settings(SSO_ENABLED=False, CACHES=SSO_SETTINGS["CACHES"])
class SSODisabledTests(TestCase):
    def test_endpoints_404_and_config_says_disabled(self):
        client = APIClient()
        self.assertEqual(client.get("/api/auth/sso/config/").json()["enabled"], False)
        self.assertEqual(client.get("/api/auth/sso/login/").status_code, 404)
        self.assertEqual(client.get("/api/auth/sso/callback/?code=x&state=y").status_code, 404)

    def test_password_login_unchanged(self):
        User.objects.create_user(
            username="local", email="local@example.com", password="Str0ng-pass!", email_verified=True
        )
        response = APIClient().post(
            "/api/auth/login/", {"username": "local", "password": "Str0ng-pass!"}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["user"]["sso_linked"])
        self.assertTrue(response.json()["user"]["has_usable_password"])


class SSOSignInTests(SSOTestBase):
    def test_config(self):
        self.assertEqual(
            self.client.get("/api/auth/sso/config/").json(),
            {"enabled": True, "label": "bdren.ai", "allow_signup": True},
        )

    def test_authorize_redirect_uses_pkce_state_and_nonce(self):
        response, query = self.start()
        self.assertTrue(response["Location"].startswith(f"{ISSUER}/oauth/v2/authorize?"))
        self.assertEqual(query["client_id"], [CLIENT_ID])
        self.assertEqual(query["redirect_uri"], [REDIRECT_URI])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        for key in ("state", "nonce", "code_challenge"):
            self.assertTrue(query[key][0])

    def test_new_user_created_and_signed_in(self):
        response = self.finish()
        user = self.assertSignedIn(response)
        location = urlsplit(response["Location"])
        self.assertEqual(
            f"{location.scheme}://{location.netloc}{location.path}",
            "http://localhost:5555/auth/sso/complete",
        )
        self.assertEqual(parse_qs(location.query)["next"], ["/surveys/abc"])
        self.assertEqual(user.email, "person@du.ac.bd")
        self.assertTrue(user.email_verified)
        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.first_name, "Rahim")
        self.assertEqual(user.organization, "University of Dhaka")
        identity = ExternalIdentity.objects.get(user=user)
        self.assertEqual((identity.issuer, identity.subject), (ISSUER, "zitadel-user-1"))
        self.assertEqual(identity.linked_via, ExternalIdentity.LinkedVia.SIGNUP)

    def test_returning_user_matched_by_subject_not_email(self):
        first = self.assertSignedIn(self.finish())
        second = self.assertSignedIn(self.finish({"email": "changed@du.ac.bd"}))
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(User.objects.count(), 1)

    def test_signed_in_user_can_load_profile_through_refresh(self):
        response = self.finish()
        self.assertSignedIn(response)
        refreshed = self.client.post("/api/auth/token/refresh/", {}, format="json")
        self.assertEqual(refreshed.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refreshed.json()['access']}")
        me = self.client.get("/api/auth/user/").json()
        self.assertTrue(me["sso_linked"])
        self.assertFalse(me["has_usable_password"])

    @override_settings(SSO_ALLOW_SIGNUP=False)
    def test_signup_disabled_refuses_unknown_person(self):
        self.assertFailed(self.finish(), sso.ERROR_SIGNUP_DISABLED)
        self.assertEqual(User.objects.count(), 0)

    def test_unverified_provider_email_refused(self):
        self.assertFailed(self.finish({"email_verified": False}), sso.ERROR_EMAIL_UNVERIFIED)

    def test_inactive_linked_user_refused(self):
        user = self.assertSignedIn(self.finish())
        user.is_active = False
        user.save()
        self.assertFailed(self.finish(), sso.ERROR_ACCOUNT_DISABLED)

    def test_unsafe_next_falls_back(self):
        for bad in ("https://evil.example/x", "//evil.example", "/\\evil"):
            response = self.finish(start_path=f"/api/auth/sso/login/?next={bad}")
            self.assertSignedIn(response)
            self.assertEqual(parse_qs(urlsplit(response["Location"]).query)["next"], ["/dashboard"])


class SSOTokenValidationTests(SSOTestBase):
    def test_wrong_state(self):
        self.assertFailed(self.finish(state="forged"), sso.ERROR_STATE)

    def test_state_is_single_use(self):
        _, query = self.start()
        token = self.sign(self.claims(query["nonce"][0]))
        self.mock.post(TOKEN_ENDPOINT, json={"access_token": "at", "token_type": "Bearer", "id_token": token})
        params = {"code": "c", "state": query["state"][0]}
        self.assertSignedIn(self.client.get("/api/auth/sso/callback/", params))
        self.assertFailed(self.client.get("/api/auth/sso/callback/", params), sso.ERROR_STATE)

    def test_callback_from_another_browser(self):
        _, query = self.start()
        other = APIClient()
        response = other.get("/api/auth/sso/callback/", {"code": "c", "state": query["state"][0]})
        self.assertFailed(response, sso.ERROR_STATE)

    def test_wrong_nonce(self):
        self.assertFailed(self.finish({"nonce": "other"}), sso.ERROR_TOKEN)

    def test_wrong_audience(self):
        self.assertFailed(self.finish({"aud": ["someone-else"], "azp": "someone-else"}), sso.ERROR_TOKEN)

    def test_wrong_issuer(self):
        self.assertFailed(self.finish({"iss": "https://evil.example"}), sso.ERROR_TOKEN)

    def test_expired_token(self):
        past = int(time.time()) - 3600
        self.assertFailed(self.finish({"exp": past, "iat": past - 60}), sso.ERROR_TOKEN)

    def test_token_signed_by_unknown_key(self):
        _, query = self.start()
        bad = self.sign(self.claims(query["nonce"][0]), key=OTHER_KEY)
        self.mock.post(TOKEN_ENDPOINT, json={"access_token": "at", "token_type": "Bearer", "id_token": bad})
        response = self.client.get("/api/auth/sso/callback/", {"code": "c", "state": query["state"][0]})
        self.assertFailed(response, sso.ERROR_TOKEN)

    def test_hs256_token_refused(self):
        _, query = self.start()
        hs = self.sign(self.claims(query["nonce"][0]), key=OctKey.import_key("secret" * 8), alg="HS256")
        self.mock.post(TOKEN_ENDPOINT, json={"access_token": "at", "token_type": "Bearer", "id_token": hs})
        response = self.client.get("/api/auth/sso/callback/", {"code": "c", "state": query["state"][0]})
        self.assertFailed(response, sso.ERROR_TOKEN)

    def test_provider_error_parameter(self):
        _, query = self.start()
        response = self.client.get(
            "/api/auth/sso/callback/", {"error": "access_denied", "state": query["state"][0]}
        )
        self.assertFailed(response, sso.ERROR_PROVIDER)

    def test_token_endpoint_failure(self):
        _, query = self.start()
        self.mock.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})
        response = self.client.get("/api/auth/sso/callback/", {"code": "c", "state": query["state"][0]})
        self.assertFailed(response, sso.ERROR_PROVIDER)


class SSOExistingAccountTests(SSOTestBase):
    def setUp(self):
        super().setUp()
        self.local = User.objects.create_user(
            username="rahim",
            email="person@du.ac.bd",
            password="Str0ng-pass!",
            email_verified=True,
        )

    def test_email_in_use_refused_without_opt_in(self):
        self.assertFailed(self.finish(), sso.ERROR_EMAIL_IN_USE)
        self.assertEqual(User.objects.count(), 1)
        self.assertFalse(ExternalIdentity.objects.exists())

    @override_settings(SSO_LINK_BY_VERIFIED_EMAIL=True)
    def test_link_by_verified_email_when_enabled(self):
        user = self.assertSignedIn(self.finish())
        self.assertEqual(user.pk, self.local.pk)
        self.assertTrue(user.has_usable_password())
        self.assertEqual(
            ExternalIdentity.objects.get(user=user).linked_via, ExternalIdentity.LinkedVia.VERIFIED_EMAIL
        )

    @override_settings(SSO_LINK_BY_VERIFIED_EMAIL=True)
    def test_link_by_email_needs_both_sides_verified(self):
        self.local.email_verified = False
        self.local.save()
        self.assertFailed(self.finish(), sso.ERROR_EMAIL_IN_USE)
        self.local.email_verified = True
        self.local.save()
        self.assertFailed(self.finish({"email_verified": False}), sso.ERROR_EMAIL_IN_USE)

    def _access(self, user):
        return str(RefreshToken.for_user(user).access_token)

    def _link_token(self, user):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self._access(user)}")
        response = self.client.post("/api/auth/sso/link/", {}, format="json")
        self.client.credentials()
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["link_token"]

    def test_link_from_profile_attaches_to_signed_in_user(self):
        token = self._link_token(self.local)
        response = self.finish(
            {"email": "different@bdren.ai"}, start_path=f"/api/auth/sso/login/?link_token={token}"
        )
        user = self.assertSignedIn(response)
        self.assertEqual(user.pk, self.local.pk)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, "/profile")
        self.assertEqual(parse_qs(location.query)["sso_linked"], ["1"])
        identity = ExternalIdentity.objects.get(user=self.local)
        self.assertEqual(identity.linked_via, ExternalIdentity.LinkedVia.PROFILE)
        # The password login still works after linking.
        login = APIClient().post(
            "/api/auth/login/", {"username": "rahim", "password": "Str0ng-pass!"}, format="json"
        )
        self.assertEqual(login.status_code, 200)

    def test_link_token_is_single_use(self):
        token = self._link_token(self.local)
        self.start(f"/api/auth/sso/login/?link_token={token}")
        response = self.client.get(f"/api/auth/sso/login/?link_token={token}")
        self.assertFailed(response, sso.ERROR_LINK_EXPIRED, path="/profile")

    def test_identity_linked_to_someone_else_refused(self):
        other = User.objects.create_user(
            username="other", email="other@example.com", password="Str0ng-pass!", email_verified=True
        )
        ExternalIdentity.objects.create(
            user=other, issuer=ISSUER, subject="zitadel-user-1", linked_via="profile"
        )
        token = self._link_token(self.local)
        response = self.finish(start_path=f"/api/auth/sso/login/?link_token={token}")
        self.assertFailed(response, sso.ERROR_IDENTITY_TAKEN, path="/profile")

    def test_link_start_refused_when_already_linked(self):
        ExternalIdentity.objects.create(user=self.local, issuer=ISSUER, subject="s", linked_via="profile")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self._access(self.local)}")
        self.assertEqual(self.client.post("/api/auth/sso/link/", {}, format="json").status_code, 409)

    def test_unlink(self):
        ExternalIdentity.objects.create(user=self.local, issuer=ISSUER, subject="s", linked_via="profile")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self._access(self.local)}")
        self.assertEqual(self.client.post("/api/auth/sso/unlink/", {}, format="json").status_code, 200)
        self.assertFalse(ExternalIdentity.objects.exists())

    def test_unlink_refused_without_password(self):
        self.local.set_unusable_password()
        self.local.save()
        ExternalIdentity.objects.create(user=self.local, issuer=ISSUER, subject="s", linked_via="signup")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self._access(self.local)}")
        response = self.client.post("/api/auth/sso/unlink/", {}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertTrue(ExternalIdentity.objects.exists())


class SSOAfterSwitchingOffTests(SSOTestBase):
    def test_sso_user_sets_password_by_reset_once_sso_is_off(self):
        user = self.assertSignedIn(self.finish())
        with override_settings(SSO_ENABLED=False):
            response = APIClient().post(
                "/api/auth/password-reset/request/", {"identifier": user.email}, format="json"
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(APIClient().get("/api/auth/sso/config/").json()["enabled"])
        # The link is kept, so switching SSO back on restores it.
        self.assertTrue(ExternalIdentity.objects.filter(user=user).exists())


class SSOLogoutTests(SSOTestBase):
    @override_settings(SSO_RP_LOGOUT=True)
    def test_logout_returns_provider_url_for_sso_sessions(self):
        self.assertSignedIn(self.finish())
        response = self.client.post("/api/auth/logout/", {}, format="json")
        self.assertTrue(response.json()["sso_logout_url"].startswith(END_SESSION))

    @override_settings(SSO_RP_LOGOUT=True)
    def test_password_session_gets_no_provider_url(self):
        user = User.objects.create_user(
            username="local", email="l@example.com", password="Str0ng-pass!", email_verified=True
        )
        self.client.cookies["questiz_refresh"] = str(RefreshToken.for_user(user))
        response = self.client.post("/api/auth/logout/", {}, format="json")
        self.assertNotIn("sso_logout_url", response.json())

    def test_rp_logout_off_by_default(self):
        self.assertSignedIn(self.finish())
        response = self.client.post("/api/auth/logout/", {}, format="json")
        self.assertNotIn("sso_logout_url", response.json())


@override_settings(CACHES=SSO_SETTINGS["CACHES"])
class RefreshRaceTests(TestCase):
    def test_blacklisted_refresh_is_401_and_keeps_cookie(self):
        cache.clear()
        user = User.objects.create_user(
            username="racer", email="r@example.com", password="Str0ng-pass!", email_verified=True
        )
        client = APIClient()
        client.cookies["questiz_refresh"] = str(RefreshToken.for_user(user))
        first = client.post("/api/auth/token/refresh/", {}, format="json")
        self.assertEqual(first.status_code, 200)
        # A second request still carrying the old (now blacklisted) token, as a parallel tab would.
        stale = APIClient()
        stale.cookies["questiz_refresh"] = first.wsgi_request.COOKIES["questiz_refresh"]
        second = stale.post("/api/auth/token/refresh/", {}, format="json")
        self.assertEqual(second.status_code, 401)
        self.assertNotIn("questiz_refresh", second.cookies)
