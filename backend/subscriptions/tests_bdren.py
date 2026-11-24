"""BILLING_MODE=bdren: limits come from the bdren.ai allowance API, payments are refused here."""

import hashlib
import hmac
import json
import time
from unittest import mock

import requests
import responses
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import ExternalIdentity
from surveys.models import Survey

from . import bdren
from .models import Plan
from .services import LicenseService

User = get_user_model()

ISSUER = "https://auth.example.test"
API = "https://bdren.example.test"
ALLOWANCE_URL = f"{API}/api/v1/entitlements/allowance/"
WEBHOOK_SECRET = "whsec-test"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "bdren-tests"}}

BDREN_SETTINGS = dict(
    BILLING_MODE="bdren",
    SSO_ENABLED=True,
    SSO_ISSUER=ISSUER,
    BDREN_API_URL=API,
    BDREN_PRODUCT_API_KEY="bdren_prod_questiz_test",
    BDREN_PRODUCT_SLUG="questiz",
    BDREN_WEBHOOK_SECRET=WEBHOOK_SECRET,
    BDREN_UPGRADE_URL="https://bdren.example.test/profile/billing",
    BDREN_HTTP_TIMEOUT=2,
    BDREN_ALLOWANCE_CACHE_SECONDS=600,
    BDREN_ALLOWANCE_STALE_SECONDS=86400,
    CACHES=LOCMEM,
)


def allowance(limits, *, package=("pro", "Pro"), etag="e1", plan_source="personal"):
    return {
        "product": "questiz",
        "plan_source": plan_source,
        "package": {"slug": package[0], "name": package[1], "version": 1},
        "institution": None,
        "limits": limits,
        "renews": "monthly",
        "upgrade_url": "https://bdren.example.test/profile/billing",
        "etag": etag,
    }


SURVEY_BODY = {
    "title": "New survey",
    "description": "",
    "theme": {},
    "settings": {},
    "welcome_page": {},
    "thank_you_page": {},
}


@override_settings(**BDREN_SETTINGS)
class BdrenLimitsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.free_plan = Plan.objects.get(slug="free")
        self.user = User.objects.create_user(
            username="member", email="member@example.com", password="TestPass123!"
        )
        ExternalIdentity.objects.create(
            user=self.user,
            issuer=ISSUER,
            subject="sub-1",
            linked_via=ExternalIdentity.LinkedVia.SIGNUP,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @responses.activate
    def test_limits_come_from_the_allowance(self):
        responses.post(
            ALLOWANCE_URL,
            json=allowance({"surveys": {"lifetime": 1}, "questions_per_survey": {"lifetime": 50}}),
        )
        Survey.objects.create(user=self.user, title="Existing")

        response = self.client.post("/api/surveys/", SURVEY_BODY, format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["code"], "plan_limit")
        self.assertIn("bdren.ai", response.data["detail"])
        sent = responses.calls[0].request
        self.assertEqual(sent.headers["X-Product-Api-Key"], "bdren_prod_questiz_test")
        self.assertEqual(
            json.loads(sent.body),
            {"issuer": ISSUER, "zitadel_subject": "sub-1", "product": "questiz"},
        )

    @responses.activate
    def test_usage_shows_bdren_plan_and_missing_features_fall_back_to_free(self):
        responses.post(ALLOWANCE_URL, json=allowance({"surveys": {"lifetime": 40}}))

        data = self.client.get("/api/subscription/usage/").data

        self.assertEqual(data["plan"]["slug"], "pro")
        self.assertEqual(data["surveys"]["limit"], 40)
        self.assertFalse(data["surveys"]["unlimited"])
        self.assertEqual(
            data["responses_per_survey"]["limit"], self.free_plan.max_responses_per_survey
        )
        self.assertEqual(data["billing"]["mode"], "bdren")
        self.assertEqual(data["billing"]["plan_source"], "personal")

    @responses.activate
    def test_zero_means_none_allowed_not_unlimited(self):
        responses.post(ALLOWANCE_URL, json=allowance({"surveys": {"monthly": 0}}))

        response = self.client.post("/api/surveys/", SURVEY_BODY, format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @responses.activate
    def test_answers_are_cached_and_revalidated_with_etag(self):
        responses.post(ALLOWANCE_URL, json=allowance({"surveys": {"lifetime": 5}}, etag="abc"))
        bdren.get_allowance(self.user)
        bdren.get_allowance(self.user)
        self.assertEqual(len(responses.calls), 1)

        responses.replace(responses.POST, ALLOWANCE_URL, status=304)
        later = time.time() + 601
        with mock.patch("subscriptions.bdren.time.time", return_value=later):
            body = bdren.get_allowance(self.user)
        self.assertEqual(body["limits"], {"surveys": {"lifetime": 5}})
        self.assertEqual(responses.calls[1].request.headers["If-None-Match"], '"abc"')

    @responses.activate
    def test_unreachable_keeps_last_answer_then_falls_back_to_free(self):
        responses.post(ALLOWANCE_URL, json=allowance({"surveys": {"lifetime": 99}}))
        bdren.get_allowance(self.user)
        responses.replace(responses.POST, ALLOWANCE_URL, body=requests.ConnectionError("down"))

        with mock.patch("subscriptions.bdren.time.time", return_value=time.time() + 3600):
            self.assertEqual(LicenseService.get_effective_plan(self.user).max_surveys, 99)
        with mock.patch("subscriptions.bdren.time.time", return_value=time.time() + 90000):
            plan = LicenseService.get_effective_plan(self.user)
        self.assertEqual(plan.slug, "free")
        self.assertEqual(plan.max_surveys, self.free_plan.max_surveys or None)

    @responses.activate
    def test_unknown_person_and_unlinked_account_get_free(self):
        responses.post(ALLOWANCE_URL, status=404, json={"error": "user_not_found"})
        self.assertEqual(LicenseService.get_effective_plan(self.user).source, "bdren_fallback")

        password_only = User.objects.create_user(
            username="local", email="local@example.com", password="TestPass123!"
        )
        plan = LicenseService.get_effective_plan(password_only)
        self.assertEqual(plan.slug, "free")
        self.assertEqual(len(responses.calls), 1)  # no call for an account with no bdren.ai link

    @responses.activate
    def test_sign_in_priming_sends_id_token_and_bypasses_cache(self):
        responses.post(ALLOWANCE_URL, json=allowance({"surveys": {"lifetime": 3}}))
        bdren.get_allowance(self.user)
        bdren.prime_after_sign_in(self.user, "header.payload.sig")
        self.assertEqual(len(responses.calls), 2)
        self.assertEqual(json.loads(responses.calls[1].request.body)["id_token"], "header.payload.sig")

    def test_new_checkouts_are_refused(self):
        pro = Plan.objects.get(slug="pro")
        for url in ("/api/payments/stripe/create-checkout/", "/api/payments/bkash/create/"):
            response = self.client.post(
                url, {"plan_id": str(pro.id), "billing_cycle": "monthly"}, format="json"
            )
            self.assertEqual(response.status_code, status.HTTP_410_GONE, url)
            self.assertEqual(response.json()["code"], "managed_in_bdren")

    def test_billing_config_is_public(self):
        response = APIClient().get("/api/billing/config/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["mode"], "bdren")
        self.assertEqual(response.data["manage_url"], "https://bdren.example.test/profile/billing")

    def test_admin_cannot_override_plan(self):
        admin = User.objects.create_superuser(
            username="root", email="root@example.com", password="TestPass123!"
        )
        client = APIClient()
        client.force_authenticate(admin)
        pro = Plan.objects.get(slug="pro")
        with mock.patch("accounts.admin_views.AdminAPIView.throttle_classes", []):
            response = client.patch(
                f"/api/admin/users/{self.user.id}/", {"plan_id": str(pro.id)}, format="json"
            )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["code"], "managed_in_bdren")


def signed(body: bytes, *, secret=WEBHOOK_SECRET, at=None):
    at = int(time.time()) if at is None else at
    sig = hmac.new(secret.encode(), f"{at}.".encode() + body, hashlib.sha256).hexdigest()
    return {"HTTP_X_BDREN_SIGNATURE": f"v1={sig}", "HTTP_X_BDREN_TIMESTAMP": str(at)}


@override_settings(**BDREN_SETTINGS)
class BdrenWebhookTests(TestCase):
    url = "/api/billing/bdren/webhook/"

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def post(self, event, **headers):
        body = json.dumps(event).encode()
        return self.client.generic(
            "POST", self.url, body, content_type="application/json", **(headers or signed(body))
        )

    def test_user_event_drops_that_persons_cached_answer(self):
        key = bdren._cache_key(ISSUER, "sub-1")
        cache.set(key, {"body": {}, "etag": "", "fetched_at": time.time()})
        event = {
            "id": "ev-1",
            "type": "subscription.limits_changed",
            "product": "questiz",
            "user": {"issuer": ISSUER, "subject": "sub-1"},
            "organization": None,
        }
        response = self.post(event)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], "refresh_user")
        self.assertIsNone(cache.get(key))

        self.assertEqual(self.post(event).json()["result"], "duplicate")

    def test_organization_event_invalidates_everyone(self):
        key = bdren._cache_key(ISSUER, "sub-2")
        cache.set(key, {"body": {}, "etag": "", "fetched_at": time.time()})
        event = {"id": "ev-2", "type": "membership.coverage_changed", "organization": {"id": "o", "slug": "du"}}
        self.assertEqual(self.post(event).json()["result"], "refresh_all")
        self.assertIsNone(cache.get(bdren._cache_key(ISSUER, "sub-2")))

    def test_bad_or_old_signatures_are_rejected(self):
        body = json.dumps({"id": "ev-3"}).encode()
        wrong = signed(body, secret="other")
        old = signed(body, at=int(time.time()) - 400)
        for headers in (wrong, old, {}):
            response = self.client.generic(
                "POST", self.url, body, content_type="application/json", **headers
            )
            self.assertEqual(response.status_code, 400)

    @override_settings(BILLING_MODE="local")
    def test_not_found_in_local_mode(self):
        self.assertEqual(self.post({"id": "x"}).status_code, 404)


@override_settings(CACHES=LOCMEM, BILLING_MODE="local")
class LocalModeUnchangedTests(TestCase):
    def test_billing_config_local(self):
        self.assertEqual(APIClient().get("/api/billing/config/").data["mode"], "local")

    @responses.activate
    def test_no_bdren_calls_in_local_mode(self):
        user = User.objects.create_user(username="u", email="u@example.com", password="TestPass123!")
        plan = LicenseService.get_effective_plan(user)
        self.assertEqual(plan.slug, "free")
        self.assertEqual(len(responses.calls), 0)
