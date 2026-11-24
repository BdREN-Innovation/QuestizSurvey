"""Plans and payments managed by bdren.ai (``BILLING_MODE=bdren``).

In this mode Questiz takes no payments and keeps no subscriptions of its own. bdren.ai owns
packages, subscriptions and payments; Questiz asks it what one person may use (the *allowance*,
``POST {BDREN_API_URL}/api/v1/entitlements/allowance/``, authenticated by the product's
``X-Product-Api-Key``) and enforces the limits locally. bdren.ai sends a signed webhook whenever an
answer may have changed, and Questiz then drops its cached answer.

The person is named by the (issuer, subject) of their linked bdren.ai SSO identity. Accounts with
no linked identity, people bdren.ai does not know, and answers that cannot be fetched for longer
than ``BDREN_ALLOWANCE_STALE_SECONDS`` all get the local Free plan's limits: never unlimited.

Feature keys of the ``questiz`` product in bdren.ai (each a count, whatever period it is stored
under; the smallest value wins when several periods are set):

- ``surveys``: surveys a person may own in total.
- ``questions_per_survey``: questions in one survey.
- ``responses_per_survey``: completed responses one survey accepts.

A feature missing from the answer falls back to the Free plan's value for that limit. A value of
0 means none is allowed. To give a package no practical cap, set a large number.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

MODE_LOCAL = "local"
MODE_BDREN = "bdren"

FEATURE_SURVEYS = "surveys"
FEATURE_QUESTIONS = "questions_per_survey"
FEATURE_RESPONSES = "responses_per_survey"

PLAN_FIELDS = {
    "max_surveys": FEATURE_SURVEYS,
    "max_questions_per_survey": FEATURE_QUESTIONS,
    "max_responses_per_survey": FEATURE_RESPONSES,
}

GONE_CODE = "managed_in_bdren"
WEBHOOK_REPLAY_WINDOW_SECONDS = 300
WEBHOOK_DEDUPE_SECONDS = 7 * 24 * 3600

_GENERATION_KEY = "bdren:allowance:generation"


def is_bdren_mode():
    return getattr(settings, "BILLING_MODE", MODE_LOCAL) == MODE_BDREN


def manage_url():
    return getattr(settings, "BDREN_UPGRADE_URL", "") or ""


def public_config():
    """What the frontend needs to know about billing (public; no secrets)."""
    bdren = is_bdren_mode()
    return {
        "mode": MODE_BDREN if bdren else MODE_LOCAL,
        "manage_url": manage_url() if bdren else "",
        "provider_label": getattr(settings, "SSO_PROVIDER_LABEL", "bdren.ai") if bdren else "",
    }


def gone_payload():
    return {
        "detail": "Plans and payments are managed on bdren.ai.",
        "code": GONE_CODE,
        "manage_url": manage_url(),
    }


# --------------------------------------------------------------------------- effective plan


@dataclass(frozen=True)
class EffectivePlan:
    """The limits that apply to one person right now. ``None`` means no limit."""

    name: str
    slug: str
    tier: int
    max_surveys: Optional[int]
    max_questions_per_survey: Optional[int]
    max_responses_per_survey: Optional[int]
    source: str = "local"  # local | bdren | bdren_fallback
    id: Optional[str] = None
    extra: dict = field(default_factory=dict, compare=False)

    @classmethod
    def from_plan(cls, plan, *, source="local", extra=None):
        # Local plans store 0 for "no limit".
        return cls(
            name=plan.name,
            slug=plan.slug,
            tier=plan.tier,
            max_surveys=plan.max_surveys or None,
            max_questions_per_survey=plan.max_questions_per_survey or None,
            max_responses_per_survey=plan.max_responses_per_survey or None,
            source=source,
            id=str(plan.id),
            extra=extra or {},
        )

    def summary(self):
        return {"id": self.id, "name": self.name, "slug": self.slug, "tier": self.tier}


def _limit_from(limits, feature_key):
    """The count for one feature from the allowance ``limits``, or the sentinel ``...`` if absent."""
    periods = limits.get(feature_key)
    if not isinstance(periods, dict) or not periods:
        return ...
    values = []
    for value in periods.values():
        try:
            values.append(max(int(value), 0))
        except (TypeError, ValueError):
            continue
    return min(values) if values else ...


def plan_from_allowance(allowance, free_plan):
    """Build the effective plan from an allowance answer; absent limits take the Free plan's."""
    free = EffectivePlan.from_plan(free_plan)
    limits = allowance.get("limits") if isinstance(allowance.get("limits"), dict) else {}
    values = {}
    for plan_field, feature_key in PLAN_FIELDS.items():
        value = _limit_from(limits, feature_key)
        values[plan_field] = getattr(free, plan_field) if value is ... else value

    package = allowance.get("package") if isinstance(allowance.get("package"), dict) else {}
    institution = allowance.get("institution") if isinstance(allowance.get("institution"), dict) else None
    return EffectivePlan(
        name=str(package.get("name") or free.name),
        slug=str(package.get("slug") or free.slug),
        tier=0,
        source="bdren",
        extra={
            "plan_source": allowance.get("plan_source") or "",
            "institution": (
                {"name": institution.get("name", ""), "slug": institution.get("slug", "")}
                if institution
                else None
            ),
            "renews": allowance.get("renews") or "",
            "upgrade_url": allowance.get("upgrade_url") or manage_url(),
        },
        **values,
    )


def effective_plan(user, free_plan):
    """The bdren.ai-managed plan for ``user``; the Free plan when no answer is available."""
    allowance = get_allowance(user)
    if allowance is None:
        return EffectivePlan.from_plan(
            free_plan,
            source="bdren_fallback",
            extra={"upgrade_url": manage_url(), "plan_source": "", "institution": None, "renews": ""},
        )
    return plan_from_allowance(allowance, free_plan)


# --------------------------------------------------------------------------- allowance client


def _identity_for(user):
    from accounts.models import ExternalIdentity

    issuer = getattr(settings, "SSO_ISSUER", "")
    if not issuer or user is None or not getattr(user, "pk", None):
        return None
    return (
        ExternalIdentity.objects.filter(user=user, issuer=issuer)
        .values_list("issuer", "subject")
        .first()
    )


def _generation():
    return cache.get(_GENERATION_KEY, 0)


def _cache_key(issuer, subject, generation=None):
    digest = hashlib.sha256(f"{issuer}|{subject}".encode()).hexdigest()[:32]
    gen = _generation() if generation is None else generation
    return f"bdren:allowance:{gen}:{digest}"


def _allowance_url():
    return f"{settings.BDREN_API_URL}/api/v1/entitlements/allowance/"


def _request_allowance(issuer, subject, *, etag="", id_token=""):
    headers = {
        "X-Product-Api-Key": settings.BDREN_PRODUCT_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if etag:
        headers["If-None-Match"] = f'"{etag}"'
    body = {"issuer": issuer, "zitadel_subject": subject}
    if settings.BDREN_PRODUCT_SLUG:
        body["product"] = settings.BDREN_PRODUCT_SLUG
    if id_token:
        body["id_token"] = id_token
    return requests.post(
        _allowance_url(),
        json=body,
        headers=headers,
        timeout=settings.BDREN_HTTP_TIMEOUT,
        allow_redirects=False,
    )


def get_allowance(user, *, id_token="", force=False):
    """The cached allowance answer for ``user``, or ``None`` (use the Free plan).

    Fresh answers are reused for ``BDREN_ALLOWANCE_CACHE_SECONDS`` and then revalidated with the
    ETag. When bdren.ai cannot be reached the last answer is kept for at most
    ``BDREN_ALLOWANCE_STALE_SECONDS``.
    """
    identity = _identity_for(user)
    if identity is None:
        return None
    issuer, subject = identity
    key = _cache_key(issuer, subject)
    entry = cache.get(key)
    now = time.time()

    if entry and not force and not id_token:
        if now - entry["fetched_at"] < settings.BDREN_ALLOWANCE_CACHE_SECONDS:
            return entry["body"]

    def keep_stale():
        if entry and now - entry["fetched_at"] < settings.BDREN_ALLOWANCE_STALE_SECONDS:
            return entry["body"]
        return None

    def store(body, etag=""):
        cache.set(
            key,
            {"body": body, "etag": etag, "fetched_at": now},
            timeout=settings.BDREN_ALLOWANCE_STALE_SECONDS,
        )
        return body

    etag = (entry or {}).get("etag", "") if entry and entry.get("body") is not None else ""
    try:
        response = _request_allowance(issuer, subject, etag=etag, id_token=id_token)
    except requests.RequestException as exc:
        logger.warning("bdren.ai allowance request failed: %s", exc.__class__.__name__)
        return keep_stale()

    if response.status_code == 304 and entry:
        return store(entry["body"], entry.get("etag", ""))
    if response.status_code == 200:
        try:
            body = response.json()
        except ValueError:
            logger.warning("bdren.ai allowance answer is not JSON")
            return keep_stale()
        if not isinstance(body, dict):
            return keep_stale()
        new_etag = str(body.get("etag") or response.headers.get("ETag", "")).strip('"')
        return store(body, new_etag)
    if response.status_code == 404:
        # bdren.ai does not know this person (yet): Free, rechecked after the cache period.
        return store(None)

    logger.warning("bdren.ai allowance answered HTTP %s", response.status_code)
    return keep_stale()


def prime_after_sign_in(user, id_token):
    """Refresh the allowance at SSO sign-in, passing the ID token so bdren.ai can provision a person
    whose first sign-in anywhere is to Questiz. Never fails the sign-in."""
    if not is_bdren_mode():
        return
    try:
        get_allowance(user, id_token=id_token or "", force=True)
    except Exception:  # pragma: no cover - defensive; sign-in must not fail on billing
        logger.exception("bdren.ai allowance refresh at sign-in failed")


def forget_subject(issuer, subject):
    cache.delete(_cache_key(issuer, subject))


def forget_everyone():
    """Invalidate every cached answer (an institution or package changed)."""
    try:
        cache.incr(_GENERATION_KEY)
    except ValueError:
        cache.set(_GENERATION_KEY, 1, timeout=None)


# --------------------------------------------------------------------------- webhooks


def _webhook_secrets():
    raw = getattr(settings, "BDREN_WEBHOOK_SECRET", "") or ""
    return [s.strip() for s in raw.split(",") if s.strip()]


def verify_signature(signature_header, timestamp, body: bytes, *, now=None):
    secrets_ = _webhook_secrets()
    if not secrets_ or not signature_header or not timestamp:
        return False
    try:
        signed_at = int(timestamp)
    except (TypeError, ValueError):
        return False
    now = time.time() if now is None else now
    if abs(now - signed_at) > WEBHOOK_REPLAY_WINDOW_SECONDS:
        return False
    given = [p.strip()[3:] for p in signature_header.split(",") if p.strip().startswith("v1=")]
    for secret in secrets_:
        expected = hmac.new(
            secret.encode(), f"{signed_at}.".encode() + body, hashlib.sha256
        ).hexdigest()
        if any(hmac.compare_digest(expected, candidate) for candidate in given):
            return True
    return False


def handle_event(event):
    """Apply one verified webhook event. Every event only means "refresh"; returns what was done."""
    event_id = str(event.get("id") or "")
    if event_id and not cache.add(f"bdren:webhook:event:{event_id}", 1, WEBHOOK_DEDUPE_SECONDS):
        return "duplicate"

    product = event.get("product")
    if product and settings.BDREN_PRODUCT_SLUG and product != settings.BDREN_PRODUCT_SLUG:
        return "ignored"

    user = event.get("user") if isinstance(event.get("user"), dict) else None
    organization = event.get("organization")
    if organization or not user or event.get("type") == "package.version_published":
        forget_everyone()
        return "refresh_all"

    issuer, subject = user.get("issuer"), user.get("subject")
    if not issuer or not subject:
        forget_everyone()
        return "refresh_all"
    forget_subject(str(issuer), str(subject))
    return "refresh_user"
